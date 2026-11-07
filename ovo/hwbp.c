//
// ovo HWBP 扩展 —— 阶段 1 实现
//
// 模型(与本机已验证的 dits_66_patched.ko 一致, 最低 panic 风险):
//   命中 overflow 回调 → 就地覆盖 GPR(x1=0xff) → 模拟首指令 → PC+=4 → 返回。
//   断点全程保持 enabled, 不停线程, 不禁用。因 PC 跳到入口+4, 不会原地重入;
//   下次函数被调用再次命中。
//
// 关键: register_user_hw_breakpoint / unregister_hw_breakpoint 不在 GKI KMI,
//       直接链接会 CRC 对不上装不了, 故用 ovo_kallsyms_lookup_name 运行时解析。
//
#include "hwbp.h"
#include "kkit.h"

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/sched/signal.h>
#include <linux/pid.h>
#include <linux/rculist.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <linux/uaccess.h>
#include <linux/err.h>
#include <asm/ptrace.h>

#define OVO_HWBP_MAX_THREADS 2048

// register_user_hw_breakpoint 的签名
typedef struct perf_event *(*reg_user_hwbp_fn)(struct perf_event_attr *attr,
					       perf_overflow_handler_t triggered,
					       void *context,
					       struct task_struct *tsk);
typedef void (*unreg_hwbp_fn)(struct perf_event *bp);

static reg_user_hwbp_fn p_register_user_hw_breakpoint;
static unreg_hwbp_fn    p_unregister_hw_breakpoint;

// 每个已安装断点一个节点; 同一 pid 的所有线程共享一个节点(同一覆盖规则)
struct ovo_hwbp_node {
	struct list_head list;
	pid_t pid;
	unsigned long address;
	u32 reg_mask;
	u32 insn;
	u64 reg_vals[OVO_HWBP_GPR_COUNT];
	struct perf_event **events; // 每线程一个 perf_event
	int n_events;
};

static LIST_HEAD(ovo_hwbp_list);
static DEFINE_MUTEX(ovo_hwbp_lock);

// ---------------------------------------------------------------------------
// 解析内核符号(懒加载)
// ---------------------------------------------------------------------------
static int ovo_hwbp_resolve(void)
{
	if (!p_register_user_hw_breakpoint)
		p_register_user_hw_breakpoint = (reg_user_hwbp_fn)(void *)
			ovo_kallsyms_lookup_name("register_user_hw_breakpoint");
	if (!p_unregister_hw_breakpoint)
		p_unregister_hw_breakpoint = (unreg_hwbp_fn)(void *)
			ovo_kallsyms_lookup_name("unregister_hw_breakpoint");

	if (!p_register_user_hw_breakpoint || !p_unregister_hw_breakpoint) {
		pr_err("[ovo-hwbp] resolve failed: reg=%d unreg=%d\n",
		       !!p_register_user_hw_breakpoint, !!p_unregister_hw_breakpoint);
		return -ENOSYS;
	}
	return 0;
}

// ---------------------------------------------------------------------------
// 命中回调: 就地改寄存器 + 模拟首指令 + PC+=4
// 运行在命中线程(current==目标线程)的调试异常上下文中, 操作的是 current 的
// 用户寄存器现场(pt_regs), 改动在 eret 回用户态后生效。
// ---------------------------------------------------------------------------
static void ovo_hwbp_handler(struct perf_event *bp,
			     struct perf_sample_data *data,
			     struct pt_regs *regs)
{
	struct ovo_hwbp_node *n = bp->overflow_handler_context;
	int i;

	if (!n)
		return;

	// 1) 覆盖 GPR (例如 regs[1] = 0xff)
	for (i = 0; i < OVO_HWBP_GPR_COUNT; i++)
		if (n->reg_mask & (1u << i))
			regs->regs[i] = n->reg_vals[i];

	// 2) 模拟首指令
	if (n->insn == OVO_INSN_STR_X30_PRE_0x30) {
		// str x30, [sp, #-0x30]!  =>  sp -= 0x30; *(u64*)sp = x30
		unsigned long new_sp = regs->sp - 0x30;
		// put_user 失败(栈页未映射, 实际几乎不可能)则不改 sp, 退化为丢一次,
		// 不主动 crash。
		if (put_user(regs->regs[30], (unsigned long __user *)new_sp) == 0)
			regs->sp = new_sp;
	}
	// 其它 insn 不会到这里: 安装时已校验 insn 必须是已知可模拟的。

	// 3) 跳过被模拟的首指令, 避免原地重入
	regs->pc += 4;
}

// ---------------------------------------------------------------------------
// 查找节点
// ---------------------------------------------------------------------------
static struct ovo_hwbp_node *find_node(pid_t pid, unsigned long address)
{
	struct ovo_hwbp_node *n;
	list_for_each_entry(n, &ovo_hwbp_list, list)
		if (n->pid == pid && n->address == address)
			return n;
	return NULL;
}

// ---------------------------------------------------------------------------
// 快照目标进程的所有线程(持 get_task_struct 引用, rcu 外注册)
// ---------------------------------------------------------------------------
static int snapshot_threads(pid_t pid, struct task_struct ***out_arr)
{
	struct pid *spid;
	struct task_struct *leader, *t;
	struct task_struct **arr;
	int nr = 0;

	spid = find_get_pid(pid);
	if (!spid)
		return -ESRCH;
	leader = get_pid_task(spid, PIDTYPE_PID);
	put_pid(spid);
	if (!leader)
		return -ESRCH;

	arr = kmalloc_array(OVO_HWBP_MAX_THREADS, sizeof(*arr), GFP_KERNEL);
	if (!arr) {
		put_task_struct(leader);
		return -ENOMEM;
	}

	rcu_read_lock();
	for_each_thread(leader, t) {
		if (nr >= OVO_HWBP_MAX_THREADS)
			break;
		get_task_struct(t);
		arr[nr++] = t;
	}
	rcu_read_unlock();

	put_task_struct(leader);

	*out_arr = arr;
	return nr;
}

// ---------------------------------------------------------------------------
// 安装
// ---------------------------------------------------------------------------
int ovo_hwbp_install(pid_t target_pid, const struct ovo_hwbp_install_args *args)
{
	struct ovo_hwbp_node *n;
	struct task_struct **tasks = NULL;
	struct perf_event_attr attr;
	int ntasks, i, ok = 0, ret;

	if (ovo_hwbp_resolve())
		return -ENOSYS;

	// 只接受我们能安全模拟的首指令
	if (args->insn != OVO_INSN_STR_X30_PRE_0x30)
		return -EOPNOTSUPP;

	mutex_lock(&ovo_hwbp_lock);
	if (find_node(target_pid, args->address)) {
		mutex_unlock(&ovo_hwbp_lock);
		return -EEXIST; // 已装, 先卸再装
	}
	mutex_unlock(&ovo_hwbp_lock);

	ntasks = snapshot_threads(target_pid, &tasks);
	if (ntasks < 0)
		return ntasks;
	if (ntasks == 0) {
		kfree(tasks);
		return -ESRCH;
	}

	n = kzalloc(sizeof(*n), GFP_KERNEL);
	if (!n) {
		ret = -ENOMEM;
		goto out_put_tasks;
	}
	n->pid = target_pid;
	n->address = args->address;
	n->reg_mask = args->reg_mask;
	n->insn = args->insn;
	memcpy(n->reg_vals, args->reg_vals, sizeof(n->reg_vals));
	n->events = kcalloc(ntasks, sizeof(*n->events), GFP_KERNEL);
	if (!n->events) {
		kfree(n);
		ret = -ENOMEM;
		goto out_put_tasks;
	}

	// 构造执行断点 attr
	memset(&attr, 0, sizeof(attr));
	attr.type = PERF_TYPE_BREAKPOINT;
	attr.size = sizeof(attr);
	attr.bp_addr = args->address;
	attr.bp_type = HW_BREAKPOINT_X;
	attr.bp_len = HW_BREAKPOINT_LEN_4;
	attr.sample_period = 1;
	attr.disabled = 0;

	for (i = 0; i < ntasks; i++) {
		struct perf_event *ev = p_register_user_hw_breakpoint(
			&attr, ovo_hwbp_handler, n, tasks[i]);
		if (IS_ERR(ev)) {
			n->events[i] = NULL;
			pr_warn("[ovo-hwbp] reg fail tid=%d err=%ld\n",
				tasks[i]->pid, PTR_ERR(ev));
		} else {
			n->events[i] = ev;
			ok++;
		}
	}
	n->n_events = ntasks;

	if (ok == 0) {
		// 全失败, 回滚
		kfree(n->events);
		kfree(n);
		ret = -EAGAIN;
		goto out_put_tasks;
	}

	mutex_lock(&ovo_hwbp_lock);
	list_add(&n->list, &ovo_hwbp_list);
	mutex_unlock(&ovo_hwbp_lock);

	pr_info("[ovo-hwbp] installed pid=%d addr=%lx mask=%x ok=%d/%d\n",
		target_pid, args->address, args->reg_mask, ok, ntasks);
	ret = 0;

out_put_tasks:
	for (i = 0; i < ntasks; i++)
		put_task_struct(tasks[i]);
	kfree(tasks);
	return ret;
}

// ---------------------------------------------------------------------------
// 卸载
// ---------------------------------------------------------------------------
static void free_node_events(struct ovo_hwbp_node *n)
{
	int i;
	for (i = 0; i < n->n_events; i++)
		if (n->events[i])
			p_unregister_hw_breakpoint(n->events[i]);
	kfree(n->events);
}

int ovo_hwbp_uninstall(pid_t target_pid, unsigned long address)
{
	struct ovo_hwbp_node *n;

	if (!p_unregister_hw_breakpoint)
		return -ENOSYS;

	mutex_lock(&ovo_hwbp_lock);
	n = find_node(target_pid, address);
	if (!n) {
		mutex_unlock(&ovo_hwbp_lock);
		return -ENOENT;
	}
	list_del(&n->list);
	mutex_unlock(&ovo_hwbp_lock);

	free_node_events(n);
	kfree(n);
	pr_info("[ovo-hwbp] uninstalled pid=%d addr=%lx\n", target_pid, address);
	return 0;
}

// ---------------------------------------------------------------------------
// 模块卸载清理
// ---------------------------------------------------------------------------
void ovo_hwbp_cleanup_all(void)
{
	struct ovo_hwbp_node *n, *tmp;

	if (!p_unregister_hw_breakpoint)
		return;

	mutex_lock(&ovo_hwbp_lock);
	list_for_each_entry_safe(n, tmp, &ovo_hwbp_list, list) {
		list_del(&n->list);
		free_node_events(n);
		kfree(n);
	}
	mutex_unlock(&ovo_hwbp_lock);
}
