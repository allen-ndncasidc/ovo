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
	// --- 条件覆盖(cond)模式: 命中时读两个用户指针比较, 按结果写 out_reg ---
	//   q = *(u64*)(regs[obj_reg] + obj_off)   目标对象首字段(类指针)
	//   P = *(u64*)cmp_global                  全局里缓存的"玩家本体类"指针
	//   regs[out_reg] = (q == P) ? val_eq : val_ne ; 然后 PC+=4, 不模拟原指令
	bool is_cond;
	u32  obj_reg;
	u32  obj_off;
	u32  out_reg;
	unsigned long cmp_global;
	u64  val_eq;
	u64  val_ne;
	// --- FP 常量模式: 命中时把单精度寄存器 sN 写成常量再 PC+=4 ---
	//   (攻速/远跳/CD/卡肉移除: 原指令 fmov s1/s8,#imm 或 fmov s8,s0)
	bool is_fp;
	u32  fp_vreg;   // 0..31 -> sN
	u32  fp_bits;   // IEEE754 单精度位模式
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

	if (!p_register_user_hw_breakpoint || !p_unregister_hw_breakpoint)
		return -ENOSYS;
	return 0;
}

// ---------------------------------------------------------------------------
// 把单精度浮点位模式 bits 写入 sN。命中线程的 FP 现场是活的(EL0 同步异常不保存
// FP); 内核以 -mgeneral-regs-only 编译, 编译器不会用 FP, 直接写硬件寄存器即可,
// eret 回用户态后生效。fmov sN, wM 会清零向量寄存器高 96 位, 与 fmov sN,#imm 等价。
// ---------------------------------------------------------------------------
static void ovo_write_sreg(u32 idx, u32 bits)
{
	// 内核以 -mgeneral-regs-only 编译, 汇编器会拒绝 fmov 助记符(instruction
	// requires: fp-armv8)。改用 .inst 直接发原始指令字, 绕过该特性门。
	// fmov sD, w9 = 0x1E270120 | D (Rn 固定为 w9); 把 bits 钉在 w9。
	register unsigned int v asm("w9") = bits;
#define OVO_WS(n) case n: \
	asm volatile(".inst %c0" : : "i"(0x1E270120u | (unsigned)(n)), "r"(v)); break;
	switch (idx) {
	OVO_WS(0)  OVO_WS(1)  OVO_WS(2)  OVO_WS(3)  OVO_WS(4)  OVO_WS(5)
	OVO_WS(6)  OVO_WS(7)  OVO_WS(8)  OVO_WS(9)  OVO_WS(10) OVO_WS(11)
	OVO_WS(12) OVO_WS(13) OVO_WS(14) OVO_WS(15) OVO_WS(16) OVO_WS(17)
	OVO_WS(18) OVO_WS(19) OVO_WS(20) OVO_WS(21) OVO_WS(22) OVO_WS(23)
	OVO_WS(24) OVO_WS(25) OVO_WS(26) OVO_WS(27) OVO_WS(28) OVO_WS(29)
	OVO_WS(30) OVO_WS(31)
	default: break;
	}
#undef OVO_WS
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

	// 0) 条件覆盖模式: 读目标类指针与全局玩家类比较, 决定写什么再 PC+=4。
	//    任一用户读失败 -> 退化为 val_ne(正常命中), 不破坏游戏。
	if (n->is_cond) {
		u64 q = 0, P = 0;
		u64 outv = n->val_ne;
		unsigned long qaddr = regs->regs[n->obj_reg] + n->obj_off;
		if (n->obj_reg < OVO_HWBP_GPR_COUNT &&
		    get_user(q, (u64 __user *)qaddr) == 0 &&
		    get_user(P, (u64 __user *)n->cmp_global) == 0)
			outv = (q == P) ? n->val_eq : n->val_ne;
		if (n->out_reg < OVO_HWBP_GPR_COUNT)
			regs->regs[n->out_reg] = outv;
		regs->pc += 4;
		return;
	}

	// 0b) FP 常量模式: 把 sN 写成常量再 PC+=4(攻速/远跳/CD/卡肉移除)。
	if (n->is_fp) {
		ovo_write_sreg(n->fp_vreg, n->fp_bits);
		regs->pc += 4;
		return;
	}

	// 1) 覆盖 GPR (例如 regs[1] = 0xff; 或免充能 regs[0] = 1)
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
	// insn == OVO_HWBP_INSN_SKIP_ONLY(0): 不模拟, 上面的 GPR 覆盖 + 下面的 PC+=4
	//   就等于把原指令整条丢弃。安装时已校验 insn 只能是这两种之一。

	// 3) 跳过首指令, 避免原地重入(skip-only 时即丢弃原指令)
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
// 给已填好 pid/address/模式字段的节点注册每线程 perf_event 并挂链。
// 无论成功失败, 本函数都会处理 node 的所有权: 失败即 kfree(node)。
// ---------------------------------------------------------------------------
static int ovo_hwbp_register(struct ovo_hwbp_node *n)
{
	struct task_struct **tasks = NULL;
	struct perf_event_attr attr;
	int ntasks, i, ok = 0, ret;

	mutex_lock(&ovo_hwbp_lock);
	if (find_node(n->pid, n->address)) {
		mutex_unlock(&ovo_hwbp_lock);
		kfree(n);
		return -EEXIST; // 已装, 先卸再装
	}
	mutex_unlock(&ovo_hwbp_lock);

	ntasks = snapshot_threads(n->pid, &tasks);
	if (ntasks < 0) {
		kfree(n);
		return ntasks;
	}
	if (ntasks == 0) {
		kfree(tasks);
		kfree(n);
		return -ESRCH;
	}

	n->events = kcalloc(ntasks, sizeof(*n->events), GFP_KERNEL);
	if (!n->events) {
		ret = -ENOMEM;
		goto out_free_node;
	}

	// 构造执行断点 attr
	memset(&attr, 0, sizeof(attr));
	attr.type = PERF_TYPE_BREAKPOINT;
	attr.size = sizeof(attr);
	attr.bp_addr = n->address;
	attr.bp_type = HW_BREAKPOINT_X;
	attr.bp_len = HW_BREAKPOINT_LEN_4;
	attr.sample_period = 1;
	attr.disabled = 0;

	for (i = 0; i < ntasks; i++) {
		struct perf_event *ev = p_register_user_hw_breakpoint(
			&attr, ovo_hwbp_handler, n, tasks[i]);
		if (IS_ERR(ev)) {
			n->events[i] = NULL;
		} else {
			n->events[i] = ev;
			ok++;
		}
	}
	n->n_events = ntasks;

	if (ok == 0) {
		kfree(n->events);
		ret = -EAGAIN;
		goto out_free_node;
	}

	mutex_lock(&ovo_hwbp_lock);
	list_add(&n->list, &ovo_hwbp_list);
	mutex_unlock(&ovo_hwbp_lock);

	for (i = 0; i < ntasks; i++)
		put_task_struct(tasks[i]);
	kfree(tasks);
	return 0;

out_free_node:
	for (i = 0; i < ntasks; i++)
		put_task_struct(tasks[i]);
	kfree(tasks);
	kfree(n);
	return ret;
}

// ---------------------------------------------------------------------------
// 安装(常规: skip-only 或 模拟 str x30)
// ---------------------------------------------------------------------------
int ovo_hwbp_install(pid_t target_pid, const struct ovo_hwbp_install_args *args)
{
	struct ovo_hwbp_node *n;

	if (ovo_hwbp_resolve())
		return -ENOSYS;

	// 只接受: (a) 能安全模拟的首指令 str x30, 或 (b) skip-only 模式(insn==0)。
	// skip-only 命中时只覆盖 GPR 再 PC+=4, 把断点那条指令整条丢弃, 适用于
	// 原指令只写 GPR 且写入可被丢弃的位置(免充能 cset / 命中判定 mov w0 等)。
	if (args->insn != OVO_INSN_STR_X30_PRE_0x30 &&
	    args->insn != OVO_HWBP_INSN_SKIP_ONLY)
		return -EOPNOTSUPP;

	n = kzalloc(sizeof(*n), GFP_KERNEL);
	if (!n)
		return -ENOMEM;
	n->pid = target_pid;
	n->address = args->address;
	n->reg_mask = args->reg_mask;
	n->insn = args->insn;
	memcpy(n->reg_vals, args->reg_vals, sizeof(n->reg_vals));
	n->is_cond = false;
	return ovo_hwbp_register(n);
}

// ---------------------------------------------------------------------------
// 安装(条件覆盖: 读目标类指针与全局玩家类比较, 决定写 out_reg)
// 用于命中判定"完全无敌"——只在受击方是玩家本体类时把判定置 0, 不影响你打敌人。
// ---------------------------------------------------------------------------
int ovo_hwbp_install_cond(pid_t target_pid, const struct ovo_hwbp_cond_args *args)
{
	struct ovo_hwbp_node *n;

	if (ovo_hwbp_resolve())
		return -ENOSYS;
	if (args->obj_reg >= OVO_HWBP_GPR_COUNT ||
	    args->out_reg >= OVO_HWBP_GPR_COUNT)
		return -EINVAL;

	n = kzalloc(sizeof(*n), GFP_KERNEL);
	if (!n)
		return -ENOMEM;
	n->pid = target_pid;
	n->address = args->address;
	n->is_cond = true;
	n->obj_reg = args->obj_reg;
	n->obj_off = args->obj_off;
	n->out_reg = args->out_reg;
	n->cmp_global = args->cmp_global;
	n->val_eq = args->val_eq;
	n->val_ne = args->val_ne;
	return ovo_hwbp_register(n);
}

// ---------------------------------------------------------------------------
// 安装(FP 常量: 命中时把 sN 写成常量再跳过原指令)
// 用于攻速/远跳/CD/卡肉移除——原指令 fmov s1/s8,#imm 或 fmov s8,s0。
// ---------------------------------------------------------------------------
int ovo_hwbp_install_fp(pid_t target_pid, const struct ovo_hwbp_fp_args *args)
{
	struct ovo_hwbp_node *n;

	if (ovo_hwbp_resolve())
		return -ENOSYS;
	if (args->vreg >= 32)
		return -EINVAL;

	n = kzalloc(sizeof(*n), GFP_KERNEL);
	if (!n)
		return -ENOMEM;
	n->pid = target_pid;
	n->address = args->address;
	n->is_fp = true;
	n->fp_vreg = args->vreg;
	n->fp_bits = args->bits;
	return ovo_hwbp_register(n);
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
