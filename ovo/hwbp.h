//
// ovo HWBP 扩展 —— 阶段 1
// 在 libGameCore+0x39053c0 入口装硬件执行断点, 命中时就地把 x1 改成 0xff,
// 模拟首指令 `str x30, [sp, #-0x30]!` 并 PC+=4, 不停线程、不禁用断点。
// 等价于已在本机验证通过的 dits_66_patched.ko 的行为, 但跑在 ovo 里
// (ovo 走 socket 通信, 不挂 syscall, 天然免疫 syscall-18 探测 = S1)。
//
#ifndef OVO_HWBP_H
#define OVO_HWBP_H

#include <linux/types.h>

#define OVO_HWBP_GPR_COUNT 31

// 已知可模拟的首指令: str x30, [sp, #-0x30]!  (小端字节 fe 0f 1d f8)
#define OVO_INSN_STR_X30_PRE_0x30  0xf81d0ffeu

// skip-only 模式: insn 字段填 0。命中时只覆盖 reg_mask 指定的 GPR, 然后 PC+=4,
// 不模拟任何原指令 —— 等于把断点那条指令整条丢弃。
// 仅适用于"原指令只写 GPR、且该写入可被丢弃/被我们的覆盖值取代"的位置, 例如:
//   免充能:        cset w0, ge   -> 覆盖 w0=1 跳过
//   命中判定·无敌: mov  w0, #1   -> 覆盖 w0=0 跳过
// 若 reg_mask 也为 0, 则纯 NOP 掉这条指令。
// 真实指令字永远不会是 0 (0x00000000 = udf), 所以用 0 当哨兵是安全的。
#define OVO_HWBP_INSN_SKIP_ONLY    0u

// 用户态传进来的安装参数 (pid 用已 ATTACH 的 os->pid, 不在这里传)
struct ovo_hwbp_install_args {
	unsigned long address;                 // 断点绝对运行时地址 = base + 0x39053c0
	__u32 reg_mask;                        // 要覆盖哪些 x0..x30 (bit i -> xi)
	__u32 insn;                            // 断点处首指令(32bit): 内核据此模拟。
	                                       //   == OVO_INSN_STR_X30_PRE_0x30 -> 模拟 str x30 再跳过
	                                       //   == OVO_HWBP_INSN_SKIP_ONLY(0) -> 只覆盖 GPR 再跳过
	                                       //   其它值 -> 拒装 (-EOPNOTSUPP)
	__u64 reg_vals[OVO_HWBP_GPR_COUNT];    // 覆盖值
};

struct ovo_hwbp_uninstall_args {
	unsigned long address;                 // 要卸载的断点地址
	unsigned long _reserved;               // 补到 16 字节: 避开 ovo_ioctl 顶部对 arg 的 16B 预读
};

// 由 ovo_ioctl 调用; target_pid = os->pid
int ovo_hwbp_install(pid_t target_pid, const struct ovo_hwbp_install_args *args);
int ovo_hwbp_uninstall(pid_t target_pid, unsigned long address);

// 模块卸载时清理所有断点
void ovo_hwbp_cleanup_all(void);

#endif // OVO_HWBP_H
