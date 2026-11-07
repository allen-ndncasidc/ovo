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

// 用户态传进来的安装参数 (pid 用已 ATTACH 的 os->pid, 不在这里传)
struct ovo_hwbp_install_args {
	unsigned long address;                 // 断点绝对运行时地址 = base + 0x39053c0
	__u32 reg_mask;                        // 要覆盖哪些 x0..x30 (bit i -> xi)
	__u32 insn;                            // 断点处首指令(32bit), 内核据此模拟; 必须是已知可模拟的
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
