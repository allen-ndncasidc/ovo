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

// 条件覆盖模式安装参数(命中判定·完全无敌用)。
// 命中时内核读两个用户指针:
//   q = *(u64*)(regs[obj_reg] + obj_off)   目标对象首字段(= il2cpp 类指针)
//   P = *(u64*)cmp_global                  全局里缓存的"玩家本体类"指针
// 然后 regs[out_reg] = (q == P) ? val_eq : val_ne; PC+=4, 不模拟原指令。
// 任一用户读失败 -> 写 val_ne(正常命中), 不破坏游戏。
// 原神示例: address=base+0xBB58A9C, obj_reg=19, obj_off=0, out_reg=0,
//           cmp_global=base+0x15833B08, val_eq=0(受击方是玩家->免伤), val_ne=1。
struct ovo_hwbp_cond_args {
	unsigned long address;                 // 断点绝对运行时地址
	__u32 obj_reg;                         // 持有对象指针的 GPR 下标 (x19 -> 19)
	__u32 obj_off;                         // 读判据前对 obj 指针加的字节偏移
	__u32 out_reg;                         // 命中时写的 GPR 下标 (x0 -> 0)
	__u32 _pad;                            // 对齐
	unsigned long cmp_global;              // 判据全局绝对地址; P = *(u64*)cmp_global
	__u64 val_eq;                          // q==P 时写入 out_reg 的值
	__u64 val_ne;                          // 否则写入的值
};

// FP 常量模式安装参数(攻速/远跳/CD/卡肉移除用)。
// 命中时把单精度寄存器 s<vreg> 写成 bits(IEEE754 单精度位模式)再 PC+=4,
// 不模拟原指令。等价于把 fmov s<vreg>,#imm / fmov s<vreg>,s? 替换成写固定常量。
// 结构体正好 16 字节, 满足 ovo_ioctl 顶部 16B 预读。
// 原神示例:
//   攻速 x3:   address=base+0xC750324, vreg=1,  bits=0x40400000(3.0)
//   远跳 x2:   address=base+0xC4CEA80, vreg=1,  bits=0x40000000(2.0)
//   CD  x0.4:  address=base+0xB2A6A58, vreg=1,  bits=0x3ED00000(0.40625)
//   卡肉移除:  address=base+0xE24F188, vreg=8,  bits=0x3F800000(1.0)
struct ovo_hwbp_fp_args {
	unsigned long address;                 // 断点绝对运行时地址
	__u32 vreg;                            // 0..31 -> sN
	__u32 bits;                            // IEEE754 单精度位模式
};

// 寄存器条件覆盖模式(无限体力用)。命中时:
//   u32 v = (u32)regs[cmp_reg];
//   regs[out_reg] = (v == cmp_imm) ? set_val : regs[pass_reg];
//   PC += 4; 不模拟原指令。
// 用于通用"按属性ID设值"函数入口 mov x22,x2:
//   只有 propId(w1==cmp_reg=1) == 10011(当前耐力) 时才把值(x22=out_reg)改成满值,
//   否则透传原值(x22 = x2 = pass_reg), 不影响等级等其它属性。
struct ovo_hwbp_regcond_args {
	unsigned long address;                 // 断点绝对运行时地址
	__u32 cmp_reg;                         // 拿来比较的 GPR 下标(propId 在 w1 -> 1)
	__u32 cmp_imm;                         // 比较的立即数(10011 = 0x271B)
	__u32 out_reg;                         // 要写的 GPR 下标(x22 -> 22)
	__u32 pass_reg;                        // 不等时透传来源 GPR 下标(x2 -> 2)
	__u64 set_val;                         // 相等时写入 out_reg 的值(体力*100)
};

// 由 ovo_ioctl 调用; target_pid = os->pid
int ovo_hwbp_install(pid_t target_pid, const struct ovo_hwbp_install_args *args);
int ovo_hwbp_install_cond(pid_t target_pid, const struct ovo_hwbp_cond_args *args);
int ovo_hwbp_install_fp(pid_t target_pid, const struct ovo_hwbp_fp_args *args);
int ovo_hwbp_install_regcond(pid_t target_pid, const struct ovo_hwbp_regcond_args *args);
int ovo_hwbp_uninstall(pid_t target_pid, unsigned long address);

// 模块卸载时清理所有断点
void ovo_hwbp_cleanup_all(void);

#endif // OVO_HWBP_H
