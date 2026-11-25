//
// BTFishhook.h —— 极简 fishhook（改 Mach-O 的 __la_symbol_ptr / __got）
// ============================================================
// 原理：
//   1. 遍历主程序 + 所有 dylib 的 Mach-O
//   2. 找 __DATA / __DATA_CONST 段的 __la_symbol_ptr 和 __got 节
//   3. 这些节存的是「符号地址表」
//   4. 通过 indirect symbol table 找到每个表项对应的符号名
//   5. 符号名匹配就改表项指向我们的函数
//
// 局限：
//   · 只能改「通过 GOT 调用的符号」
//   · 不能改库内部的直接调用（但 boringssl 内部不会调自己的 SSL_read）
//   · 对 lazy binding 需要先触发一次绑定
// ============================================================

#ifndef BTFishhook_h
#define BTFishhook_h

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

struct bt_rebinding {
    const char *name;
    void *replacement;
    void **replaced;
};

/// 批量重绑定符号
/// 返回成功绑定的数量
int bt_rebind_symbols(struct bt_rebinding rebindings[], size_t count);

#ifdef __cplusplus
}
#endif

#endif /* BTFishhook_h */
