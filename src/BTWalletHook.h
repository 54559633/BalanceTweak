//
// BTWalletHook.h —— 方案 2：直接 Swizzle 抖音钱包 Model / Manager 层
// ============================================================
// 绕过 TTNet / QUIC / HTTP3 / WebSocket / Protobuf，
// 直接在纯 ObjC Runtime 层拦截钱包对象的余额 getter / setter：
//   - setter 收到服务端真实值 → 记录真实余额（带回声防误判）
//   - getter 返回时 → 开关开启则返回 computedDisplay，关闭则立即还原真实值
// ============================================================

#ifndef BTWalletHook_h
#define BTWalletHook_h

#import <Foundation/Foundation.h>

/// 记录真实余额的回调（由 BalanceTweak.m 注入，对接 BTPrefs）
typedef void (*BTWalletRecordRealFunc)(int64_t realVal, NSString * _Nullable source);

/// 查询当前是否开启改写以及应显示的余额值
typedef BOOL (*BTWalletGetDisplayFunc)(int64_t * _Nonnull outDisplay, int64_t * _Nonnull outLastReal);

/// 注册回调
void BTSetWalletCallbacks(BTWalletRecordRealFunc _Nullable recordFunc,
                          BTWalletGetDisplayFunc _Nullable getDisplayFunc);

/// 运行期启用/停用钱包 Hook（用于安全模式实时切换，无需重启）
void BTSetWalletHookActive(BOOL active);

/// 安装钱包 Model / Manager 层 Hook（纯 ObjC Runtime，非越狱零崩溃）
void BTInstallWalletModelHook(void);

#endif /* BTWalletHook_h */
