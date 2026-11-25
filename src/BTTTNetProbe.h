//
// BTTTNetProbe.h —— TTNet 精准拦截器（非越狱安全版）
// ============================================================
// 不使用 _objc_msgForward，不批量 hook 无关类，
// 仅按运行期签名校验后精准 swizzle TTNetworkManagerChromium / TTHttpTaskChromium。
// ============================================================

#ifndef BTTTNetProbe_h
#define BTTTNetProbe_h

#import <Foundation/Foundation.h>

/// 改写回调：输入 URL 和原始响应 NSData，返回改写后的 NSData（不改写返回 nil）
typedef NSData * _Nullable (*BTTTNetPatchFunc)(NSURL * _Nonnull url, NSData * _Nonnull data);

/// 设置改写回调（需在 BTInstallTTNetProbe 之前或之后调用）
void BTSetTTNetPatchFunc(BTTTNetPatchFunc _Nullable func);

/// 安装精准 TTNet Hook（零崩溃，非越狱可用）
void BTInstallTTNetProbe(void);

/// 暂停/恢复拦截
void BTStopTTNetProbe(void);

#endif /* BTTTNetProbe_h */
