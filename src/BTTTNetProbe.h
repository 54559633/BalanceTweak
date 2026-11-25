//
// BTTTNetProbe.h —— 钱包首页 JSON / TTNet / BDXBridge 精准拦截器（非越狱安全版）
// ============================================================

#ifndef BTTTNetProbe_h
#define BTTTNetProbe_h

#import <Foundation/Foundation.h>

/// 改写回调：输入 URL 和原始响应 NSData，返回改写后的 NSData（不改写返回 nil）
typedef NSData * _Nullable (*BTTTNetPatchFunc)(NSURL * _Nonnull url, NSData * _Nonnull data);

/// 设置改写回调
void BTSetTTNetPatchFunc(BTTTNetPatchFunc _Nullable func);

/// 递归改写钱包首页 JSON 对象（支持 NSDictionary / NSArray / 嵌套 JSON 字符串）
id _Nullable BTPatchWalletJSONObject(id _Nullable obj,
                                     int64_t realVal,
                                     BOOL hasRealVal,
                                     int64_t dispVal,
                                     BOOL shouldPatch,
                                     int64_t * _Nullable outDetectedReal,
                                     BOOL * _Nullable outDidChange);

/// 安装精准拦截（TTNetworkManagerChromium PreProcessing + BDXBridgeTtcjpayMultiNetRequestMethod）
void BTInstallTTNetProbe(void);

void BTStopTTNetProbe(void);

#endif /* BTTTNetProbe_h */
