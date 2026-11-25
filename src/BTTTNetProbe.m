//
// BTTTNetProbe.m —— 钱包首页（CJPay/Lynx）JSON + TTNet 精准拦截器
// ============================================================
// 覆盖「我 → 我的钱包」首页的「钻石」数值：
//   1. TTNetworkManagerChromium
//      -handleResponsePreProcessing_:data:error:request:preprocessor:headerCallback:dataCallback:completedCallback:
//      （真机实测签名: B80@0:8@16@24@32@40@48@?56@?64@?72）
//   2. BDXBridgeTtcjpayMultiNetRequestMethod
//      -p_handleResponse:object:error:expectedTrafficPath:completionHandler:
//      （财经钱包 Lynx 页面专用 JSBridge 网络回调）
// ============================================================

#import "BTTTNetProbe.h"
#import "BTLog.h"
#import <objc/runtime.h>
#import <objc/message.h>
#include <string.h>

#define TTHLOG(fmt, ...) BT_LOG_M(@"TTNetHook", fmt, ##__VA_ARGS__)

static BTTTNetPatchFunc g_patchFunc = NULL;
static BOOL g_active = YES;
static char kBTPatchedKey;

void BTSetTTNetPatchFunc(BTTTNetPatchFunc func) {
    g_patchFunc = func;
}

void BTSetTTNetActive(BOOL active) {
    g_active = active;
    TTHLOG(@"运行状态切换: %@", active ? @"启用" : @"暂停（安全模式）");
}

void BTStopTTNetProbe(void) {
    BTSetTTNetActive(NO);
}

// ============================================================
// 钱包首页 JSON 递归改写（定位 "钻石" 卡片并替换余额数值）
// ============================================================
static BOOL btIsPureNonNegIntString(NSString *s, int64_t *outVal) {
    if (![s isKindOfClass:[NSString class]] || s.length == 0 || s.length > 18) return NO;
    uint64_t acc = 0;
    for (NSUInteger i = 0; i < s.length; i++) {
        unichar c = [s characterAtIndex:i];
        if (c < '0' || c > '9') return NO;
        acc = acc * 10ULL + (uint64_t)(c - '0');
    }
    if (outVal) *outVal = (int64_t)acc;
    return YES;
}

static BOOL btIsBoolNumber(id obj) {
    if (![obj isKindOfClass:[NSNumber class]]) return NO;
    return CFGetTypeID((__bridge CFTypeRef)obj) == CFBooleanGetTypeID();
}

static BOOL btDictLooksLikeDiamondCard(NSDictionary *dict) {
    for (id key in dict) {
        id val = dict[key];
        if ([val isKindOfClass:[NSString class]]) {
            NSString *s = (NSString *)val;
            if ([s isEqualToString:@"钻石"] || ([s containsString:@"钻石"] && s.length <= 6)) {
                return YES;
            }
            if ([key isKindOfClass:[NSString class]]) {
                NSString *kl = [(NSString *)key lowercaseString];
                if (([kl isEqualToString:@"code"] || [kl isEqualToString:@"biz_code"] ||
                     [kl isEqualToString:@"asset_type"] || [kl isEqualToString:@"type"]) &&
                    [s.lowercaseString containsString:@"diamond"]) {
                    return YES;
                }
            }
        }
    }
    return NO;
}

static BOOL btKeyLooksLikeBalanceField(id key) {
    if (![key isKindOfClass:[NSString class]]) return NO;
    NSString *kl = [(NSString *)key lowercaseString];
    return ([kl containsString:@"amount"] || [kl containsString:@"value"] ||
            [kl containsString:@"balance"] || [kl containsString:@"count"] ||
            [kl containsString:@"cnt"] || [kl containsString:@"num"] ||
            [kl containsString:@"sub_title"] || [kl containsString:@"subtitle"] ||
            [kl containsString:@"desc"] || [kl containsString:@"text"] ||
            [kl containsString:@"display"]);
}

static id btPatchJSONRecursive(id obj,
                               int64_t realVal,
                               BOOL hasRealVal,
                               NSString *realStr,
                               int64_t dispVal,
                               NSString *dispStr,
                               BOOL shouldPatch,
                               BOOL inDiamondCtx,
                               int depth,
                               int64_t *outDetectedReal,
                               BOOL *outDidChange) {
    if (!obj || depth > 12) return obj;

    if ([obj isKindOfClass:[NSDictionary class]]) {
        NSDictionary *dict = (NSDictionary *)obj;
        BOOL isDiamond = inDiamondCtx || btDictLooksLikeDiamondCard(dict);
        NSMutableDictionary *mut = nil;

        for (id key in dict) {
            id val = dict[key];
            id newVal = val;

            if (isDiamond && [val isKindOfClass:[NSString class]]) {
                NSString *s = (NSString *)val;
                int64_t parsed = 0;
                if (btIsPureNonNegIntString(s, &parsed)) {
                    BOOL matches = (hasRealVal && parsed == realVal) ||
                                   (!hasRealVal && btKeyLooksLikeBalanceField(key));
                    if (matches) {
                        if (outDetectedReal && *outDetectedReal < 0) *outDetectedReal = parsed;
                        if (shouldPatch) {
                            newVal = dispStr;
                            if (outDidChange) *outDidChange = YES;
                            TTHLOG(@"★ [WalletJSON] 改写字段 %@: \"%@\" -> \"%@\"", key, s, dispStr);
                        }
                    }
                } else if (s.length >= 2 && ([s hasPrefix:@"{"] || [s hasPrefix:@"["])) {
                    newVal = btPatchJSONRecursive(val, realVal, hasRealVal, realStr, dispVal, dispStr,
                                                  shouldPatch, isDiamond, depth + 1, outDetectedReal, outDidChange);
                }
            } else if (isDiamond && [val isKindOfClass:[NSNumber class]] && !btIsBoolNumber(val)) {
                int64_t nv = [(NSNumber *)val longLongValue];
                BOOL matches = (hasRealVal && nv == realVal) ||
                               (!hasRealVal && btKeyLooksLikeBalanceField(key));
                if (matches) {
                    if (outDetectedReal && *outDetectedReal < 0) *outDetectedReal = nv;
                    if (shouldPatch) {
                        newVal = @(dispVal);
                        if (outDidChange) *outDidChange = YES;
                        TTHLOG(@"★ [WalletJSON] 改写数值 %@: %lld -> %lld", key, (long long)nv, (long long)dispVal);
                    }
                }
            } else {
                newVal = btPatchJSONRecursive(val, realVal, hasRealVal, realStr, dispVal, dispStr,
                                              shouldPatch, isDiamond, depth + 1, outDetectedReal, outDidChange);
            }

            if (newVal != val) {
                if (!mut) mut = [dict mutableCopy];
                mut[key] = newVal;
            }
        }
        return mut ?: dict;
    }

    if ([obj isKindOfClass:[NSArray class]]) {
        NSArray *arr = (NSArray *)obj;
        NSMutableArray *mut = nil;
        for (NSUInteger i = 0; i < arr.count; i++) {
            id item = arr[i];
            id newItem = btPatchJSONRecursive(item, realVal, hasRealVal, realStr, dispVal, dispStr,
                                              shouldPatch, inDiamondCtx, depth + 1, outDetectedReal, outDidChange);
            if (newItem != item) {
                if (!mut) mut = [arr mutableCopy];
                mut[i] = newItem;
            }
        }
        return mut ?: arr;
    }

    // 处理抖音财经接口常见的嵌套 JSON 字符串（如 biz_data / data 字段）
    if ([obj isKindOfClass:[NSString class]]) {
        NSString *s = (NSString *)obj;
        if (s.length >= 4 && s.length < 500000 &&
            ([s hasPrefix:@"{"] || [s hasPrefix:@"["]) &&
            ([s containsString:@"钻石"] || [s.lowercaseString containsString:@"diamond"])) {
            NSData *subData = [s dataUsingEncoding:NSUTF8StringEncoding];
            if (subData) {
                id subObj = [NSJSONSerialization JSONObjectWithData:subData options:0 error:nil];
                if (subObj) {
                    BOOL subChanged = NO;
                    id patchedSub = btPatchJSONRecursive(subObj, realVal, hasRealVal, realStr, dispVal, dispStr,
                                                         shouldPatch, inDiamondCtx, depth + 1,
                                                         outDetectedReal, &subChanged);
                    if (subChanged && patchedSub && [NSJSONSerialization isValidJSONObject:patchedSub]) {
                        NSData *reEnc = [NSJSONSerialization dataWithJSONObject:patchedSub options:0 error:nil];
                        if (reEnc) {
                            NSString *reStr = [[NSString alloc] initWithData:reEnc encoding:NSUTF8StringEncoding];
                            if (reStr) {
                                if (outDidChange) *outDidChange = YES;
                                return reStr;
                            }
                        }
                    }
                }
            }
        }
    }

    return obj;
}

id BTPatchWalletJSONObject(id obj,
                           int64_t realVal,
                           BOOL hasRealVal,
                           int64_t dispVal,
                           BOOL shouldPatch,
                           int64_t *outDetectedReal,
                           BOOL *outDidChange) {
    if (!obj) return nil;
    if (outDetectedReal) *outDetectedReal = -1;
    if (outDidChange) *outDidChange = NO;

    NSString *realStr = [NSString stringWithFormat:@"%lld", (long long)realVal];
    NSString *dispStr = [NSString stringWithFormat:@"%lld", (long long)dispVal];
    return btPatchJSONRecursive(obj, realVal, hasRealVal, realStr, dispVal, dispStr,
                                shouldPatch, NO, 0, outDetectedReal, outDidChange);
}

// ============================================================
// 安全读取对象属性与 URL 匹配
// ============================================================
static id btSafeGetObjectProp(id obj, SEL sel) {
    if (!obj || !sel) return nil;
    Class cls = object_getClass(obj);
    if (!cls) return nil;
    Method m = class_getInstanceMethod(cls, sel);
    if (!m || method_getNumberOfArguments(m) != 2) return nil;
    char retType[16] = {0};
    method_getReturnType(m, retType, sizeof(retType));
    if (retType[0] != '@') return nil;
    @try {
        return ((id (*)(id, SEL))objc_msgSend)(obj, sel);
    } @catch (NSException *e) {
        (void)e;
        return nil;
    }
}

static NSURL *btExtractURLDepth(id obj, int depth) {
    if (!obj || depth > 2) return nil;
    if ([obj isKindOfClass:[NSURL class]]) return (NSURL *)obj;
    if ([obj isKindOfClass:[NSString class]]) {
        NSString *s = (NSString *)obj;
        if (s.length == 0) return nil;
        return [NSURL URLWithString:s];
    }

    static SEL urlSels[5];
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        urlSels[0] = @selector(URL);
        urlSels[1] = @selector(url);
        urlSels[2] = @selector(requestURL);
        urlSels[3] = @selector(URLString);
        urlSels[4] = @selector(request);
    });

    for (int i = 0; i < 5; i++) {
        id val = btSafeGetObjectProp(obj, urlSels[i]);
        if (!val || val == obj) continue;
        NSURL *u = btExtractURLDepth(val, depth + 1);
        if (u) return u;
    }
    return nil;
}

static NSURL *btExtractURL(id obj) {
    return btExtractURLDepth(obj, 0);
}

static BOOL btIsTargetWalletURL(NSURL *url) {
    if (!url) return NO;
    NSString *s = (url.path.length > 0 ? url.path : (url.absoluteString ?: @"")).lowercaseString;
    return ([s containsString:@"/webcast/wallet/info"] ||
            [s containsString:@"wallet_api/recharge_page"] ||
            [s containsString:@"wallet/core/v1/homepage"] ||
            [s containsString:@"caijing/wallet"] ||
            [s containsString:@"wallet/homepage"]);
}

static id btMaybePatchData(NSURL *url, id rawData, id dedupObj, const char *source) {
    if (!g_active || !g_patchFunc || !url || !rawData) return rawData;
    if (![rawData isKindOfClass:[NSData class]]) return rawData;

    NSData *data = (NSData *)rawData;
    if (data.length == 0) return rawData;

    if (objc_getAssociatedObject(rawData, &kBTPatchedKey) != nil) return rawData;
    if (dedupObj && objc_getAssociatedObject(dedupObj, &kBTPatchedKey) != nil) return rawData;

    TTHLOG(@"★★★ 命中 [%s] %@ (%luB)", source, url.path ?: url.absoluteString, (unsigned long)data.length);

    NSData *patched = nil;
    @try {
        patched = g_patchFunc(url, data);
    } @catch (NSException *e) {
        TTHLOG(@"patch 异常 [%s]: %@", source, e);
        return rawData;
    }

    if (dedupObj) {
        objc_setAssociatedObject(dedupObj, &kBTPatchedKey, @YES, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    }

    if (!patched || patched.length == 0) return rawData;

    id result = [rawData isKindOfClass:[NSMutableData class]] ? [patched mutableCopy] : patched;
    objc_setAssociatedObject(result, &kBTPatchedKey, @YES, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    return result;
}

static BOOL btVerifyObjectArgs(Method m, unsigned int expectedTotalArgs, char *outRetType) {
    if (!m) return NO;
    unsigned int argc = method_getNumberOfArguments(m);
    if (argc != expectedTotalArgs) return NO;

    char ret[16] = {0};
    method_getReturnType(m, ret, sizeof(ret));
    if (ret[0] != 'v' && ret[0] != '@' && ret[0] != 'B' && ret[0] != 'c') return NO;
    if (outRetType) *outRetType = ret[0];

    for (unsigned int i = 2; i < argc; i++) {
        char arg[16] = {0};
        method_getArgumentType(m, i, arg, sizeof(arg));
        if (arg[0] != '@') return NO;
    }
    return YES;
}

// ============================================================
// Hook 1: TTNetworkManagerChromium -handleResponsePreProcessing_:...
//   实测签名: B80@0:8@16@24@32@40@48@?56@?64@?72
// ============================================================
static void btHookHandleResponsePreProcessing(void) {
    Class cls = NSClassFromString(@"TTNetworkManagerChromium");
    if (!cls) return;

    SEL sel = NSSelectorFromString(
        @"handleResponsePreProcessing_:data:error:request:preprocessor:headerCallback:dataCallback:completedCallback:");
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return;

    char retType = 0;
    if (!btVerifyObjectArgs(m, 10, &retType)) {
        TTHLOG(@"handleResponsePreProcessing_ 签名不符: %s", method_getTypeEncoding(m) ?: "?");
        return;
    }

    IMP origImp = method_getImplementation(m);
    if (retType == 'B' || retType == 'c') {
        typedef BOOL (*Fn)(id, SEL, id, id, id, id, id, id, id, id);
        Fn fn = (Fn)origImp;
        BOOL (^blk)(id, id, id, id, id, id, id, id, id) =
            ^BOOL(id self_, id resp, id data, id err, id req, id pre, id hdrCb, id dataCb, id compCb) {
            id outData = data;
            if (data && !err) {
                NSURL *url = btExtractURL(req) ?: btExtractURL(resp);
                if (btIsTargetWalletURL(url)) {
                    outData = btMaybePatchData(url, data, req ?: resp, "PreProcessing");
                }
            }
            return fn(self_, sel, resp, outData, err, req, pre, hdrCb, dataCb, compCb);
        };
        method_setImplementation(m, imp_implementationWithBlock(blk));
        TTHLOG(@"✓ 已 hook TTNetworkManagerChromium -handleResponsePreProcessing_:");
    }
}

// ============================================================
// Hook 2: BDXBridgeTtcjpayMultiNetRequestMethod
//   -p_handleResponse:object:error:expectedTrafficPath:completionHandler:
// ============================================================
static void btHookCJPayBridgeResponse(void) {
    Class cls = NSClassFromString(@"BDXBridgeTtcjpayMultiNetRequestMethod");
    if (!cls) return;

    SEL sel = NSSelectorFromString(@"p_handleResponse:object:error:expectedTrafficPath:completionHandler:");
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return;

    const char *enc = method_getTypeEncoding(m);
    TTHLOG(@"CJPayBridge p_handleResponse 签名: %s", enc ?: "?");

    char retType = 0;
    if (!btVerifyObjectArgs(m, 7, &retType) || retType != 'v') {
        TTHLOG(@"CJPayBridge 签名不符，跳过");
        return;
    }

    IMP origImp = method_getImplementation(m);
    typedef void (*Fn)(id, SEL, id, id, id, id, id);
    Fn fn = (Fn)origImp;

    void (^blk)(id, id, id, id, id, id) = ^(id self_, id resp, id obj, id err, id trafficPath, id comp) {
        id outObj = obj;
        if (g_active && g_patchFunc && obj && !err) {
            NSURL *url = btExtractURL(resp);
            if (!url && [trafficPath isKindOfClass:[NSString class]]) {
                url = [NSURL URLWithString:(NSString *)trafficPath];
            }
            if (btIsTargetWalletURL(url)) {
                if ([obj isKindOfClass:[NSData class]]) {
                    outObj = btMaybePatchData(url, obj, resp, "CJPayBridge");
                } else if ([obj isKindOfClass:[NSDictionary class]] || [obj isKindOfClass:[NSArray class]]) {
                    if ([NSJSONSerialization isValidJSONObject:obj]) {
                        NSData *jsonData = [NSJSONSerialization dataWithJSONObject:obj options:0 error:nil];
                        if (jsonData) {
                            NSData *patchedData = btMaybePatchData(url, jsonData, resp, "CJPayBridge-Obj");
                            if (patchedData != jsonData && [patchedData isKindOfClass:[NSData class]]) {
                                id newObj = [NSJSONSerialization JSONObjectWithData:patchedData options:0 error:nil];
                                if (newObj) outObj = newObj;
                            }
                        }
                    }
                } else if ([obj isKindOfClass:[NSString class]]) {
                    NSData *strData = [(NSString *)obj dataUsingEncoding:NSUTF8StringEncoding];
                    if (strData) {
                        NSData *patchedData = btMaybePatchData(url, strData, resp, "CJPayBridge-Str");
                        if (patchedData != strData && [patchedData isKindOfClass:[NSData class]]) {
                            NSString *newStr = [[NSString alloc] initWithData:patchedData encoding:NSUTF8StringEncoding];
                            if (newStr) outObj = newStr;
                        }
                    }
                }
            }
        }
        fn(self_, sel, resp, outObj, err, trafficPath, comp);
    };

    method_setImplementation(m, imp_implementationWithBlock(blk));
    TTHLOG(@"✓ 已 hook BDXBridgeTtcjpayMultiNetRequestMethod -p_handleResponse:...");
}

// ============================================================
// Hook 3: NSJSONSerialization +JSONObjectWithData:options:error:
//   极速 memmem 过滤（仅命中含 "asset_virtual_item" 且含 "diamond" 的钱包首页 JSON），
//   无论走 TTNet / QUIC / 磁盘缓存 / CJPay / BDXBridge 均能 100% 生效！
// ============================================================
static _Thread_local BOOL t_inJSONHook = NO;

static void btHookJSONSerialization(void) {
    Class cls = [NSJSONSerialization class];
    SEL sel = @selector(JSONObjectWithData:options:error:);
    Method m = class_getClassMethod(cls, sel);
    if (!m) return;

    IMP origImp = method_getImplementation(m);
    typedef id (*Fn)(id, SEL, NSData *, NSJSONReadingOptions, NSError **);
    Fn fn = (Fn)origImp;

    id (^blk)(id, NSData *, NSJSONReadingOptions, NSError **) =
        ^id(id self_, NSData *data, NSJSONReadingOptions opt, NSError **err) {
        if (!t_inJSONHook && g_active && g_patchFunc && data && data.length >= 32) {
            const void *bytes = data.bytes;
            size_t len = (size_t)data.length;
            if (memmem(bytes, len, "asset_virtual_item", 18) != NULL &&
                memmem(bytes, len, "\"diamond\"", 9) != NULL) {
                t_inJSONHook = YES;
                NSData *patched = nil;
                @try {
                    NSURL *fakeURL = [NSURL URLWithString:@"https://webcast5-normal-lf.amemv.com/caijing/wallet/core/v1/homepage/index/"];
                    patched = g_patchFunc(fakeURL, data);
                } @catch (NSException *e) {
                    TTHLOG(@"JSONSerialization patch 异常: %@", e);
                }
                t_inJSONHook = NO;

                if (patched && patched.length > 0) {
                    return fn(self_, sel, patched, opt, err);
                }
            }
        }
        return fn(self_, sel, data, opt, err);
    };

    method_setImplementation(m, imp_implementationWithBlock(blk));
    TTHLOG(@"✓ 已 hook NSJSONSerialization +JSONObjectWithData:options:error:");
}

// ============================================================
// 入口
// ============================================================
void BTInstallTTNetProbe(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        TTHLOG(@"========== 钱包首页 JSON/TTNet Hook 启动 ==========");
        btHookJSONSerialization();
        btHookHandleResponsePreProcessing();
        btHookCJPayBridgeResponse();
        TTHLOG(@"========== 钱包首页 Hook 安装完成 ==========");
    });
}
