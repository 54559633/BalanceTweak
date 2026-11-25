//
// BTTTNetProbe.m —— TTNet 精准拦截器（v5 非越狱安全版）
// ============================================================
// 基于真机日志确认的精准方法：
//   1. TTNetworkManagerChromium
//      -handleResponsePreProcessing_:data:error:request:preprocessor:headerCallback:dataCallback:completedCallback:
//   2. TTHttpTaskChromium
//      -onReadResponseData:
//
// 安全保障：
//   - 完全移除 _objc_msgForward 和批量类扫描 hook（零崩溃）
//   - swizzle 前严格校验参数个数、返回类型、每个参数类型编码
//   - 通过 associated object 防止同一请求被两个 hook 重复改写
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

void BTStopTTNetProbe(void) {
    g_active = NO;
}

// ============================================================
// 安全读取对象属性（仅当方法返回类型为 '@' 时调用）
// ============================================================
static id btSafeGetObjectProp(id obj, SEL sel) {
    if (!obj || !sel) return nil;
    Class cls = object_getClass(obj);
    if (!cls) return nil;
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return nil;
    if (method_getNumberOfArguments(m) != 2) return nil;
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
    NSString *s = url.path.length > 0 ? url.path : (url.absoluteString ?: @"");
    return ([s containsString:@"/webcast/wallet/info/"] ||
            [s containsString:@"wallet_api/recharge_page"] ||
            [s containsString:@"wallet/core/v1/homepage/index"]);
}

// ============================================================
// 统一改写入口（带去重，防止重复 patch）
// ============================================================
static id btMaybePatchData(NSURL *url, id rawData, id dedupObj, const char *source) {
    if (!g_active || !g_patchFunc || !url || !rawData) return rawData;
    if (![rawData isKindOfClass:[NSData class]]) return rawData;

    NSData *data = (NSData *)rawData;
    if (data.length == 0) return rawData;

    if (objc_getAssociatedObject(rawData, &kBTPatchedKey) != nil) {
        return rawData;
    }
    if (dedupObj && objc_getAssociatedObject(dedupObj, &kBTPatchedKey) != nil) {
        return rawData;
    }

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

    if (!patched || patched.length == 0) {
        return rawData;
    }

    id result = [rawData isKindOfClass:[NSMutableData class]] ? [patched mutableCopy] : patched;
    objc_setAssociatedObject(result, &kBTPatchedKey, @YES, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    return result;
}

// ============================================================
// 校验所有显式参数是否为对象/Block ('@')，确保 arm64/arm64e ABI 100% 安全
// ============================================================
static BOOL btVerifyObjectArgs(Method m, unsigned int expectedTotalArgs, char *outRetType) {
    if (!m) return NO;
    unsigned int argc = method_getNumberOfArguments(m);
    if (argc != expectedTotalArgs) return NO;

    char ret[16] = {0};
    method_getReturnType(m, ret, sizeof(ret));
    if (ret[0] != 'v' && ret[0] != '@') return NO;
    if (outRetType) *outRetType = ret[0];

    for (unsigned int i = 2; i < argc; i++) {
        char arg[16] = {0};
        method_getArgumentType(m, i, arg, sizeof(arg));
        if (arg[0] != '@') return NO;
    }
    return YES;
}

// ============================================================
// Hook 1: TTNetworkManagerChromium
//   -handleResponsePreProcessing_:data:error:request:preprocessor:headerCallback:dataCallback:completedCallback:
// ============================================================
static void btHookHandleResponsePreProcessing(void) {
    Class cls = NSClassFromString(@"TTNetworkManagerChromium");
    if (!cls) {
        TTHLOG(@"未找到 TTNetworkManagerChromium");
        return;
    }

    SEL sel = NSSelectorFromString(
        @"handleResponsePreProcessing_:data:error:request:preprocessor:headerCallback:dataCallback:completedCallback:");
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) {
        TTHLOG(@"TTNetworkManagerChromium 无 handleResponsePreProcessing_:");
        return;
    }

    const char *enc = method_getTypeEncoding(m);
    TTHLOG(@"handleResponsePreProcessing_ 签名: %s", enc ?: "?");

    char retType = 0;
    if (!btVerifyObjectArgs(m, 10, &retType)) {
        TTHLOG(@"handleResponsePreProcessing_ 参数签名不符，跳过以防崩溃");
        return;
    }

    IMP origImp = method_getImplementation(m);
    if (retType == 'v') {
        typedef void (*Fn)(id, SEL, id, id, id, id, id, id, id, id);
        Fn fn = (Fn)origImp;
        void (^blk)(id, id, id, id, id, id, id, id, id) =
            ^(id self_, id resp, id data, id err, id req, id pre, id hdrCb, id dataCb, id compCb) {
            id outData = data;
            if (data && !err) {
                NSURL *url = btExtractURL(req) ?: btExtractURL(resp);
                if (btIsTargetWalletURL(url)) {
                    outData = btMaybePatchData(url, data, req ?: resp, "PreProcessing");
                }
            }
            fn(self_, sel, resp, outData, err, req, pre, hdrCb, dataCb, compCb);
        };
        method_setImplementation(m, imp_implementationWithBlock(blk));
    } else {
        typedef id (*Fn)(id, SEL, id, id, id, id, id, id, id, id);
        Fn fn = (Fn)origImp;
        id (^blk)(id, id, id, id, id, id, id, id, id) =
            ^id(id self_, id resp, id data, id err, id req, id pre, id hdrCb, id dataCb, id compCb) {
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
    }
    TTHLOG(@"✓ 已 hook TTNetworkManagerChromium -handleResponsePreProcessing_:");
}

// ============================================================
// Hook 2: TTHttpTaskChromium -onReadResponseData:
// ============================================================
static void btHookOnReadResponseData(void) {
    Class cls = NSClassFromString(@"TTHttpTaskChromium");
    if (!cls) {
        TTHLOG(@"未找到 TTHttpTaskChromium");
        return;
    }

    SEL sel = NSSelectorFromString(@"onReadResponseData:");
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) {
        TTHLOG(@"TTHttpTaskChromium 无 onReadResponseData:");
        return;
    }

    const char *enc = method_getTypeEncoding(m);
    TTHLOG(@"onReadResponseData: 签名: %s", enc ?: "?");

    char retType = 0;
    if (!btVerifyObjectArgs(m, 3, &retType) || retType != 'v') {
        TTHLOG(@"onReadResponseData: 签名不符，跳过");
        return;
    }

    IMP origImp = method_getImplementation(m);
    typedef void (*Fn)(id, SEL, id);
    Fn fn = (Fn)origImp;

    void (^blk)(id, id) = ^(id self_, id data) {
        id outData = data;
        if (data) {
            NSURL *url = btExtractURL(self_);
            if (btIsTargetWalletURL(url)) {
                outData = btMaybePatchData(url, data, self_, "onReadResponseData");
            }
        }
        fn(self_, sel, outData);
    };

    method_setImplementation(m, imp_implementationWithBlock(blk));
    TTHLOG(@"✓ 已 hook TTHttpTaskChromium -onReadResponseData:");
}

// ============================================================
// 只读诊断：打印 TTNetworkManager 相关关键方法签名（绝不 hook）
// ============================================================
static void btLogKeySignatures(void) {
    Class mgr = NSClassFromString(@"TTNetworkManager");
    if (mgr) {
        SEL s1 = NSSelectorFromString(@"addResponseMutableDataFilterBlock:");
        Method m1 = class_getInstanceMethod(mgr, s1);
        if (m1) {
            TTHLOG(@"[诊断] TTNetworkManager -addResponseMutableDataFilterBlock: => %s",
                   method_getTypeEncoding(m1) ?: "?");
        }
    }
    Class chr = NSClassFromString(@"TTNetworkManagerChromium");
    if (chr) {
        SEL s2 = NSSelectorFromString(@"requestForBinaryWithResponse:params:method:needCommonParams:callback:");
        Method m2 = class_getInstanceMethod(chr, s2);
        if (m2) {
            TTHLOG(@"[诊断] TTNetworkManagerChromium -requestForBinaryWithResponse:... => %s",
                   method_getTypeEncoding(m2) ?: "?");
        }
    }
}

// ============================================================
// 入口
// ============================================================
void BTInstallTTNetProbe(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        TTHLOG(@"========== TTNet 精准 Hook (v5) 启动 ==========");
        btLogKeySignatures();
        btHookHandleResponsePreProcessing();
        btHookOnReadResponseData();
        TTHLOG(@"========== TTNet 精准 Hook 安装完成 ==========");
    });
}
