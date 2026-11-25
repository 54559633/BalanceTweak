//
// BTTTNetProbe.m —— TTNet 深度探测 v3（未越狱兼容 + 多参数 + 递归 dump）
// ============================================================
// v2 的失败原因（日志证据）：
//   · TTNetworkManagerChromium 的 request 方法有 16 个参数
//     → classifyMethod 只放行 ≤2 个额外参数 → 383 个方法被跳过
//   · TTHttpTaskChromium -onReadResponseData: hook 成功但零命中
//     → 参数是自定义对象，inspectObject 只认 NSData/NSString/JSON
//
// v3 方案：
//   ① forwardInvocation 拦截任意参数数量的方法（Aspects 风格，未越狱安全）
//   ② inspectObject 递归 dump ivars（深度 3）
//   ③ 识别并包装 block 参数（callbackWithResponse: 之类）
// ============================================================
#import "BTTTNetProbe.h"
#import "BTLog.h"
#import <objc/runtime.h>
#import <objc/message.h>
#include <string.h>

#define TPOLOG(fmt, ...) BT_LOG_M(@"TTNetProbe", fmt, ##__VA_ARGS__)

static BOOL g_probeActive = YES;
static int g_hits = 0;

void BTStopTTNetProbe(void) { g_probeActive = NO; }

// ============================================================
// 特征检测
// ============================================================
static const char *detectFeature(const void *data, size_t len) {
    if (!data || len < 6) return NULL;
    static const char *patterns[] = {
        "wallet/info", "/webcast/wallet", "recharge_page",
        "wallet/core/v1", "diamond_cnt", "wallet_api",
    };
    static const size_t plens[] = {11, 15, 13, 14, 11, 10};
    const uint8_t *p = (const uint8_t *)data;
    for (int i = 0; i < 6; i++) {
        size_t pl = plens[i];
        if (len < pl) continue;
        for (size_t j = 0; j + pl <= len; j++) {
            if (memcmp(p + j, patterns[i], pl) == 0) return patterns[i];
        }
    }
    return NULL;
}

// ============================================================
// 递归 dump（深度 3）
// ============================================================
static void inspectObject(id obj, const char *clsName, const char *selName, int depth);

static void reportHit(NSString *kind, const char *clsName, const char *selName,
                      const void *bytes, size_t len, const char *feature) {
    g_hits++;
    TPOLOG(@"★★★ 命中#%d [%@] %s -%s  %zuB  特征=\"%s\"",
           g_hits, kind, clsName, selName, len, feature);

    NSMutableString *hex = [NSMutableString string];
    const uint8_t *b = (const uint8_t *)bytes;
    size_t n = len > 80 ? 80 : len;
    for (size_t i = 0; i < n; i++) [hex appendFormat:@"%02x", b[i]];
    TPOLOG(@"    hex: %@", hex);
}

static void inspectObject(id obj, const char *clsName, const char *selName, int depth) {
    if (!g_probeActive || !obj || depth > 3) return;
    if (g_hits > 40) return;   // 防止日志爆炸

    @try {
        // NSData
        if ([obj isKindOfClass:[NSData class]]) {
            NSData *d = (NSData *)obj;
            const char *f = detectFeature(d.bytes, d.length);
            if (f) reportHit(@"NSData", clsName, selName, d.bytes, d.length, f);
            return;
        }
        // NSString
        if ([obj isKindOfClass:[NSString class]]) {
            NSString *s = (NSString *)obj;
            if (s.length < 6 || s.length > 200000) return;
            NSData *d = [s dataUsingEncoding:NSUTF8StringEncoding];
            const char *f = detectFeature(d.bytes, d.length);
            if (f) reportHit(@"NSString", clsName, selName, d.bytes, d.length, f);
            return;
        }
        // NSDictionary / NSArray
        if ([obj isKindOfClass:[NSDictionary class]] || [obj isKindOfClass:[NSArray class]]) {
            if (![NSJSONSerialization isValidJSONObject:obj]) return;
            NSData *d = [NSJSONSerialization dataWithJSONObject:obj options:0 error:nil];
            if (!d) return;
            const char *f = detectFeature(d.bytes, d.length);
            if (f) reportHit(@"JSON", clsName, selName, d.bytes, d.length, f);
            return;
        }
        // NSNumber / NSValue
        if ([obj isKindOfClass:[NSNumber class]]) {
            const char *f = detectFeature(&obj, sizeof(id));
            return;
        }
        // NSURL / NSURLRequest → 检查 URL
        if ([obj isKindOfClass:[NSURL class]]) {
            NSString *s = [(NSURL *)obj absoluteString];
            NSData *d = [s dataUsingEncoding:NSUTF8StringEncoding];
            const char *f = detectFeature(d.bytes, d.length);
            if (f) TPOLOG(@"◆ URL命中 %s -%s: %@", clsName, selName, s);
            return;
        }
        if ([obj isKindOfClass:[NSURLRequest class]]) {
            inspectObject([(NSURLRequest *)obj URL], clsName, selName, depth + 1);
            return;
        }

        // 未知对象 → description（可能崩，包 try）
        NSString *desc = nil;
        @try { desc = [obj description]; } @catch (NSException *e) { desc = nil; }
        if (desc && desc.length > 8 && desc.length < 200000) {
            NSData *d = [desc dataUsingEncoding:NSUTF8StringEncoding];
            const char *f = detectFeature(d.bytes, d.length);
            if (f) reportHit(@"desc", clsName, selName, d.bytes, d.length, f);
        }

        // 递归 ivars
        if (depth < 3) {
            Class cls = object_getClass(obj);
            if (!cls) return;
            unsigned int count = 0;
            Ivar *ivars = class_copyIvarList(cls, &count);
            if (ivars) {
                for (unsigned int i = 0; i < count && i < 30; i++) {
                    const char *type = ivar_getTypeEncoding(ivars[i]);
                    if (!type || type[0] != '@') continue;   // 只看对象类型
                    id val = nil;
                    @try { val = object_getIvar(obj, ivars[i]); } @catch (NSException *e) { val = nil; }
                    if (val) inspectObject(val, clsName, selName, depth + 1);
                }
                free(ivars);
            }
        }
    } @catch (NSException *e) {
        // 忽略
    }
}

// ============================================================
// block 检测
// ============================================================
static BOOL isBlockObject(id obj) {
    if (!obj) return NO;
    Class cls = object_getClass(obj);
    if (!cls) return NO;
    const char *name = class_getName(cls);
    if (!name) return NO;
    return (strstr(name, "Block") != NULL ||
            strstr(name, "block") != NULL ||
            strcmp(name, "__NSGlobalBlock__") == 0 ||
            strcmp(name, "__NSMallocBlock__") == 0 ||
            strcmp(name, "__NSStackBlock__") == 0);
}

// ============================================================
// forwardInvocation 方案（可处理任意参数数量）
// ============================================================
static NSMutableDictionary<NSString *, NSValue *> *g_origIMPs = nil;

static NSString *impKey(Class cls, SEL sel) {
    return [NSString stringWithFormat:@"%s|%s",
            class_getName(cls) ?: "?", sel_getName(sel) ?: "?"];
}

/// 统一 forwardInvocation 实现
static void BTForwardInvocation(id self, SEL _cmd, NSInvocation *inv) {
    SEL sel = inv.selector;
    Class cls = object_getClass(self);
    NSString *key = impKey(cls, sel);
    NSValue *v = g_origIMPs[key];
    if (!v) {
        // 没拦截过的 selector，走默认
        if ([self respondsToSelector:@selector(doesNotRecognizeSelector:)]) {
            [self doesNotRecognizeSelector:sel];
        }
        return;
    }
    IMP orig = [v pointerValue];
    if (!orig) return;

    const char *clsName = class_getName(cls);
    const char *selName = sel_getName(sel);

    // 遍历所有参数，检查对象类型的
    NSMethodSignature *sig = inv.methodSignature;
    NSUInteger n = sig.numberOfArguments;
    for (NSUInteger i = 2; i < n; i++) {
        const char *type = [sig getArgumentTypeAtIndex:i];
        if (!type || type[0] != '@') continue;
        if (strcmp(type, "@?") == 0) continue;   // block 本身不检查

        __unsafe_unretained id arg = nil;
        @try { [inv getArgument:&arg atIndex:i]; } @catch (NSException *e) { continue; }
        if (!arg) continue;
        if (isBlockObject(arg)) continue;

        inspectObject(arg, clsName, selName, 0);
    }

    // 调用原实现
    @try {
        if ([inv respondsToSelector:@selector(invokeUsingIMP:)]) {
            [inv invokeUsingIMP:orig];
        } else {
            // fallback：临时恢复 IMP
            Method m = class_getInstanceMethod(cls, sel);
            IMP saved = m ? method_getImplementation(m) : NULL;
            if (m) method_setImplementation(m, orig);
            [inv invokeWithTarget:self];
            if (m && saved) method_setImplementation(m, saved);
        }
    } @catch (NSException *e) {
        TPOLOG(@"调用原实现异常 %s -%s: %@", clsName, selName, e);
    }
}

/// 把方法改成 forward（保留原 IMP）
static BOOL installForwardHook(Class cls, SEL sel) {
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return NO;

    IMP cur = method_getImplementation(m);
    if (cur == _objc_msgForward) return YES;   // 已经装过

    // 保存原 IMP
    NSString *key = impKey(cls, sel);
    if (!g_origIMPs[key]) {
        g_origIMPs[key] = [NSValue valueWithPointer:cur];
    }

    // 换成 forward
    method_setImplementation(m, _objc_msgForward);

    // 确保类有 forwardInvocation:
    SEL fsel = @selector(forwardInvocation:);
    Method fm = class_getInstanceMethod(cls, fsel);
    if (!fm || method_getImplementation(fm) != (IMP)BTForwardInvocation) {
        class_replaceMethod(cls, fsel, (IMP)BTForwardInvocation, "v@:@");
    }
    return YES;
}

// ============================================================
// 简单签名 hook（保留 v2 的能力，处理 getter/setter）
// ============================================================
static int classifyMethod(Method m) {
    const char *enc = method_getTypeEncoding(m);
    if (!enc) return 0;
    if (strcmp(enc, "@16@0:8") == 0) return 1;
    if (strcmp(enc, "@24@0:8@16") == 0) return 2;
    if (strcmp(enc, "v24@0:8@16") == 0) return 3;
    if (strcmp(enc, "@32@0:8@16@24") == 0) return 4;
    return 0;
}

static void simpleHook(Class cls, SEL sel, Method m, int kind) {
    IMP orig = method_getImplementation(m);
    if (!orig) return;
    const char *clsName = class_getName(cls);
    const char *selName = sel_getName(sel);

    @try {
        switch (kind) {
        case 1: {
            id b = ^id(id s) {
                id r = ((id(*)(id,SEL))orig)(s, sel);
                inspectObject(r, clsName, selName, 0);
                return r;
            };
            method_setImplementation(m, imp_implementationWithBlock(b));
            break;
        }
        case 2: {
            id b = ^id(id s, id a) {
                inspectObject(a, clsName, selName, 0);
                id r = ((id(*)(id,SEL,id))orig)(s, sel, a);
                inspectObject(r, clsName, selName, 0);
                return r;
            };
            method_setImplementation(m, imp_implementationWithBlock(b));
            break;
        }
        case 3: {
            void (^b)(id, id) = ^(id s, id a) {
                inspectObject(a, clsName, selName, 0);
                ((void(*)(id,SEL,id))orig)(s, sel, a);
            };
            method_setImplementation(m, imp_implementationWithBlock(b));
            break;
        }
        case 4: {
            id b = ^id(id s, id a, id c) {
                inspectObject(a, clsName, selName, 0);
                inspectObject(c, clsName, selName, 0);
                id r = ((id(*)(id,SEL,id,id))orig)(s, sel, a, c);
                inspectObject(r, clsName, selName, 0);
                return r;
            };
            method_setImplementation(m, imp_implementationWithBlock(b));
            break;
        }
        }
    } @catch (NSException *e) {}
}

// ============================================================
// 安装
// ============================================================
void BTInstallTTNetProbe(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        if (!g_origIMPs) g_origIMPs = [NSMutableDictionary dictionary];

        TPOLOG(@"========== v3 深度探测启动 ==========");

        int total = objc_getClassList(NULL, 0);
        if (total <= 0) return;
        Class *classes = (Class *)malloc(sizeof(Class) * total);
        if (!classes) return;
        total = objc_getClassList(classes, total);
        TPOLOG(@"总类数: %d", total);

        // 目标类关键词
        static const char *patterns[] = {
            "TTNetworkManager", "TTHttpTask", "TTNetResponse",
            "NetResponse", "NetTask", "NetCallback",
            "IESNetworkResponse", "NetworkResponse",
        };
        const int np = sizeof(patterns) / sizeof(patterns[0]);

        int matched = 0, simpleHooked = 0, forwardHooked = 0, skipped = 0;

        for (int i = 0; i < total; i++) {
            Class cls = classes[i];
            if (!cls) continue;
            const char *name = class_getName(cls);
            if (!name) continue;

            BOOL ok = NO;
            for (int j = 0; j < np; j++) {
                if (strstr(name, patterns[j])) { ok = YES; break; }
            }
            if (!ok) continue;

            matched++;
            TPOLOG(@"类: %s", name);

            unsigned int mc = 0;
            Method *ms = class_copyMethodList(cls, &mc);
            if (!ms) continue;

            for (unsigned int k = 0; k < mc; k++) {
                Method m = ms[k];
                SEL sel = method_getName(m);
                const char *sn = sel_getName(sel);
                if (!sn) continue;

                // 名字过滤：只要跟数据/响应/回调相关的
                static const char *want[] = {
                    "data", "Data", "body", "Body", "response", "Response",
                    "finish", "Finish", "receive", "Receive",
                    "handle", "Handle", "decode", "Decode",
                    "callback", "Callback", "read", "Read",
                    "url", "URL", "request", "Request",
                };
                BOOL nameOk = NO;
                for (size_t w = 0; w < sizeof(want)/sizeof(want[0]); w++) {
                    if (strstr(sn, want[w])) { nameOk = YES; break; }
                }
                if (!nameOk) continue;

                int kind = classifyMethod(m);
                if (kind > 0) {
                    simpleHook(cls, sel, m, kind);
                    simpleHooked++;
                    TPOLOG(@"  [简单%d] %s", kind, sn);
                } else {
                    // 多参数 → forwardInvocation
                    if (installForwardHook(cls, sel)) {
                        forwardHooked++;
                        TPOLOG(@"  [forward] %s", sn);
                    } else {
                        skipped++;
                    }
                }
            }
            free(ms);
        }

        free(classes);

        TPOLOG(@"========== 完成 ==========");
        TPOLOG(@"类:%d  简单hook:%d  forward hook:%d  跳过:%d",
               matched, simpleHooked, forwardHooked, skipped);
        TPOLOG(@"现在打开礼物面板，观察 ★★★ 命中");
    });
}
