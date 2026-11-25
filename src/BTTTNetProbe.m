//
// BTTTNetProbe.m —— TTNet 深度探测 v4（稳定版）
// ============================================================
// v3 的崩溃原因（日志证据）：
//   [forward hook:334] —— 334 个方法全被换成 _objc_msgForward
//   其中包含 getter/setter（netCallback、setNetCallback:、hasCallback...）
//   → 任一被 C++ 内部直接调用 → 崩溃
//
// v4 修复：
//   ① 简单签名扩展到 6 个参数（覆盖 95% 方法），不用 forward
//   ② 跳过 getter/setter（名字以 set 开头 / 无冒号 / is+has 开头且无参）
//   ③ forward 只在参数 > 6 时使用，且只限 TTNetworkManager* 类
//   ④ forward 总数硬上限 40 个
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
// 递归 dump
// ============================================================
static void inspectObject(id obj, const char *clsName, const char *selName, int depth);

static void reportHit(NSString *kind, const char *cn, const char *sn,
                      const void *bytes, size_t len, const char *feature) {
    g_hits++;
    TPOLOG(@"★★★ 命中#%d [%@] %s -%s  %zuB  特征=\"%s\"",
           g_hits, kind, cn, sn, len, feature);
    NSMutableString *hex = [NSMutableString string];
    const uint8_t *b = (const uint8_t *)bytes;
    size_t n = len > 80 ? 80 : len;
    for (size_t i = 0; i < n; i++) [hex appendFormat:@"%02x", b[i]];
    TPOLOG(@"    hex: %@", hex);
}

static void inspectObject(id obj, const char *cn, const char *sn, int depth) {
    if (!g_probeActive || !obj || depth > 3 || g_hits > 40) return;
    @try {
        if ([obj isKindOfClass:[NSData class]]) {
            NSData *d = (NSData *)obj;
            const char *f = detectFeature(d.bytes, d.length);
            if (f) reportHit(@"NSData", cn, sn, d.bytes, d.length, f);
            return;
        }
        if ([obj isKindOfClass:[NSString class]]) {
            NSString *s = (NSString *)obj;
            if (s.length < 6 || s.length > 200000) return;
            NSData *d = [s dataUsingEncoding:NSUTF8StringEncoding];
            const char *f = detectFeature(d.bytes, d.length);
            if (f) reportHit(@"NSString", cn, sn, d.bytes, d.length, f);
            return;
        }
        if ([obj isKindOfClass:[NSDictionary class]] || [obj isKindOfClass:[NSArray class]]) {
            if (![NSJSONSerialization isValidJSONObject:obj]) return;
            NSData *d = [NSJSONSerialization dataWithJSONObject:obj options:0 error:nil];
            if (!d) return;
            const char *f = detectFeature(d.bytes, d.length);
            if (f) reportHit(@"JSON", cn, sn, d.bytes, d.length, f);
            return;
        }
        if ([obj isKindOfClass:[NSURL class]]) {
            NSString *s = [(NSURL *)obj absoluteString];
            NSData *d = [s dataUsingEncoding:NSUTF8StringEncoding];
            const char *f = detectFeature(d.bytes, d.length);
            if (f) TPOLOG(@"◆ URL %s -%s: %@", cn, sn, s);
            return;
        }
        if ([obj isKindOfClass:[NSURLRequest class]]) {
            inspectObject([(NSURLRequest *)obj URL], cn, sn, depth + 1);
            return;
        }
        if ([obj isKindOfClass:[NSNumber class]] || [obj isKindOfClass:[NSValue class]]) return;

        // description
        NSString *desc = nil;
        @try { desc = [obj description]; } @catch (NSException *e) { desc = nil; }
        if (desc && desc.length > 8 && desc.length < 200000) {
            NSData *d = [desc dataUsingEncoding:NSUTF8StringEncoding];
            const char *f = detectFeature(d.bytes, d.length);
            if (f) reportHit(@"desc", cn, sn, d.bytes, d.length, f);
        }

        // 递归 ivars
        if (depth < 3) {
            Class cls = object_getClass(obj);
            if (!cls) return;
            unsigned int count = 0;
            Ivar *ivars = class_copyIvarList(cls, &count);
            if (ivars) {
                for (unsigned int i = 0; i < count && i < 30; i++) {
                    const char *t = ivar_getTypeEncoding(ivars[i]);
                    if (!t || t[0] != '@') continue;
                    id val = nil;
                    @try { val = object_getIvar(obj, ivars[i]); } @catch (NSException *e) { val = nil; }
                    if (val) inspectObject(val, cn, sn, depth + 1);
                }
                free(ivars);
            }
        }
    } @catch (NSException *e) {}
}

static BOOL isBlockObject(id obj) {
    if (!obj) return NO;
    Class cls = object_getClass(obj);
    if (!cls) return NO;
    const char *n = class_getName(cls);
    if (!n) return NO;
    return (strstr(n, "Block") || strstr(n, "block") ||
            strcmp(n, "__NSGlobalBlock__") == 0 ||
            strcmp(n, "__NSMallocBlock__") == 0 ||
            strcmp(n, "__NSStackBlock__") == 0);
}

// ============================================================
// 名字过滤：跳过 getter/setter
// ============================================================
static BOOL shouldSkipSelector(const char *sn) {
    if (!sn || !*sn) return YES;

    // setter
    if (strncmp(sn, "set", 3) == 0) return YES;
    // 无参数（纯 getter）
    if (!strchr(sn, ':')) return YES;
    // 常见 BOOL getter
    if (strncmp(sn, "is", 2) == 0 && !strchr(sn, ':')) return YES;
    if (strncmp(sn, "has", 3) == 0 && !strchr(sn, ':')) return YES;
    if (strncmp(sn, "skip", 4) == 0 && !strchr(sn, ':')) return YES;

    // 计数参数个数
    int n = 0;
    for (const char *p = sn; *p; p++) if (*p == ':') n++;

    // 1 个参数且名字不像数据相关的 → 跳过（避免 hook 大量无关 setter 型方法）
    // 但保留明确的数据/回调类
    static const char *keep[] = {
        "data", "Data", "body", "Body",
        "response", "Response",
        "callback", "Callback",
        "receive", "Receive", "read", "Read",
        "handle", "Handle", "decode", "Decode",
        "parse", "Parse", "finish", "Finish",
    };
    if (n == 1) {
        for (size_t i = 0; i < sizeof(keep)/sizeof(keep[0]); i++) {
            if (strstr(sn, keep[i])) return NO;
        }
        return YES;   // 1 参数但名字不相关 → 跳过
    }

    return NO;
}

// ============================================================
// classifyMethod：扩展到 6 个参数
//   kind 1: @16@0:8                    (id)method
//   kind 2: @24@0:8@16                 (id)method:(id)
//   kind 3: v24@0:8@16                 (void)method:(id)
//   kind 4: @32@0:8@16@24              (id)method:(id):(id)
//   kind 5: v32@0:8@16@24              (void)method:(id):(id)
//   kind 6: v40@0:8@16@24@32           (void) 3 id
//   kind 7: v48@0:8@16@24@32@40        (void) 4 id
//   kind 8: v56@0:8@16@24@32@40@48     (void) 5 id
//   kind 9: v64@0:8@16@24@32@40@48@56  (void) 6 id
// ============================================================
static int classifyMethod(Method m) {
    const char *enc = method_getTypeEncoding(m);
    if (!enc) return 0;

    static const struct { const char *enc; int kind; } table[] = {
        {"@16@0:8", 1},
        {"@24@0:8@16", 2},
        {"v24@0:8@16", 3},
        {"@32@0:8@16@24", 4},
        {"v32@0:8@16@24", 5},
        {"v40@0:8@16@24@32", 6},
        {"v48@0:8@16@24@32@40", 7},
        {"v56@0:8@16@24@32@40@48", 8},
        {"v64@0:8@16@24@32@40@48@56", 9},
    };
    for (size_t i = 0; i < sizeof(table)/sizeof(table[0]); i++) {
        if (strcmp(enc, table[i].enc) == 0) return table[i].kind;
    }
    return 0;
}

// ============================================================
// 简单 hook（1-9）
// ============================================================
static void simpleHook(Class cls, SEL sel, Method m, int kind) {
    IMP orig = method_getImplementation(m);
    if (!orig) return;
    const char *cn = class_getName(cls);
    const char *sn = sel_getName(sel);

    @try {
        switch (kind) {
        case 1: {
            id b = ^id(id s) {
                id r = ((id(*)(id,SEL))orig)(s, sel);
                inspectObject(r, cn, sn, 0); return r;
            };
            method_setImplementation(m, imp_implementationWithBlock(b));
            break;
        }
        case 2: {
            id b = ^id(id s, id a) {
                inspectObject(a, cn, sn, 0);
                id r = ((id(*)(id,SEL,id))orig)(s, sel, a);
                inspectObject(r, cn, sn, 0); return r;
            };
            method_setImplementation(m, imp_implementationWithBlock(b));
            break;
        }
        case 3: {
            void (^b)(id, id) = ^(id s, id a) {
                inspectObject(a, cn, sn, 0);
                ((void(*)(id,SEL,id))orig)(s, sel, a);
            };
            method_setImplementation(m, imp_implementationWithBlock(b));
            break;
        }
        case 4: {
            id b = ^id(id s, id a, id c) {
                inspectObject(a, cn, sn, 0); inspectObject(c, cn, sn, 0);
                id r = ((id(*)(id,SEL,id,id))orig)(s, sel, a, c);
                inspectObject(r, cn, sn, 0); return r;
            };
            method_setImplementation(m, imp_implementationWithBlock(b));
            break;
        }
        case 5: {
            void (^b)(id, id, id) = ^(id s, id a, id c) {
                inspectObject(a, cn, sn, 0); inspectObject(c, cn, sn, 0);
                ((void(*)(id,SEL,id,id))orig)(s, sel, a, c);
            };
            method_setImplementation(m, imp_implementationWithBlock(b));
            break;
        }
        case 6: {
            void (^b)(id, id, id, id) = ^(id s, id a, id c, id d) {
                inspectObject(a, cn, sn, 0); inspectObject(c, cn, sn, 0); inspectObject(d, cn, sn, 0);
                ((void(*)(id,SEL,id,id,id))orig)(s, sel, a, c, d);
            };
            method_setImplementation(m, imp_implementationWithBlock(b));
            break;
        }
        case 7: {
            void (^b)(id, id, id, id, id) = ^(id s, id a, id c, id d, id e) {
                inspectObject(a, cn, sn, 0); inspectObject(c, cn, sn, 0);
                inspectObject(d, cn, sn, 0); inspectObject(e, cn, sn, 0);
                ((void(*)(id,SEL,id,id,id,id))orig)(s, sel, a, c, d, e);
            };
            method_setImplementation(m, imp_implementationWithBlock(b));
            break;
        }
        case 8: {
            void (^b)(id, id, id, id, id, id) = ^(id s, id a, id c, id d, id e, id f) {
                inspectObject(a, cn, sn, 0); inspectObject(c, cn, sn, 0);
                inspectObject(d, cn, sn, 0); inspectObject(e, cn, sn, 0); inspectObject(f, cn, sn, 0);
                ((void(*)(id,SEL,id,id,id,id,id))orig)(s, sel, a, c, d, e, f);
            };
            method_setImplementation(m, imp_implementationWithBlock(b));
            break;
        }
        case 9: {
            void (^b)(id, id, id, id, id, id, id) = ^(id s, id a, id c, id d, id e, id f, id g) {
                inspectObject(a, cn, sn, 0); inspectObject(c, cn, sn, 0);
                inspectObject(d, cn, sn, 0); inspectObject(e, cn, sn, 0);
                inspectObject(f, cn, sn, 0); inspectObject(g, cn, sn, 0);
                ((void(*)(id,SEL,id,id,id,id,id,id))orig)(s, sel, a, c, d, e, f, g);
            };
            method_setImplementation(m, imp_implementationWithBlock(b));
            break;
        }
        }
    } @catch (NSException *e) {}
}

// ============================================================
// forward hook（只在参数 > 6 且类是 TTNetworkManager* 时用）
// ============================================================
static NSMutableDictionary<NSString *, NSValue *> *g_origIMPs = nil;
static int g_forwardCount = 0;
#define BT_MAX_FORWARD 40

static void BTForwardInvocation(id self, SEL _cmd, NSInvocation *inv) {
    SEL sel = inv.selector;
    Class cls = object_getClass(self);
    NSString *key = [NSString stringWithFormat:@"%s|%s",
                     class_getName(cls) ?: "?", sel_getName(sel) ?: "?"];
    NSValue *v = g_origIMPs[key];
    if (!v) { [self doesNotRecognizeSelector:sel]; return; }
    IMP orig = [v pointerValue];
    if (!orig) return;

    const char *cn = class_getName(cls);
    const char *sn = sel_getName(sel);

    NSMethodSignature *sig = inv.methodSignature;
    NSUInteger n = sig.numberOfArguments;
    for (NSUInteger i = 2; i < n; i++) {
        const char *t = [sig getArgumentTypeAtIndex:i];
        if (!t || t[0] != '@') continue;
        if (strcmp(t, "@?") == 0) continue;
        __unsafe_unretained id arg = nil;
        @try { [inv getArgument:&arg atIndex:i]; } @catch (NSException *e) { continue; }
        if (!arg || isBlockObject(arg)) continue;
        inspectObject(arg, cn, sn, 0);
    }

    @try {
        if ([inv respondsToSelector:@selector(invokeUsingIMP:)]) {
            [inv invokeUsingIMP:orig];
        } else {
            Method m = class_getInstanceMethod(cls, sel);
            IMP saved = m ? method_getImplementation(m) : NULL;
            if (m) method_setImplementation(m, orig);
            [inv invokeWithTarget:self];
            if (m && saved) method_setImplementation(m, saved);
        }
    } @catch (NSException *e) {
        TPOLOG(@"forward 异常 %s -%s: %@", cn, sn, e);
    }
}

static BOOL installForwardHook(Class cls, SEL sel) {
    if (g_forwardCount >= BT_MAX_FORWARD) return NO;
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return NO;
    IMP cur = method_getImplementation(m);
    if (cur == _objc_msgForward) return NO;

    NSString *key = [NSString stringWithFormat:@"%s|%s",
                     class_getName(cls), sel_getName(sel)];
    if (!g_origIMPs[key]) g_origIMPs[key] = [NSValue valueWithPointer:cur];
    method_setImplementation(m, _objc_msgForward);

    SEL fsel = @selector(forwardInvocation:);
    Method fm = class_getInstanceMethod(cls, fsel);
    if (!fm || method_getImplementation(fm) != (IMP)BTForwardInvocation) {
        class_replaceMethod(cls, fsel, (IMP)BTForwardInvocation, "v@:@");
    }
    g_forwardCount++;
    return YES;
}

// ============================================================
// 安装
// ============================================================
void BTInstallTTNetProbe(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        if (!g_origIMPs) g_origIMPs = [NSMutableDictionary dictionary];

        TPOLOG(@"========== v4 稳定探测启动 ==========");

        int total = objc_getClassList(NULL, 0);
        if (total <= 0) return;
        Class *classes = (Class *)malloc(sizeof(Class) * total);
        if (!classes) return;
        total = objc_getClassList(classes, total);
        TPOLOG(@"总类数: %d", total);

        static const char *patterns[] = {
            "TTNetworkManager", "TTHttpTask", "TTNetResponse",
            "NetResponse", "NetTask",
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

            // forward 只在 TTNetworkManager* 类上启用
            BOOL allowForward = (strncmp(name, "TTNetworkManager", 16) == 0 ||
                                 strncmp(name, "TTHttpTask", 10) == 0);

            matched++;
            TPOLOG(@"类: %s%@", name, allowForward ? @"  [允许forward]" : @"");

            unsigned int mc = 0;
            Method *ms = class_copyMethodList(cls, &mc);
            if (!ms) continue;

            for (unsigned int k = 0; k < mc; k++) {
                Method m = ms[k];
                SEL sel = method_getName(m);
                const char *sn = sel_getName(sel);
                if (!sn) continue;
                if (shouldSkipSelector(sn)) { skipped++; continue; }

                int kind = classifyMethod(m);
                if (kind > 0) {
                    simpleHook(cls, sel, m, kind);
                    simpleHooked++;
                    TPOLOG(@"  [S%d] %s", kind, sn);
                } else if (allowForward) {
                    if (installForwardHook(cls, sel)) {
                        forwardHooked++;
                        TPOLOG(@"  [F] %s", sn);
                    } else {
                        skipped++;
                    }
                } else {
                    skipped++;
                }
            }
            free(ms);
        }

        free(classes);

        TPOLOG(@"========== 完成 ==========");
        TPOLOG(@"类:%d  简单hook:%d  forward:%d  跳过:%d",
               matched, simpleHooked, forwardHooked, skipped);
        TPOLOG(@"现在打开礼物面板，观察 ★★★ 命中");
    });
}
