//
// BTTTNetProbe.m —— TTNet 安全探测（未越狱兼容）
// ============================================================
// 未越狱设备只允许 ObjC method swizzling，禁止改代码段
//
// 之前崩溃原因：
//   imp_implementationWithBlock 的 block 签名与方法签名不匹配
//   → 调用时栈帧错乱 → 崩
//
// 修复：
//   1. 用 NSMethodSignature 严格解析方法签名
//   2. 只 hook 签名确定的三种：
//        (A) - (id)method             @16@0:8
//        (B) - (id)method:(id)arg     @24@0:8@16
//        (C) - (void)method:(id)arg   v24@0:8@16
//   3. 其他签名一律跳过
// ============================================================
#import "BTTTNetProbe.h"
#import "BTLog.h"
#import <objc/runtime.h>
#include <string.h>

#define TPOLOG(fmt, ...) BT_LOG_M(@"TTNetProbe", fmt, ##__VA_ARGS__)

static BOOL g_probeActive = YES;

void BTStopTTNetProbe(void) {
    g_probeActive = NO;
    TPOLOG(@"探测已停止");
}

// ============================================================
// 特征检测
// ============================================================
static const char *detectFeature(const void *data, size_t len) {
    if (!data || len < 8) return NULL;

    static const char *patterns[] = {
        "wallet/info",
        "/webcast/wallet",
        "wallet_api/recharge_page",
        "wallet/core/v1/homepage",
        "diamond_cnt",
    };
    static const size_t plens[] = {11, 15, 24, 23, 11};

    const uint8_t *p = (const uint8_t *)data;
    for (int i = 0; i < 5; i++) {
        const char *pat = patterns[i];
        size_t plen = plens[i];
        if (len < plen) continue;
        for (size_t j = 0; j + plen <= len; j++) {
            if (memcmp(p + j, pat, plen) == 0) return pat;
        }
    }
    return NULL;
}

/// 从 id 对象里提取可检查的字节
static void inspectObject(id obj, const char *clsName, const char *selName) {
    if (!g_probeActive || !obj) return;

    // NSData
    if ([obj isKindOfClass:[NSData class]]) {
        NSData *d = (NSData *)obj;
        const char *hit = detectFeature(d.bytes, d.length);
        if (hit) {
            TPOLOG(@"★命中 NSData %s -%s  %luB  特征=\"%s\"",
                   clsName, selName, (unsigned long)d.length, hit);
            // hex dump 前 48 字节
            NSMutableString *hex = [NSMutableString string];
            NSUInteger n = MIN(d.length, 48);
            const uint8_t *b = d.bytes;
            for (NSUInteger i = 0; i < n; i++) [hex appendFormat:@"%02x", b[i]];
            TPOLOG(@"   hex: %@", hex);
        }
        return;
    }

    // NSString
    if ([obj isKindOfClass:[NSString class]]) {
        NSString *s = (NSString *)obj;
        NSData *d = [s dataUsingEncoding:NSUTF8StringEncoding];
        const char *hit = detectFeature(d.bytes, d.length);
        if (hit) {
            TPOLOG(@"★命中 NSString %s -%s  特征=\"%s\"", clsName, selName, hit);
        }
        return;
    }

    // NSDictionary / NSArray / NSNumber → 转 JSON 检查
    if ([obj isKindOfClass:[NSDictionary class]] ||
        [obj isKindOfClass:[NSArray class]]) {
        if (![NSJSONSerialization isValidJSONObject:obj]) return;
        NSData *d = [NSJSONSerialization dataWithJSONObject:obj options:0 error:nil];
        if (!d) return;
        const char *hit = detectFeature(d.bytes, d.length);
        if (hit) {
            TPOLOG(@"★命中 JSON %s -%s  %luB  特征=\"%s\"",
                   clsName, selName, (unsigned long)d.length, hit);
        }
        return;
    }
}

// ============================================================
// 安全 hook（严格签名）
// ============================================================

/// 解析方法签名，返回类型代号：
///   1 = @16@0:8      (id)method
///   2 = @24@0:8@16   (id)method:(id)
///   3 = v24@0:8@16   (void)method:(id)
///   4 = @32@0:8@16@24 (id)method:(id):(id)
///   0 = 不安全，跳过
static int classifyMethod(Method m) {
    if (!m) return 0;
    const char *enc = method_getTypeEncoding(m);
    if (!enc) return 0;

    // 精确字符串匹配（最安全）
    if (strcmp(enc, "@16@0:8") == 0) return 1;
    if (strcmp(enc, "@24@0:8@16") == 0) return 2;
    if (strcmp(enc, "v24@0:8@16") == 0) return 3;
    if (strcmp(enc, "@32@0:8@16@24") == 0) return 4;

    // 带引号/其他修饰的变体：用 NSMethodSignature 二次校验
    @try {
        NSMethodSignature *sig = [NSMethodSignature signatureWithObjCTypes:enc];
        if (!sig) return 0;
        NSUInteger n = sig.numberOfArguments;
        const char *ret = sig.methodReturnType;

        // 所有参数必须是 @ 或 :
        for (NSUInteger i = 0; i < n; i++) {
            const char *t = [sig getArgumentTypeAtIndex:i];
            if (!t) return 0;
            if (t[0] != '@' && t[0] != ':') return 0;
        }

        BOOL retIsId = (ret[0] == '@');
        BOOL retIsVoid = (ret[0] == 'v');

        if (n == 2 && retIsId) return 1;
        if (n == 3 && retIsId) return 2;
        if (n == 3 && retIsVoid) return 3;
        if (n == 4 && retIsId) return 4;
    } @catch (NSException *e) {
        return 0;
    }
    return 0;
}

static int g_hookedCount = 0;
static int g_skippedCount = 0;

static void safeHook(Class cls, SEL sel, Method m, int kind) {
    const char *clsName = class_getName(cls);
    const char *selName = sel_getName(sel);
    IMP orig = method_getImplementation(m);
    if (!orig) return;

    @try {
        switch (kind) {
        case 1: {
            // - (id)method
            id block = ^id(id self_) {
                id r = ((id (*)(id, SEL))orig)(self_, sel);
                inspectObject(r, clsName, selName);
                return r;
            };
            method_setImplementation(m, imp_implementationWithBlock(block));
            break;
        }
        case 2: {
            // - (id)method:(id)arg
            id block = ^id(id self_, id arg) {
                inspectObject(arg, clsName, selName);
                id r = ((id (*)(id, SEL, id))orig)(self_, sel, arg);
                inspectObject(r, clsName, selName);
                return r;
            };
            method_setImplementation(m, imp_implementationWithBlock(block));
            break;
        }
        case 3: {
            // - (void)method:(id)arg
            void (^block)(id, id) = ^(id self_, id arg) {
                inspectObject(arg, clsName, selName);
                ((void (*)(id, SEL, id))orig)(self_, sel, arg);
            };
            method_setImplementation(m, imp_implementationWithBlock(block));
            break;
        }
        case 4: {
            // - (id)method:(id)a arg2:(id)b
            id block = ^id(id self_, id a, id b) {
                inspectObject(a, clsName, selName);
                inspectObject(b, clsName, selName);
                id r = ((id (*)(id, SEL, id, id))orig)(self_, sel, a, b);
                inspectObject(r, clsName, selName);
                return r;
            };
            method_setImplementation(m, imp_implementationWithBlock(block));
            break;
        }
        default:
            g_skippedCount++;
            return;
        }
        g_hookedCount++;
        TPOLOG(@"  hooked [%d] %s -%s", kind, clsName, selName);
    } @catch (NSException *e) {
        TPOLOG(@"  hook 异常 %s -%s: %@", clsName, selName, e);
        g_skippedCount++;
    }
}

// ============================================================
// 安装
// ============================================================
void BTInstallTTNetProbe(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        TPOLOG(@"开始探测（安全模式，严格签名）");

        int numClasses = objc_getClassList(NULL, 0);
        if (numClasses <= 0) {
            TPOLOG(@"objc_getClassList 失败: %d", numClasses);
            return;
        }

        Class *classes = (Class *)malloc(sizeof(Class) * numClasses);
        if (!classes) return;
        numClasses = objc_getClassList(classes, numClasses);
        TPOLOG(@"总类数: %d", numClasses);

        // 目标类名关键词
        static const char *clsPatterns[] = {
            "NetResponse", "TTNetResponse", "NetTask",
            "TTNetCallback", "NetCallback",
            "NetDispatcher", "ResponseInfo",
            "NetworkResponse", "TTHttpTask",
        };
        const int nPat = sizeof(clsPatterns) / sizeof(clsPatterns[0]);

        int matchedClasses = 0;

        for (int i = 0; i < numClasses; i++) {
            Class cls = classes[i];
            if (!cls) continue;
            const char *name = class_getName(cls);
            if (!name) continue;

            BOOL matched = NO;
            for (int j = 0; j < nPat; j++) {
                if (strstr(name, clsPatterns[j])) { matched = YES; break; }
            }
            if (!matched) continue;

            matchedClasses++;
            TPOLOG(@"类: %s", name);

            // 实例方法
            unsigned int mCount = 0;
            Method *methods = class_copyMethodList(cls, &mCount);
            if (methods) {
                for (unsigned int k = 0; k < mCount; k++) {
                    Method m = methods[k];
                    SEL sel = method_getName(m);
                    int kind = classifyMethod(m);
                    if (kind == 0) { g_skippedCount++; continue; }

                    // 只 hook 名字相关的
                    const char *selName = sel_getName(sel);
                    static const char *want[] = {
                        "data", "Data", "body", "Body",
                        "response", "Response",
                        "finish", "Finish", "receive", "Receive",
                        "handle", "Handle", "decode", "Decode",
                    };
                    BOOL nameOk = NO;
                    for (size_t w = 0; w < sizeof(want)/sizeof(want[0]); w++) {
                        if (strstr(selName, want[w])) { nameOk = YES; break; }
                    }
                    if (!nameOk) continue;

                    safeHook(cls, sel, m, kind);
                }
                free(methods);
            }

            // 类方法
            unsigned int cmCount = 0;
            Method *cms = class_copyMethodList(object_getClass(cls), &cmCount);
            if (cms) free(cms);
        }

        free(classes);

        TPOLOG(@"完成: %d 个类, %d 个方法 hook, %d 个跳过",
               matchedClasses, g_hookedCount, g_skippedCount);
        TPOLOG(@"去打开礼物面板，看有没有 ★命中");
    });
}
