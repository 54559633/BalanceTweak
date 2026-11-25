//
// BTTTNetProbe.m —— TTNet 运行时探测
// ============================================================
#import "BTTTNetProbe.h"
#import <objc/runtime.h>
#include <string.h>

#define TPOLog(fmt, ...) NSLog(@"[TTNetProbe] " fmt, ##__VA_ARGS__)

static BOOL g_probeActive = YES;

void BTStopTTNetProbe(void) {
    g_probeActive = NO;
    TPOLog(@"探测已停止");
}

// ============================================================
// 工具函数
// ============================================================

/// 安全读 NSString from id
static NSString *safeStr(id obj) {
    if (!obj) return nil;
    if ([obj isKindOfClass:[NSString class]]) return obj;
    return nil;
}

/// 安全读 NSData from id
static NSData *safeData(id obj) {
    if (!obj) return nil;
    if ([obj isKindOfClass:[NSData class]]) return obj;
    return nil;
}

/// 从 NSData 里找 URL 特征
static NSString *detectPathInData(NSData *data) {
    if (!data || data.length < 16) return nil;

    const uint8_t *bytes = data.bytes;
    size_t len = data.length;

    const char *patterns[] = {
        "wallet/info",
        "/webcast/wallet",
        "recharge_page",
        "wallet/core/v1",
        "diamond_cnt",
    };
    const int n = 5;

    for (int i = 0; i < n; i++) {
        const char *p = patterns[i];
        size_t plen = strlen(p);
        if (len < plen) continue;

        // 简单字节搜索
        for (size_t j = 0; j + plen <= len; j++) {
            if (memcmp(bytes + j, p, plen) == 0) {
                return [NSString stringWithUTF8String:p];
            }
        }
    }
    return nil;
}

/// 判断方法签名是否值得 hook
static BOOL shouldHookMethod(Method m, const char *selName) {
    if (!m || !selName) return NO;

    const char *name = selName;

    // 排除明显无关的
    const char *skip[] = {
        "set", "init", "dealloc", "class", "description", "debug",
        "hash", "isEqual", "copyWith", "shared", "default",
        "count", "enumerate", "add", "remove", "insert", "replace",
        "URL", "url", "header", "Header", "cookie", "Cookie",
        "timing", "Timing", "stat", "Stat", "log", "Log",
    };
    for (int i = 0; i < 20; i++) { }  // placeholder
    for (size_t i = 0; i < sizeof(skip) / sizeof(skip[0]); i++) {
        if (strncmp(name, skip[i], strlen(skip[i])) == 0) return NO;
    }

    // 只要含这些词
    const char *want[] = {
        "data", "Data", "body", "Body",
        "response", "Response",
        "finish", "Finish",
        "didReceive", "receive", "Receive",
        "handle", "Handle",
        "decode", "Decode",
        "json", "Json", "JSON",
        "protobuf", "Protobuf",
        "prepare", "Prepare",
    };
    for (size_t i = 0; i < sizeof(want) / sizeof(want[0]); i++) {
        if (strstr(name, want[i])) return YES;
    }

    return NO;
}

// ============================================================
// 探测 hook
// ============================================================

/// 对一个方法挂上探测钩子
static void hookForProbe(Class cls, SEL sel, Method m, int idx) {
    const char *clsName = class_getName(cls);
    const char *selName = sel_getName(sel);

    IMP orig = method_getImplementation(m);
    if (!orig) return;

    // 根据方法签名判断返回类型和参数
    const char *typeEnc = method_getTypeEncoding(m);
    if (!typeEnc) return;

    // 只处理返回 id 或者参数里有 id 的方法
    // typeEnc 形如: "@24@0:8@16" (返回 id, self, sel, 参数 id)
    BOOL retIsId = (typeEnc[0] == '@');
    if (!retIsId) return;

    // 用 NSInvocation 的方式没法在 imp_implementationWithBlock 里用
    // 简单方案：hook 返回 id 的无参/单参方法
    const char *p = typeEnc;
    int numArgs = 0;
    while (*p) {
        if (*p == ':') {
            p++;
            numArgs++;
        } else {
            p++;
        }
    }

    // 只 hook 0-1 个额外参数的方法（self + sel + 0~1）
    if (numArgs > 3) return;

    static int hookCount = 0;
    hookCount++;

    // 用 Interceptor? 没有，用 method_setImplementation + 通用 trampoline
    // 简化：用 objc_msgSend 转发的 block（需要匹配签名）

    if (numArgs == 2) {
        // - (id)method  (无参)
        id block = ^id(id self_) {
            id r = ((id (*)(id, SEL))orig)(self_, sel);
            if (g_probeActive && r) {
                NSData *d = safeData(r);
                if (d && d.length > 20) {
                    NSString *hit = detectPathInData(d);
                    if (hit) {
                        TPOLog(@"★命中 %s -%s  NSData %luB  特征=%@",
                               clsName, selName, (unsigned long)d.length, hit);
                    }
                } else {
                    NSString *s = safeStr(r);
                    if (s) {
                        NSData *sd = [s dataUsingEncoding:NSUTF8StringEncoding];
                        NSString *hit = detectPathInData(sd);
                        if (hit) {
                            TPOLog(@"★命中 %s -%s  NSString 特征=%@", clsName, selName, hit);
                        }
                    }
                }
            }
            return r;
        };
        method_setImplementation(m, imp_implementationWithBlock(block));

    } else if (numArgs == 3) {
        // - (id)method:(id)arg
        id block = ^id(id self_, id arg) {
            id r = ((id (*)(id, SEL, id))orig)(self_, sel, arg);
            if (g_probeActive) {
                // 检查参数
                NSData *ad = safeData(arg);
                if (ad && ad.length > 20) {
                    NSString *hit = detectPathInData(ad);
                    if (hit) {
                        TPOLog(@"★命中(参数) %s -%s  NSData %luB  特征=%@",
                               clsName, selName, (unsigned long)ad.length, hit);
                    }
                }
                // 检查返回值
                if (r) {
                    NSData *d = safeData(r);
                    if (d && d.length > 20) {
                        NSString *hit = detectPathInData(d);
                        if (hit) {
                            TPOLog(@"★命中(返回) %s -%s  NSData %luB  特征=%@",
                                   clsName, selName, (unsigned long)d.length, hit);
                        }
                    }
                }
            }
            return r;
        };
        method_setImplementation(m, imp_implementationWithBlock(block));
    }
}

// ============================================================
// 安装
// ============================================================
void BTInstallTTNetProbe(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        TPOLog(@"开始探测 TTNet 相关类...");

        int numClasses = objc_getClassList(NULL, 0);
        if (numClasses <= 0) {
            TPOLog(@"objc_getClassList 返回 %d", numClasses);
            return;
        }

        Class *classes = (Class *)malloc(sizeof(Class) * numClasses);
        if (!classes) return;
        numClasses = objc_getClassList(classes, numClasses);

        // 目标类名关键词
        const char *clsPatterns[] = {
            "NetResponse", "TTNetResponse", "NetTask", "TTHttpTask",
            "NetRequest", "TTNetworkManager", "NetDispatcher",
            "ResponseInfo", "ResponseModel", "NetworkResponse",
            "TTNetCallback", "NetCallback", "CronetResponse",
        };
        const int nPat = sizeof(clsPatterns) / sizeof(clsPatterns[0]);

        int matchedClasses = 0;
        int hookedMethods = 0;

        for (int i = 0; i < numClasses; i++) {
            Class cls = classes[i];
            if (!cls) continue;
            const char *name = class_getName(cls);
            if (!name) continue;

            BOOL matched = NO;
            for (int j = 0; j < nPat; j++) {
                if (strstr(name, clsPatterns[j])) {
                    matched = YES;
                    break;
                }
            }
            if (!matched) continue;

            matchedClasses++;
            TPOLog(@"找到类: %s", name);

            // 枚举实例方法
            unsigned int mCount = 0;
            Method *methods = class_copyMethodList(cls, &mCount);
            if (!methods) continue;

            for (unsigned int k = 0; k < mCount; k++) {
                Method m = methods[k];
                SEL sel = method_getName(m);
                const char *selName = sel_getName(sel);
                if (!shouldHookMethod(m, selName)) continue;

                @try {
                    hookForProbe(cls, sel, m, (int)k);
                    hookedMethods++;
                    TPOLog(@"  hooked -%s", selName);
                } @catch (NSException *e) {
                    TPOLog(@"  hook -%s 异常: %@", selName, e);
                }
            }
            free(methods);
        }

        free(classes);

        TPOLog(@"探测完成: %d 个类, %d 个方法", matchedClasses, hookedMethods);
        TPOLog(@"现在去打开礼物面板，看日志里哪个 ★命中 出现了 wallet/info");
    });
}
