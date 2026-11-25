//
// BTWalletHook.m —— 方案 2：直接 Swizzle 抖音钱包 Model / Manager 层
// ============================================================
// 基于真机日志确认的精准类与方法：
//   1. IESLiveWalletMyCoinModel:
//        -diamondCntX10 (q16@0:8)          → 真实余额×10，读回真实值并改写返回 disp×10
//        -setDiamondCntX10: (v24@0:8q16)   → 记录真实余额 v/10
//        -diamondCntDisplayString (@16@0:8)→ 改写返回格式化后的 disp 字符串
//   2. IESLiveWalletModel:
//        -diamondNumDisplayString (@16@0:8)→ 改写返回格式化后的 disp 字符串
//   3. 通用钱包/钻石类（排除 UI/商品/档位/订单类）的整数/double/NSNumber 余额属性
//
// 关键机制：
//   - setter 原样写入真实值到 ivar，确保 ivar 永远保存真实余额
//   - getter 读取 ivar 真实值时也会同步记录 lastReal（即使首次赋值发生在 hook 之前也能立即捕获！）
//   - 开关打开时 getter 返回 computedDisplay，关闭开关立即还原真实余额
// ============================================================

#import "BTWalletHook.h"
#import "BTLog.h"
#import <objc/runtime.h>
#include <string.h>
#include <stdlib.h>
#include <stdatomic.h>

#define WHLOG(fmt, ...) BT_LOG_M(@"WalletHook", fmt, ##__VA_ARGS__)

static BTWalletRecordRealFunc g_recordReal = NULL;
static BTWalletGetDisplayFunc g_getDisplay = NULL;
static _Atomic int g_setLogCount = 0;
static _Atomic int g_getLogCount = 0;

void BTSetWalletCallbacks(BTWalletRecordRealFunc recordFunc,
                          BTWalletGetDisplayFunc getDisplayFunc) {
    g_recordReal = recordFunc;
    g_getDisplay = getDisplayFunc;
}

// ============================================================
// 真实余额记录（带回声防护）
// ============================================================
static void btWalletRecordSafe(const char *tag, const char *clsName, const char *selName, int64_t val) {
    if (!g_recordReal || val < 0) return;

    if (g_getDisplay) {
        int64_t curDisp = 0;
        int64_t lastReal = 0;
        if (g_getDisplay(&curDisp, &lastReal)) {
            if (val == curDisp && val != lastReal) {
                return;
            }
        }
    }

    g_recordReal(val);

    int c = atomic_fetch_add(&g_setLogCount, 1);
    if (c < 30) {
        WHLOG(@"★ %s %s -%s => real=%lld", tag, clsName, selName, (long long)val);
    }
}

static BOOL btWalletComputeGetterValue(const char *clsName, const char *selName,
                                       int64_t origVal, int64_t *outVal) {
    // 即使 setter 未触发或发生在 hook 之前，从 ivar 读出的真实值也能立即同步 lastReal
    if (origVal >= 0) {
        btWalletRecordSafe("GET-SYNC", clsName, selName, origVal);
    }

    if (!g_getDisplay || !outVal) return NO;

    int64_t disp = 0;
    int64_t lastReal = 0;
    if (!g_getDisplay(&disp, &lastReal)) {
        return NO;
    }

    *outVal = disp;
    int c = atomic_fetch_add(&g_getLogCount, 1);
    if (c < 30) {
        WHLOG(@"★ GET %s -%s: %lld -> %lld", clsName, selName, (long long)origVal, (long long)disp);
    }
    return YES;
}

// 尝试从纯数字展示字符串（如 "13"）解析真实余额，仅在未启用改写或非回声时记录
static void btWalletTryRecordFromString(const char *clsName, const char *selName, NSString *s) {
    if (![s isKindOfClass:[NSString class]] || s.length == 0 || s.length > 18) return;
    uint64_t acc = 0;
    for (NSUInteger i = 0; i < s.length; i++) {
        unichar c = [s characterAtIndex:i];
        if (c < '0' || c > '9') return;
        acc = acc * 10ULL + (uint64_t)(c - '0');
    }
    btWalletRecordSafe("STR-SYNC", clsName, selName, (int64_t)acc);
}

// ============================================================
// 精准 Hook：IESLiveWalletMyCoinModel & IESLiveWalletModel
// ============================================================
static void btHookDisplayStringGetter(Class cls, const char *clsName, const char *selName) {
    SEL sel = sel_registerName(selName);
    Method m = class_getInstanceMethod(cls, sel);
    if (!m || method_getNumberOfArguments(m) != 2) return;

    char ret[16] = {0};
    method_getReturnType(m, ret, sizeof(ret));
    if (ret[0] != '@') return;

    IMP origImp = method_getImplementation(m);
    if (!origImp) return;

    typedef id (*Fn)(id, SEL);
    Fn fn = (Fn)origImp;
    id (^blk)(id) = ^id(id self_) {
        id origObj = fn(self_, sel);
        if ([origObj isKindOfClass:[NSString class]]) {
            btWalletTryRecordFromString(clsName, selName, (NSString *)origObj);
        }
        if (g_getDisplay) {
            int64_t disp = 0;
            int64_t lastReal = 0;
            if (g_getDisplay(&disp, &lastReal)) {
                int c = atomic_fetch_add(&g_getLogCount, 1);
                if (c < 30) {
                    WHLOG(@"★ STR %s -%s: %@ -> %lld", clsName, selName, origObj, (long long)disp);
                }
                return [NSString stringWithFormat:@"%lld", (long long)disp];
            }
        }
        return origObj;
    };

    method_setImplementation(m, imp_implementationWithBlock(blk));
    WHLOG(@"  [STR] %s -%s (%s)", clsName, selName, method_getTypeEncoding(m) ?: "?");
}

static void btHookDiamondCntX10(Class cls, const char *clsName) {
    // 1. getter: -diamondCntX10 (q16@0:8)
    {
        SEL sel = sel_registerName("diamondCntX10");
        Method m = class_getInstanceMethod(cls, sel);
        if (m && method_getNumberOfArguments(m) == 2) {
            char ret[16] = {0};
            method_getReturnType(m, ret, sizeof(ret));
            if (ret[0] == 'q' || ret[0] == 'Q') {
                IMP origImp = method_getImplementation(m);
                typedef long long (*Fn)(id, SEL);
                Fn fn = (Fn)origImp;
                long long (^blk)(id) = ^long long(id self_) {
                    long long origX10 = fn(self_, sel);
                    int64_t origReal = origX10 >= 0 ? (int64_t)(origX10 / 10) : -1;
                    int64_t disp = 0;
                    if (btWalletComputeGetterValue(clsName, "diamondCntX10", origReal, &disp)) {
                        return (long long)(disp * 10);
                    }
                    return origX10;
                };
                method_setImplementation(m, imp_implementationWithBlock(blk));
                WHLOG(@"  [GETx10] %s -diamondCntX10 (%s)", clsName, method_getTypeEncoding(m) ?: "?");
            }
        }
    }

    // 2. setter: -setDiamondCntX10: (v24@0:8q16)
    {
        SEL sel = sel_registerName("setDiamondCntX10:");
        Method m = class_getInstanceMethod(cls, sel);
        if (m && method_getNumberOfArguments(m) == 3) {
            char ret[16] = {0};
            char arg[16] = {0};
            method_getReturnType(m, ret, sizeof(ret));
            method_getArgumentType(m, 2, arg, sizeof(arg));
            if (ret[0] == 'v' && (arg[0] == 'q' || arg[0] == 'Q')) {
                IMP origImp = method_getImplementation(m);
                typedef void (*Fn)(id, SEL, long long);
                Fn fn = (Fn)origImp;
                void (^blk)(id, long long) = ^(id self_, long long vX10) {
                    if (vX10 >= 0) {
                        btWalletRecordSafe("SETx10", clsName, "setDiamondCntX10:", (int64_t)(vX10 / 10));
                    }
                    fn(self_, sel, vX10);
                };
                method_setImplementation(m, imp_implementationWithBlock(blk));
                WHLOG(@"  [SETx10] %s -setDiamondCntX10: (%s)", clsName, method_getTypeEncoding(m) ?: "?");
            }
        }
    }
}

static void btDumpTargetClassMethods(const char *clsName) {
    Class cls = NSClassFromString([NSString stringWithUTF8String:clsName]);
    if (!cls) return;
    unsigned int mc = 0;
    Method *ms = class_copyMethodList(cls, &mc);
    if (!ms) return;
    NSMutableArray<NSString *> *list = [NSMutableArray array];
    for (unsigned int i = 0; i < mc; i++) {
        const char *sn = sel_getName(method_getName(ms[i]));
        if (!sn) continue;
        if (strcasestr(sn, "diamond") || strcasestr(sn, "balance") || strcasestr(sn, "coin")) {
            [list addObject:[NSString stringWithFormat:@"%s(%s)", sn, method_getTypeEncoding(ms[i]) ?: "?"]];
        }
    }
    free(ms);
    if (list.count > 0) {
        WHLOG(@"[详表] %s (%lu): %@", clsName, (unsigned long)list.count, [list componentsJoinedByString:@", "]);
    }
}

static void btHookKnownDouyinWalletClasses(void) {
    Class myCoin = NSClassFromString(@"IESLiveWalletMyCoinModel");
    if (myCoin) {
        WHLOG(@"精准命中类: IESLiveWalletMyCoinModel");
        btHookDiamondCntX10(myCoin, "IESLiveWalletMyCoinModel");
        btHookDisplayStringGetter(myCoin, "IESLiveWalletMyCoinModel", "diamondCntDisplayString");
        btDumpTargetClassMethods("IESLiveWalletMyCoinModel");
    }

    Class walletModel = NSClassFromString(@"IESLiveWalletModel");
    if (walletModel) {
        WHLOG(@"精准命中类: IESLiveWalletModel");
        btHookDisplayStringGetter(walletModel, "IESLiveWalletModel", "diamondNumDisplayString");
        btDumpTargetClassMethods("IESLiveWalletModel");
    }

    btDumpTargetClassMethods("IESLiveWalletManager");
}

// ============================================================
// 通用类名过滤：锁定钱包/钻石数据模型与管理器（排除系统框架与 UI/商品类）
// ============================================================
static BOOL btIsSystemPrefix(const char *name) {
    static const char *sysPrefixes[] = {
        "NS", "UI", "CA", "CF", "CG", "CI", "CL", "CN", "CT", "CV",
        "PK", "WK", "MK", "MT", "AV", "CM", "SK", "SF", "BS", "FB",
        "OS_", "_NS", "_UI", "_CA", "_CF", "_PK", "GEO", "IN", "HK",
        "MP", "MS", "NE", "NW", "PH", "RL", "SC", "VN", "AX", "AC",
        "AMS", "ASD", "DMF", "FMD", "IDS", "IM", "MC", "MN", "MTR",
        "PassKit", "WalletUI", "FinanceKit", "StoreKit",
    };
    for (size_t i = 0; i < sizeof(sysPrefixes) / sizeof(sysPrefixes[0]); i++) {
        if (strncmp(name, sysPrefixes[i], strlen(sysPrefixes[i])) == 0) return YES;
    }
    return NO;
}

static BOOL btIsTargetWalletClass(const char *name) {
    if (!name || !*name) return NO;
    if (btIsSystemPrefix(name)) return NO;

    if (!strstr(name, "Wallet") && !strstr(name, "Diamond")) {
        return NO;
    }

    static const char *excludes[] = {
        "ViewController", "Cell", "Button", "Label", "Image", "Icon",
        "Banner", "Popup", "Alert", "Dialog", "Sheet", "Layout", "Style",
        "Theme", "Color", "Font", "Tracker", "Track", "Log", "Monitor",
        "Report", "Metric", "Config", "ABTest", "Experiment", "Setting",
        "Animator", "Transition", "Bridge", "Method", "Param", "Router",
        "Schema", "Product", "Goods", "Item", "Gift", "Order", "Package",
        "Pack", "Combo", "Coupon", "Discount", "Price", "ChargeOption",
        "RechargeOption", "IAP", "Receipt", "Record", "History", "Detail",
        "Transaction", "Bill", "Task", "Award", "Reward", "RedPacket",
        "Packet", "Lucky", "Lottery", "Activity", "Notice", "Tip", "Guide",
        "Entrance", "Card", "Tab", "List", "Buy",
    };
    for (size_t i = 0; i < sizeof(excludes) / sizeof(excludes[0]); i++) {
        if (strstr(name, excludes[i])) return NO;
    }

    if (strstr(name, "View") && !strstr(name, "ViewModel")) {
        return NO;
    }

    return YES;
}

// ============================================================
// 通用方法名精确白名单
// ============================================================
static BOOL btIsBalanceGetter(const char *sn) {
    static const char *getters[] = {
        "diamond",
        "diamonds",
        "diamondCount",
        "diamondCnt",
        "diamond_cnt",
        "diamond_count",
        "diamondNum",
        "diamondBalance",
        "diamond_balance",
        "currentDiamond",
        "currentDiamondNum",
        "currentDiamondCount",
        "availableDiamond",
        "availableDiamonds",
        "totalDiamond",
        "totalDiamonds",
        "realDiamond",
        "balance",
        "walletBalance",
        "coinBalance",
        "availableBalance",
    };
    for (size_t i = 0; i < sizeof(getters) / sizeof(getters[0]); i++) {
        if (strcmp(sn, getters[i]) == 0) return YES;
    }
    return NO;
}

static BOOL btIsBalanceSetter(const char *sn) {
    static const char *setters[] = {
        "setDiamond:",
        "setDiamonds:",
        "setDiamondCount:",
        "setDiamondCnt:",
        "setDiamond_cnt:",
        "setDiamond_count:",
        "setDiamondNum:",
        "setDiamondBalance:",
        "setDiamond_balance:",
        "setCurrentDiamond:",
        "setCurrentDiamondNum:",
        "setCurrentDiamondCount:",
        "setAvailableDiamond:",
        "setAvailableDiamonds:",
        "setTotalDiamond:",
        "setTotalDiamonds:",
        "setRealDiamond:",
        "setBalance:",
        "setWalletBalance:",
        "setCoinBalance:",
        "setAvailableBalance:",
    };
    for (size_t i = 0; i < sizeof(setters) / sizeof(setters[0]); i++) {
        if (strcmp(sn, setters[i]) == 0) return YES;
    }
    return NO;
}

// ============================================================
// 按严格类型编码 Swizzle Getter（含 q / Q / i / I / d / @）
// ============================================================
static BOOL btSwizzleGetter(Class cls, Method m, const char *clsName, const char *selName) {
    (void)cls;
    if (method_getNumberOfArguments(m) != 2) return NO;

    char ret[16] = {0};
    method_getReturnType(m, ret, sizeof(ret));
    SEL sel = method_getName(m);
    IMP origImp = method_getImplementation(m);
    if (!origImp) return NO;

    switch (ret[0]) {
    case 'q': {
        typedef long long (*Fn)(id, SEL);
        Fn fn = (Fn)origImp;
        long long (^blk)(id) = ^long long(id self_) {
            long long origVal = fn(self_, sel);
            int64_t disp = 0;
            if (btWalletComputeGetterValue(clsName, selName, (int64_t)origVal, &disp)) {
                return (long long)disp;
            }
            return origVal;
        };
        method_setImplementation(m, imp_implementationWithBlock(blk));
        return YES;
    }
    case 'Q': {
        typedef unsigned long long (*Fn)(id, SEL);
        Fn fn = (Fn)origImp;
        unsigned long long (^blk)(id) = ^unsigned long long(id self_) {
            unsigned long long origVal = fn(self_, sel);
            int64_t disp = 0;
            if (btWalletComputeGetterValue(clsName, selName, (int64_t)origVal, &disp)) {
                return (unsigned long long)(disp < 0 ? 0 : disp);
            }
            return origVal;
        };
        method_setImplementation(m, imp_implementationWithBlock(blk));
        return YES;
    }
    case 'i': {
        typedef int (*Fn)(id, SEL);
        Fn fn = (Fn)origImp;
        int (^blk)(id) = ^int(id self_) {
            int origVal = fn(self_, sel);
            int64_t disp = 0;
            if (btWalletComputeGetterValue(clsName, selName, (int64_t)origVal, &disp)) {
                if (disp > INT32_MAX) disp = INT32_MAX;
                return (int)disp;
            }
            return origVal;
        };
        method_setImplementation(m, imp_implementationWithBlock(blk));
        return YES;
    }
    case 'I': {
        typedef unsigned int (*Fn)(id, SEL);
        Fn fn = (Fn)origImp;
        unsigned int (^blk)(id) = ^unsigned int(id self_) {
            unsigned int origVal = fn(self_, sel);
            int64_t disp = 0;
            if (btWalletComputeGetterValue(clsName, selName, (int64_t)origVal, &disp)) {
                if (disp < 0) disp = 0;
                if (disp > UINT32_MAX) disp = UINT32_MAX;
                return (unsigned int)disp;
            }
            return origVal;
        };
        method_setImplementation(m, imp_implementationWithBlock(blk));
        return YES;
    }
    case 'd': {
        typedef double (*Fn)(id, SEL);
        Fn fn = (Fn)origImp;
        double (^blk)(id) = ^double(id self_) {
            double origVal = fn(self_, sel);
            int64_t disp = 0;
            if (btWalletComputeGetterValue(clsName, selName, (int64_t)origVal, &disp)) {
                return (double)disp;
            }
            return origVal;
        };
        method_setImplementation(m, imp_implementationWithBlock(blk));
        return YES;
    }
    case '@': {
        typedef id (*Fn)(id, SEL);
        Fn fn = (Fn)origImp;
        id (^blk)(id) = ^id(id self_) {
            id origObj = fn(self_, sel);
            if ([origObj isKindOfClass:[NSNumber class]]) {
                int64_t origVal = [(NSNumber *)origObj longLongValue];
                int64_t disp = 0;
                if (btWalletComputeGetterValue(clsName, selName, origVal, &disp)) {
                    return @(disp);
                }
            }
            return origObj;
        };
        method_setImplementation(m, imp_implementationWithBlock(blk));
        return YES;
    }
    default:
        return NO;
    }
}

// ============================================================
// 按严格类型编码 Swizzle Setter（记录真实值，原样写入）
// ============================================================
static BOOL btSwizzleSetter(Class cls, Method m, const char *clsName, const char *selName) {
    (void)cls;
    if (method_getNumberOfArguments(m) != 3) return NO;

    char ret[16] = {0};
    method_getReturnType(m, ret, sizeof(ret));
    if (ret[0] != 'v') return NO;

    char arg[16] = {0};
    method_getArgumentType(m, 2, arg, sizeof(arg));
    SEL sel = method_getName(m);
    IMP origImp = method_getImplementation(m);
    if (!origImp) return NO;

    switch (arg[0]) {
    case 'q': {
        typedef void (*Fn)(id, SEL, long long);
        Fn fn = (Fn)origImp;
        void (^blk)(id, long long) = ^(id self_, long long v) {
            btWalletRecordSafe("SET", clsName, selName, (int64_t)v);
            fn(self_, sel, v);
        };
        method_setImplementation(m, imp_implementationWithBlock(blk));
        return YES;
    }
    case 'Q': {
        typedef void (*Fn)(id, SEL, unsigned long long);
        Fn fn = (Fn)origImp;
        void (^blk)(id, unsigned long long) = ^(id self_, unsigned long long v) {
            int64_t sv = (v > (unsigned long long)INT64_MAX) ? INT64_MAX : (int64_t)v;
            btWalletRecordSafe("SET", clsName, selName, sv);
            fn(self_, sel, v);
        };
        method_setImplementation(m, imp_implementationWithBlock(blk));
        return YES;
    }
    case 'i': {
        typedef void (*Fn)(id, SEL, int);
        Fn fn = (Fn)origImp;
        void (^blk)(id, int) = ^(id self_, int v) {
            btWalletRecordSafe("SET", clsName, selName, (int64_t)v);
            fn(self_, sel, v);
        };
        method_setImplementation(m, imp_implementationWithBlock(blk));
        return YES;
    }
    case 'I': {
        typedef void (*Fn)(id, SEL, unsigned int);
        Fn fn = (Fn)origImp;
        void (^blk)(id, unsigned int) = ^(id self_, unsigned int v) {
            btWalletRecordSafe("SET", clsName, selName, (int64_t)v);
            fn(self_, sel, v);
        };
        method_setImplementation(m, imp_implementationWithBlock(blk));
        return YES;
    }
    case 'd': {
        typedef void (*Fn)(id, SEL, double);
        Fn fn = (Fn)origImp;
        void (^blk)(id, double) = ^(id self_, double v) {
            if (v >= 0) btWalletRecordSafe("SET", clsName, selName, (int64_t)v);
            fn(self_, sel, v);
        };
        method_setImplementation(m, imp_implementationWithBlock(blk));
        return YES;
    }
    case '@': {
        typedef void (*Fn)(id, SEL, id);
        Fn fn = (Fn)origImp;
        void (^blk)(id, id) = ^(id self_, id obj) {
            if ([obj isKindOfClass:[NSNumber class]]) {
                btWalletRecordSafe("SET", clsName, selName, [(NSNumber *)obj longLongValue]);
            }
            fn(self_, sel, obj);
        };
        method_setImplementation(m, imp_implementationWithBlock(blk));
        return YES;
    }
    default:
        return NO;
    }
}

// ============================================================
// 安装入口
// ============================================================
void BTInstallWalletModelHook(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        WHLOG(@"========== 方案2: 钱包 Model/Manager Hook 启动 ==========");

        // 1. 优先精准 Hook 真机已确认的抖音核心钱包模型
        btHookKnownDouyinWalletClasses();

        // 2. 补充扫描其他钱包/钻石类的标准余额属性
        int total = objc_getClassList(NULL, 0);
        if (total <= 0) return;
        Class *classes = (Class *)malloc(sizeof(Class) * (size_t)total);
        if (!classes) return;
        total = objc_getClassList(classes, total);

        int matchedClasses = 0;
        int hookedGetters = 0;
        int hookedSetters = 0;

        for (int i = 0; i < total; i++) {
            Class cls = classes[i];
            if (!cls) continue;
            const char *clsName = class_getName(cls);
            if (!btIsTargetWalletClass(clsName)) continue;

            unsigned int mc = 0;
            Method *methods = class_copyMethodList(cls, &mc);
            if (!methods) continue;

            BOOL classLogged = NO;
            for (unsigned int k = 0; k < mc; k++) {
                Method m = methods[k];
                const char *sn = sel_getName(method_getName(m));
                if (!sn) continue;

                BOOL hooked = NO;
                const char *kind = NULL;
                if (btIsBalanceGetter(sn)) {
                    hooked = btSwizzleGetter(cls, m, clsName, sn);
                    if (hooked) { hookedGetters++; kind = "GET"; }
                } else if (btIsBalanceSetter(sn)) {
                    hooked = btSwizzleSetter(cls, m, clsName, sn);
                    if (hooked) { hookedSetters++; kind = "SET"; }
                }

                if (hooked) {
                    if (!classLogged) {
                        matchedClasses++;
                        WHLOG(@"类: %s", clsName);
                        classLogged = YES;
                    }
                    WHLOG(@"  [%s] -%s (%s)", kind, sn, method_getTypeEncoding(m) ?: "?");
                }
            }
            free(methods);
        }

        free(classes);
        WHLOG(@"========== 完成: 通用命中类 %d, getter %d, setter %d ==========",
              matchedClasses, hookedGetters, hookedSetters);
    });
}
