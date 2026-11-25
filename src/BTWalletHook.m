//
// BTWalletHook.m —— 方案 2：直接 Swizzle 抖音钱包 Model / Manager 层
// ============================================================
// 纯 ObjC Runtime Swizzle，完全兼容非越狱设备，不依赖网络协议/Protobuf：
//   1. 按严格白名单前缀 + 关键词筛选钱包/钻石数据类，排除 UI/商品/礼包/订单类
//   2. 仅 Hook 精确匹配的余额属性 getter / setter，并做严格 ABI 类型校验
//   3. setter 收到真实值 → 同步 BTPrefs（带防回声校验，避免被自身改写值污染）
//   4. getter 读取时 → 开关开启返回 computedDisplay，开关关闭立即恢复真实值
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
// 真实余额记录（带回声防护：避免 Model A getter -> Model B setter 污染 lastReal）
// ============================================================
static void btWalletOnSetterValue(const char *clsName, const char *selName, int64_t val) {
    if (!g_recordReal || val < 0) return;

    if (g_getDisplay) {
        int64_t curDisp = 0;
        int64_t lastReal = 0;
        if (g_getDisplay(&curDisp, &lastReal)) {
            // 若开关开启且传入值恰好等于我们伪造的显示值（且不等于真实余额），视为内部回声，忽略
            if (val == curDisp && val != lastReal) {
                return;
            }
        }
    }

    g_recordReal(val);

    int c = atomic_fetch_add(&g_setLogCount, 1);
    if (c < 30) {
        WHLOG(@"★ SET %s -%s => real=%lld", clsName, selName, (long long)val);
    }
}

static BOOL btWalletComputeGetterValue(const char *clsName, const char *selName,
                                       int64_t origVal, int64_t *outVal) {
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

// ============================================================
// 类名过滤：锁定钱包/钻石数据模型与管理器（排除系统框架与 UI/商品类）
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

    // 必须包含核心关键词
    if (!strstr(name, "Wallet") && !strstr(name, "Diamond")) {
        return NO;
    }

    // 排除 UI / 商品 / 充值档位 / 礼物 / 订单 / 埋点 / 配置类（防止误改商品价格或档位）
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
        if (strstr(name, excludes[i])) {
            return NO;
        }
    }

    // 排除普通 View（保留 ViewModel）
    if (strstr(name, "View") && !strstr(name, "ViewModel")) {
        return NO;
    }

    return YES;
}

// ============================================================
// 方法名精确白名单
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
// 按严格类型编码 Swizzle Getter
// ============================================================
static BOOL btSwizzleGetter(Class cls, Method m, const char *clsName, const char *selName) {
    if (method_getNumberOfArguments(m) != 2) return NO;

    char ret[16] = {0};
    method_getReturnType(m, ret, sizeof(ret));
    SEL sel = method_getName(m);
    IMP origImp = method_getImplementation(m);
    if (!origImp) return NO;

    switch (ret[0]) {
    case 'q': { // long long / int64_t / NSInteger
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
    case 'Q': { // unsigned long long / uint64_t / NSUInteger
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
    case 'i': { // int
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
    case 'I': { // unsigned int
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
    case '@': { // NSNumber *（仅当运行时返回值为 NSNumber 时替换，其他对象原样返回）
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
// 按严格类型编码 Swizzle Setter（记录真实值，并原样写入真实值）
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
            btWalletOnSetterValue(clsName, selName, (int64_t)v);
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
            btWalletOnSetterValue(clsName, selName, sv);
            fn(self_, sel, v);
        };
        method_setImplementation(m, imp_implementationWithBlock(blk));
        return YES;
    }
    case 'i': {
        typedef void (*Fn)(id, SEL, int);
        Fn fn = (Fn)origImp;
        void (^blk)(id, int) = ^(id self_, int v) {
            btWalletOnSetterValue(clsName, selName, (int64_t)v);
            fn(self_, sel, v);
        };
        method_setImplementation(m, imp_implementationWithBlock(blk));
        return YES;
    }
    case 'I': {
        typedef void (*Fn)(id, SEL, unsigned int);
        Fn fn = (Fn)origImp;
        void (^blk)(id, unsigned int) = ^(id self_, unsigned int v) {
            btWalletOnSetterValue(clsName, selName, (int64_t)v);
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
                btWalletOnSetterValue(clsName, selName, [(NSNumber *)obj longLongValue]);
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

        int total = objc_getClassList(NULL, 0);
        if (total <= 0) return;
        Class *classes = (Class *)malloc(sizeof(Class) * (size_t)total);
        if (!classes) return;
        total = objc_getClassList(classes, total);

        int matchedClasses = 0;
        int hookedGetters = 0;
        int hookedSetters = 0;
        int candidateLogged = 0;

        for (int i = 0; i < total; i++) {
            Class cls = classes[i];
            if (!cls) continue;
            const char *clsName = class_getName(cls);
            if (!btIsTargetWalletClass(clsName)) continue;

            unsigned int mc = 0;
            Method *methods = class_copyMethodList(cls, &mc);
            if (!methods) continue;

            BOOL classLogged = NO;
            NSMutableArray<NSString *> *otherHits = nil;

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
                } else if (candidateLogged < 20 &&
                           (strcasestr(sn, "diamond") || strcasestr(sn, "balance"))) {
                    if (!otherHits) otherHits = [NSMutableArray array];
                    if (otherHits.count < 6) {
                        [otherHits addObject:[NSString stringWithFormat:@"%s(%s)", sn, method_getTypeEncoding(m) ?: "?"]];
                    }
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
            if (!classLogged && otherHits.count > 0 && candidateLogged < 20) {
                candidateLogged++;
                WHLOG(@"[候选] %s: %@", clsName, [otherHits componentsJoinedByString:@", "]);
            }
            free(methods);
        }

        free(classes);
        WHLOG(@"========== 完成: 命中类 %d, getter %d, setter %d (候选 %d) ==========",
              matchedClasses, hookedGetters, hookedSetters, candidateLogged);
    });
}
