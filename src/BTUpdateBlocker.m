//
// BTUpdateBlocker.m —— 屏蔽抖音应用内版本检查与更新弹窗
// ============================================================
// 机理（均来自对目标 dylib「屏蔽抖音检测更新 1.0.2」的实测，非推测）：
//
//   1. AWEVersionUpdateAlert -canShow           → 恒定 NO，弹窗不呈现
//   2. AWENewVersionAlertManager 的 5 个检查方法 → 空实现，请求不发起
//   3. 晚注册兜底：原实现用 dyld_register_func_for_add_image，但该符号
//      在 iOS SDK 的 libSystem 导出表中缺失，链接期会报 undefined。
//      此处改用有限次定时重试，效果等价且不引入链接依赖。
//
// 设计要点：
//   · 挂钩前先校验返回类型编码，不匹配就不挂 —— 把 void 当 BOOL 挂钩，
//     宿主取返回值会拿到垃圾数据，表现为随机闪退，极难定位。
//   · 优先 class_addMethod（方法只在父类实现时加到本类），
//     不牵连同父类的兄弟类；失败再 class_replaceMethod / method_setImplementation。
//   · 本模块与卡密授权门禁无关：无论是否已授权都安装，且不提供关闭入口。
//
// 不含任何网络请求、不含任何账号相关逻辑。
// ============================================================

#import "BTUpdateBlocker.h"
#import "BTLog.h"

#import <objc/runtime.h>
#import <string.h>

#define BTUPLOG(fmt, ...) BT_LOG_M(@"UpdBlk", fmt, ##__VA_ARGS__)

#pragma mark - 替代实现
// 保持最简签名：arm64 调用约定下，被调方忽略多余参数即可，
// 类型编码仍用 method_getTypeEncoding 原样保留。

static BOOL BTUPCanShowNo(id self, SEL _cmd) {
    (void)self;
    (void)_cmd;
    return NO;
}

static void BTUPVersionCheckNoop(id self, SEL _cmd) {
    (void)self;
    (void)_cmd;
}

#pragma mark - 安全挂钩助手

// 类型编码可能带 r/n/N/o/O/R/V 限定符（const / in / inout / out / bycopy /
// byref / oneway）。必须先跳过它们再取真正的返回类型字符，
// 否则遇到 "r@16@0:8" 这类编码会把 'r' 当成返回类型而误判跳过。
static char BTUPReturnTypeChar(Method method) {
    char buffer[64] = {0};
    method_getReturnType(method, buffer, sizeof(buffer));
    const size_t skip = strspn(buffer, "rnNoORV");
    return buffer[skip];
}

static BOOL BTUPHookInstanceMethod(Class cls, SEL sel, char expectedReturn, IMP replacement) {
    if (!cls || !sel || !replacement) return NO;

    Method method = class_getInstanceMethod(cls, sel);
    if (!method) return NO;

    const char actual = BTUPReturnTypeChar(method);
    if (actual != expectedReturn) {
        // BOOL 在不同 ABI / 编译器下可能是 'B' 或 'c'，这一对互为等价
        const BOOL boolPair = (actual == 'B' && expectedReturn == 'c') ||
                              (actual == 'c' && expectedReturn == 'B');
        if (!boolPair) {
            BTUPLOG(@"跳过 %@ - 返回类型不符（期望 %c 实际 %c）",
                    NSStringFromSelector(sel), expectedReturn, actual);
            return NO;
        }
    }

    const char *types = method_getTypeEncoding(method);

    // 先尝试加到本类：若方法只在父类实现，这样不会牵连同父类的其他子类
    if (class_addMethod(cls, sel, replacement, types)) return YES;

    IMP previous = class_replaceMethod(cls, sel, replacement, types);
    if (previous != NULL) return YES;

    method_setImplementation(method, replacement);
    return YES;
}

#pragma mark - 各目标

// 5 个版本检查入口。名字取自抖音实测版本，版本变更后在此追加即可。
static NSArray<NSString *> *BTUPVersionCheckSelectors(void) {
    static NSArray<NSString *> *names;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        names = @[
            @"checkAppNewVersion",
            @"checkAppNewVersionInhouse",
            @"checkAppNewVersionTestFlight",
            @"checkInhouseNewVersionWithDelay",
            @"checkAppNewVersionInhouseWithDelay",
        ];
    });
    return names;
}

static BOOL BTUPInstallAlertBlocking(void) {
    Class cls = NSClassFromString(@"AWEVersionUpdateAlert");
    if (!cls) return NO;
    return BTUPHookInstanceMethod(cls, @selector(canShow), 'B', (IMP)&BTUPCanShowNo);
}

static BOOL BTUPInstallManagerBlocking(void) {
    Class cls = NSClassFromString(@"AWENewVersionAlertManager");
    if (!cls) return NO;

    BOOL any = NO;
    for (NSString *name in BTUPVersionCheckSelectors()) {
        SEL sel = NSSelectorFromString(name);
        if (!sel) continue;
        if (BTUPHookInstanceMethod(cls, sel, 'v', (IMP)&BTUPVersionCheckNoop)) {
            any = YES;
        }
    }
    return any;
}

#pragma mark - 安装调度

static BOOL gBTUPAlertDone = NO;
static BOOL gBTUPManagerDone = NO;
static BOOL gBTUPLogged = NO;
static NSInteger gBTUPDoneCount = 0;

// 每个目标只从 NO 变 YES 一次，重复写入同一值是幂等的，
// 因此这里不引入锁；调用点都在主队列上。
static void BTUPInstallIfPossible(void) {
    if (!gBTUPAlertDone) gBTUPAlertDone = BTUPInstallAlertBlocking();
    if (!gBTUPManagerDone) gBTUPManagerDone = BTUPInstallManagerBlocking();

    gBTUPDoneCount = (gBTUPAlertDone ? 1 : 0) + (gBTUPManagerDone ? 1 : 0);

    if (gBTUPDoneCount == 2 && !gBTUPLogged) {
        gBTUPLogged = YES;
        BTUPLOG(@"✅ 版本检查屏蔽已生效（弹窗 + 检查入口 全部就位）");
    }
}

// 晚注册兜底：抖音部分类可能在 ctor 之后才注册。
// 用有限次递增间隔重试替代 dyld 回调 —— 后者依赖的
// dyld_register_func_for_add_image 在 iOS SDK 中链接不到。
// 4 次重试覆盖启动后 6 秒内的类注册，装齐后每次都是空转。
static void BTUPScheduleRetries(void) {
    static const int64_t delaysMs[] = {500, 1500, 3000, 6000};
    static BOOL scheduled = NO;
    if (scheduled) return;
    scheduled = YES;

    const size_t count = sizeof(delaysMs) / sizeof(delaysMs[0]);
    for (size_t i = 0; i < count; i++) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
                                     (int64_t)delaysMs[i] * (int64_t)NSEC_PER_MSEC),
                       dispatch_get_main_queue(), ^{
            if (gBTUPAlertDone && gBTUPManagerDone) return;
            BTUPInstallIfPossible();
        });
    }
}

#pragma mark - 对外接口

NSInteger BTUpdateBlockingInstalledCount(void) {
    return gBTUPDoneCount;
}

void BTInstallUpdateBlocking(void) {
    @autoreleasepool {
        // 强制启用：不读任何偏好键，也没有关闭分支。
        // 与卡密授权门禁完全独立 —— 未授权时其它功能关闭，本项照常工作。
        //
        // ctor 阶段主可执行文件的 ObjC 类已完成注册（_objc_init 早于
        // 各镜像的初始化函数），所以这里通常一次就能装齐。
        BTUPInstallIfPossible();

        BTUPScheduleRetries();

        BTUPLOG(@"版本检查屏蔽已安装（首轮）；当前就位 %ld/2",
                (long)gBTUPDoneCount);
    }
}
