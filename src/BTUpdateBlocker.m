//
// BTUpdateBlocker.m —— 屏蔽抖音应用内版本检查与更新弹窗
// ============================================================
// 机理（均来自对目标 dylib「屏蔽抖音检测更新 1.0.2」的实测，非推测）：
//
//   1. AWEVersionUpdateAlert -canShow          → 恒定 NO，弹窗不呈现
//   2. AWENewVersionAlertManager 的 5 个检查方法 → 空实现，请求不发起
//   3. 抖音部分类晚于本 dylib 注册，ctor 阶段 NSClassFromString 会返回 nil，
//      因此挂 dyld_register_func_for_add_image 回调补装。
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

#import <mach-o/dyld.h>
#import <objc/runtime.h>
#import <string.h>

// 部分 iOS SDK 的 <mach-o/dyld.h> 未暴露该原型（实测 iOS 16.5 SDK 编译期报
// implicit-function-declaration）。此处显式声明，与头文件原型一致，重复声明合法。
extern void dyld_register_func_for_add_image(void (*func)(const struct mach_header *mh,
                                                                 intptr_t vmaddr_slide));

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

// 抖音类可能在任意时刻注册，因此这里不加锁：
// 两条路径（ctor / dyld 回调）都在主线程或 dyld 加载回调中执行，
// 且每个目标只从 NO 变 YES 一次，重复写入同一值是幂等的。
static void BTUPInstallIfPossible(void) {
    if (!gBTUPAlertDone) gBTUPAlertDone = BTUPInstallAlertBlocking();
    if (!gBTUPManagerDone) gBTUPManagerDone = BTUPInstallManagerBlocking();

    NSInteger done = (gBTUPAlertDone ? 1 : 0) + (gBTUPManagerDone ? 1 : 0);
    gBTUPDoneCount = done;

    if (done == 2 && !gBTUPLogged) {
        gBTUPLogged = YES;
        BTUPLOG(@"✅ 版本检查屏蔽已生效（弹窗 + 检查入口 全部就位）");
    }
}

static void BTUPImageAdded(const struct mach_header *header, intptr_t slide) {
    (void)header;
    (void)slide;

    if (gBTUPAlertDone && gBTUPManagerDone) return;   // 已装齐，直接返回
    BTUPInstallIfPossible();
}

#pragma mark - 对外接口

NSInteger BTUpdateBlockingInstalledCount(void) {
    return gBTUPDoneCount;
}

void BTInstallUpdateBlocking(void) {
    @autoreleasepool {
        // 强制启用：不读任何偏好键，也没有关闭分支。
        // 与卡密授权门禁完全独立 —— 未授权时其它功能关闭，本项照常工作。
        BTUPInstallIfPossible();

        // 抖音存在多个版本检查入口，且部分类晚于 ctor 注册。
        // 回调在装齐后是空转，代价可忽略。
        dyld_register_func_for_add_image(&BTUPImageAdded);

        BTUPLOG(@"版本检查屏蔽已安装（第 1 轮）；当前就位 %ld/2",
                (long)gBTUPDoneCount);
    }
}
