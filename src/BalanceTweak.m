//
// BalanceTweak.m —— 抖音钻石余额自定义显示
// ============================================================
// 功能：
//   1. 三指长按 1 秒 → 呼出设置界面（可设置显示数字）
//   2. 自动追踪真实余额变化：
//        显示值 = 设置值 + (当前真实余额 - 基准真实余额)
//        送礼（真实减少）→ 显示减少；收礼（真实增加）→ 显示增加
//   3. 配置持久化（NSUserDefaults）
//
// 编译（macOS）：
//   SDK=$(xcrun --sdk iphoneos --show-sdk-path)
//   xcrun clang -dynamiclib -target arm64-apple-ios14.0 \
//     -isysroot "$SDK" -fobjc-arc -O2 -fvisibility=hidden \
//     -install_name @rpath/BalanceTweak.dylib \
//     -framework UIKit -framework Foundation \
//     -o build-arm64.dylib src/BalanceTweak.m
// ============================================================

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#include <stdlib.h>

#import "BTProto.h"
#import "BTProtocol.h"
#import "BTTTNetProbe.h"

// ============================================================
// 日志与通知
// ============================================================
#define BTLOG(fmt, ...) NSLog(@"[BalanceTweak] " fmt, ##__VA_ARGS__)

static NSString *const BTBalanceDidUpdateNotification = @"BTBalanceDidUpdateNotification";

// ============================================================
// 配置管理（线程安全 + 区分「未设置」与「0」）
// ============================================================
static NSString *const kKeyEnabled     = @"BT_enabled";
static NSString *const kKeyBaseDisplay = @"BT_baseDisplay";
static NSString *const kKeyBaseReal    = @"BT_baseReal";
static NSString *const kKeyLastReal    = @"BT_lastReal";

@interface BTPrefsSnapshot : NSObject
@property (nonatomic, assign) BOOL enabled;
@property (nonatomic, assign) BOOL hasBaseDisplay;
@property (nonatomic, assign) int64_t baseDisplay;
@property (nonatomic, assign) BOOL hasBaseReal;
@property (nonatomic, assign) int64_t baseReal;
@property (nonatomic, assign) BOOL hasLastReal;
@property (nonatomic, assign) int64_t lastReal;
@property (nonatomic, assign) int64_t computedDisplay;
@end

@implementation BTPrefsSnapshot
@end

@interface BTPrefs : NSObject
@property (class, readonly) BTPrefs *shared;
- (BTPrefsSnapshot *)snapshot;
- (void)applyBaseDisplay:(int64_t)display;
- (void)setEnabled:(BOOL)enabled;
- (void)reset;
// 原子更新真实余额并计算本次是否需要改写以及目标显示值
- (void)recordRealBalance:(int64_t)realVal
               outDisplay:(int64_t *)outDisplay
              shouldPatch:(BOOL *)shouldPatch;
@end

@implementation BTPrefs {
    BOOL _enabled;
    BOOL _hasBaseDisplay;
    int64_t _baseDisplay;
    BOOL _hasBaseReal;
    int64_t _baseReal;
    BOOL _hasLastReal;
    int64_t _lastReal;
}

+ (BTPrefs *)shared {
    static BTPrefs *inst;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ inst = [[BTPrefs alloc] init]; });
    return inst;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
        _enabled = [d boolForKey:kKeyEnabled];

        NSNumber *bd = [d objectForKey:kKeyBaseDisplay];
        if ([bd isKindOfClass:[NSNumber class]]) {
            _hasBaseDisplay = YES;
            _baseDisplay = bt_clamp_display([bd longLongValue]);
        }

        NSNumber *br = [d objectForKey:kKeyBaseReal];
        if ([br isKindOfClass:[NSNumber class]]) {
            _hasBaseReal = YES;
            _baseReal = [br longLongValue];
        }

        NSNumber *lr = [d objectForKey:kKeyLastReal];
        if ([lr isKindOfClass:[NSNumber class]]) {
            _hasLastReal = YES;
            _lastReal = [lr longLongValue];
        }
    }
    return self;
}

- (int64_t)_lockedComputedDisplay {
    return bt_compute_display(_enabled,
                              _hasBaseDisplay, _baseDisplay,
                              _hasBaseReal, _baseReal,
                              _hasLastReal ? _lastReal : 0);
}

- (BTPrefsSnapshot *)snapshot {
    @synchronized (self) {
        BTPrefsSnapshot *s = [[BTPrefsSnapshot alloc] init];
        s.enabled = _enabled;
        s.hasBaseDisplay = _hasBaseDisplay;
        s.baseDisplay = _baseDisplay;
        s.hasBaseReal = _hasBaseReal;
        s.baseReal = _baseReal;
        s.hasLastReal = _hasLastReal;
        s.lastReal = _lastReal;
        s.computedDisplay = [self _lockedComputedDisplay];
        return s;
    }
}

- (void)applyBaseDisplay:(int64_t)display {
    int64_t clamped = bt_clamp_display(display);
    @synchronized (self) {
        _hasBaseDisplay = YES;
        _baseDisplay = clamped;
        _enabled = YES;

        NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
        [d setObject:@(clamped) forKey:kKeyBaseDisplay];
        [d setBool:YES forKey:kKeyEnabled];

        if (_hasLastReal) {
            _hasBaseReal = YES;
            _baseReal = _lastReal;
            [d setObject:@(_baseReal) forKey:kKeyBaseReal];
        } else {
            // 尚未捕获过真实余额：清除旧基准，待下次 wallet/info 返回时自动锁定为基准
            _hasBaseReal = NO;
            _baseReal = 0;
            [d removeObjectForKey:kKeyBaseReal];
        }
    }
}

- (void)setEnabled:(BOOL)enabled {
    @synchronized (self) {
        _enabled = enabled;
        [[NSUserDefaults standardUserDefaults] setBool:enabled forKey:kKeyEnabled];
    }
}

- (void)reset {
    @synchronized (self) {
        _enabled = NO;
        _hasBaseDisplay = NO;
        _baseDisplay = 0;
        _hasBaseReal = NO;
        _baseReal = 0;
        _hasLastReal = NO;
        _lastReal = 0;

        NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
        [d removeObjectForKey:kKeyEnabled];
        [d removeObjectForKey:kKeyBaseDisplay];
        [d removeObjectForKey:kKeyBaseReal];
        [d removeObjectForKey:kKeyLastReal];
    }
}

- (void)recordRealBalance:(int64_t)realVal
               outDisplay:(int64_t *)outDisplay
              shouldPatch:(BOOL *)shouldPatch {
    BOOL didUpdateLastReal = NO;
    int64_t disp = realVal;
    BOOL patch = NO;

    @synchronized (self) {
        NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
        if (!_hasLastReal || _lastReal != realVal) {
            _hasLastReal = YES;
            _lastReal = realVal;
            [d setObject:@(realVal) forKey:kKeyLastReal];
            didUpdateLastReal = YES;
        }

        // 若用户先点了应用、当时还没捕获到真实余额，则在首次捕获到真实余额时自动锁定基准
        if (_enabled && _hasBaseDisplay && !_hasBaseReal) {
            _hasBaseReal = YES;
            _baseReal = realVal;
            [d setObject:@(realVal) forKey:kKeyBaseReal];
            didUpdateLastReal = YES;
        }

        patch = (_enabled && _hasBaseDisplay);
        disp = [self _lockedComputedDisplay];
    }

    if (outDisplay) *outDisplay = disp;
    if (shouldPatch) *shouldPatch = patch;

    if (didUpdateLastReal) {
        dispatch_async(dispatch_get_main_queue(), ^{
            [[NSNotificationCenter defaultCenter] postNotificationName:BTBalanceDidUpdateNotification
                                                                object:nil];
        });
    }
}

@end

// ============================================================
// wallet/info 响应处理（无论开关是否打开，均先记录真实余额）
// ============================================================
static NSData *btHandleWalletInfo(NSData *data) {
    if (!data || data.length < 4) return data;

    const uint8_t *buf = (const uint8_t *)data.bytes;
    size_t len = (size_t)data.length;

    int64_t realVal = 0;
    if (!bt_read_wallet_real_balance(buf, len, &realVal)) {
        return data;
    }

    int64_t disp = realVal;
    BOOL shouldPatch = NO;
    [[BTPrefs shared] recordRealBalance:realVal outDisplay:&disp shouldPatch:&shouldPatch];

    if (!shouldPatch) {
        return data;
    }

    uint8_t *outBuf = NULL;
    size_t outLen = 0;
    if (!bt_patch_wallet_info_buf(buf, len, disp, &outBuf, &outLen) || !outBuf) {
        return data;
    }

    BTLOG(@"改写: 真实=%lld 显示=%lld  %zuB -> %zuB", realVal, disp, len, outLen);
    return [NSData dataWithBytesNoCopy:outBuf length:(NSUInteger)outLen freeWhenDone:YES];
}

// ============================================================
// 严格解析非负整数输入（防止溢出或非法字符）
// ============================================================
static BOOL btParseDisplayInput(NSString *raw, int64_t *outVal) {
    NSString *s = [raw stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if (s.length == 0) return NO;

    uint64_t acc = 0;
    for (NSUInteger i = 0; i < s.length; i++) {
        unichar c = [s characterAtIndex:i];
        if (c < '0' || c > '9') return NO;
        uint64_t digit = (uint64_t)(c - '0');
        if (acc > ((uint64_t)BT_MAX_DISPLAY - digit) / 10ULL) {
            return NO;
        }
        acc = acc * 10ULL + digit;
    }
    if (outVal) *outVal = (int64_t)acc;
    return YES;
}

// ============================================================
// 设置界面
// ============================================================
@interface BTSettingsVC : UIViewController
@end

@implementation BTSettingsVC {
    UILabel *_status;
    UITextField *_tf;
    UIButton *_toggleBtn;
}

- (void)dealloc {
    [[NSNotificationCenter defaultCenter] removeObserver:self];
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor systemBackgroundColor];
    self.title = @"钻石显示";
    self.navigationItem.rightBarButtonItem =
        [[UIBarButtonItem alloc] initWithTitle:@"关闭"
                                         style:UIBarButtonItemStyleDone
                                        target:self
                                        action:@selector(onClose)];

    UITapGestureRecognizer *tap =
        [[UITapGestureRecognizer alloc] initWithTarget:self action:@selector(onDismissKeyboard)];
    tap.cancelsTouchesInView = NO;
    [self.view addGestureRecognizer:tap];

    BTPrefsSnapshot *snap = [[BTPrefs shared] snapshot];

    _status = [[UILabel alloc] init];
    _status.numberOfLines = 0;
    _status.font = [UIFont monospacedSystemFontOfSize:13 weight:UIFontWeightRegular];
    _status.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:_status];

    _tf = [[UITextField alloc] init];
    _tf.placeholder = @"输入显示数字，如 1500254";
    _tf.keyboardType = UIKeyboardTypeNumberPad;
    _tf.borderStyle = UITextBorderStyleRoundedRect;
    _tf.clearButtonMode = UITextFieldViewModeWhileEditing;
    _tf.translatesAutoresizingMaskIntoConstraints = NO;
    if (snap.hasBaseDisplay) {
        _tf.text = [NSString stringWithFormat:@"%lld", snap.baseDisplay];
    }
    [self.view addSubview:_tf];

    UIButton *applyBtn = [self makeButtonWithTitle:@"应用（以当前真实余额为基准）" tag:0 destructive:NO];
    _toggleBtn = [self makeButtonWithTitle:@"" tag:1 destructive:NO];
    UIButton *resetBtn = [self makeButtonWithTitle:@"重置" tag:2 destructive:YES];

    NSArray<UIButton *> *btns = @[applyBtn, _toggleBtn, resetBtn];

    UILayoutGuide *g = self.view.safeAreaLayoutGuide;
    NSMutableArray<NSLayoutConstraint *> *cs = [NSMutableArray array];
    [cs addObject:[_status.topAnchor constraintEqualToAnchor:g.topAnchor constant:20]];
    [cs addObject:[_status.leadingAnchor constraintEqualToAnchor:g.leadingAnchor constant:20]];
    [cs addObject:[_status.trailingAnchor constraintEqualToAnchor:g.trailingAnchor constant:-20]];
    [cs addObject:[_tf.topAnchor constraintEqualToAnchor:_status.bottomAnchor constant:16]];
    [cs addObject:[_tf.leadingAnchor constraintEqualToAnchor:g.leadingAnchor constant:20]];
    [cs addObject:[_tf.trailingAnchor constraintEqualToAnchor:g.trailingAnchor constant:-20]];
    [cs addObject:[_tf.heightAnchor constraintEqualToConstant:40]];

    UIView *prev = _tf;
    for (UIButton *b in btns) {
        [cs addObject:[b.topAnchor constraintEqualToAnchor:prev.bottomAnchor constant:12]];
        [cs addObject:[b.centerXAnchor constraintEqualToAnchor:g.centerXAnchor]];
        prev = b;
    }
    [NSLayoutConstraint activateConstraints:cs];

    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(refresh)
                                                 name:BTBalanceDidUpdateNotification
                                               object:nil];

    [self refresh];
}

- (UIButton *)makeButtonWithTitle:(NSString *)title tag:(NSInteger)tag destructive:(BOOL)destructive {
    UIButton *b = [UIButton buttonWithType:UIButtonTypeSystem];
    [b setTitle:title forState:UIControlStateNormal];
    b.titleLabel.font = [UIFont systemFontOfSize:15];
    b.translatesAutoresizingMaskIntoConstraints = NO;
    b.tag = tag;
    if (destructive) {
        [b setTitleColor:[UIColor systemRedColor] forState:UIControlStateNormal];
    }
    [b addTarget:self action:@selector(onButton:) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:b];
    return b;
}

- (void)refresh {
    BTPrefsSnapshot *s = [[BTPrefs shared] snapshot];
    NSString *realStr = s.hasLastReal ? [NSString stringWithFormat:@"%lld", s.lastReal] : @"未获取";
    NSString *baseRealStr = s.hasBaseReal ? [NSString stringWithFormat:@"%lld", s.baseReal] : @"未设置";
    NSString *baseDispStr = s.hasBaseDisplay ? [NSString stringWithFormat:@"%lld", s.baseDisplay] : @"未设置";
    NSString *currDispStr = (s.hasLastReal || (s.enabled && s.hasBaseDisplay))
        ? [NSString stringWithFormat:@"%lld", s.computedDisplay]
        : @"未获取";

    _status.text = [NSString stringWithFormat:
        @"真实余额:   %@\n"
        @"基准真实:   %@\n"
        @"基准显示:   %@\n"
        @"当前显示:   %@\n"
        @"改写开关:   %@",
        realStr, baseRealStr, baseDispStr, currDispStr,
        s.enabled ? @"开" : @"关"];

    [_toggleBtn setTitle:(s.enabled ? @"关闭改写" : @"开启改写") forState:UIControlStateNormal];
}

- (void)onDismissKeyboard {
    [self.view endEditing:YES];
}

- (void)onButton:(UIButton *)sender {
    [self.view endEditing:YES];
    BTPrefs *p = [BTPrefs shared];

    if (sender.tag == 0) {
        int64_t v = 0;
        if (!btParseDisplayInput(_tf.text, &v)) {
            [self toast:[NSString stringWithFormat:@"请输入 0 ~ %lld 之间的整数", (long long)BT_MAX_DISPLAY]];
            return;
        }
        [p applyBaseDisplay:v];
        [self refresh];

        BTPrefsSnapshot *s = [p snapshot];
        NSString *msg = s.hasBaseReal
            ? [NSString stringWithFormat:@"已设置显示值 %lld（基准真实 %lld）", v, s.baseReal]
            : [NSString stringWithFormat:@"已设置显示值 %lld（待首次获取真实余额后自动锁定基准）", v];
        [self toast:msg];
    } else if (sender.tag == 1) {
        BTPrefsSnapshot *s = [p snapshot];
        [p setEnabled:!s.enabled];
        [self refresh];
    } else if (sender.tag == 2) {
        [p reset];
        _tf.text = @"";
        [self refresh];
    }
}

- (void)toast:(NSString *)msg {
    UIAlertController *a = [UIAlertController alertControllerWithTitle:nil
                                                               message:msg
                                                        preferredStyle:UIAlertControllerStyleAlert];
    [a addAction:[UIAlertAction actionWithTitle:@"好" style:UIAlertActionStyleDefault handler:nil]];
    [self presentViewController:a animated:YES completion:nil];
}

- (void)onClose {
    [self dismissViewControllerAnimated:YES completion:nil];
}

@end

// ============================================================
// 手势（支持与其他手势并发识别，避免重复弹窗）
// ============================================================
@interface BTGesture : NSObject <UIGestureRecognizerDelegate>
+ (void)install;
@end

@implementation BTGesture

+ (instancetype)shared {
    static BTGesture *inst;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ inst = [[BTGesture alloc] init]; });
    return inst;
}

+ (UIWindow *)keyWindow {
    UIWindow *fallback = nil;
    for (UIScene *s in [UIApplication sharedApplication].connectedScenes) {
        if (![s isKindOfClass:[UIWindowScene class]]) continue;
        UIWindowScene *ws = (UIWindowScene *)s;
        BOOL isActive = (ws.activationState == UISceneActivationStateForegroundActive);
        for (UIWindow *w in ws.windows) {
            if (w.isKeyWindow) {
                if (isActive) return w;
                if (!fallback) fallback = w;
            }
        }
    }
    return fallback;
}

+ (void)install {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        [[NSNotificationCenter defaultCenter]
            addObserverForName:UIApplicationDidBecomeActiveNotification
                        object:nil
                         queue:[NSOperationQueue mainQueue]
                    usingBlock:^(NSNotification *n) {
            (void)n;
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{
                [self attach];
            });
        }];
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            [self attach];
        });
    });
}

+ (void)attach {
    UIWindow *w = [self keyWindow];
    if (!w) return;

    for (UIGestureRecognizer *g in w.gestureRecognizers) {
        if ([g isKindOfClass:[UILongPressGestureRecognizer class]]) {
            UILongPressGestureRecognizer *lp0 = (UILongPressGestureRecognizer *)g;
            if (lp0.numberOfTouchesRequired == 3 && lp0.delegate == [self shared]) {
                return;
            }
        }
    }

    UILongPressGestureRecognizer *lp =
        [[UILongPressGestureRecognizer alloc] initWithTarget:self action:@selector(onLP:)];
    lp.numberOfTouchesRequired = 3;
    lp.minimumPressDuration = 1.0;
    lp.cancelsTouchesInView = NO;
    lp.delegate = [self shared];
    [w addGestureRecognizer:lp];

    BTLOG(@"三指长按手势已安装");
}

- (BOOL)gestureRecognizer:(UIGestureRecognizer *)gestureRecognizer
shouldRecognizeSimultaneouslyWithGestureRecognizer:(UIGestureRecognizer *)otherGestureRecognizer {
    (void)gestureRecognizer;
    (void)otherGestureRecognizer;
    return YES;
}

+ (BOOL)isSettingsPresentedFrom:(UIViewController *)vc {
    if ([vc isKindOfClass:[BTSettingsVC class]]) return YES;
    if ([vc isKindOfClass:[UINavigationController class]]) {
        UIViewController *top = ((UINavigationController *)vc).topViewController;
        if ([top isKindOfClass:[BTSettingsVC class]]) return YES;
    }
    return NO;
}

+ (void)onLP:(UILongPressGestureRecognizer *)g {
    if (g.state != UIGestureRecognizerStateBegan) return;

    BTLOG(@"三指长按触发");

    UIWindow *w = [self keyWindow];
    UIViewController *root = w.rootViewController;
    if (!root) return;
    while (root.presentedViewController) {
        if ([self isSettingsPresentedFrom:root.presentedViewController]) {
            return;
        }
        root = root.presentedViewController;
    }
    if ([self isSettingsPresentedFrom:root]) return;

    BTSettingsVC *vc = [[BTSettingsVC alloc] init];
    UINavigationController *nav = [[UINavigationController alloc] initWithRootViewController:vc];
    nav.modalPresentationStyle = UIModalPresentationPageSheet;
    [root presentViewController:nav animated:YES completion:nil];
}

@end

// ============================================================
// 网络 Hook
// ============================================================
static NSString *const kWIPath = @"/webcast/wallet/info/";

static void (^btWrapCompletion(void (^completion)(NSData *, NSURLResponse *, NSError *)))(NSData *, NSURLResponse *, NSError *) {
    return ^(NSData *data, NSURLResponse *resp, NSError *err) {
        NSData *out = data;
        if (data && data.length > 0 && !err) {
            @try {
                out = btHandleWalletInfo(data);
            } @catch (NSException *e) {
                BTLOG(@"patch 异常: %@", e);
            }
        }
        if (completion) completion(out, resp, err);
    };
}

@interface BTNet : NSObject
+ (void)install;
@end

@implementation BTNet

+ (void)install {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        [self hookDataTaskWithRequestCompletion];
        [self hookDataTaskWithURLCompletion];
    });
}

+ (void)hookDataTaskWithRequestCompletion {
    Class cls = NSClassFromString(@"NSURLSession");
    if (!cls) return;

    SEL sel = @selector(dataTaskWithRequest:completionHandler:);
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) {
        BTLOG(@"NSURLSession 没有 dataTaskWithRequest:completionHandler:");
        return;
    }

    IMP origImp = method_getImplementation(m);
    typedef id (*Fn)(id, SEL, NSURLRequest *, void (^)(NSData *, NSURLResponse *, NSError *));
    Fn fn = (Fn)origImp;

    id block = ^id(id self_, NSURLRequest *req, void (^completion)(NSData *, NSURLResponse *, NSError *)) {
        NSString *path = req.URL.path ?: @"";
        if (![path containsString:kWIPath] || !completion) {
            return fn(self_, sel, req, completion);
        }
        BTLOG(@"拦截 wallet/info (request)");
        return fn(self_, sel, req, btWrapCompletion(completion));
    };

    method_setImplementation(m, imp_implementationWithBlock(block));
    BTLOG(@"hooked NSURLSession dataTaskWithRequest:completionHandler:");
}

+ (void)hookDataTaskWithURLCompletion {
    Class cls = NSClassFromString(@"NSURLSession");
    if (!cls) return;

    SEL sel = @selector(dataTaskWithURL:completionHandler:);
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return;

    IMP origImp = method_getImplementation(m);
    typedef id (*Fn)(id, SEL, NSURL *, void (^)(NSData *, NSURLResponse *, NSError *));
    Fn fn = (Fn)origImp;

    id block = ^id(id self_, NSURL *url, void (^completion)(NSData *, NSURLResponse *, NSError *)) {
        NSString *path = url.path ?: @"";
        if (![path containsString:kWIPath] || !completion) {
            return fn(self_, sel, url, completion);
        }
        BTLOG(@"拦截 wallet/info (url)");
        return fn(self_, sel, url, btWrapCompletion(completion));
    };

    method_setImplementation(m, imp_implementationWithBlock(block));
    BTLOG(@"hooked NSURLSession dataTaskWithURL:completionHandler:");
}

@end

// ============================================================
// NSURLProtocol 改写回调（只处理 wallet/info）
// ============================================================
static NSData *btProtocolPatch(NSURL *url, NSData *data) {
    if (!url || !data || data.length < 8) return nil;

    NSString *path = url.path ?: @"";
    if (![path containsString:@"/webcast/wallet/info/"]) return nil;

    const uint8_t *buf = (const uint8_t *)data.bytes;
    size_t len = (size_t)data.length;

    // 1. 读真实余额
    int64_t realVal = 0;
    if (!bt_read_wallet_real_balance(buf, len, &realVal)) {
        BTLOG(@"[protocol] 读真实余额失败 (%luB)", (unsigned long)len);
        return nil;
    }

    // 2. 记录 + 计算显示值 + 判断是否改写
    int64_t display = 0;
    BOOL shouldPatch = NO;
    [[BTPrefs shared] recordRealBalance:realVal
                             outDisplay:&display
                            shouldPatch:&shouldPatch];

    if (!shouldPatch) {
        BTLOG(@"[protocol] 真实=%lld 不改写（未启用或未设置）", realVal);
        return nil;
    }

    // 3. 改写 protobuf
    uint8_t *outBuf = NULL;
    size_t outLen = 0;
    if (!bt_patch_wallet_info_buf(buf, len, display, &outBuf, &outLen)) {
        BTLOG(@"[protocol] protobuf 改写失败");
        return nil;
    }

    NSData *result = [NSData dataWithBytes:outBuf length:outLen];
    free(outBuf);

    BTLOG(@"[protocol] 真实=%lld 显示=%lld  %luB -> %luB",
          realVal, display, (unsigned long)len, (unsigned long)outLen);

    return result;
}

// ============================================================
// 入口
// ============================================================
__attribute__((constructor))
static void BTInit(void) {
    BTLOG(@"================ 加载 ================");
    BTLOG(@"三指长按 1 秒 → 打开设置");

    // ★ 方案 A：NSURLProtocol 拦截（最稳，覆盖所有 NSURLSession 请求）
    BTInstallURLProtocol();
    BTSetPatchFunc(btProtocolPatch);

    // ★ 方案 C：TTNet 探测（抖音不走 NSURLSession 时）
    BTInstallTTNetProbe();

    // ★ 方案 B：NSURLSession completion hook（兜底）
    [BTNet install];

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        [BTGesture install];
        BTLOG(@"初始化完成");
    });
}
