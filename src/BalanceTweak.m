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
#import "BTLog.h"
#import "BTProtocol.h"
#import "BTTTNetProbe.h"
#import "BTWalletHook.h"
#import "BTLogVC.h"
#import "BTSSLHook.h"
#include "JJCloudVerifier.h"   // ★ gogo-v2 卡密验证（C ABI）

// ============================================================
// 日志与通知
// ============================================================
#define BTLOG(fmt, ...) BT_LOG_M(@"Main", fmt, ##__VA_ARGS__)

static NSString *const BTBalanceDidUpdateNotification = @"BTBalanceDidUpdateNotification";

// ============================================================
// 配置与内置状态同步中心（线程安全 + 区分「未设置」与「0」）
// ============================================================
static NSString *const kKeyEnabled     = @"BT_enabled";
static NSString *const kKeySafeMode    = @"BT_safemode_v5";
static NSString *const kKeyBaseDisplay = @"BT_baseDisplay";
static NSString *const kKeyBaseReal    = @"BT_baseReal";
static NSString *const kKeyLastReal    = @"BT_lastReal";

static void btSyncRuntimeHooksWithSafeMode(BOOL safeMode) {
    if (safeMode) {
        BTSetWalletHookActive(NO);
        BTSetTTNetActive(NO);
    } else {
        // 若启动时因安全模式跳过了安装，此处即时补装，无需重启 App
        BTInstallWalletModelHook();
        BTInstallTTNetProbe();
        BTSetWalletHookActive(YES);
        BTSetTTNetActive(YES);
    }
}

@interface BTPrefsSnapshot : NSObject
@property (nonatomic, assign) BOOL enabled;
@property (nonatomic, assign) BOOL safeMode;
@property (nonatomic, assign) BOOL hasBaseDisplay;
@property (nonatomic, assign) int64_t baseDisplay;
@property (nonatomic, assign) BOOL hasBaseReal;
@property (nonatomic, assign) int64_t baseReal;
@property (nonatomic, assign) BOOL hasLastReal;
@property (nonatomic, assign) int64_t lastReal;
@property (nonatomic, assign) int64_t computedDisplay;
@property (nonatomic, assign) BOOL hasDelta;
@property (nonatomic, assign) int64_t delta;
@property (nonatomic, copy) NSString *lastSyncSource;
@property (nonatomic, strong) NSDate *lastSyncDate;
@end

@implementation BTPrefsSnapshot
@end

@interface BTPrefs : NSObject
@property (class, readonly) BTPrefs *shared;
- (BTPrefsSnapshot *)snapshot;
- (void)applyBaseDisplay:(int64_t)display;
- (void)setEnabled:(BOOL)enabled;
- (void)setSafeMode:(BOOL)safeMode;
- (BOOL)realignBaseToCurrentReal;
- (void)reset;
// 原子更新真实余额并计算本次是否需要改写以及目标显示值
- (void)recordRealBalance:(int64_t)realVal
                   source:(NSString *)source
               outDisplay:(int64_t *)outDisplay
              shouldPatch:(BOOL *)shouldPatch;
@end

@implementation BTPrefs {
    BOOL _enabled;
    BOOL _safeMode;
    BOOL _hasBaseDisplay;
    int64_t _baseDisplay;
    BOOL _hasBaseReal;
    int64_t _baseReal;
    BOOL _hasLastReal;
    int64_t _lastReal;
    NSString *_lastSyncSource;
    NSDate *_lastSyncDate;
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
        _safeMode = [d boolForKey:kKeySafeMode];

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

- (void)_notifyStateChanged {
    dispatch_async(dispatch_get_main_queue(), ^{
        [[NSNotificationCenter defaultCenter] postNotificationName:BTBalanceDidUpdateNotification
                                                            object:nil];
    });
}

- (int64_t)_lockedComputedDisplay {
    BOOL effectiveEnabled = (_enabled && !_safeMode);
    return bt_compute_display(effectiveEnabled,
                              _hasBaseDisplay, _baseDisplay,
                              _hasBaseReal, _baseReal,
                              _hasLastReal ? _lastReal : 0);
}

- (BTPrefsSnapshot *)snapshot {
    @synchronized (self) {
        BTPrefsSnapshot *s = [[BTPrefsSnapshot alloc] init];
        s.enabled = _enabled;
        s.safeMode = _safeMode;
        s.hasBaseDisplay = _hasBaseDisplay;
        s.baseDisplay = _baseDisplay;
        s.hasBaseReal = _hasBaseReal;
        s.baseReal = _baseReal;
        s.hasLastReal = _hasLastReal;
        s.lastReal = _lastReal;
        s.computedDisplay = [self _lockedComputedDisplay];
        s.hasDelta = (_hasBaseReal && _hasLastReal);
        s.delta = s.hasDelta ? (_lastReal - _baseReal) : 0;
        s.lastSyncSource = _lastSyncSource;
        s.lastSyncDate = _lastSyncDate;
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
            _hasBaseReal = NO;
            _baseReal = 0;
            [d removeObjectForKey:kKeyBaseReal];
        }
    }
    [self _notifyStateChanged];
}

- (void)setEnabled:(BOOL)enabled {
    @synchronized (self) {
        _enabled = enabled;
        [[NSUserDefaults standardUserDefaults] setBool:enabled forKey:kKeyEnabled];
    }
    [self _notifyStateChanged];
}

- (void)setSafeMode:(BOOL)safeMode {
    @synchronized (self) {
        _safeMode = safeMode;
        NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
        [d setBool:safeMode forKey:kKeySafeMode];
        if (!safeMode) {
            [d removeObjectForKey:@"BT_safemode"];
        }
    }
    btSyncRuntimeHooksWithSafeMode(safeMode);
    [self _notifyStateChanged];
}

- (BOOL)realignBaseToCurrentReal {
    BOOL ok = NO;
    @synchronized (self) {
        if (_hasLastReal && _hasBaseDisplay) {
            int64_t cur = [self _lockedComputedDisplay];
            _baseDisplay = bt_clamp_display(cur);
            _baseReal = _lastReal;
            _hasBaseReal = YES;

            NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
            [d setObject:@(_baseDisplay) forKey:kKeyBaseDisplay];
            [d setObject:@(_baseReal) forKey:kKeyBaseReal];
            ok = YES;
        }
    }
    if (ok) [self _notifyStateChanged];
    return ok;
}

- (void)reset {
    @synchronized (self) {
        _enabled = NO;
        _safeMode = NO;
        _hasBaseDisplay = NO;
        _baseDisplay = 0;
        _hasBaseReal = NO;
        _baseReal = 0;
        _hasLastReal = NO;
        _lastReal = 0;
        _lastSyncSource = nil;
        _lastSyncDate = nil;

        NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
        [d removeObjectForKey:kKeyEnabled];
        [d removeObjectForKey:kKeySafeMode];
        [d removeObjectForKey:@"BT_safemode"];
        [d removeObjectForKey:kKeyBaseDisplay];
        [d removeObjectForKey:kKeyBaseReal];
        [d removeObjectForKey:kKeyLastReal];
    }
    btSyncRuntimeHooksWithSafeMode(NO);
    [self _notifyStateChanged];
}

- (void)recordRealBalance:(int64_t)realVal
                   source:(NSString *)source
               outDisplay:(int64_t *)outDisplay
              shouldPatch:(BOOL *)shouldPatch {
    BOOL didChange = NO;
    int64_t disp = realVal;
    BOOL patch = NO;

    @synchronized (self) {
        NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
        if (!_hasLastReal || _lastReal != realVal) {
            _hasLastReal = YES;
            _lastReal = realVal;
            [d setObject:@(realVal) forKey:kKeyLastReal];
            didChange = YES;
        }

        if (source.length > 0 && ![_lastSyncSource isEqualToString:source]) {
            _lastSyncSource = [source copy];
            didChange = YES;
        }
        _lastSyncDate = [NSDate date];

        // 若用户先点了应用、当时还没捕获到真实余额，则在首次捕获到真实余额时自动锁定基准
        if (_enabled && !_safeMode && _hasBaseDisplay && !_hasBaseReal) {
            _hasBaseReal = YES;
            _baseReal = realVal;
            [d setObject:@(realVal) forKey:kKeyBaseReal];
            didChange = YES;
        }

        patch = (_enabled && !_safeMode && _hasBaseDisplay);
        disp = [self _lockedComputedDisplay];
    }

    if (outDisplay) *outDisplay = disp;
    if (shouldPatch) *shouldPatch = patch;

    if (didChange) {
        [self _notifyStateChanged];
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
    [[BTPrefs shared] recordRealBalance:realVal
                                 source:@"网络接口"
                             outDisplay:&disp
                            shouldPatch:&shouldPatch];

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
// 设置界面（现代 iOS 分组卡片 UI + 安全模式开关 + 内置状态实时同步）
// ============================================================
@interface BTSettingsVC : UIViewController
@end

@implementation BTSettingsVC {
    UILabel *_badgeLabel;
    UIView *_badgeBg;
    UILabel *_syncLabel;
    UILabel *_heroNumber;
    UILabel *_realValLabel;
    UILabel *_baseRealValLabel;
    UILabel *_deltaValLabel;
    UITextField *_tf;
    UISwitch *_enableSwitch;
    UISwitch *_safeModeSwitch;
}

- (void)dealloc {
    [[NSNotificationCenter defaultCenter] removeObserver:self];
}

+ (NSString *)formatNumber:(int64_t)val {
    static NSNumberFormatter *nf = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        nf = [[NSNumberFormatter alloc] init];
        nf.numberStyle = NSNumberFormatterDecimalStyle;
        nf.groupingSeparator = @",";
    });
    return [nf stringFromNumber:@(val)] ?: [NSString stringWithFormat:@"%lld", (long long)val];
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor systemGroupedBackgroundColor];
    self.title = @"钻石显示设置";
    self.navigationItem.rightBarButtonItem =
        [[UIBarButtonItem alloc] initWithTitle:@"完成"
                                         style:UIBarButtonItemStyleDone
                                        target:self
                                        action:@selector(onClose)];

    UITapGestureRecognizer *tap =
        [[UITapGestureRecognizer alloc] initWithTarget:self action:@selector(onDismissKeyboard)];
    tap.cancelsTouchesInView = NO;
    [self.view addGestureRecognizer:tap];

    UIScrollView *scroll = [[UIScrollView alloc] init];
    scroll.translatesAutoresizingMaskIntoConstraints = NO;
    scroll.alwaysBounceVertical = YES;
    scroll.keyboardDismissMode = UIScrollViewKeyboardDismissModeOnDrag;
    [self.view addSubview:scroll];

    UIStackView *stack = [[UIStackView alloc] init];
    stack.axis = UILayoutConstraintAxisVertical;
    stack.spacing = 16;
    stack.translatesAutoresizingMaskIntoConstraints = NO;
    [scroll addSubview:stack];

    UILayoutGuide *g = self.view.safeAreaLayoutGuide;
    [NSLayoutConstraint activateConstraints:@[
        [scroll.topAnchor constraintEqualToAnchor:g.topAnchor],
        [scroll.bottomAnchor constraintEqualToAnchor:g.bottomAnchor],
        [scroll.leadingAnchor constraintEqualToAnchor:g.leadingAnchor],
        [scroll.trailingAnchor constraintEqualToAnchor:g.trailingAnchor],

        [stack.topAnchor constraintEqualToAnchor:scroll.contentLayoutGuide.topAnchor constant:16],
        [stack.bottomAnchor constraintEqualToAnchor:scroll.contentLayoutGuide.bottomAnchor constant:-28],
        [stack.leadingAnchor constraintEqualToAnchor:scroll.contentLayoutGuide.leadingAnchor constant:16],
        [stack.trailingAnchor constraintEqualToAnchor:scroll.contentLayoutGuide.trailingAnchor constant:-16],
        [stack.widthAnchor constraintEqualToAnchor:scroll.frameLayoutGuide.widthAnchor constant:-32],
    ]];

    // 1. 顶部余额状态主卡片
    [stack addArrangedSubview:[self buildHeroCard]];

    // 2. 自定义数值 + 快捷预设卡片
    [stack addArrangedSubview:[self buildInputCard]];

    // 3. 开关分组卡片（改写开关 + 安全模式）
    [stack addArrangedSubview:[self buildSwitchGroupCard]];

    // 4. 工具与重置分组卡片
    [stack addArrangedSubview:[self buildActionGroupCard]];

    BTPrefsSnapshot *snap = [[BTPrefs shared] snapshot];
    if (snap.hasBaseDisplay) {
        _tf.text = [NSString stringWithFormat:@"%lld", snap.baseDisplay];
    }

    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(refresh)
                                                 name:BTBalanceDidUpdateNotification
                                               object:nil];

    [self refresh];
}

- (UIView *)makeCardContainer {
    UIView *v = [[UIView alloc] init];
    v.backgroundColor = [UIColor secondarySystemGroupedBackgroundColor];
    v.layer.cornerRadius = 16;
    v.layer.masksToBounds = YES;
    v.translatesAutoresizingMaskIntoConstraints = NO;
    return v;
}

- (UIView *)makeHairline {
    UIView *line = [[UIView alloc] init];
    line.backgroundColor = [UIColor separatorColor];
    line.translatesAutoresizingMaskIntoConstraints = NO;
    [line.heightAnchor constraintEqualToConstant:(1.0 / [UIScreen mainScreen].scale)].active = YES;
    return line;
}

- (UIView *)buildHeroCard {
    UIView *card = [self makeCardContainer];

    // 状态胶囊
    _badgeBg = [[UIView alloc] init];
    _badgeBg.layer.cornerRadius = 11;
    _badgeBg.translatesAutoresizingMaskIntoConstraints = NO;
    [card addSubview:_badgeBg];

    _badgeLabel = [[UILabel alloc] init];
    _badgeLabel.font = [UIFont systemFontOfSize:12 weight:UIFontWeightSemibold];
    _badgeLabel.translatesAutoresizingMaskIntoConstraints = NO;
    [_badgeBg addSubview:_badgeLabel];

    _syncLabel = [[UILabel alloc] init];
    _syncLabel.font = [UIFont systemFontOfSize:11];
    _syncLabel.textColor = [UIColor secondaryLabelColor];
    _syncLabel.textAlignment = NSTextAlignmentRight;
    _syncLabel.translatesAutoresizingMaskIntoConstraints = NO;
    [card addSubview:_syncLabel];

    UILabel *caption = [[UILabel alloc] init];
    caption.text = @"当前显示钻石";
    caption.font = [UIFont systemFontOfSize:13 weight:UIFontWeightMedium];
    caption.textColor = [UIColor secondaryLabelColor];
    caption.translatesAutoresizingMaskIntoConstraints = NO;
    [card addSubview:caption];

    _heroNumber = [[UILabel alloc] init];
    _heroNumber.font = [UIFont monospacedDigitSystemFontOfSize:34 weight:UIFontWeightBold];
    _heroNumber.textColor = [UIColor labelColor];
    _heroNumber.adjustsFontSizeToFitWidth = YES;
    _heroNumber.minimumScaleFactor = 0.6;
    _heroNumber.translatesAutoresizingMaskIntoConstraints = NO;
    [card addSubview:_heroNumber];

    UIView *sep = [self makeHairline];
    [card addSubview:sep];

    UIStackView *metrics = [[UIStackView alloc] init];
    metrics.axis = UILayoutConstraintAxisHorizontal;
    metrics.distribution = UIStackViewDistributionFillEqually;
    metrics.translatesAutoresizingMaskIntoConstraints = NO;
    [card addSubview:metrics];

    [metrics addArrangedSubview:[self buildMetricColumnWithTitle:@"真实余额" outValue:&_realValLabel]];
    [metrics addArrangedSubview:[self buildMetricColumnWithTitle:@"基准真实" outValue:&_baseRealValLabel]];
    [metrics addArrangedSubview:[self buildMetricColumnWithTitle:@"累计变化" outValue:&_deltaValLabel]];

    [NSLayoutConstraint activateConstraints:@[
        [_badgeBg.topAnchor constraintEqualToAnchor:card.topAnchor constant:16],
        [_badgeBg.leadingAnchor constraintEqualToAnchor:card.leadingAnchor constant:16],
        [_badgeBg.heightAnchor constraintEqualToConstant:22],

        [_badgeLabel.leadingAnchor constraintEqualToAnchor:_badgeBg.leadingAnchor constant:10],
        [_badgeLabel.trailingAnchor constraintEqualToAnchor:_badgeBg.trailingAnchor constant:-10],
        [_badgeLabel.centerYAnchor constraintEqualToAnchor:_badgeBg.centerYAnchor],

        [_syncLabel.centerYAnchor constraintEqualToAnchor:_badgeBg.centerYAnchor],
        [_syncLabel.trailingAnchor constraintEqualToAnchor:card.trailingAnchor constant:-16],
        [_syncLabel.leadingAnchor constraintGreaterThanOrEqualToAnchor:_badgeBg.trailingAnchor constant:8],

        [caption.topAnchor constraintEqualToAnchor:_badgeBg.bottomAnchor constant:14],
        [caption.leadingAnchor constraintEqualToAnchor:card.leadingAnchor constant:16],

        [_heroNumber.topAnchor constraintEqualToAnchor:caption.bottomAnchor constant:4],
        [_heroNumber.leadingAnchor constraintEqualToAnchor:card.leadingAnchor constant:16],
        [_heroNumber.trailingAnchor constraintEqualToAnchor:card.trailingAnchor constant:-16],

        [sep.topAnchor constraintEqualToAnchor:_heroNumber.bottomAnchor constant:16],
        [sep.leadingAnchor constraintEqualToAnchor:card.leadingAnchor constant:16],
        [sep.trailingAnchor constraintEqualToAnchor:card.trailingAnchor constant:-16],

        [metrics.topAnchor constraintEqualToAnchor:sep.bottomAnchor constant:12],
        [metrics.leadingAnchor constraintEqualToAnchor:card.leadingAnchor constant:8],
        [metrics.trailingAnchor constraintEqualToAnchor:card.trailingAnchor constant:-8],
        [metrics.bottomAnchor constraintEqualToAnchor:card.bottomAnchor constant:-14],
    ]];
    return card;
}

- (UIView *)buildMetricColumnWithTitle:(NSString *)title outValue:(UILabel * __strong *)outVal {
    UIStackView *col = [[UIStackView alloc] init];
    col.axis = UILayoutConstraintAxisVertical;
    col.alignment = UIStackViewAlignmentCenter;
    col.spacing = 4;

    UILabel *val = [[UILabel alloc] init];
    val.font = [UIFont monospacedDigitSystemFontOfSize:16 weight:UIFontWeightSemibold];
    val.textColor = [UIColor labelColor];
    val.adjustsFontSizeToFitWidth = YES;
    val.minimumScaleFactor = 0.7;
    if (outVal) *outVal = val;

    UILabel *lbl = [[UILabel alloc] init];
    lbl.text = title;
    lbl.font = [UIFont systemFontOfSize:11];
    lbl.textColor = [UIColor secondaryLabelColor];

    [col addArrangedSubview:val];
    [col addArrangedSubview:lbl];
    return col;
}

- (UIView *)buildInputCard {
    UIView *card = [self makeCardContainer];

    UILabel *title = [[UILabel alloc] init];
    title.text = @"自定义显示余额";
    title.font = [UIFont systemFontOfSize:14 weight:UIFontWeightSemibold];
    title.textColor = [UIColor labelColor];
    title.translatesAutoresizingMaskIntoConstraints = NO;
    [card addSubview:title];

    _tf = [[UITextField alloc] init];
    _tf.placeholder = @"输入任意整数，如 1500254";
    _tf.keyboardType = UIKeyboardTypeNumberPad;
    _tf.font = [UIFont monospacedDigitSystemFontOfSize:18 weight:UIFontWeightMedium];
    _tf.backgroundColor = [UIColor tertiarySystemFillColor];
    _tf.layer.cornerRadius = 10;
    _tf.clearButtonMode = UITextFieldViewModeWhileEditing;
    _tf.leftView = [[UIView alloc] initWithFrame:CGRectMake(0, 0, 12, 1)];
    _tf.leftViewMode = UITextFieldViewModeAlways;
    _tf.translatesAutoresizingMaskIntoConstraints = NO;
    [card addSubview:_tf];

    UIButton *applyBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    [applyBtn setTitle:@"应用" forState:UIControlStateNormal];
    [applyBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    applyBtn.backgroundColor = [UIColor systemBlueColor];
    applyBtn.titleLabel.font = [UIFont systemFontOfSize:16 weight:UIFontWeightSemibold];
    applyBtn.layer.cornerRadius = 10;
    applyBtn.tag = 0;
    applyBtn.translatesAutoresizingMaskIntoConstraints = NO;
    [applyBtn addTarget:self action:@selector(onButton:) forControlEvents:UIControlEventTouchUpInside];
    [card addSubview:applyBtn];

    // 快捷预设胶囊
    UIStackView *presets = [[UIStackView alloc] init];
    presets.axis = UILayoutConstraintAxisHorizontal;
    presets.distribution = UIStackViewDistributionFillEqually;
    presets.spacing = 8;
    presets.translatesAutoresizingMaskIntoConstraints = NO;
    [card addSubview:presets];

    NSArray<NSString *> *presetTitles = @[@"10万", @"50万", @"100万", @"500万"];
    NSArray<NSNumber *> *presetValues = @[@100000, @500000, @1000000, @5000000];
    for (NSUInteger i = 0; i < presetTitles.count; i++) {
        UIButton *chip = [UIButton buttonWithType:UIButtonTypeSystem];
        [chip setTitle:presetTitles[i] forState:UIControlStateNormal];
        chip.titleLabel.font = [UIFont systemFontOfSize:12 weight:UIFontWeightMedium];
        chip.backgroundColor = [UIColor tertiarySystemFillColor];
        [chip setTitleColor:[UIColor labelColor] forState:UIControlStateNormal];
        chip.layer.cornerRadius = 8;
        chip.tag = 100 + (NSInteger)i;
        objc_setAssociatedObject(chip, @selector(onPresetTap:), presetValues[i], OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        [chip addTarget:self action:@selector(onPresetTap:) forControlEvents:UIControlEventTouchUpInside];
        [presets addArrangedSubview:chip];
    }

    [NSLayoutConstraint activateConstraints:@[
        [title.topAnchor constraintEqualToAnchor:card.topAnchor constant:14],
        [title.leadingAnchor constraintEqualToAnchor:card.leadingAnchor constant:16],

        [_tf.topAnchor constraintEqualToAnchor:title.bottomAnchor constant:10],
        [_tf.leadingAnchor constraintEqualToAnchor:card.leadingAnchor constant:16],
        [_tf.heightAnchor constraintEqualToConstant:44],

        [applyBtn.centerYAnchor constraintEqualToAnchor:_tf.centerYAnchor],
        [applyBtn.leadingAnchor constraintEqualToAnchor:_tf.trailingAnchor constant:10],
        [applyBtn.trailingAnchor constraintEqualToAnchor:card.trailingAnchor constant:-16],
        [applyBtn.widthAnchor constraintEqualToConstant:76],
        [applyBtn.heightAnchor constraintEqualToConstant:44],

        [presets.topAnchor constraintEqualToAnchor:_tf.bottomAnchor constant:10],
        [presets.leadingAnchor constraintEqualToAnchor:card.leadingAnchor constant:16],
        [presets.trailingAnchor constraintEqualToAnchor:card.trailingAnchor constant:-16],
        [presets.heightAnchor constraintEqualToConstant:30],
        [presets.bottomAnchor constraintEqualToAnchor:card.bottomAnchor constant:-14],
    ]];
    return card;
}

- (UIView *)buildSwitchGroupCard {
    UIView *card = [self makeCardContainer];
    UIStackView *v = [[UIStackView alloc] init];
    v.axis = UILayoutConstraintAxisVertical;
    v.translatesAutoresizingMaskIntoConstraints = NO;
    [card addSubview:v];

    UIView *enableRow = [self makeSwitchRowWithTitle:@"改写开关"
                                            subtitle:@"关闭后立即恢复显示真实余额"
                                           tintColor:[UIColor systemGreenColor]
                                              action:@selector(onEnableSwitchChanged:)
                                           outSwitch:&_enableSwitch];

    UIView *safeRow = [self makeSwitchRowWithTitle:@"安全模式"
                                          subtitle:@"开启后停用全部 Hook，保留当前配置，无需重启"
                                         tintColor:[UIColor systemOrangeColor]
                                            action:@selector(onSafeModeSwitchChanged:)
                                         outSwitch:&_safeModeSwitch];

    UIView *sepWrap = [[UIView alloc] init];
    UIView *sep = [self makeHairline];
    [sepWrap addSubview:sep];
    [NSLayoutConstraint activateConstraints:@[
        [sep.topAnchor constraintEqualToAnchor:sepWrap.topAnchor],
        [sep.bottomAnchor constraintEqualToAnchor:sepWrap.bottomAnchor],
        [sep.leadingAnchor constraintEqualToAnchor:sepWrap.leadingAnchor constant:16],
        [sep.trailingAnchor constraintEqualToAnchor:sepWrap.trailingAnchor],
    ]];

    [v addArrangedSubview:enableRow];
    [v addArrangedSubview:sepWrap];
    [v addArrangedSubview:safeRow];

    [NSLayoutConstraint activateConstraints:@[
        [v.topAnchor constraintEqualToAnchor:card.topAnchor],
        [v.bottomAnchor constraintEqualToAnchor:card.bottomAnchor],
        [v.leadingAnchor constraintEqualToAnchor:card.leadingAnchor],
        [v.trailingAnchor constraintEqualToAnchor:card.trailingAnchor],
    ]];
    return card;
}

- (UIView *)makeSwitchRowWithTitle:(NSString *)title
                          subtitle:(NSString *)subtitle
                         tintColor:(UIColor *)tint
                            action:(SEL)action
                         outSwitch:(UISwitch * __strong *)outSwitch {
    UIView *row = [[UIView alloc] init];
    row.translatesAutoresizingMaskIntoConstraints = NO;

    UILabel *t = [[UILabel alloc] init];
    t.text = title;
    t.font = [UIFont systemFontOfSize:15 weight:UIFontWeightMedium];
    t.translatesAutoresizingMaskIntoConstraints = NO;
    [row addSubview:t];

    UILabel *sub = [[UILabel alloc] init];
    sub.text = subtitle;
    sub.font = [UIFont systemFontOfSize:12];
    sub.textColor = [UIColor secondaryLabelColor];
    sub.numberOfLines = 0;
    sub.translatesAutoresizingMaskIntoConstraints = NO;
    [row addSubview:sub];

    UISwitch *sw = [[UISwitch alloc] init];
    sw.onTintColor = tint;
    sw.translatesAutoresizingMaskIntoConstraints = NO;
    [sw addTarget:self action:action forControlEvents:UIControlEventValueChanged];
    [row addSubview:sw];
    if (outSwitch) *outSwitch = sw;

    [NSLayoutConstraint activateConstraints:@[
        [sw.trailingAnchor constraintEqualToAnchor:row.trailingAnchor constant:-16],
        [sw.centerYAnchor constraintEqualToAnchor:row.centerYAnchor],
        [t.topAnchor constraintEqualToAnchor:row.topAnchor constant:12],
        [t.leadingAnchor constraintEqualToAnchor:row.leadingAnchor constant:16],
        [t.trailingAnchor constraintEqualToAnchor:sw.leadingAnchor constant:-12],
        [sub.topAnchor constraintEqualToAnchor:t.bottomAnchor constant:2],
        [sub.leadingAnchor constraintEqualToAnchor:row.leadingAnchor constant:16],
        [sub.trailingAnchor constraintEqualToAnchor:sw.leadingAnchor constant:-12],
        [sub.bottomAnchor constraintEqualToAnchor:row.bottomAnchor constant:-12],
    ]];
    return row;
}

- (UIView *)buildActionGroupCard {
    UIView *card = [self makeCardContainer];
    UIStackView *v = [[UIStackView alloc] init];
    v.axis = UILayoutConstraintAxisVertical;
    v.translatesAutoresizingMaskIntoConstraints = NO;
    [card addSubview:v];

    NSArray<NSDictionary *> *items = @[
        @{@"title": @"对齐基准（保持当前显示值，清零累计变化）", @"tag": @1, @"destructive": @NO},
        @{@"title": @"查看机器码（后台绑定用）", @"tag": @4, @"destructive": @NO},
        @{@"title": @"查看运行日志", @"tag": @3, @"destructive": @NO},
        @{@"title": @"重置全部配置", @"tag": @2, @"destructive": @YES},
    ];

    for (NSUInteger i = 0; i < items.count; i++) {
        NSDictionary *item = items[i];
        UIButton *btn = [UIButton buttonWithType:UIButtonTypeSystem];
        [btn setTitle:item[@"title"] forState:UIControlStateNormal];
        btn.titleLabel.font = [UIFont systemFontOfSize:15 weight:UIFontWeightRegular];
        btn.contentHorizontalAlignment = UIControlContentHorizontalAlignmentLeft;
        btn.contentEdgeInsets = UIEdgeInsetsMake(0, 16, 0, 16);
        btn.tag = [item[@"tag"] integerValue];
        if ([item[@"destructive"] boolValue]) {
            [btn setTitleColor:[UIColor systemRedColor] forState:UIControlStateNormal];
        } else {
            [btn setTitleColor:[UIColor systemBlueColor] forState:UIControlStateNormal];
        }
        [btn addTarget:self action:@selector(onButton:) forControlEvents:UIControlEventTouchUpInside];
        [btn.heightAnchor constraintEqualToConstant:48].active = YES;
        [v addArrangedSubview:btn];

        if (i + 1 < items.count) {
            UIView *sepWrap = [[UIView alloc] init];
            UIView *sep = [self makeHairline];
            [sepWrap addSubview:sep];
            [NSLayoutConstraint activateConstraints:@[
                [sep.topAnchor constraintEqualToAnchor:sepWrap.topAnchor],
                [sep.bottomAnchor constraintEqualToAnchor:sepWrap.bottomAnchor],
                [sep.leadingAnchor constraintEqualToAnchor:sepWrap.leadingAnchor constant:16],
                [sep.trailingAnchor constraintEqualToAnchor:sepWrap.trailingAnchor],
            ]];
            [v addArrangedSubview:sepWrap];
        }
    }

    [NSLayoutConstraint activateConstraints:@[
        [v.topAnchor constraintEqualToAnchor:card.topAnchor],
        [v.bottomAnchor constraintEqualToAnchor:card.bottomAnchor],
        [v.leadingAnchor constraintEqualToAnchor:card.leadingAnchor],
        [v.trailingAnchor constraintEqualToAnchor:card.trailingAnchor],
    ]];
    return card;
}

- (void)refresh {
    BTPrefsSnapshot *s = [[BTPrefs shared] snapshot];

    // 状态胶囊样式
    if (s.safeMode) {
        _badgeLabel.text = @"● 安全模式";
        _badgeLabel.textColor = [UIColor systemOrangeColor];
        _badgeBg.backgroundColor = [[UIColor systemOrangeColor] colorWithAlphaComponent:0.15];
    } else if (s.enabled && s.hasBaseDisplay) {
        _badgeLabel.text = @"● 改写生效中";
        _badgeLabel.textColor = [UIColor systemGreenColor];
        _badgeBg.backgroundColor = [[UIColor systemGreenColor] colorWithAlphaComponent:0.15];
    } else {
        _badgeLabel.text = @"● 未开启";
        _badgeLabel.textColor = [UIColor secondaryLabelColor];
        _badgeBg.backgroundColor = [UIColor tertiarySystemFillColor];
    }

    // 同步来源与时间
    if (s.lastSyncSource.length > 0 && s.lastSyncDate) {
        static NSDateFormatter *fmt = nil;
        static dispatch_once_t once;
        dispatch_once(&once, ^{
            fmt = [[NSDateFormatter alloc] init];
            fmt.dateFormat = @"HH:mm:ss";
        });
        _syncLabel.text = [NSString stringWithFormat:@"已同步 · %@ %@", s.lastSyncSource, [fmt stringFromDate:s.lastSyncDate]];
    } else {
        _syncLabel.text = @"等待余额同步…";
    }

    // 主数字
    if (s.hasLastReal || (s.enabled && !s.safeMode && s.hasBaseDisplay)) {
        _heroNumber.text = [BTSettingsVC formatNumber:s.computedDisplay];
    } else {
        _heroNumber.text = @"--";
    }

    // 三列指标
    _realValLabel.text = s.hasLastReal ? [BTSettingsVC formatNumber:s.lastReal] : @"未获取";
    _baseRealValLabel.text = s.hasBaseReal ? [BTSettingsVC formatNumber:s.baseReal] : @"未设置";
    if (s.hasDelta) {
        _deltaValLabel.text = [NSString stringWithFormat:@"%@%lld", (s.delta >= 0 ? @"+" : @""), s.delta];
        if (s.delta > 0) {
            _deltaValLabel.textColor = [UIColor systemGreenColor];
        } else if (s.delta < 0) {
            _deltaValLabel.textColor = [UIColor systemRedColor];
        } else {
            _deltaValLabel.textColor = [UIColor labelColor];
        }
    } else {
        _deltaValLabel.text = @"--";
        _deltaValLabel.textColor = [UIColor secondaryLabelColor];
    }

    [_enableSwitch setOn:s.enabled animated:NO];
    [_safeModeSwitch setOn:s.safeMode animated:NO];
}

- (void)onDismissKeyboard {
    [self.view endEditing:YES];
}

- (void)onPresetTap:(UIButton *)sender {
    NSNumber *n = objc_getAssociatedObject(sender, @selector(onPresetTap:));
    if (!n) return;
    _tf.text = [NSString stringWithFormat:@"%lld", [n longLongValue]];
}

- (void)onEnableSwitchChanged:(UISwitch *)sw {
    [[BTPrefs shared] setEnabled:sw.isOn];
    [self refresh];
}

- (void)onSafeModeSwitchChanged:(UISwitch *)sw {
    BOOL on = sw.isOn;
    [[BTPrefs shared] setSafeMode:on];
    [self refresh];
    [self toast:(on
        ? @"已开启安全模式：全部 Hook 已即时暂停，配置已保留。"
        : @"已关闭安全模式：全部 Hook 已即时恢复生效。")];
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
            ? [NSString stringWithFormat:@"已设置显示值 %@（基准真实 %@）",
               [BTSettingsVC formatNumber:v], [BTSettingsVC formatNumber:s.baseReal]]
            : [NSString stringWithFormat:@"已设置显示值 %@（待首次获取真实余额后自动锁定基准）",
               [BTSettingsVC formatNumber:v]];
        if (s.safeMode) {
            msg = [msg stringByAppendingString:@"\n注意：当前处于安全模式，关闭安全模式后立即生效。"];
        }
        [self toast:msg];
    } else if (sender.tag == 1) {
        if ([p realignBaseToCurrentReal]) {
            BTPrefsSnapshot *s = [p snapshot];
            _tf.text = [NSString stringWithFormat:@"%lld", s.baseDisplay];
            [self refresh];
            [self toast:[NSString stringWithFormat:@"已对齐基准：基准显示 %@，基准真实 %@",
                         [BTSettingsVC formatNumber:s.baseDisplay],
                         [BTSettingsVC formatNumber:s.baseReal]]];
        } else {
            [self toast:@"请先获取真实余额并设置显示值后再对齐基准。"];
        }
    } else if (sender.tag == 2) {
        [p reset];
        _tf.text = @"";
        [self refresh];
        [self toast:@"已重置全部配置并关闭安全模式。"];
    } else if (sender.tag == 3) {
        BTLogVC *vc = [[BTLogVC alloc] init];
        [self.navigationController pushViewController:vc animated:YES];
    } else if (sender.tag == 4) {
        [self showMachineCode];
    }
}

// ============================================================
// 机器码（后台绑定用）
// ============================================================
- (void)showMachineCode {
    char *rawId = jjv_device_id();
    NSString *deviceId = rawId ? [NSString stringWithUTF8String:rawId] : nil;
    if (rawId) jjv_free(rawId);

    BOOL authorized = jjv_is_authorized() ? YES : NO;

    NSString *display = deviceId.length > 0 ? deviceId : @"(设备身份未就绪，请先触发一次网络请求)";

    // 详情 JSON（含 device_prefix / protocol / build）
    char *rawInfo = jjv_device_info_json();
    NSString *infoJSON = rawInfo ? [NSString stringWithUTF8String:rawInfo] : @"{}";
    if (rawInfo) jjv_free(rawInfo);

    // 美化 JSON
    NSData *jd = [infoJSON dataUsingEncoding:NSUTF8StringEncoding];
    if (jd) {
        id obj = [NSJSONSerialization JSONObjectWithData:jd options:0 error:nil];
        if (obj) {
            NSData *pretty = [NSJSONSerialization dataWithJSONObject:obj
                                                             options:NSJSONWritingPrettyPrinted
                                                               error:nil];
            if (pretty) {
                infoJSON = [[NSString alloc] initWithData:pretty encoding:NSUTF8StringEncoding] ?: infoJSON;
            }
        }
    }

    NSString *title = [NSString stringWithFormat:@"机器码（%@）",
                       authorized ? @"已授权" : @"未授权"];

    UIAlertController *a = [UIAlertController alertControllerWithTitle:title
                                                              message:display
                                                       preferredStyle:UIAlertControllerStyleAlert];

    // 复制纯机器码
    if (deviceId.length > 0) {
        [a addAction:[UIAlertAction actionWithTitle:@"复制机器码"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *act) {
            [UIPasteboard generalPasteboard].string = deviceId;
            [self toast:@"机器码已复制到剪贴板"];
        }]];
    }

    // 复制完整 JSON
    [a addAction:[UIAlertAction actionWithTitle:@"复制完整信息(JSON)"
                                          style:UIAlertActionStyleDefault
                                        handler:^(UIAlertAction *act) {
        [UIPasteboard generalPasteboard].string = infoJSON;
        [self toast:@"完整信息已复制"];
    }]];

    // 查看完整 JSON
    [a addAction:[UIAlertAction actionWithTitle:@"查看完整信息"
                                          style:UIAlertActionStyleDefault
                                        handler:^(UIAlertAction *act) {
        UIAlertController *b = [UIAlertController alertControllerWithTitle:@"设备信息"
                                                                   message:infoJSON
                                                            preferredStyle:UIAlertControllerStyleAlert];
        [b addAction:[UIAlertAction actionWithTitle:@"复制" style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *x) {
            [UIPasteboard generalPasteboard].string = infoJSON;
        }]];
        [b addAction:[UIAlertAction actionWithTitle:@"关闭" style:UIAlertActionStyleCancel handler:nil]];
        [self presentViewController:b animated:YES completion:nil];
    }]];

    [a addAction:[UIAlertAction actionWithTitle:@"关闭" style:UIAlertActionStyleCancel handler:nil]];

    [self presentViewController:a animated:YES completion:nil];
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
static NSData *btPatchHomepageJSONData(NSData *data) {
    if (!data || data.length < 2) return nil;
    id jsonObj = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
    if (!jsonObj) return nil;

    BTPrefsSnapshot *snap = [[BTPrefs shared] snapshot];
    if (snap.safeMode) return nil;

    BOOL shouldPatch = (snap.enabled && snap.hasBaseDisplay);
    int64_t detectedReal = -1;
    BOOL didChange = NO;

    id patchedObj = BTPatchWalletJSONObject(jsonObj,
                                            snap.hasLastReal ? snap.lastReal : 0,
                                            snap.hasLastReal,
                                            snap.computedDisplay,
                                            shouldPatch,
                                            &detectedReal,
                                            &didChange);

    if (detectedReal >= 0) {
        int64_t newDisp = 0;
        BOOL newPatch = NO;
        [[BTPrefs shared] recordRealBalance:detectedReal
                                     source:@"钱包首页"
                                 outDisplay:&newDisp
                                shouldPatch:&newPatch];
        // 若此前尚未捕获过真实余额，刚捕获后重算一次显示值再补改
        if (!snap.hasLastReal && newPatch && !didChange) {
            patchedObj = BTPatchWalletJSONObject(jsonObj,
                                                 detectedReal,
                                                 YES,
                                                 newDisp,
                                                 YES,
                                                 NULL,
                                                 &didChange);
        }
    }

    if (!didChange || !patchedObj || ![NSJSONSerialization isValidJSONObject:patchedObj]) {
        return nil;
    }

    NSData *outData = [NSJSONSerialization dataWithJSONObject:patchedObj options:0 error:nil];
    if (outData) {
        BTLOG(@"[homepage] JSON 改写成功 %luB -> %luB", (unsigned long)data.length, (unsigned long)outData.length);
    }
    return outData;
}

static NSData *btProtocolPatch(NSURL *url, NSData *data) {
    if (!url || !data || data.length < 4) return nil;
    if (!jjv_is_authorized()) return nil;
    if ([[BTPrefs shared] snapshot].safeMode) return nil;

    NSString *path = (url.path.length > 0 ? url.path : (url.absoluteString ?: @"")).lowercaseString;

    // 1. 钱包首页（CJPay / Lynx JSON）
    if ([path containsString:@"wallet/core/v1/homepage"] ||
        [path containsString:@"caijing/wallet"] ||
        [path containsString:@"wallet/homepage"]) {
        return btPatchHomepageJSONData(data);
    }

    // 2. 礼物面板（Protobuf）
    if (![path containsString:@"/webcast/wallet/info"]) return nil;

    const uint8_t *buf = (const uint8_t *)data.bytes;
    size_t len = (size_t)data.length;

    int64_t realVal = 0;
    if (!bt_read_wallet_real_balance(buf, len, &realVal)) {
        BTLOG(@"[patch] 读真实余额失败 (%luB)", (unsigned long)len);
        return nil;
    }

    int64_t display = 0;
    BOOL shouldPatch = NO;
    [[BTPrefs shared] recordRealBalance:realVal
                                 source:@"网络接口"
                             outDisplay:&display
                            shouldPatch:&shouldPatch];

    if (!shouldPatch) {
        BTLOG(@"[patch] 真实=%lld 不改写（未启用或未设置）", realVal);
        return nil;
    }

    uint8_t *outBuf = NULL;
    size_t outLen = 0;
    if (!bt_patch_wallet_info_buf(buf, len, display, &outBuf, &outLen)) {
        BTLOG(@"[patch] protobuf 改写失败");
        return nil;
    }

    NSData *result = [NSData dataWithBytesNoCopy:outBuf length:outLen freeWhenDone:YES];

    BTLOG(@"[patch] 真实=%lld 显示=%lld  %luB -> %luB",
          realVal, display, (unsigned long)len, (unsigned long)outLen);

    return result;
}

// ============================================================
// 方案 2（钱包 Model / Manager 层）回调桥接
// ============================================================
static void btWalletRecordReal(int64_t realVal, NSString *source) {
    [[BTPrefs shared] recordRealBalance:realVal
                                 source:(source ?: @"直播钱包")
                             outDisplay:NULL
                            shouldPatch:NULL];
}

static BOOL btWalletGetDisplay(int64_t *outDisplay, int64_t *outLastReal) {
    BTPrefsSnapshot *s = [[BTPrefs shared] snapshot];
    if (outLastReal) *outLastReal = s.hasLastReal ? s.lastReal : 0;
    if (s.safeMode || !s.enabled || !s.hasBaseDisplay) return NO;
    if (outDisplay) *outDisplay = s.computedDisplay;
    return YES;
}

// ============================================================
// 入口
// ============================================================
__attribute__((constructor))
static void BTInit(void) {
    // ============================================================
    // 崩溃自动降级保护
    // ============================================================
    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,
                                                          NSUserDomainMask, YES) firstObject];
    NSString *flag = [docs stringByAppendingPathComponent:@"BT_booting_v5.flag"];
    BOOL crashed = [[NSFileManager defaultManager] fileExistsAtPath:flag];
    if (crashed) {
        [[NSUserDefaults standardUserDefaults] setBool:YES forKey:kKeySafeMode];
        [[NSFileManager defaultManager] removeItemAtPath:flag error:nil];
    }
    [[NSFileManager defaultManager] createFileAtPath:flag contents:[NSData data] attributes:nil];

    BOOL safeMode = [[BTPrefs shared] snapshot].safeMode;

    BTLOG(@"================ 加载 (v7+SafeMode+SyncUI) ================");
    if (crashed) BTLOG(@"⚠ 检测到上次崩溃 → 已自动开启安全模式");
    BTLOG(@"安全模式: %@", safeMode ? @"开" : @"关");
    BTLOG(@"三指长按 1 秒 → 打开设置");
    BTLOG(@"★ 卡密授权状态: %@ (protocol=%s)", jjv_is_authorized() ? @"已授权" : @"未授权", "gogo-v2");

    // 绑定回调（即使处于安全模式，先绑定好回调以便随时关闭安全模式即时生效）
    BTSetWalletCallbacks(btWalletRecordReal, btWalletGetDisplay);
    BTSetTTNetPatchFunc(btProtocolPatch);

    // 兜底网络层
    BTInstallURLProtocol();
    BTSetPatchFunc(btProtocolPatch);
    [BTNet install];

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        // ★★★ 卡密验证：未授权 → 弹窗，功能全部关闭 ★★★
        if (!jjv_is_authorized()) {
            BTLOG(@"[AUTH] 未授权，弹出卡密验证窗口");
            jjv_show_popup();
        } else {
            BTLOG(@"[AUTH] 已授权 (gogo-v2)，功能已启用");
        }

        if (!safeMode) {
            BTInstallWalletModelHook();
            BTInstallTTNetProbe();
            BTSetWalletHookActive(YES);
            BTSetTTNetActive(YES);
        } else {
            BTSetWalletHookActive(NO);
            BTSetTTNetActive(NO);
        }
        [BTGesture install];
        // 初始化完成 → 删 flag（表示这次没崩）
        [[NSFileManager defaultManager] removeItemAtPath:flag error:nil];
        BTLOG(@"初始化完成（已清除启动标记）");
    });
}
