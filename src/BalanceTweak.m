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
// 编译（GitHub Actions / macOS）：
//   xcrun clang -dynamiclib -arch arm64e -arch arm64 \
//     -miphoneos-version-min=14.0 \
//     -isysroot $(xcrun --sdk iphoneos --show-sdk-path) \
//     -fobjc-arc \
//     -framework UIKit -framework Foundation \
//     -o BalanceTweak.dylib BalanceTweak.m
//   ldid -S BalanceTweak.dylib
// ============================================================

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <stdio.h>

// ============================================================
// 日志
// ============================================================
#define BTLOG(fmt, ...) NSLog(@"[BalanceTweak] " fmt, ##__VA_ARGS__)

// ============================================================
// 配置
// ============================================================
static NSString *const kKeyEnabled     = @"BT_enabled";
static NSString *const kKeyBaseDisplay = @"BT_baseDisplay";
static NSString *const kKeyBaseReal    = @"BT_baseReal";
static NSString *const kKeyLastReal    = @"BT_lastReal";

// ============================================================
// 配置管理
// ============================================================
@interface BTPrefs : NSObject
@property (class, readonly) BTPrefs *shared;
@property (nonatomic, assign) BOOL enabled;
@property (nonatomic, assign) long long baseDisplay;
@property (nonatomic, assign) long long baseReal;
@property (nonatomic, assign) long long lastReal;
@property (nonatomic, readonly) long long computedDisplay;
- (void)reset;
@end

@implementation BTPrefs

+ (BTPrefs *)shared {
    static BTPrefs *inst;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ inst = [[BTPrefs alloc] init]; });
    return inst;
}

- (NSUserDefaults *)d { return [NSUserDefaults standardUserDefaults]; }

- (BOOL)enabled { return [[self d] boolForKey:kKeyEnabled]; }
- (void)setEnabled:(BOOL)v { [[self d] setBool:v forKey:kKeyEnabled]; [[self d] synchronize]; }

- (long long)baseDisplay { return [[self d] integerForKey:kKeyBaseDisplay]; }
- (void)setBaseDisplay:(long long)v { [[self d] setObject:@(v) forKey:kKeyBaseDisplay]; [[self d] synchronize]; }

- (long long)baseReal { return [[self d] integerForKey:kKeyBaseReal]; }
- (void)setBaseReal:(long long)v { [[self d] setObject:@(v) forKey:kKeyBaseReal]; [[self d] synchronize]; }

- (long long)lastReal { return [[self d] integerForKey:kKeyLastReal]; }
- (void)setLastReal:(long long)v { [[self d] setObject:@(v) forKey:kKeyLastReal]; [[self d] synchronize]; }

- (long long)computedDisplay {
    long long bd = self.baseDisplay;
    long long br = self.baseReal;
    long long lr = self.lastReal;
    if (!self.enabled) return lr;
    if (bd == 0) return lr;
    if (br == 0) return bd;
    long long v = bd + (lr - br);
    return v < 0 ? 0 : v;
}

- (void)reset {
    NSUserDefaults *d = [self d];
    [d removeObjectForKey:kKeyBaseDisplay];
    [d removeObjectForKey:kKeyBaseReal];
    [d removeObjectForKey:kKeyLastReal];
    [d synchronize];
}

@end

// ============================================================
// protobuf 工具
// ============================================================
// 返回新的 offset（读取后），失败返回原 offset
static NSUInteger btReadVarint(const uint8_t *buf, NSUInteger len, NSUInteger pos,
                                unsigned long long *out) {
    unsigned long long v = 0;
    int shift = 0;
    NSUInteger i = pos;
    while (i < len) {
        uint8_t b = buf[i];
        i++;
        v |= ((unsigned long long)(b & 0x7F)) << shift;
        if (!(b & 0x80)) {
            *out = v;
            return i;
        }
        shift += 7;
        if (shift > 63) break;
    }
    return pos;
}

static NSMutableData *btWriteVarint(unsigned long long v) {
    NSMutableData *d = [NSMutableData dataWithCapacity:10];
    while (1) {
        uint8_t b = v & 0x7F;
        v >>= 7;
        if (v) {
            uint8_t x = b | 0x80;
            [d appendBytes:&x length:1];
        } else {
            [d appendBytes:&b length:1];
            break;
        }
    }
    return d;
}

// ============================================================
// wallet/info 改写
// ============================================================
// 原始结构（27 字节）：
//   0a 07 [28 <ts varint>]                        field1 {field5: 时间戳}
//   12 10                                         field2 (16 字节)
//     0a 0e                                       field2.field1 (14 字节)
//       10 <uid varint>                           field 2: UID
//       18 <b1 01>                                field 3: 余额
//       70 <ea 0d>                                field14: 余额 × 10
//
// 策略：
//   1. 定位 root.field2 的 (tagStart, lenStart, bodyStart, bodyEnd)
//   2. 定位 field2.field1 的 (tagStart, lenStart, bodyStart, bodyEnd)
//   3. 解析 field1 body 的所有字段，重建时替换 field3 和 field14
//   4. 逐层重算长度
// ============================================================

typedef struct {
    NSUInteger tagStart;    // tag 开始
    NSUInteger lenStart;    // len 开始（wire==2 时有效）
    NSUInteger bodyStart;   // body 开始
    NSUInteger bodyEnd;     // body 结束
    BOOL valid;
} BTRange;

static BTRange btFindField(const uint8_t *buf, NSUInteger start, NSUInteger end,
                            NSUInteger targetField) {
    BTRange r = {0, 0, 0, 0, NO};
    NSUInteger i = start;
    while (i < end) {
        NSUInteger tagStart = i;
        unsigned long long tag = 0;
        NSUInteger j = btReadVarint(buf, end, i, &tag);
        if (j == i) break;
        NSUInteger fieldNo = (NSUInteger)(tag >> 3);
        NSUInteger wire = (NSUInteger)(tag & 7);
        i = j;

        if (wire == 0) {
            unsigned long long v = 0;
            NSUInteger k = btReadVarint(buf, end, i, &v);
            if (k == i) break;
            i = k;
        } else if (wire == 2) {
            unsigned long long ln = 0;
            NSUInteger lenStart = i;
            NSUInteger k = btReadVarint(buf, end, i, &ln);
            if (k == i) break;
            NSUInteger bodyStart = k;
            NSUInteger bodyEnd = bodyStart + (NSUInteger)ln;
            if (bodyEnd > end) break;
            if (fieldNo == targetField && !r.valid) {
                r.tagStart = tagStart;
                r.lenStart = lenStart;
                r.bodyStart = bodyStart;
                r.bodyEnd = bodyEnd;
                r.valid = YES;
                return r;   // 找到即返回
            }
            i = bodyEnd;
        } else if (wire == 1) {
            if (i + 8 > end) break;
            i += 8;
        } else if (wire == 5) {
            if (i + 4 > end) break;
            i += 4;
        } else {
            break;
        }
    }
    return r;
}

// 重建 field1 body：替换 field3 和 field14
static NSData *btRebuildField1(NSData *f1Body, long long newDisplay, BOOL *didChange) {
    const uint8_t *buf = f1Body.bytes;
    NSUInteger len = f1Body.length;
    NSMutableData *out = [NSMutableData dataWithCapacity:len + 16];
    NSUInteger i = 0;
    BOOL changed = NO;

    while (i < len) {
        NSUInteger tagStart = i;
        unsigned long long tag = 0;
        NSUInteger j = btReadVarint(buf, len, i, &tag);
        if (j == i) {
            // 解析失败，原样复制剩余
            [out appendBytes:(buf + i) length:(len - i)];
            break;
        }
        NSUInteger fieldNo = (NSUInteger)(tag >> 3);
        NSUInteger wire = (NSUInteger)(tag & 7);

        if (wire == 0) {
            unsigned long long v = 0;
            NSUInteger k = btReadVarint(buf, len, j, &v);
            if (k == j) {
                [out appendBytes:(buf + i) length:(len - i)];
                break;
            }

            // 复制 tag
            [out appendBytes:(buf + tagStart) length:(j - tagStart)];

            if (fieldNo == 3) {
                [out appendData:btWriteVarint((unsigned long long)newDisplay)];
                changed = YES;
            } else if (fieldNo == 14) {
                [out appendData:btWriteVarint((unsigned long long)(newDisplay * 10))];
                changed = YES;
            } else {
                [out appendBytes:(buf + j) length:(k - j)];
            }
            i = k;
        } else if (wire == 2) {
            unsigned long long ln = 0;
            NSUInteger k = btReadVarint(buf, len, j, &ln);
            if (k == j) {
                [out appendBytes:(buf + i) length:(len - i)];
                break;
            }
            NSUInteger bodyEnd = k + (NSUInteger)ln;
            if (bodyEnd > len) {
                [out appendBytes:(buf + i) length:(len - i)];
                break;
            }
            [out appendBytes:(buf + tagStart) length:(bodyEnd - tagStart)];
            i = bodyEnd;
        } else if (wire == 1) {
            NSUInteger end2 = j + 8;
            if (end2 > len) {
                [out appendBytes:(buf + i) length:(len - i)];
                break;
            }
            [out appendBytes:(buf + tagStart) length:(end2 - tagStart)];
            i = end2;
        } else if (wire == 5) {
            NSUInteger end2 = j + 4;
            if (end2 > len) {
                [out appendBytes:(buf + i) length:(len - i)];
                break;
            }
            [out appendBytes:(buf + tagStart) length:(end2 - tagStart)];
            i = end2;
        } else {
            [out appendBytes:(buf + i) length:(len - i)];
            break;
        }
    }

    *didChange = changed;
    return out;
}

// 主改写函数
static NSData *btPatchWalletInfo(NSData *data) {
    BTPrefs *p = [BTPrefs shared];
    if (!p.enabled) return data;

    const uint8_t *buf = data.bytes;
    NSUInteger len = data.length;
    if (len < 8) return data;

    // 1. 找 root.field2
    BTRange f2 = btFindField(buf, 0, len, 2);
    if (!f2.valid) return data;

    // 2. 在 field2 body 里找 field1
    BTRange f1 = btFindField(buf, f2.bodyStart, f2.bodyEnd, 1);
    if (!f1.valid) return data;

    NSData *f1Body = [data subdataWithRange:NSMakeRange(f1.bodyStart, f1.bodyEnd - f1.bodyStart)];

    // 3. 先读真实余额（field3）
    long long realVal = 0;
    {
        BTRange f3 = btFindField(f1Body.bytes, 0, f1Body.length, 3);
        if (f3.valid) {
            unsigned long long v = 0;
            btReadVarint(f1Body.bytes, f1Body.length, f3.bodyStart, &v);
            realVal = (long long)v;
        }
    }
    if (realVal > 0) {
        [p setLastReal:realVal];
    }

    long long disp = [p computedDisplay];

    // 4. 重建 field1 body
    BOOL changed = NO;
    NSData *newF1 = btRebuildField1(f1Body, disp, &changed);
    if (!changed) return data;

    // 5. 重建 field2 body
    NSMutableData *newF2 = [NSMutableData data];
    // field2 body 里 field1 之前的部分
    [newF2 appendData:[data subdataWithRange:NSMakeRange(f2.bodyStart, f1.tagStart - f2.bodyStart)]];
    // field1 tag
    [newF2 appendData:[data subdataWithRange:NSMakeRange(f1.tagStart, f1.lenStart - f1.tagStart)]];
    // field1 新长度
    [newF2 appendData:btWriteVarint(newF1.length)];
    // field1 新 body
    [newF2 appendData:newF1];
    // field2 body 里 field1 之后的部分
    if (f1.bodyEnd < f2.bodyEnd) {
        [newF2 appendData:[data subdataWithRange:NSMakeRange(f1.bodyEnd, f2.bodyEnd - f1.bodyEnd)]];
    }

    // 6. 重建 root
    NSMutableData *out = [NSMutableData data];
    [out appendData:[data subdataWithRange:NSMakeRange(0, f2.tagStart)]];
    [out appendData:[data subdataWithRange:NSMakeRange(f2.tagStart, f2.lenStart - f2.tagStart)]];
    [out appendData:btWriteVarint(newF2.length)];
    [out appendData:newF2];
    if (f2.bodyEnd < len) {
        [out appendData:[data subdataWithRange:NSMakeRange(f2.bodyEnd, len - f2.bodyEnd)]];
    }

    BTLOG(@"改写: 真实=%lld 显示=%lld  %luB -> %luB",
          realVal, disp, (unsigned long)len, (unsigned long)out.length);

    return out;
}

// ============================================================
// 设置界面
// ============================================================
@interface BTSettingsVC : UIViewController
@end

@implementation BTSettingsVC {
    UILabel *_status;
    UITextField *_tf;
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

    BTPrefs *p = [BTPrefs shared];

    _status = [[UILabel alloc] init];
    _status.numberOfLines = 0;
    _status.font = [UIFont monospacedSystemFontOfSize:13 weight:UIFontWeightRegular];
    _status.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:_status];

    _tf = [[UITextField alloc] init];
    _tf.placeholder = @"输入显示数字，如 1500254";
    _tf.keyboardType = UIKeyboardTypeNumberPad;
    _tf.borderStyle = UITextBorderStyleRoundedRect;
    _tf.translatesAutoresizingMaskIntoConstraints = NO;
    if (p.baseDisplay > 0) _tf.text = [NSString stringWithFormat:@"%lld", p.baseDisplay];
    [self.view addSubview:_tf];

    NSMutableArray *btns = [NSMutableArray array];
    NSArray *titles = @[@"应用（以当前真实余额为基准）",
                        p.enabled ? @"关闭改写" : @"开启改写",
                        @"重置"];

    for (NSString *t in titles) {
        UIButton *b = [UIButton buttonWithType:UIButtonTypeSystem];
        [b setTitle:t forState:UIControlStateNormal];
        b.titleLabel.font = [UIFont systemFontOfSize:15];
        b.translatesAutoresizingMaskIntoConstraints = NO;
        b.tag = [btns count];
        [b addTarget:self action:@selector(onButton:) forControlEvents:UIControlEventTouchUpInside];
        if (b.tag == 2) [b setTitleColor:[UIColor systemRedColor] forState:UIControlStateNormal];
        [self.view addSubview:b];
        [btns addObject:b];
    }

    UILayoutGuide *g = self.view.safeAreaLayoutGuide;
    NSMutableArray *cs = [NSMutableArray array];
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

    [self refresh];
}

- (void)refresh {
    BTPrefs *p = [BTPrefs shared];
    _status.text = [NSString stringWithFormat:
        @"真实余额:   %lld\n"
        @"基准真实:   %lld\n"
        @"基准显示:   %lld\n"
        @"当前显示:   %lld\n"
        @"改写开关:   %@",
        p.lastReal, p.baseReal, p.baseDisplay, p.computedDisplay,
        p.enabled ? @"开" : @"关"];
}

- (void)onButton:(UIButton *)sender {
    BTPrefs *p = [BTPrefs shared];

    if (sender.tag == 0) {
        // 应用
        if (_tf.text.length == 0) return;
        long long v = [_tf.text longLongValue];
        if (v <= 0) return;
        p.baseDisplay = v;
        p.baseReal = p.lastReal;
        p.enabled = YES;
        [self refresh];
        [self toast:[NSString stringWithFormat:@"已设置显示值 %lld（基准真实 %lld）", v, p.lastReal]];
    } else if (sender.tag == 1) {
        p.enabled = !p.enabled;
        [self reloadUI];
    } else if (sender.tag == 2) {
        [p reset];
        _tf.text = @"";
        [self reloadUI];
    }
}

- (void)reloadUI {
    for (UIView *v in self.view.subviews) [v removeFromSuperview];
    [self viewDidLoad];
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
// 手势
// ============================================================
@interface BTGesture : NSObject
+ (void)install;
@end

@implementation BTGesture

+ (UIWindow *)keyWindow {
    if (@available(iOS 13.0, *)) {
        for (UIScene *s in [UIApplication sharedApplication].connectedScenes) {
            if (![s isKindOfClass:[UIWindowScene class]]) continue;
            for (UIWindow *w in ((UIWindowScene *)s).windows) {
                if (w.isKeyWindow) return w;
            }
        }
    }
    return [UIApplication sharedApplication].keyWindow;
}

+ (void)install {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        [[NSNotificationCenter defaultCenter]
            addObserverForName:UIApplicationDidBecomeActiveNotification
                        object:nil
                         queue:[NSOperationQueue mainQueue]
                    usingBlock:^(NSNotification *n) {
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
            if (lp0.numberOfTouchesRequired == 3) {
                return;
            }
        }
    }

    UILongPressGestureRecognizer *lp =
        [[UILongPressGestureRecognizer alloc] initWithTarget:self action:@selector(onLP:)];
    lp.numberOfTouchesRequired = 3;
    lp.minimumPressDuration = 1.0;
    lp.cancelsTouchesInView = NO;
    [w addGestureRecognizer:lp];

    BTLOG(@"三指长按手势已安装");
}

+ (void)onLP:(UILongPressGestureRecognizer *)g {
    if (g.state != UIGestureRecognizerStateBegan) return;

    BTLOG(@"三指长按触发");

    UIWindow *w = [self keyWindow];
    UIViewController *root = w.rootViewController;
    if (!root) return;
    while (root.presentedViewController) root = root.presentedViewController;

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

@interface BTNet : NSObject
+ (void)install;
@end

@implementation BTNet

+ (void)install {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        [self hookDataTaskWithCompletion];
        [self hookDelegate];
    });
}

+ (void)hookDataTaskWithCompletion {
    Class cls = NSClassFromString(@"NSURLSession");
    if (!cls) return;

    SEL sel = @selector(dataTaskWithRequest:completionHandler:);
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) {
        BTLOG(@"NSURLSession 没有 dataTaskWithRequest:completionHandler:");
        return;
    }

    IMP orig = method_getImplementation(m);
    __block IMP origImp = orig;
    __block SEL origSel = sel;

    id block = ^id(id self_, NSURLRequest *req, void (^completion)(NSData *, NSURLResponse *, NSError *)) {
        NSURL *url = req.URL;
        NSString *path = url.path ?: @"";

        typedef id (*Fn)(id, SEL, NSURLRequest *, void (^)(NSData *, NSURLResponse *, NSError *));
        Fn fn = (Fn)origImp;

        if (![path containsString:kWIPath] || ![BTPrefs shared].enabled) {
            return fn(self_, origSel, req, completion);
        }

        BTLOG(@"拦截 wallet/info");

        void (^wrapped)(NSData *, NSURLResponse *, NSError *) =
            ^(NSData *data, NSURLResponse *resp, NSError *err) {
            NSData *out = data;
            if (data && data.length > 0 && !err) {
                @try {
                    out = btPatchWalletInfo(data);
                } @catch (NSException *e) {
                    BTLOG(@"patch 异常: %@", e);
                }
            }
            if (completion) completion(out, resp, err);
        };

        return fn(self_, origSel, req, wrapped);
    };

    IMP newImp = imp_implementationWithBlock(block);
    method_setImplementation(m, newImp);
    BTLOG(@"hooked NSURLSession dataTaskWithRequest:completionHandler:");
}

// hook NSURLSessionTaskDelegate 的 didCompleteWithError（异步请求走这里）
+ (void)hookDelegate {
    // 抖音多数走 TTNet，不做深度 hook，靠上面的 completion 覆盖标准路径
    BTLOG(@"delegate hook 跳过（依赖 completion 路径）");
}

@end

// ============================================================
// 入口
// ============================================================
__attribute__((constructor))
static void BTInit(void) {
    BTLOG(@"================ 加载 ================");
    BTLOG(@"三指长按 1 秒 → 打开设置");

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        [BTGesture install];
        [BTNet install];
        BTLOG(@"初始化完成");
    });
}
