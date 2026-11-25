//
// BTLogVC.m —— 日志查看界面
// ============================================================
#import "BTLogVC.h"
#import "BTLog.h"

@interface BTLogVC ()
@property (nonatomic, strong) UITextView *textView;
@property (nonatomic, strong) UILabel *pathLabel;
@property (nonatomic, strong) NSTimer *refreshTimer;
@property (nonatomic, assign) BOOL autoScroll;
@end

@implementation BTLogVC

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor systemBackgroundColor];
    self.title = @"运行日志";
    self.autoScroll = YES;

    // 导航栏按钮
    self.navigationItem.rightBarButtonItem =
        [[UIBarButtonItem alloc] initWithTitle:@"关闭"
                                         style:UIBarButtonItemStyleDone
                                        target:self
                                        action:@selector(onClose)];

    // 路径标签
    _pathLabel = [[UILabel alloc] init];
    _pathLabel.numberOfLines = 2;
    _pathLabel.font = [UIFont monospacedSystemFontOfSize:9 weight:UIFontWeightRegular];
    _pathLabel.textColor = [UIColor secondaryLabelColor];
    _pathLabel.text = [NSString stringWithFormat:@"文件: %@", BTLogFilePath() ?: @"(未初始化)"];
    _pathLabel.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:_pathLabel];

    // 文本框
    _textView = [[UITextView alloc] init];
    _textView.editable = NO;
    _textView.font = [UIFont monospacedSystemFontOfSize:10 weight:UIFontWeightRegular];
    _textView.backgroundColor = [UIColor secondarySystemBackgroundColor];
    _textView.textContainerInset = UIEdgeInsetsMake(8, 8, 8, 8);
    _textView.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:_textView];

    // 按钮行
    UIStackView *stack = [[UIStackView alloc] init];
    stack.axis = UILayoutConstraintAxisHorizontal;
    stack.distribution = UIStackViewDistributionFillEqually;
    stack.spacing = 8;
    stack.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:stack];

    NSArray *titles = @[@"刷新", @"复制", @"清空", @"分享"];
    NSArray *sels = @[@"onRefresh", @"onCopy", @"onClear", @"onShare"];
    for (NSUInteger i = 0; i < titles.count; i++) {
        UIButton *b = [UIButton buttonWithType:UIButtonTypeSystem];
        [b setTitle:titles[i] forState:UIControlStateNormal];
        b.titleLabel.font = [UIFont systemFontOfSize:13];
        b.backgroundColor = [UIColor tertiarySystemFillColor];
        b.layer.cornerRadius = 6;
        SEL sel = NSSelectorFromString(sels[i]);
        [b addTarget:self action:sel forControlEvents:UIControlEventTouchUpInside];
        [stack addArrangedSubview:b];
    }

    // 布局
    UILayoutGuide *g = self.view.safeAreaLayoutGuide;
    [NSLayoutConstraint activateConstraints:@[
        [_pathLabel.topAnchor constraintEqualToAnchor:g.topAnchor constant:4],
        [_pathLabel.leadingAnchor constraintEqualToAnchor:g.leadingAnchor constant:12],
        [_pathLabel.trailingAnchor constraintEqualToAnchor:g.trailingAnchor constant:-12],

        [_textView.topAnchor constraintEqualToAnchor:_pathLabel.bottomAnchor constant:4],
        [_textView.leadingAnchor constraintEqualToAnchor:g.leadingAnchor constant:8],
        [_textView.trailingAnchor constraintEqualToAnchor:g.trailingAnchor constant:-8],

        [stack.topAnchor constraintEqualToAnchor:_textView.bottomAnchor constant:8],
        [stack.leadingAnchor constraintEqualToAnchor:g.leadingAnchor constant:12],
        [stack.trailingAnchor constraintEqualToAnchor:g.trailingAnchor constant:-12],
        [stack.heightAnchor constraintEqualToConstant:36],
        [stack.bottomAnchor constraintEqualToAnchor:g.bottomAnchor constant:-8],
    ]];

    // 初次加载
    [self reloadLog];

    // 自动刷新（每 2 秒）
    __weak typeof(self) weakSelf = self;
    _refreshTimer = [NSTimer scheduledTimerWithTimeInterval:2.0 repeats:YES block:^(NSTimer *t) {
        __strong typeof(weakSelf) self2 = weakSelf;
        if (self2 && self2.isViewLoaded && self2.view.window) {
            [self2 reloadLog];
        }
    }];
}

- (void)viewWillDisappear:(BOOL)animated {
    [super viewWillDisappear:animated];
    [_refreshTimer invalidate];
    _refreshTimer = nil;
}

- (void)dealloc {
    [_refreshTimer invalidate];
    _refreshTimer = nil;
}

// ============================================================
// 日志读取
// ============================================================
- (void)reloadLog {
    NSString *path = BTLogFilePath();
    if (!path) {
        _textView.text = @"(日志路径未初始化)";
        return;
    }

    NSError *err = nil;
    NSString *content = [NSString stringWithContentsOfFile:path
                                                  encoding:NSUTF8StringEncoding
                                                     error:&err];
    if (err) {
        _textView.text = [NSString stringWithFormat:@"读取失败: %@\n路径: %@", err.localizedDescription, path];
        return;
    }
    if (!content || content.length == 0) {
        _textView.text = [NSString stringWithFormat:@"(日志为空)\n路径: %@\n\n如果这里一直是空的，说明 BTLog 没写成功。", path];
        return;
    }

    // 只显示最后 20000 字符（避免卡顿）
    if (content.length > 20000) {
        content = [NSString stringWithFormat:@"...(截断前 %lu 字符)\n%@",
                   (unsigned long)(content.length - 20000),
                   [content substringFromIndex:content.length - 20000]];
    }

    _textView.text = content;
    _pathLabel.text = [NSString stringWithFormat:@"文件: %@  (%lu 字节)",
                       path, (unsigned long)content.length];

    // 自动滚到底
    if (_autoScroll && content.length > 0) {
        NSRange bottom = NSMakeRange(content.length - 1, 1);
        [_textView scrollRangeToVisible:bottom];
    }
}

// ============================================================
// 按钮
// ============================================================
- (void)onRefresh {
    _autoScroll = YES;
    [self reloadLog];
}

- (void)onCopy {
    if (_textView.text.length == 0) return;
    [UIPasteboard generalPasteboard].string = _textView.text;
    [self toast:@"已复制到剪贴板"];
}

- (void)onClear {
    UIAlertController *a = [UIAlertController alertControllerWithTitle:@"清空日志?"
                                                               message:@"这会删除当前日志文件"
                                                        preferredStyle:UIAlertControllerStyleAlert];
    [a addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    __weak typeof(self) weakSelf = self;
    [a addAction:[UIAlertAction actionWithTitle:@"清空" style:UIAlertActionStyleDestructive handler:^(UIAlertAction *act) {
        BTLogClear();
        [weakSelf reloadLog];
        [weakSelf toast:@"已清空"];
    }]];
    [self presentViewController:a animated:YES completion:nil];
}

- (void)onShare {
    NSString *path = BTLogFilePath();
    if (!path) return;

    NSURL *url = [NSURL fileURLWithPath:path];
    UIActivityViewController *av = [[UIActivityViewController alloc]
        initWithActivityItems:@[url] applicationActivities:nil];

    // iPad 适配
    if (av.popoverPresentationController) {
        av.popoverPresentationController.sourceView = self.view;
        av.popoverPresentationController.sourceRect =
            CGRectMake(self.view.bounds.size.width / 2, self.view.bounds.size.height / 2, 1, 1);
    }

    [self presentViewController:av animated:YES completion:nil];
}

- (void)onClose {
    [self dismissViewControllerAnimated:YES completion:nil];
}

- (void)toast:(NSString *)msg {
    UIAlertController *a = [UIAlertController alertControllerWithTitle:nil
                                                               message:msg
                                                        preferredStyle:UIAlertControllerStyleAlert];
    [self presentViewController:a animated:YES completion:nil];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        [a dismissViewControllerAnimated:YES completion:nil];
    });
}

@end
