#include "JJCloudAppleBridge.hpp"
#include "JJCloudAuthInternal.hpp"
#ifndef JJV_AUTH_TESTING
#include "JJVServerConfig.h"
#endif
#ifndef JJV_BUILD_VERSION
#define JJV_BUILD_VERSION "0905R10"
#endif

#if JJV_AUTH_UI_ENABLED
#include <chrono>
#include <cmath>
#include <stdlib.h>
#import <Network/Network.h>
#import <UIKit/UIKit.h>

static BOOL JJVNoticeTextIsVisible(UITextView *textView) {
    UIWindow *window = textView.window;
    if (!textView.text.length || !window || window.hidden || window.alpha <= 0.01 ||
        UIApplication.sharedApplication.applicationState != UIApplicationStateActive) {
        return NO;
    }
    UIWindowScene *scene = window.windowScene;
    if (scene && (scene.activationState == UISceneActivationStateBackground ||
                  scene.activationState == UISceneActivationStateUnattached)) {
        return NO;
    }
    CGRect visible = [textView convertRect:textView.bounds toView:window];
    for (UIView *view = textView; view; view = view.superview) {
        if (view.hidden || view.alpha <= 0.01) return NO;
        if (view.clipsToBounds || view == window) {
            visible = CGRectIntersection(visible, [view convertRect:view.bounds toView:window]);
        }
    }
    return !CGRectIsNull(visible) && visible.size.height >= 24 && visible.size.width >= 40;
}

@interface JJVAuthGateController : UIViewController
@property (nonatomic, strong) UIView *panelView;
@property (nonatomic, strong) UITextField *cardField;
@property (nonatomic, strong) UIView *cardInputContainer;
@property (nonatomic, strong) UIButton *secureToggleButton;
@property (nonatomic, strong) UIButton *verifyButton;
@property (nonatomic, strong) UIActivityIndicatorView *verifySpinner;
@property (nonatomic, strong) UIBarButtonItem *keyboardVerifyButton;
@property (nonatomic, strong) UILabel *statusLabel;
@property (nonatomic, strong) UIView *statusBanner;
@property (nonatomic, strong) UILabel *titleLabel;
@property (nonatomic, strong) UILabel *instructionsLabel;
@property (nonatomic, strong) UILabel *expiryLabel;
@property (nonatomic, strong) UIView *expiryBanner;
@property (nonatomic, strong) UIButton *deviceCopyButton;
@property (nonatomic, copy) NSString *devicePrefix;
@property (nonatomic, copy) NSString *fullDeviceId;
@property (nonatomic, copy) void (^submitCard)(NSString *card);
- (void)applyFormStateWaiting:(BOOL)waiting errorText:(NSString *)errorText showingSuccess:(BOOL)showingSuccess;
- (void)showSuccessWithExpiryText:(NSString *)expiryText;
- (void)updateDeviceIdentityPrefix:(NSString *)prefix fullId:(NSString *)fullId;
@end

@implementation JJVAuthGateController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [[UIColor blackColor] colorWithAlphaComponent:0.46];
    self.view.accessibilityIdentifier = @"JJVAuthGateView";
    self.view.accessibilityViewIsModal = YES;
    self.modalInPresentation = YES;

    UIVisualEffectView *backdropBlur = [[UIVisualEffectView alloc] initWithEffect:
        [UIBlurEffect effectWithStyle:UIBlurEffectStyleSystemUltraThinMaterialDark]];
    backdropBlur.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:backdropBlur];

    UIScrollView *scroll = [UIScrollView new];
    scroll.translatesAutoresizingMaskIntoConstraints = NO;
    scroll.keyboardDismissMode = UIScrollViewKeyboardDismissModeOnDrag;
    scroll.showsVerticalScrollIndicator = NO;
    [self.view addSubview:scroll];

    UIView *content = [UIView new];
    content.translatesAutoresizingMaskIntoConstraints = NO;
    [scroll addSubview:content];

    UIView *panel = [UIView new];
    panel.backgroundColor = [UIColor secondarySystemGroupedBackgroundColor];
    panel.layer.cornerRadius = 24.0;
    panel.layer.borderWidth = 0.5;
    panel.layer.borderColor = [[UIColor separatorColor] colorWithAlphaComponent:0.45].CGColor;
    panel.layer.shadowColor = [UIColor blackColor].CGColor;
    panel.layer.shadowOpacity = 0.18;
    panel.layer.shadowRadius = 24.0;
    panel.layer.shadowOffset = CGSizeMake(0.0, 10.0);
    panel.translatesAutoresizingMaskIntoConstraints = NO;
    self.panelView = panel;
    [content addSubview:panel];

    UIView *iconCircle = [UIView new];
    iconCircle.translatesAutoresizingMaskIntoConstraints = NO;
    iconCircle.backgroundColor = [[UIColor systemBlueColor] colorWithAlphaComponent:0.14];
    iconCircle.layer.cornerRadius = 28.0;
    UIImageView *iconView = [UIImageView new];
    iconView.translatesAutoresizingMaskIntoConstraints = NO;
    if (@available(iOS 13.0, *)) {
        UIImageSymbolConfiguration *cfg = [UIImageSymbolConfiguration configurationWithPointSize:24.0 weight:UIImageSymbolWeightSemibold];
        iconView.image = [UIImage systemImageNamed:@"key.fill" withConfiguration:cfg];
    }
    iconView.tintColor = [UIColor systemBlueColor];
    iconView.contentMode = UIViewContentModeScaleAspectFit;
    [iconCircle addSubview:iconView];

    UIView *iconRow = [UIView new];
    iconRow.translatesAutoresizingMaskIntoConstraints = NO;
    [iconRow addSubview:iconCircle];
    [NSLayoutConstraint activateConstraints:@[
        [iconCircle.centerXAnchor constraintEqualToAnchor:iconRow.centerXAnchor],
        [iconCircle.topAnchor constraintEqualToAnchor:iconRow.topAnchor],
        [iconCircle.bottomAnchor constraintEqualToAnchor:iconRow.bottomAnchor],
        [iconCircle.widthAnchor constraintEqualToConstant:56.0],
        [iconCircle.heightAnchor constraintEqualToConstant:56.0],
        [iconView.centerXAnchor constraintEqualToAnchor:iconCircle.centerXAnchor],
        [iconView.centerYAnchor constraintEqualToAnchor:iconCircle.centerYAnchor],
    ]];

    self.titleLabel = [UILabel new];
    self.titleLabel.text = @"卡密验证";
    self.titleLabel.font = [UIFont systemFontOfSize:22.0 weight:UIFontWeightBold];
    self.titleLabel.textColor = [UIColor labelColor];
    self.titleLabel.textAlignment = NSTextAlignmentCenter;

    UILabel *versionBadge = [UILabel new];
    versionBadge.text = [NSString stringWithFormat:@" GOGO V2 · %s ", JJV_BUILD_VERSION];
    versionBadge.font = [UIFont monospacedSystemFontOfSize:11.0 weight:UIFontWeightSemibold];
    versionBadge.textColor = [UIColor systemBlueColor];
    versionBadge.backgroundColor = [[UIColor systemBlueColor] colorWithAlphaComponent:0.12];
    versionBadge.layer.cornerRadius = 6.0;
    versionBadge.layer.masksToBounds = YES;
    versionBadge.textAlignment = NSTextAlignmentCenter;

    UIStackView *titleStack = [[UIStackView alloc] initWithArrangedSubviews:@[self.titleLabel, versionBadge]];
    titleStack.axis = UILayoutConstraintAxisVertical;
    titleStack.alignment = UIStackViewAlignmentCenter;
    titleStack.spacing = 6.0;

    self.instructionsLabel = [UILabel new];
    self.instructionsLabel.text = @"当前设备尚未激活或离线凭证已到期，请输入卡密联网加密验证。";
    self.instructionsLabel.font = [UIFont systemFontOfSize:14.0];
    self.instructionsLabel.textColor = [UIColor secondaryLabelColor];
    self.instructionsLabel.numberOfLines = 0;
    self.instructionsLabel.textAlignment = NSTextAlignmentCenter;

    self.cardInputContainer = [UIView new];
    self.cardInputContainer.translatesAutoresizingMaskIntoConstraints = NO;
    self.cardInputContainer.backgroundColor = [UIColor tertiarySystemFillColor];
    self.cardInputContainer.layer.cornerRadius = 13.0;
    self.cardInputContainer.layer.borderWidth = 0.5;
    self.cardInputContainer.layer.borderColor = [[UIColor separatorColor] colorWithAlphaComponent:0.4].CGColor;

    self.cardField = [UITextField new];
    self.cardField.translatesAutoresizingMaskIntoConstraints = NO;
    self.cardField.placeholder = @"请输入卡密";
    self.cardField.borderStyle = UITextBorderStyleNone;
    self.cardField.font = [UIFont systemFontOfSize:16.0 weight:UIFontWeightMedium];
    self.cardField.textColor = [UIColor labelColor];
    self.cardField.secureTextEntry = YES;
    self.cardField.clearButtonMode = UITextFieldViewModeWhileEditing;
    self.cardField.autocorrectionType = UITextAutocorrectionTypeNo;
    self.cardField.autocapitalizationType = UITextAutocapitalizationTypeNone;
    self.cardField.returnKeyType = UIReturnKeyGo;
    [self.cardField addTarget:self action:@selector(submitTapped:) forControlEvents:UIControlEventEditingDidEndOnExit];
    self.cardField.accessibilityIdentifier = @"JJVAuthCardInput";
    self.cardField.accessibilityLabel = @"卡密";

    self.secureToggleButton = [UIButton buttonWithType:UIButtonTypeSystem];
    self.secureToggleButton.translatesAutoresizingMaskIntoConstraints = NO;
    self.secureToggleButton.tintColor = [UIColor secondaryLabelColor];
    if (@available(iOS 13.0, *)) {
        [self.secureToggleButton setImage:[UIImage systemImageNamed:@"eye.slash.fill"] forState:UIControlStateNormal];
    } else {
        [self.secureToggleButton setTitle:@"显" forState:UIControlStateNormal];
    }
    [self.secureToggleButton addTarget:self action:@selector(toggleSecureEntry:) forControlEvents:UIControlEventTouchUpInside];

    [self.cardInputContainer addSubview:self.cardField];
    [self.cardInputContainer addSubview:self.secureToggleButton];
    [NSLayoutConstraint activateConstraints:@[
        [self.cardInputContainer.heightAnchor constraintEqualToConstant:48.0],
        [self.cardField.leadingAnchor constraintEqualToAnchor:self.cardInputContainer.leadingAnchor constant:14.0],
        [self.cardField.topAnchor constraintEqualToAnchor:self.cardInputContainer.topAnchor],
        [self.cardField.bottomAnchor constraintEqualToAnchor:self.cardInputContainer.bottomAnchor],
        [self.cardField.trailingAnchor constraintEqualToAnchor:self.secureToggleButton.leadingAnchor constant:-6.0],
        [self.secureToggleButton.trailingAnchor constraintEqualToAnchor:self.cardInputContainer.trailingAnchor constant:-10.0],
        [self.secureToggleButton.centerYAnchor constraintEqualToAnchor:self.cardInputContainer.centerYAnchor],
        [self.secureToggleButton.widthAnchor constraintEqualToConstant:32.0],
        [self.secureToggleButton.heightAnchor constraintEqualToConstant:32.0],
    ]];

    UIToolbar *keyboardToolbar = [[UIToolbar alloc] initWithFrame:CGRectMake(0, 0, 0, 44)];
    keyboardToolbar.autoresizingMask = UIViewAutoresizingFlexibleWidth;
    self.keyboardVerifyButton = [[UIBarButtonItem alloc] initWithTitle:@"验证" style:UIBarButtonItemStyleDone target:self action:@selector(submitTapped:)];
    self.keyboardVerifyButton.accessibilityIdentifier = @"JJVAuthKeyboardVerifyButton";
    UIBarButtonItem *hideKeyboard = [[UIBarButtonItem alloc] initWithTitle:@"收起键盘" style:UIBarButtonItemStylePlain target:self action:@selector(hideKeyboard:)];
    hideKeyboard.accessibilityIdentifier = @"JJVAuthHideKeyboardButton";
    keyboardToolbar.items = @[
        hideKeyboard,
        [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemFlexibleSpace target:nil action:nil],
        self.keyboardVerifyButton
    ];
    self.cardField.inputAccessoryView = keyboardToolbar;

    self.verifyButton = [UIButton buttonWithType:UIButtonTypeSystem];
    self.verifyButton.translatesAutoresizingMaskIntoConstraints = NO;
    self.verifyButton.backgroundColor = [UIColor systemBlueColor];
    self.verifyButton.tintColor = [UIColor whiteColor];
    self.verifyButton.layer.cornerRadius = 13.0;
    self.verifyButton.layer.masksToBounds = YES;
    [self.verifyButton setTitle:@"立即验证" forState:UIControlStateNormal];
    self.verifyButton.titleLabel.font = [UIFont systemFontOfSize:17.0 weight:UIFontWeightSemibold];
    self.verifyButton.accessibilityIdentifier = @"JJVAuthVerifyButton";
    [self.verifyButton addTarget:self action:@selector(submitTapped:) forControlEvents:UIControlEventTouchUpInside];

    self.verifySpinner = [[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleMedium];
    self.verifySpinner.translatesAutoresizingMaskIntoConstraints = NO;
    self.verifySpinner.color = [UIColor whiteColor];
    self.verifySpinner.hidesWhenStopped = YES;
    [self.verifyButton addSubview:self.verifySpinner];
    [NSLayoutConstraint activateConstraints:@[
        [self.verifySpinner.centerYAnchor constraintEqualToAnchor:self.verifyButton.centerYAnchor],
        [self.verifySpinner.trailingAnchor constraintEqualToAnchor:self.verifyButton.trailingAnchor constant:-16.0],
    ]];

    self.statusBanner = [UIView new];
    self.statusBanner.translatesAutoresizingMaskIntoConstraints = NO;
    self.statusBanner.backgroundColor = [UIColor tertiarySystemFillColor];
    self.statusBanner.layer.cornerRadius = 10.0;

    self.statusLabel = [UILabel new];
    self.statusLabel.translatesAutoresizingMaskIntoConstraints = NO;
    self.statusLabel.text = @"请输入卡密并点击验证";
    self.statusLabel.font = [UIFont systemFontOfSize:13.0 weight:UIFontWeightMedium];
    self.statusLabel.textColor = [UIColor secondaryLabelColor];
    self.statusLabel.numberOfLines = 0;
    self.statusLabel.textAlignment = NSTextAlignmentCenter;
    self.statusLabel.accessibilityIdentifier = @"JJVAuthStatusLabel";
    [self.statusBanner addSubview:self.statusLabel];
    [NSLayoutConstraint activateConstraints:@[
        [self.statusLabel.topAnchor constraintEqualToAnchor:self.statusBanner.topAnchor constant:9.0],
        [self.statusLabel.bottomAnchor constraintEqualToAnchor:self.statusBanner.bottomAnchor constant:-9.0],
        [self.statusLabel.leadingAnchor constraintEqualToAnchor:self.statusBanner.leadingAnchor constant:12.0],
        [self.statusLabel.trailingAnchor constraintEqualToAnchor:self.statusBanner.trailingAnchor constant:-12.0],
    ]];

    self.expiryBanner = [UIView new];
    self.expiryBanner.translatesAutoresizingMaskIntoConstraints = NO;
    self.expiryBanner.backgroundColor = [[UIColor systemGreenColor] colorWithAlphaComponent:0.14];
    self.expiryBanner.layer.cornerRadius = 14.0;
    self.expiryBanner.hidden = YES;

    self.expiryLabel = [UILabel new];
    self.expiryLabel.translatesAutoresizingMaskIntoConstraints = NO;
    self.expiryLabel.text = @"";
    self.expiryLabel.font = [UIFont systemFontOfSize:15.0 weight:UIFontWeightSemibold];
    self.expiryLabel.textColor = [UIColor systemGreenColor];
    self.expiryLabel.numberOfLines = 0;
    self.expiryLabel.textAlignment = NSTextAlignmentCenter;
    self.expiryLabel.hidden = YES;
    self.expiryLabel.accessibilityIdentifier = @"JJVAuthExpiryLabel";
    [self.expiryBanner addSubview:self.expiryLabel];
    [NSLayoutConstraint activateConstraints:@[
        [self.expiryLabel.topAnchor constraintEqualToAnchor:self.expiryBanner.topAnchor constant:14.0],
        [self.expiryLabel.bottomAnchor constraintEqualToAnchor:self.expiryBanner.bottomAnchor constant:-14.0],
        [self.expiryLabel.leadingAnchor constraintEqualToAnchor:self.expiryBanner.leadingAnchor constant:14.0],
        [self.expiryLabel.trailingAnchor constraintEqualToAnchor:self.expiryBanner.trailingAnchor constant:-14.0],
    ]];

    self.deviceCopyButton = [UIButton buttonWithType:UIButtonTypeSystem];
    self.deviceCopyButton.translatesAutoresizingMaskIntoConstraints = NO;
    self.deviceCopyButton.titleLabel.font = [UIFont monospacedSystemFontOfSize:11.5 weight:UIFontWeightMedium];
    self.deviceCopyButton.titleLabel.numberOfLines = 1;
    self.deviceCopyButton.titleLabel.adjustsFontSizeToFitWidth = YES;
    self.deviceCopyButton.titleLabel.minimumScaleFactor = 0.8;
    [self.deviceCopyButton setTitleColor:[UIColor secondaryLabelColor] forState:UIControlStateNormal];
    self.deviceCopyButton.backgroundColor = [UIColor tertiarySystemFillColor];
    self.deviceCopyButton.layer.cornerRadius = 8.0;
    [self.deviceCopyButton.heightAnchor constraintEqualToConstant:30.0].active = YES;
    self.deviceCopyButton.hidden = YES;
    [self.deviceCopyButton addTarget:self action:@selector(copyDeviceIdTapped:) forControlEvents:UIControlEventTouchUpInside];

    UIStackView *stack = [[UIStackView alloc] initWithArrangedSubviews:@[
        iconRow,
        titleStack,
        self.instructionsLabel,
        self.cardInputContainer,
        self.verifyButton,
        self.statusBanner,
        self.expiryBanner,
        self.deviceCopyButton
    ]];
    stack.axis = UILayoutConstraintAxisVertical;
    stack.spacing = 14.0;
    stack.translatesAutoresizingMaskIntoConstraints = NO;
    [panel addSubview:stack];

    NSLayoutConstraint *preferredWidth = [panel.widthAnchor constraintEqualToAnchor:self.view.widthAnchor multiplier:0.88];
    preferredWidth.priority = UILayoutPriorityDefaultHigh;
    NSLayoutConstraint *preferredHeight = [content.heightAnchor constraintEqualToAnchor:scroll.frameLayoutGuide.heightAnchor];
    preferredHeight.priority = UILayoutPriorityDefaultLow;
    NSLayoutConstraint *verifyHeight = [self.verifyButton.heightAnchor constraintEqualToConstant:48.0];
    verifyHeight.priority = UILayoutPriorityDefaultHigh;

    [NSLayoutConstraint activateConstraints:@[
        [backdropBlur.topAnchor constraintEqualToAnchor:self.view.topAnchor],
        [backdropBlur.bottomAnchor constraintEqualToAnchor:self.view.bottomAnchor],
        [backdropBlur.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor],
        [backdropBlur.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor],

        [scroll.leadingAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.leadingAnchor],
        [scroll.trailingAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.trailingAnchor],
        [scroll.topAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.topAnchor],
        [scroll.bottomAnchor constraintEqualToAnchor:self.view.keyboardLayoutGuide.topAnchor],

        [content.leadingAnchor constraintEqualToAnchor:scroll.contentLayoutGuide.leadingAnchor],
        [content.trailingAnchor constraintEqualToAnchor:scroll.contentLayoutGuide.trailingAnchor],
        [content.topAnchor constraintEqualToAnchor:scroll.contentLayoutGuide.topAnchor],
        [content.bottomAnchor constraintEqualToAnchor:scroll.contentLayoutGuide.bottomAnchor],
        [content.widthAnchor constraintEqualToAnchor:scroll.frameLayoutGuide.widthAnchor],
        [content.heightAnchor constraintGreaterThanOrEqualToAnchor:scroll.frameLayoutGuide.heightAnchor],
        preferredHeight,

        [panel.centerXAnchor constraintEqualToAnchor:content.centerXAnchor],
        [panel.centerYAnchor constraintEqualToAnchor:content.centerYAnchor],
        [panel.topAnchor constraintGreaterThanOrEqualToAnchor:content.topAnchor constant:20.0],
        [panel.bottomAnchor constraintLessThanOrEqualToAnchor:content.bottomAnchor constant:-20.0],
        [panel.widthAnchor constraintLessThanOrEqualToConstant:400.0],
        [panel.leadingAnchor constraintGreaterThanOrEqualToAnchor:self.view.safeAreaLayoutGuide.leadingAnchor constant:20.0],
        [panel.trailingAnchor constraintLessThanOrEqualToAnchor:self.view.safeAreaLayoutGuide.trailingAnchor constant:-20.0],
        preferredWidth,

        [stack.leadingAnchor constraintEqualToAnchor:panel.leadingAnchor constant:22.0],
        [stack.trailingAnchor constraintEqualToAnchor:panel.trailingAnchor constant:-22.0],
        [stack.topAnchor constraintEqualToAnchor:panel.topAnchor constant:26.0],
        [stack.bottomAnchor constraintEqualToAnchor:panel.bottomAnchor constant:-20.0],
        verifyHeight,
    ]];
}

- (void)traitCollectionDidChange:(UITraitCollection *)previousTraitCollection {
    [super traitCollectionDidChange:previousTraitCollection];
    if ([self.traitCollection hasDifferentColorAppearanceComparedToTraitCollection:previousTraitCollection]) {
        self.panelView.layer.borderColor = [[UIColor separatorColor] colorWithAlphaComponent:0.45].CGColor;
        self.cardInputContainer.layer.borderColor = [[UIColor separatorColor] colorWithAlphaComponent:0.4].CGColor;
    }
}

- (void)updateDeviceIdentityPrefix:(NSString *)prefix fullId:(NSString *)fullId {
    if (prefix.length == 0) return;
    self.devicePrefix = prefix;
    self.fullDeviceId = fullId.length > 0 ? fullId : prefix;
    self.deviceCopyButton.hidden = NO;
    [self.deviceCopyButton setTitle:[NSString stringWithFormat:@"设备标识：%@  · 点击复制", prefix]
                           forState:UIControlStateNormal];
}

- (void)copyDeviceIdTapped:(__unused id)sender {
    NSString *valueToCopy = self.fullDeviceId.length > 0 ? self.fullDeviceId : self.devicePrefix;
    if (valueToCopy.length == 0) return;
    UIPasteboard.generalPasteboard.string = valueToCopy;
    if (@available(iOS 10.0, *)) {
        [[[UINotificationFeedbackGenerator alloc] init] notificationOccurred:UINotificationFeedbackTypeSuccess];
    }
    [self.deviceCopyButton setTitle:@"已复制完整设备标识，可发给管理员授权" forState:UIControlStateNormal];
    [self.deviceCopyButton setTitleColor:[UIColor systemGreenColor] forState:UIControlStateNormal];
    __weak JJVAuthGateController *weakSelf = self;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.8 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        JJVAuthGateController *strongSelf = weakSelf;
        if (!strongSelf || strongSelf.devicePrefix.length == 0) return;
        [strongSelf.deviceCopyButton setTitleColor:[UIColor secondaryLabelColor] forState:UIControlStateNormal];
        [strongSelf.deviceCopyButton setTitle:[NSString stringWithFormat:@"设备标识：%@  · 点击复制", strongSelf.devicePrefix]
                                     forState:UIControlStateNormal];
    });
}

- (void)applyFormStateWaiting:(BOOL)waiting errorText:(NSString *)errorText showingSuccess:(BOOL)showingSuccess {
    if (showingSuccess) return;
    self.cardInputContainer.hidden = NO;
    self.cardField.hidden = NO;
    self.verifyButton.hidden = NO;
    self.statusBanner.hidden = NO;
    self.statusLabel.hidden = NO;
    self.expiryBanner.hidden = YES;
    self.expiryLabel.hidden = YES;

    self.cardField.enabled = !waiting;
    self.secureToggleButton.enabled = !waiting;
    self.verifyButton.enabled = !waiting;
    self.verifyButton.alpha = waiting ? 0.72 : 1.0;
    self.keyboardVerifyButton.enabled = !waiting;
    [self.verifyButton setTitle:waiting ? @"加密验证中…" : @"立即验证" forState:UIControlStateNormal];
    if (waiting) {
        [self.verifySpinner startAnimating];
        self.statusLabel.text = @"正在建立 ECDH 加密通道并验证，请稍候…";
        self.statusLabel.textColor = [UIColor systemBlueColor];
        self.statusBanner.backgroundColor = [[UIColor systemBlueColor] colorWithAlphaComponent:0.12];
    } else {
        [self.verifySpinner stopAnimating];
        if (errorText.length > 0) {
            self.statusLabel.text = errorText;
            self.statusLabel.textColor = [UIColor systemRedColor];
            self.statusBanner.backgroundColor = [[UIColor systemRedColor] colorWithAlphaComponent:0.12];
        } else {
            self.statusLabel.text = @"请输入卡密并点击验证";
            self.statusLabel.textColor = [UIColor secondaryLabelColor];
            self.statusBanner.backgroundColor = [UIColor tertiarySystemFillColor];
        }
    }
}

- (void)showSuccessWithExpiryText:(NSString *)expiryText {
    [self.verifySpinner stopAnimating];
    if (@available(iOS 10.0, *)) {
        [[[UINotificationFeedbackGenerator alloc] init] notificationOccurred:UINotificationFeedbackTypeSuccess];
    }
    self.cardInputContainer.hidden = YES;
    self.cardField.hidden = YES;
    self.verifyButton.hidden = YES;
    self.statusBanner.hidden = YES;
    self.statusLabel.hidden = YES;
    self.expiryLabel.text = expiryText;
    self.expiryLabel.hidden = NO;
    self.expiryBanner.hidden = NO;
    [self.view layoutIfNeeded];
}

- (void)toggleSecureEntry:(__unused id)sender {
    NSString *existingText = self.cardField.text;
    BOOL wasFirstResponder = self.cardField.isFirstResponder;
    self.cardField.secureTextEntry = !self.cardField.secureTextEntry;
    // Prevent UIKit clearsOnInsertion from wiping existing card text on next keystroke after re-enabling secureTextEntry.
    if (wasFirstResponder && existingText.length > 0) {
        self.cardField.text = @"";
        [self.cardField insertText:existingText];
    }
    if (@available(iOS 13.0, *)) {
        NSString *symbol = self.cardField.secureTextEntry ? @"eye.slash.fill" : @"eye.fill";
        [self.secureToggleButton setImage:[UIImage systemImageNamed:symbol] forState:UIControlStateNormal];
    }
}

- (void)submitTapped:(__unused id)sender {
    if (self.verifyButton.enabled && self.submitCard) {
        self.submitCard(self.cardField.text ?: @"");
    }
}

- (void)hideKeyboard:(__unused id)sender {
    [self.view endEditing:YES];
}

@end

@interface JJVAuthGateWindow : UIWindow
@property (nonatomic, weak) UIWindow *previousKeyWindow;
@end
@implementation JJVAuthGateWindow
@end

@interface JJVStandaloneNoticeController : UIViewController
@property (nonatomic, strong) UIView *cardView;
@property (nonatomic, copy) NSString *notice;
@property (nonatomic, strong) UITextView *noticeTextView;
@property (nonatomic, strong) UILabel *statusLabel;
@property (nonatomic, strong) UIButton *retryButton;
@property (nonatomic, copy) void (^retryNotice)(void);
@property (nonatomic, copy) void (^closeNotice)(void);
@property (nonatomic, copy) BOOL (^noticeDidDisplay)(void);
@property (nonatomic) BOOL noticeVisibilityCheckPending;
@property (nonatomic) BOOL noticeVisibilityReported;
- (void)reportNoticeVisibility;
@end

@implementation JJVStandaloneNoticeController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [[UIColor blackColor] colorWithAlphaComponent:0.44];
    self.view.accessibilityIdentifier = @"JJVStandaloneNoticeView";
    self.view.accessibilityViewIsModal = YES;

    UIVisualEffectView *backdropBlur = [[UIVisualEffectView alloc] initWithEffect:
        [UIBlurEffect effectWithStyle:UIBlurEffectStyleSystemUltraThinMaterialDark]];
    backdropBlur.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:backdropBlur];

    UIView *card = [UIView new];
    card.translatesAutoresizingMaskIntoConstraints = NO;
    card.backgroundColor = [UIColor secondarySystemGroupedBackgroundColor];
    card.layer.cornerRadius = 24.0;
    card.layer.borderWidth = 0.5;
    card.layer.borderColor = [[UIColor separatorColor] colorWithAlphaComponent:0.45].CGColor;
    card.layer.shadowColor = [UIColor blackColor].CGColor;
    card.layer.shadowOpacity = 0.18;
    card.layer.shadowRadius = 24.0;
    card.layer.shadowOffset = CGSizeMake(0.0, 10.0);
    self.cardView = card;
    [self.view addSubview:card];

    UIView *iconBadge = [UIView new];
    iconBadge.translatesAutoresizingMaskIntoConstraints = NO;
    iconBadge.backgroundColor = [[UIColor systemOrangeColor] colorWithAlphaComponent:0.16];
    iconBadge.layer.cornerRadius = 18.0;
    UIImageView *iconView = [UIImageView new];
    iconView.translatesAutoresizingMaskIntoConstraints = NO;
    if (@available(iOS 13.0, *)) {
        UIImageSymbolConfiguration *cfg = [UIImageSymbolConfiguration configurationWithPointSize:17.0 weight:UIImageSymbolWeightSemibold];
        iconView.image = [UIImage systemImageNamed:@"megaphone.fill" withConfiguration:cfg];
    }
    iconView.tintColor = [UIColor systemOrangeColor];
    [iconBadge addSubview:iconView];

    UILabel *title = [UILabel new];
    title.text = @"后台公告";
    title.font = [UIFont systemFontOfSize:20.0 weight:UIFontWeightBold];
    title.textColor = [UIColor labelColor];
    title.translatesAutoresizingMaskIntoConstraints = NO;

    UIView *textContainer = [UIView new];
    textContainer.translatesAutoresizingMaskIntoConstraints = NO;
    textContainer.backgroundColor = [UIColor tertiarySystemGroupedBackgroundColor];
    textContainer.layer.cornerRadius = 14.0;

    self.noticeTextView = [UITextView new];
    self.noticeTextView.editable = NO;
    self.noticeTextView.selectable = YES;
    self.noticeTextView.scrollEnabled = YES;
    self.noticeTextView.backgroundColor = [UIColor clearColor];
    self.noticeTextView.textContainerInset = UIEdgeInsetsMake(14.0, 12.0, 14.0, 12.0);
    self.noticeTextView.dataDetectorTypes = UIDataDetectorTypeNone;
    self.noticeTextView.font = [UIFont systemFontOfSize:15.5];
    self.noticeTextView.textColor = [UIColor labelColor];
    self.noticeTextView.text = self.notice ?: @"";
    self.noticeTextView.accessibilityIdentifier = @"JJVStandaloneNoticeText";
    self.noticeTextView.translatesAutoresizingMaskIntoConstraints = NO;
    [textContainer addSubview:self.noticeTextView];

    self.statusLabel = [UILabel new];
    self.statusLabel.font = [UIFont systemFontOfSize:13.0 weight:UIFontWeightMedium];
    self.statusLabel.textColor = [UIColor secondaryLabelColor];
    self.statusLabel.textAlignment = NSTextAlignmentCenter;
    self.statusLabel.numberOfLines = 0;
    self.statusLabel.accessibilityIdentifier = @"JJVStandaloneNoticeStatus";
    self.statusLabel.translatesAutoresizingMaskIntoConstraints = NO;

    self.retryButton = [UIButton buttonWithType:UIButtonTypeSystem];
    [self.retryButton setTitle:@"重试公告" forState:UIControlStateNormal];
    self.retryButton.titleLabel.font = [UIFont systemFontOfSize:15.0 weight:UIFontWeightSemibold];
    self.retryButton.backgroundColor = [UIColor tertiarySystemFillColor];
    self.retryButton.tintColor = [UIColor systemBlueColor];
    self.retryButton.layer.cornerRadius = 12.0;
    self.retryButton.accessibilityIdentifier = @"JJVStandaloneNoticeRetryButton";
    self.retryButton.translatesAutoresizingMaskIntoConstraints = NO;
    [self.retryButton addTarget:self action:@selector(retryTapped:) forControlEvents:UIControlEventTouchUpInside];

    UIButton *close = [UIButton buttonWithType:UIButtonTypeSystem];
    [close setTitle:@"关闭公告" forState:UIControlStateNormal];
    close.titleLabel.font = [UIFont systemFontOfSize:16.5 weight:UIFontWeightSemibold];
    close.backgroundColor = [UIColor systemBlueColor];
    close.tintColor = [UIColor whiteColor];
    close.layer.cornerRadius = 13.0;
    close.accessibilityIdentifier = @"JJVStandaloneNoticeCloseButton";
    close.translatesAutoresizingMaskIntoConstraints = NO;
    [close addTarget:self action:@selector(closeTapped:) forControlEvents:UIControlEventTouchUpInside];

    [card addSubview:iconBadge];
    [card addSubview:title];
    [card addSubview:textContainer];
    [card addSubview:self.statusLabel];
    [card addSubview:self.retryButton];
    [card addSubview:close];

    UILayoutGuide *safe = self.view.safeAreaLayoutGuide;
    NSLayoutConstraint *cardWidth = [card.widthAnchor constraintEqualToAnchor:self.view.widthAnchor multiplier:0.88];
    cardWidth.priority = UILayoutPriorityDefaultHigh;
    NSLayoutConstraint *cardHeight = [card.heightAnchor constraintEqualToAnchor:safe.heightAnchor multiplier:0.64];
    cardHeight.priority = UILayoutPriorityDefaultHigh;

    [NSLayoutConstraint activateConstraints:@[
        [backdropBlur.topAnchor constraintEqualToAnchor:self.view.topAnchor],
        [backdropBlur.bottomAnchor constraintEqualToAnchor:self.view.bottomAnchor],
        [backdropBlur.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor],
        [backdropBlur.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor],

        [card.centerXAnchor constraintEqualToAnchor:safe.centerXAnchor],
        [card.centerYAnchor constraintEqualToAnchor:safe.centerYAnchor],
        [card.leadingAnchor constraintGreaterThanOrEqualToAnchor:safe.leadingAnchor constant:20.0],
        [card.trailingAnchor constraintLessThanOrEqualToAnchor:safe.trailingAnchor constant:-20.0],
        [card.topAnchor constraintGreaterThanOrEqualToAnchor:safe.topAnchor constant:28.0],
        [card.bottomAnchor constraintLessThanOrEqualToAnchor:safe.bottomAnchor constant:-28.0],
        [card.widthAnchor constraintLessThanOrEqualToConstant:420.0],
        cardWidth,
        cardHeight,

        [iconBadge.topAnchor constraintEqualToAnchor:card.topAnchor constant:20.0],
        [iconBadge.leadingAnchor constraintEqualToAnchor:card.leadingAnchor constant:20.0],
        [iconBadge.widthAnchor constraintEqualToConstant:36.0],
        [iconBadge.heightAnchor constraintEqualToConstant:36.0],
        [iconView.centerXAnchor constraintEqualToAnchor:iconBadge.centerXAnchor],
        [iconView.centerYAnchor constraintEqualToAnchor:iconBadge.centerYAnchor],

        [title.leadingAnchor constraintEqualToAnchor:iconBadge.trailingAnchor constant:12.0],
        [title.trailingAnchor constraintEqualToAnchor:card.trailingAnchor constant:-20.0],
        [title.centerYAnchor constraintEqualToAnchor:iconBadge.centerYAnchor],

        [textContainer.topAnchor constraintEqualToAnchor:iconBadge.bottomAnchor constant:16.0],
        [textContainer.leadingAnchor constraintEqualToAnchor:card.leadingAnchor constant:20.0],
        [textContainer.trailingAnchor constraintEqualToAnchor:card.trailingAnchor constant:-20.0],
        [textContainer.bottomAnchor constraintEqualToAnchor:self.statusLabel.topAnchor constant:-10.0],

        [self.noticeTextView.topAnchor constraintEqualToAnchor:textContainer.topAnchor],
        [self.noticeTextView.bottomAnchor constraintEqualToAnchor:textContainer.bottomAnchor],
        [self.noticeTextView.leadingAnchor constraintEqualToAnchor:textContainer.leadingAnchor],
        [self.noticeTextView.trailingAnchor constraintEqualToAnchor:textContainer.trailingAnchor],

        [self.statusLabel.leadingAnchor constraintEqualToAnchor:card.leadingAnchor constant:20.0],
        [self.statusLabel.trailingAnchor constraintEqualToAnchor:card.trailingAnchor constant:-20.0],
        [self.statusLabel.bottomAnchor constraintEqualToAnchor:self.retryButton.topAnchor constant:-8.0],

        [self.retryButton.leadingAnchor constraintEqualToAnchor:card.leadingAnchor constant:20.0],
        [self.retryButton.trailingAnchor constraintEqualToAnchor:card.trailingAnchor constant:-20.0],
        [self.retryButton.heightAnchor constraintEqualToConstant:40.0],
        [self.retryButton.bottomAnchor constraintEqualToAnchor:close.topAnchor constant:-10.0],

        [close.leadingAnchor constraintEqualToAnchor:card.leadingAnchor constant:20.0],
        [close.trailingAnchor constraintEqualToAnchor:card.trailingAnchor constant:-20.0],
        [close.heightAnchor constraintEqualToConstant:48.0],
        [close.bottomAnchor constraintEqualToAnchor:card.bottomAnchor constant:-20.0],
    ]];
}

- (void)retryTapped:(__unused id)sender {
    if (self.retryButton.enabled && self.retryNotice) self.retryNotice();
}

- (void)closeTapped:(__unused id)sender {
    if (self.noticeDidDisplay && JJVNoticeTextIsVisible(self.noticeTextView)) {
        self.noticeVisibilityReported = self.noticeDidDisplay();
    }
    if (self.closeNotice) self.closeNotice();
}

- (void)viewDidAppear:(BOOL)animated {
    [super viewDidAppear:animated];
    [self reportNoticeVisibility];
}

- (void)viewDidLayoutSubviews {
    [super viewDidLayoutSubviews];
    [self reportNoticeVisibility];
}

- (void)reportNoticeVisibility {
    if (self.noticeVisibilityReported || self.noticeVisibilityCheckPending || !self.noticeDidDisplay ||
        !JJVNoticeTextIsVisible(self.noticeTextView)) {
        return;
    }
    self.noticeVisibilityCheckPending = YES;
    NSString *text = self.noticeTextView.text;
    __weak JJVStandaloneNoticeController *weakSelf = self;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 50 * NSEC_PER_MSEC), dispatch_get_main_queue(), ^{
        JJVStandaloneNoticeController *controller = weakSelf;
        if (!controller) return;
        controller.noticeVisibilityCheckPending = NO;
        if ([controller.noticeTextView.text isEqualToString:text] &&
            JJVNoticeTextIsVisible(controller.noticeTextView) &&
            controller.noticeDidDisplay) {
            controller.noticeVisibilityReported = controller.noticeDidDisplay();
        }
    });
}

- (void)traitCollectionDidChange:(UITraitCollection *)previousTraitCollection {
    [super traitCollectionDidChange:previousTraitCollection];
    if ([self.traitCollection hasDifferentColorAppearanceComparedToTraitCollection:previousTraitCollection]) {
        self.cardView.layer.borderColor = [[UIColor separatorColor] colorWithAlphaComponent:0.45].CGColor;
    }
}

@end

@interface JJVStandaloneNoticeWindow : UIWindow
@property (nonatomic, weak) UIWindow *previousKeyWindow;
@end
@implementation JJVStandaloneNoticeWindow
@end

namespace jjcloud {
namespace {

BOOL gHeartbeatRunning = NO;
BOOL gPermanentSyncRunning = NO;
double gLastPermanentSyncSteady = -1000.0;
BOOL gStartupRestoreScheduled = NO;
BOOL gStartupRestoreInProgress = YES;
BOOL gShowingVerifiedExpiry = NO;
BOOL gManualRequestRunning = NO;
BOOL gReconcilingGateWindows = NO;
BOOL gNetworkSatisfied = YES;
BOOL gIniSyncedThisLaunch = NO;
int gNetworkBackoffStep = 0;
NSString *gCachedDevicePrefix = @"";
NSString *gCachedFullDeviceId = @"";

NSMutableDictionary<NSString *, JJVAuthGateWindow *> *gGateWindows;
NSString *gLastError;
NSString *gInputDraft;

enum class NoticeState { NotRequested, Loading, Ready, Empty, Failed };
NoticeState gNoticeState = NoticeState::NotRequested;
NSString *gNoticeText;
BOOL gNoticeShownThisLaunch = NO;
BOOL gNoticeDismissedWithoutText = NO;
BOOL gReconcilingStandaloneNotice = NO;
JJVStandaloneNoticeWindow *gStandaloneNoticeWindow;

double uiSteadyNow() {
    using namespace std::chrono;
    return duration<double>(steady_clock::now().time_since_epoch()).count();
}

void tryPresentPopup();
void tryPresentPendingNotice();
void dismissStandaloneNotice(BOOL restoreHost);
void refreshHeartbeatAsynchronously();
void syncPermanentEntitlementAsynchronously(BOOL force);
void showPermanentActivatedToast();
void fetchNoticeAsynchronously();
NSArray<UIWindow *> *applicationWindows(UIApplication *app);
UIWindow *hostKeyWindow(NSArray<UIWindow *> *windows);

NSDateFormatter *sharedExpiryFormatter() {
    static NSDateFormatter *formatter;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        formatter = [[NSDateFormatter alloc] init];
        formatter.dateStyle = NSDateFormatterMediumStyle;
        formatter.timeStyle = NSDateFormatterShortStyle;
        formatter.locale = [NSLocale localeWithLocaleIdentifier:@"zh_CN"];
    });
    return formatter;
}

BOOL noticeMayBePresented() {
    if (gManualRequestRunning || gGateWindows.count) return NO;
    return isAuthorized();
}

BOOL markNoticeDisplayed() {
    if (!noticeMayBePresented()) return NO;
    if (gNoticeShownThisLaunch) return YES;
    if (gNoticeState != NoticeState::Ready || !trimmed(gNoticeText).length) return NO;
    gNoticeShownThisLaunch = YES;
    recordDiagnostic(@"notice_displayed", @{@"notice_shown_this_launch": @YES});
    return YES;
}

void updateNoticeContents() {
    JJVStandaloneNoticeController *controller = (JJVStandaloneNoticeController *)gStandaloneNoticeWindow.rootViewController;
    if (!controller) return;
    [controller loadViewIfNeeded];
    NSString *body = gNoticeState == NoticeState::Ready ? (gNoticeText ?: @"") : @"";
    if (![controller.noticeTextView.text isEqualToString:body]) {
        controller.noticeTextView.text = body;
        controller.noticeVisibilityReported = NO;
    }
    switch (gNoticeState) {
        case NoticeState::Loading: controller.statusLabel.text = @"正在获取后台公告…"; break;
        case NoticeState::Ready: controller.statusLabel.text = @""; break;
        case NoticeState::Empty: controller.statusLabel.text = @"后台暂无公告"; break;
        case NoticeState::Failed: controller.statusLabel.text = @"公告获取或校验失败，请重试。"; break;
        default: controller.statusLabel.text = @"等待获取后台公告"; break;
    }
    controller.retryButton.hidden = (gNoticeState == NoticeState::Ready);
    controller.retryButton.enabled = (gNoticeState != NoticeState::Loading);
    [controller.view layoutIfNeeded];
    [controller reportNoticeVisibility];
}

void fetchNoticeAsynchronously() {
    if (gNoticeState == NoticeState::Loading || !gNetworkSatisfied) return;
    gNoticeState = NoticeState::Loading;
    gNoticeText = nil;
    gNoticeDismissedWithoutText = NO;
    updateNoticeContents();
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        NSDictionary *result = dictionaryFromJSON(performNoticeJSON());
        BOOL verified = [result[@"ok"] boolValue] && [result[@"response_verified"] boolValue] &&
                        [strictString(result[@"api"]) isEqualToString:@"notice"];
        NSString *notice = verified ? strictString(result[@"app_gg"]) : nil;
        dispatch_async(dispatch_get_main_queue(), ^{
            if (!verified) {
                gNoticeText = nil;
                gNoticeState = NoticeState::Failed;
            } else if (!trimmed(notice).length) {
                gNoticeText = nil;
                gNoticeState = NoticeState::Empty;
            } else {
                gNoticeText = notice;
                gNoticeState = NoticeState::Ready;
                gNoticeDismissedWithoutText = NO;
            }
            updateNoticeContents();
            tryPresentPendingNotice();
        });
    });
}

void syncIniAsynchronously() {
    if (gIniSyncedThisLaunch || !gNetworkSatisfied) return;
    gIniSyncedThisLaunch = YES;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        NSDictionary *res = dictionaryFromJSON(performIniJSON());
        if (![res[@"ok"] boolValue]) {
            dispatch_async(dispatch_get_main_queue(), ^{
                gIniSyncedThisLaunch = NO;
            });
        }
    });
}

bool resultIsCurrent(NSDictionary *result) {
    NSNumber *generation = result[@"request_generation"];
    if (!generation) return true;
    return isGenerationCurrent(generation.unsignedLongLongValue);
}

void dismissGateWindows() {
    const BOOL wasReconciling = gReconcilingGateWindows;
    gReconcilingGateWindows = YES;
    gShowingVerifiedExpiry = NO;
    for (JJVAuthGateWindow *window in gGateWindows.allValues) {
        [window endEditing:YES];
        window.hidden = YES;
        UIWindow *previous = window.previousKeyWindow;
        if (!previous || previous.hidden || !previous.rootViewController) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
            previous = hostKeyWindow(window.windowScene ? window.windowScene.windows : UIApplication.sharedApplication.windows);
#pragma clang diagnostic pop
        }
        if (previous && !previous.hidden && ![previous isKindOfClass:JJVAuthGateWindow.class]) {
            [previous makeKeyWindow];
        }
    }
    [gGateWindows removeAllObjects];
    gReconcilingGateWindows = wasReconciling;
}

void dismissVerifiedPopup() {
    if (!isAuthorized()) {
        gShowingVerifiedExpiry = NO;
        tryPresentPopup();
        return;
    }
    gLastError = nil;
    dismissGateWindows();
    tryPresentPendingNotice();
}

void ensureCachedDeviceId() {
    if (gCachedDevicePrefix.length > 0 && gCachedFullDeviceId.length > 0) return;
    const std::string full = currentDeviceIdHex();
    if (!full.empty()) {
        gCachedFullDeviceId = ns(full);
        gCachedDevicePrefix = ns(full.substr(0, std::min<std::size_t>(16, full.size())));
    }
}

void updateGateContents() {
    ensureCachedDeviceId();
    const BOOL waiting = gManualRequestRunning || isLoginInFlight();
    for (JJVAuthGateWindow *window in gGateWindows.allValues) {
        JJVAuthGateController *controller = (JJVAuthGateController *)window.rootViewController;
        [controller applyFormStateWaiting:waiting errorText:gLastError showingSuccess:gShowingVerifiedExpiry];
        [controller updateDeviceIdentityPrefix:gCachedDevicePrefix fullId:gCachedFullDeviceId];
    }
}

void submitManualCard(NSString *input) {
    if (gManualRequestRunning || gStartupRestoreInProgress) return;
    gManualRequestRunning = YES;
    gShowingVerifiedExpiry = NO;
    gInputDraft = trimmed(input);
    gLastError = nil;
    for (JJVAuthGateWindow *window in gGateWindows.allValues) [window endEditing:YES];
    updateGateContents();

    const std::string card = cpp(gInputDraft);
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSDictionary *result = dictionaryFromJSON(performLoginJSON(card, ""));
        dispatch_async(dispatch_get_main_queue(), ^{
            gManualRequestRunning = NO;
            if ([result[@"superseded"] boolValue] || !resultIsCurrent(result)) {
                tryPresentPopup();
                updateGateContents();
                return;
            }
            if ([result[@"ok"] boolValue] && isAuthorized()) {
                // Clear in-memory card draft immediately on success (§13).
                gInputDraft = @"";
                gShowingVerifiedExpiry = YES;
                gNetworkBackoffStep = 0;

                NSString *expiryText = nil;
                if (isPermanentOfflineAuthorized()) {
                    expiryText = @"验证成功\n授权状态：永久离线授权";
                } else {
                    double expWall = currentAuthorizationExpiryWall();
                    NSDate *expiryDate = [NSDate dateWithTimeIntervalSince1970:expWall];
                    expiryText = [NSString stringWithFormat:@"验证成功\n到期时间：%@",
                                  [sharedExpiryFormatter() stringFromDate:expiryDate]];
                }
                for (JJVAuthGateWindow *window in gGateWindows.allValues) {
                    JJVAuthGateController *controller = (JJVAuthGateController *)window.rootViewController;
                    controller.cardField.text = @"";
                    [controller showSuccessWithExpiryText:expiryText];
                }
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                    dismissVerifiedPopup();
                });
            } else {
                gLastError = strictString(result[@"error"]) ?: @"验证失败，请重试";
                tryPresentPopup();
                updateGateContents();
            }
        });
    });
}

void restoreStartupAsynchronously() {
    if (gStartupRestoreScheduled) return;
    gStartupRestoreScheduled = YES;
    gStartupRestoreInProgress = YES;
    recordDiagnostic(@"startup_restore", @{@"startup_restore": @"pending"});
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        std::string fullDevId = currentDeviceIdHex();
        NSDictionary *result = dictionaryFromJSON(restoreStartupAuthorization());
        dispatch_async(dispatch_get_main_queue(), ^{
            if (!fullDevId.empty()) {
                gCachedFullDeviceId = ns(fullDevId);
                gCachedDevicePrefix = ns(fullDevId.substr(0, std::min<std::size_t>(16, fullDevId.size())));
            }
            gStartupRestoreInProgress = NO;

            if ([result[@"ok"] boolValue] && isAuthorized()) {
                recordDiagnostic(@"startup_restore", @{
                    @"startup_restore": @"offline_verified",
                    @"permanent": @(isPermanentOfflineAuthorized())
                });
                tryPresentPopup();
                if (hasActiveOnlineSession() && gNetworkSatisfied) {
                    refreshHeartbeatAsynchronously();
                }
                syncIniAsynchronously();
                syncPermanentEntitlementAsynchronously(YES);
            } else {
                gLastError = [result[@"no_saved_license"] boolValue]
                    ? nil
                    : (strictString(result[@"error"]) ?: @"请输入卡密联网验证");
                recordDiagnostic(@"startup_restore", @{@"startup_restore": @"manual_required"});
                tryPresentPopup();
                updateGateContents();
                syncPermanentEntitlementAsynchronously(YES);
            }
        });
    });
}

void showPermanentActivatedToast() {
    UIApplication *app = UIApplication.sharedApplication;
    if (app.applicationState != UIApplicationStateActive) return;
    UIWindow *host = hostKeyWindow(applicationWindows(app));
    if (!host) return;

    UIVisualEffectView *pill = [[UIVisualEffectView alloc] initWithEffect:
        [UIBlurEffect effectWithStyle:UIBlurEffectStyleSystemMaterial]];
    pill.translatesAutoresizingMaskIntoConstraints = NO;
    pill.userInteractionEnabled = NO;
    pill.layer.cornerRadius = 20.0;
    pill.layer.masksToBounds = YES;
    pill.layer.borderWidth = 0.5;
    pill.layer.borderColor = [[UIColor systemGreenColor] colorWithAlphaComponent:0.35].CGColor;
    pill.alpha = 0.0;
    pill.transform = CGAffineTransformMakeTranslation(0.0, -14.0);

    UIStackView *row = [UIStackView new];
    row.axis = UILayoutConstraintAxisHorizontal;
    row.alignment = UIStackViewAlignmentCenter;
    row.spacing = 8.0;
    row.translatesAutoresizingMaskIntoConstraints = NO;

    if (@available(iOS 13.0, *)) {
        UIImageSymbolConfiguration *cfg = [UIImageSymbolConfiguration configurationWithPointSize:16.0 weight:UIImageSymbolWeightSemibold];
        UIImageView *icon = [[UIImageView alloc] initWithImage:[UIImage systemImageNamed:@"checkmark.seal.fill" withConfiguration:cfg]];
        icon.tintColor = [UIColor systemGreenColor];
        icon.contentMode = UIViewContentModeScaleAspectFit;
        [row addArrangedSubview:icon];
    }

    UILabel *label = [UILabel new];
    label.text = @"已自动生效：永久离线授权";
    label.font = [UIFont systemFontOfSize:14.0 weight:UIFontWeightSemibold];
    label.textColor = [UIColor labelColor];
    [row addArrangedSubview:label];

    [pill.contentView addSubview:row];
    [host addSubview:pill];

    [NSLayoutConstraint activateConstraints:@[
        [pill.centerXAnchor constraintEqualToAnchor:host.centerXAnchor],
        [pill.topAnchor constraintEqualToAnchor:host.safeAreaLayoutGuide.topAnchor constant:12.0],
        [pill.leadingAnchor constraintGreaterThanOrEqualToAnchor:host.leadingAnchor constant:20.0],
        [pill.trailingAnchor constraintLessThanOrEqualToAnchor:host.trailingAnchor constant:-20.0],
        [row.topAnchor constraintEqualToAnchor:pill.contentView.topAnchor constant:10.0],
        [row.bottomAnchor constraintEqualToAnchor:pill.contentView.bottomAnchor constant:-10.0],
        [row.leadingAnchor constraintEqualToAnchor:pill.contentView.leadingAnchor constant:16.0],
        [row.trailingAnchor constraintEqualToAnchor:pill.contentView.trailingAnchor constant:-16.0],
    ]];

    [UIView animateWithDuration:0.28 delay:0.0 options:UIViewAnimationOptionCurveEaseOut animations:^{
        pill.alpha = 1.0;
        pill.transform = CGAffineTransformIdentity;
    } completion:^(__unused BOOL finished) {
        [UIView animateWithDuration:0.32 delay:2.8 options:UIViewAnimationOptionCurveEaseIn animations:^{
            pill.alpha = 0.0;
            pill.transform = CGAffineTransformMakeTranslation(0.0, -10.0);
        } completion:^(__unused BOOL done) {
            [pill removeFromSuperview];
        }];
    }];
}

void syncPermanentEntitlementAsynchronously(BOOL force) {
    if (gPermanentSyncRunning || gManualRequestRunning || gStartupRestoreInProgress || !gNetworkSatisfied) {
        return;
    }
    const double now = uiSteadyNow();
    const double minInterval = force
        ? 3.0
        : (!isAuthorized()
            ? 10.0
            : (isPermanentOfflineAuthorized() ? 300.0 : 60.0));
    if ((now - gLastPermanentSyncSteady) < minInterval) {
        return;
    }

    gPermanentSyncRunning = YES;
    gLastPermanentSyncSteady = now;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        NSDictionary *result = dictionaryFromJSON(performPermanentEntitlementSyncJSON());
        dispatch_async(dispatch_get_main_queue(), ^{
            gPermanentSyncRunning = NO;
            gLastPermanentSyncSteady = uiSteadyNow();

            if ([result[@"granted"] boolValue] && isAuthorized()) {
                gNetworkBackoffStep = 0;
                const BOOL newlyGranted = [result[@"newly_granted"] boolValue];
                recordDiagnostic(@"permanent_entitlement_granted", @{
                    @"newly_granted": @(newlyGranted),
                    @"gate_open": @(gGateWindows.count > 0)
                });
                syncIniAsynchronously();
                if (gGateWindows.count > 0) {
                    gInputDraft = @"";
                    gShowingVerifiedExpiry = YES;
                    gLastError = nil;
                    NSString *expiryText = @"验证成功\n授权状态：永久离线授权";
                    for (JJVAuthGateWindow *window in gGateWindows.allValues) {
                        JJVAuthGateController *controller = (JJVAuthGateController *)window.rootViewController;
                        controller.cardField.text = @"";
                        [controller showSuccessWithExpiryText:expiryText];
                    }
                    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                        dismissVerifiedPopup();
                    });
                } else {
                    if (newlyGranted) {
                        showPermanentActivatedToast();
                    }
                    tryPresentPendingNotice();
                }
            } else if ([result[@"revoked"] boolValue] && !isAuthorized()) {
                gShowingVerifiedExpiry = NO;
                gLastError = strictString(result[@"error"]) ?: @"永久离线授权已被管理员停止，请重新验证卡密";
                recordDiagnostic(@"permanent_entitlement_revoked", @{
                    @"server_error": strictString(result[@"server_error"]) ?: @""
                });
                tryPresentPopup();
                updateGateContents();
            } else if (![result[@"response_verified"] boolValue]) {
                gNetworkBackoffStep = MIN(gNetworkBackoffStep + 1, 4);
            } else {
                gNetworkBackoffStep = 0;
            }
        });
    });
}

void refreshHeartbeatAsynchronously() {
    if (gHeartbeatRunning || gManualRequestRunning || gStartupRestoreInProgress || !gNetworkSatisfied) {
        return;
    }
    if (!isAuthorized() || !hasActiveOnlineSession() || !isHeartbeatDue()) {
        return;
    }
    gHeartbeatRunning = YES;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        NSDictionary *result = dictionaryFromJSON(performHeartbeatJSON());
        dispatch_async(dispatch_get_main_queue(), ^{
            gHeartbeatRunning = NO;
            if ([result[@"skipped"] boolValue]) return;

            if ([result[@"ok"] boolValue]) {
                gNetworkBackoffStep = 0;
                recordDiagnostic(@"heartbeat_ok", @{});
                if ([result[@"permanent_newly_granted"] boolValue]) {
                    recordDiagnostic(@"heartbeat_permanent_granted", @{});
                    if (gGateWindows.count == 0) {
                        showPermanentActivatedToast();
                    }
                }
            } else if ([result[@"revoked"] boolValue]) {
                gLastError = strictString(result[@"error"]) ?: @"授权已被撤销，请重新验证";
                recordDiagnostic(@"heartbeat_revoked", @{@"server_error": strictString(result[@"server_error"]) ?: @""});
                tryPresentPopup();
                updateGateContents();
            } else if (!isAuthorized()) {
                gLastError = strictString(result[@"error"]) ?: @"离线凭证已到期，请联网重新验证";
                tryPresentPopup();
                updateGateContents();
            } else if (![result[@"response_verified"] boolValue]) {
                gNetworkBackoffStep = MIN(gNetworkBackoffStep + 1, 4);
            }
        });
    });
}

void startNetworkPathMonitor() {
    static nw_path_monitor_t monitor;
    static dispatch_queue_t monitorQueue;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        monitorQueue = dispatch_queue_create("com.dyyli.locationtweak.nwmonitor", DISPATCH_QUEUE_SERIAL);
        monitor = nw_path_monitor_create();
        nw_path_monitor_set_update_handler(monitor, ^(nw_path_t path) {
            const BOOL satisfied = (nw_path_get_status(path) == nw_path_status_satisfied);
            dispatch_async(dispatch_get_main_queue(), ^{
                const BOOL recovered = (!gNetworkSatisfied && satisfied);
                gNetworkSatisfied = satisfied;
                if (!satisfied) return;

                // Jittered backoff self-healing when network recovers.
                double baseDelay = recovered ? 0.5 : 0.0;
                if (gNetworkBackoffStep > 0) {
                    baseDelay = MIN(30.0, (double)(1 << MIN(gNetworkBackoffStep, 4)));
                }
                double jitter = (double)arc4random_uniform(1200) / 1000.0;
                int64_t delayNs = (int64_t)((baseDelay + jitter) * NSEC_PER_SEC);
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, delayNs), dispatch_get_main_queue(), ^{
                    if (!gNetworkSatisfied || UIApplication.sharedApplication.applicationState != UIApplicationStateActive) {
                        return;
                    }
                    if (gNoticeState == NoticeState::NotRequested || gNoticeState == NoticeState::Failed) {
                        fetchNoticeAsynchronously();
                    }
                    syncIniAsynchronously();
                    refreshHeartbeatAsynchronously();
                    syncPermanentEntitlementAsynchronously(YES);
                });
            });
        });
        nw_path_monitor_set_queue(monitor, monitorQueue);
        nw_path_monitor_start(monitor);
    });
}

BOOL isKeyboardWindow(UIWindow *window) {
    NSString *name = NSStringFromClass(window.class);
    return [name rangeOfString:@"Keyboard" options:NSCaseInsensitiveSearch].location != NSNotFound ||
           [name rangeOfString:@"TextEffects" options:NSCaseInsensitiveSearch].location != NSNotFound;
}

BOOL isVisibleHostWindow(UIWindow *window) {
    return window && ![window isKindOfClass:JJVAuthGateWindow.class] &&
           ![window isKindOfClass:JJVStandaloneNoticeWindow.class] && !isKeyboardWindow(window) &&
           !window.hidden && window.alpha > 0.01 && window.rootViewController;
}

NSArray<UIWindow *> *applicationWindows(UIApplication *app) {
    NSMutableOrderedSet<UIWindow *> *windows = [NSMutableOrderedSet orderedSet];
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    [windows addObjectsFromArray:app.windows];
#pragma clang diagnostic pop
    for (UIScene *scene in app.connectedScenes) {
        if ([scene isKindOfClass:UIWindowScene.class]) {
            [windows addObjectsFromArray:((UIWindowScene *)scene).windows];
        }
    }
    if ([app.delegate respondsToSelector:@selector(window)] && app.delegate.window) {
        [windows addObject:app.delegate.window];
    }
    return windows.array;
}

UIWindow *hostKeyWindow(NSArray<UIWindow *> *windows) {
    for (UIWindow *window in windows) {
        if (isVisibleHostWindow(window) && window.isKeyWindow) return window;
    }
    for (UIWindow *window in windows) {
        if (isVisibleHostWindow(window) && window.windowLevel == UIWindowLevelNormal) return window;
    }
    for (UIWindow *window in windows) {
        if (isVisibleHostWindow(window)) return window;
    }
    return nil;
}

CGFloat gateLevelForHostWindows(NSArray<UIWindow *> *windows) {
    const CGFloat base = UIWindowLevelAlert + 1;
    CGFloat desired = base, ceiling = UIWindowLevelAlert + 10000;
    for (UIWindow *window in windows) {
        if (window.hidden || window.alpha <= 0.01 || !std::isfinite((double)window.windowLevel)) continue;
        if (isKeyboardWindow(window)) {
            if (window.windowLevel > base + 1) ceiling = MIN(ceiling, window.windowLevel - 1);
        } else if (isVisibleHostWindow(window)) {
            desired = MAX(desired, window.windowLevel + 1);
        }
    }
    return MAX(base, MIN(desired, ceiling));
}

void dismissStandaloneNotice(BOOL restoreHost) {
    JJVStandaloneNoticeWindow *window = gStandaloneNoticeWindow;
    if (!window) return;
    const BOOL wasReconciling = gReconcilingStandaloneNotice;
    gReconcilingStandaloneNotice = YES;
    gStandaloneNoticeWindow = nil;
    window.hidden = YES;
    if (restoreHost) {
        UIWindow *previous = window.previousKeyWindow;
        if (!isVisibleHostWindow(previous)) {
            previous = hostKeyWindow(applicationWindows(UIApplication.sharedApplication));
        }
        if (previous) [previous makeKeyWindow];
    }
    recordDiagnostic(@"notice_closed", @{
        @"notice_window_count": @0,
        @"notice_shown_this_launch": @(gNoticeShownThisLaunch)
    });
    gReconcilingStandaloneNotice = wasReconciling;
}

void tryPresentPendingNotice() {
    if (gReconcilingStandaloneNotice) return;
    gReconcilingStandaloneNotice = YES;
    UIApplication *app = UIApplication.sharedApplication;
    if (!noticeMayBePresented()) {
        dismissStandaloneNotice(NO);
        gReconcilingStandaloneNotice = NO;
        return;
    }
    if (app.applicationState != UIApplicationStateActive) {
        gStandaloneNoticeWindow.hidden = YES;
        gReconcilingStandaloneNotice = NO;
        return;
    }
    if (gStandaloneNoticeWindow) {
        UIWindowScene *scene = gStandaloneNoticeWindow.windowScene;
        if (scene && (scene.activationState == UISceneActivationStateBackground ||
                      scene.activationState == UISceneActivationStateUnattached)) {
            gStandaloneNoticeWindow.hidden = YES;
            if (gNoticeShownThisLaunch) {
                gReconcilingStandaloneNotice = NO;
                return;
            }
            dismissStandaloneNotice(NO);
        } else {
            if (gStandaloneNoticeWindow.hidden || !gStandaloneNoticeWindow.isKeyWindow) {
                [gStandaloneNoticeWindow makeKeyAndVisible];
            }
            [(JJVStandaloneNoticeController *)gStandaloneNoticeWindow.rootViewController reportNoticeVisibility];
            gReconcilingStandaloneNotice = NO;
            return;
        }
    }
    if (gNoticeShownThisLaunch || gNoticeDismissedWithoutText || gNoticeState != NoticeState::Ready) {
        gReconcilingStandaloneNotice = NO;
        return;
    }
    NSMutableArray<UIWindow *> *eligible = [NSMutableArray array];
    for (UIWindow *host in applicationWindows(app)) {
        if (!isVisibleHostWindow(host)) continue;
        UIWindowScene *scene = host.windowScene;
        if (!scene || (scene.activationState != UISceneActivationStateBackground &&
                       scene.activationState != UISceneActivationStateUnattached)) {
            [eligible addObject:host];
        }
    }
    UIWindow *host = hostKeyWindow(eligible);
    UIWindowScene *scene = host.windowScene;
    if (!host) {
        for (UIScene *candidate in app.connectedScenes) {
            if ([candidate isKindOfClass:UIWindowScene.class] &&
                candidate.activationState == UISceneActivationStateForegroundActive) {
                scene = (UIWindowScene *)candidate;
                break;
            }
        }
        if (!scene) {
            gReconcilingStandaloneNotice = NO;
            return;
        }
    }
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    JJVStandaloneNoticeWindow *window = scene
        ? [[JJVStandaloneNoticeWindow alloc] initWithWindowScene:scene]
        : [[JJVStandaloneNoticeWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    window.frame = scene ? scene.coordinateSpace.bounds : UIScreen.mainScreen.bounds;
#pragma clang diagnostic pop
    window.windowLevel = gateLevelForHostWindows(scene ? scene.windows : eligible);
    window.accessibilityIdentifier = @"JJVStandaloneNoticeWindow";
    window.previousKeyWindow = host;
    JJVStandaloneNoticeController *controller = [JJVStandaloneNoticeController new];
    controller.notice = gNoticeState == NoticeState::Ready ? gNoticeText : nil;
    controller.noticeDidDisplay = ^BOOL { return markNoticeDisplayed(); };
    controller.retryNotice = ^{ fetchNoticeAsynchronously(); };
    controller.closeNotice = ^{
        if (!gNoticeShownThisLaunch) gNoticeDismissedWithoutText = YES;
        dismissStandaloneNotice(YES);
    };
    window.rootViewController = controller;
    gStandaloneNoticeWindow = window;
    updateNoticeContents();
    [window makeKeyAndVisible];
    [controller.view layoutIfNeeded];
    [controller reportNoticeVisibility];
    recordDiagnostic(@"notice_window", @{
        @"notice_window_count": @1,
        @"notice_shown_this_launch": @(gNoticeShownThisLaunch)
    });
    gReconcilingStandaloneNotice = NO;
}

void ensureGateWindow(NSString *key, UIWindowScene *scene, NSArray<UIWindow *> *hostWindows) {
    JJVAuthGateWindow *window = gGateWindows[key];
    if (!window) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        window = scene ? [[JJVAuthGateWindow alloc] initWithWindowScene:scene] :
                         [[JJVAuthGateWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
        window.frame = scene ? scene.coordinateSpace.bounds : UIScreen.mainScreen.bounds;
#pragma clang diagnostic pop
        window.accessibilityIdentifier = @"JJVAuthGateWindow";
        window.previousKeyWindow = hostKeyWindow(hostWindows);
        JJVAuthGateController *controller = [JJVAuthGateController new];
        controller.submitCard = ^(NSString *card) { submitManualCard(card); };
        window.rootViewController = controller;
        [controller loadViewIfNeeded];
        controller.cardField.text = gInputDraft ?: @"";
        gGateWindows[key] = window;
    }
    window.windowLevel = gateLevelForHostWindows(hostWindows);
    if (!window.isKeyWindow) {
        UIWindow *previous = hostKeyWindow(hostWindows);
        if (previous) window.previousKeyWindow = previous;
        [window makeKeyAndVisible];
    } else if (window.hidden) {
        window.hidden = NO;
    }
}

void tryPresentPopup() {
    if (gReconcilingGateWindows) return;
    UIApplication *app = UIApplication.sharedApplication;
    if (app.applicationState == UIApplicationStateActive && gNoticeState == NoticeState::NotRequested) {
        fetchNoticeAsynchronously();
    }

    static BOOL gLoggedAuthorizedIdle = NO;
    const BOOL authorized = isAuthorized();
    if (!authorized) {
        gLoggedAuthorizedIdle = NO;
    } else if (gLoggedAuthorizedIdle && gGateWindows.count == 0 && !gStandaloneNoticeWindow &&
               (gNoticeShownThisLaunch || gNoticeDismissedWithoutText || gNoticeState != NoticeState::Ready)) {
        return;
    }

    gReconcilingGateWindows = YES;
    NSArray<UIWindow *> *windows = applicationWindows(app);
    NSUInteger visibleHosts = 0, windowScenes = 0;
    for (UIWindow *window in windows) if (isVisibleHostWindow(window)) ++visibleHosts;
    for (UIScene *scene in app.connectedScenes) if ([scene isKindOfClass:UIWindowScene.class]) ++windowScenes;

    if (authorized) {
        if (!gShowingVerifiedExpiry) {
            dismissVerifiedPopup();
        }
        gLoggedAuthorizedIdle = (gGateWindows.count == 0 && !gShowingVerifiedExpiry);
        recordDiagnostic(@"ui_state", @{
            @"authorized": @YES,
            @"ui": @"authorized_skip",
            @"scene_count": @(app.connectedScenes.count),
            @"host_window_count": @(visibleHosts),
            @"gate_window_count": @(gGateWindows.count),
            @"app_state": @(app.applicationState),
            @"notice_shown_this_launch": @(gNoticeShownThisLaunch),
            @"notice_window_count": @(gStandaloneNoticeWindow ? 1 : 0)
        });
        gReconcilingGateWindows = NO;
        return;
    }
    if (gStartupRestoreInProgress) {
        dismissGateWindows();
        recordDiagnostic(@"ui_state", @{
            @"authorized": @NO,
            @"ui": @"silent_restore",
            @"scene_count": @(app.connectedScenes.count),
            @"host_window_count": @(visibleHosts),
            @"gate_window_count": @0,
            @"app_state": @(app.applicationState),
            @"notice_shown_this_launch": @(gNoticeShownThisLaunch),
            @"notice_window_count": @(gStandaloneNoticeWindow ? 1 : 0)
        });
        gReconcilingGateWindows = NO;
        return;
    }

    if (!gGateWindows) gGateWindows = [NSMutableDictionary dictionary];
    dismissStandaloneNotice(NO);
    NSMutableSet<NSString *> *activeKeys = [NSMutableSet set];
    if (app.applicationState != UIApplicationStateBackground) {
        for (UIScene *scene in app.connectedScenes) {
            if (![scene isKindOfClass:UIWindowScene.class] ||
                scene.activationState != UISceneActivationStateForegroundActive) {
                continue;
            }
            UIWindowScene *windowScene = (UIWindowScene *)scene;
            NSString *key = [@"scene:" stringByAppendingString:scene.session.persistentIdentifier];
            [activeKeys addObject:key];
            ensureGateWindow(key, windowScene, windowScene.windows);
        }
        if (app.applicationState == UIApplicationStateActive) {
            BOOL visibleLegacyHost = NO;
            for (UIWindow *host in windows) {
                if (!isVisibleHostWindow(host)) continue;
                UIWindowScene *scene = host.windowScene;
                if (!scene) {
                    visibleLegacyHost = YES;
                    continue;
                }
                if (scene.activationState == UISceneActivationStateBackground ||
                    scene.activationState == UISceneActivationStateUnattached) {
                    continue;
                }
                NSString *key = [@"scene:" stringByAppendingString:scene.session.persistentIdentifier];
                [activeKeys addObject:key];
                ensureGateWindow(key, scene, scene.windows);
            }
            if (visibleLegacyHost || windowScenes == 0) {
                [activeKeys addObject:@"legacy"];
                NSArray<UIWindow *> *legacyWindows = [windows filteredArrayUsingPredicate:
                    [NSPredicate predicateWithBlock:^BOOL(UIWindow *window, __unused NSDictionary *bindings) {
                        return window.windowScene == nil;
                    }]];
                ensureGateWindow(@"legacy", nil, legacyWindows);
            }
        }
    }
    for (NSString *key in gGateWindows.allKeys) {
        if (![activeKeys containsObject:key]) {
            JJVAuthGateWindow *window = gGateWindows[key];
            if (!gManualRequestRunning && !gStartupRestoreInProgress) {
                JJVAuthGateController *controller = (JJVAuthGateController *)window.rootViewController;
                gInputDraft = controller.cardField.text;
            }
            [window endEditing:YES];
            window.hidden = YES;
            [gGateWindows removeObjectForKey:key];
        }
    }
    updateGateContents();
    if (gGateWindows.count && gNoticeState == NoticeState::NotRequested) fetchNoticeAsynchronously();
    NSString *state = gGateWindows.count ? @"shown" :
        (app.applicationState == UIApplicationStateBackground ? @"background" : @"waiting_for_window");
    recordDiagnostic(@"ui_state", @{
        @"authorized": @NO,
        @"ui": state,
        @"scene_count": @(app.connectedScenes.count),
        @"host_window_count": @(visibleHosts),
        @"gate_window_count": @(gGateWindows.count),
        @"app_state": @(app.applicationState),
        @"notice_shown_this_launch": @(gNoticeShownThisLaunch),
        @"notice_window_count": @0
    });
    gReconcilingGateWindows = NO;
}

}  // namespace

void showAuthPopupUI() {
    dispatch_async(dispatch_get_main_queue(), ^{
        tryPresentPopup();
    });
}

void notifyLeaseExpiredUI() {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (isAuthorized()) return;
        gShowingVerifiedExpiry = NO;
        gLastError = @"离线凭证有效期已结束，请联网输入卡密重新验证";
        tryPresentPopup();
    });
}

void initializeAuthUI() {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        recordDiagnostic(@"bootstrap_queued", @{});
        dispatch_async(dispatch_get_main_queue(), ^{
            recordDiagnostic(@"bootstrap", @{@"bootstrap_seen": @YES});
            startNetworkPathMonitor();
            restoreStartupAsynchronously();

            NSNotificationCenter *center = NSNotificationCenter.defaultCenter;
            [center addObserverForName:UIApplicationDidBecomeActiveNotification object:nil queue:NSOperationQueue.mainQueue usingBlock:^(__unused NSNotification *note) {
                isAuthorized();
                refreshHeartbeatAsynchronously();
                syncPermanentEntitlementAsynchronously(YES);
                tryPresentPopup();
            }];
            for (NSNotificationName winNote in @[UIWindowDidBecomeKeyNotification, UIWindowDidBecomeVisibleNotification]) {
                [center addObserverForName:winNote object:nil queue:NSOperationQueue.mainQueue usingBlock:^(NSNotification *note) {
                    if (![note.object isKindOfClass:JJVAuthGateWindow.class] &&
                        ![note.object isKindOfClass:JJVStandaloneNoticeWindow.class]) {
                        tryPresentPopup();
                    }
                }];
            }
            for (NSNotificationName name in @[
                UISceneDidActivateNotification,
                UISceneWillDeactivateNotification,
                UISceneDidDisconnectNotification,
                UIApplicationDidEnterBackgroundNotification
            ]) {
                [center addObserverForName:name object:nil queue:NSOperationQueue.mainQueue usingBlock:^(__unused NSNotification *note) {
                    dispatch_async(dispatch_get_main_queue(), ^{ tryPresentPopup(); });
                }];
            }
            static dispatch_source_t timer;
            timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, dispatch_get_main_queue());
            dispatch_source_set_timer(timer, dispatch_time(DISPATCH_TIME_NOW, 3 * NSEC_PER_SEC), 5 * NSEC_PER_SEC, 500 * NSEC_PER_MSEC);
            dispatch_source_set_event_handler(timer, ^{
                isAuthorized();
                if (UIApplication.sharedApplication.applicationState == UIApplicationStateActive) {
                    refreshHeartbeatAsynchronously();
                    syncPermanentEntitlementAsynchronously(NO);
                }
                tryPresentPopup();
            });
            dispatch_resume(timer);
            tryPresentPopup();
        });
    });
}

}  // namespace jjcloud
#endif
