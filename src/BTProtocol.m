//
// BTProtocol.m —— NSURLProtocol 拦截器实现（简化版）
// ============================================================
#import "BTProtocol.h"
#import "BTLog.h"

#define BTPLOG(fmt, ...) BT_LOG_M(@"BTProtocol", fmt, ##__VA_ARGS__)

static BTPatchFunc g_patchFunc = NULL;

void BTSetPatchFunc(BTPatchFunc func) {
    g_patchFunc = func;
    BTPLOG(@"patch func 已设置");
}

// ============================================================
@interface BTURLProtocol : NSURLProtocol
@property (nonatomic, strong) NSURLSessionDataTask *task;
@property (nonatomic, strong) NSMutableData *buffer;
@end

@implementation BTURLProtocol

+ (BOOL)canInitWithRequest:(NSURLRequest *)request {
    NSString *scheme = request.URL.scheme.lowercaseString;
    if (![scheme isEqualToString:@"http"] && ![scheme isEqualToString:@"https"]) {
        return NO;
    }
    if ([NSURLProtocol propertyForKey:@"BT_handled" inRequest:request]) {
        return NO;
    }

    // ★ 精确过滤：只拦截余额相关接口，其他一概不碰
    NSString *path = request.URL.path ?: @"";
    if ([path containsString:@"/webcast/wallet/info/"] ||
        [path containsString:@"wallet_api/recharge_page"] ||
        [path containsString:@"wallet/core/v1/homepage/index"] ||
        [path containsString:@"wallet/core/v1/portal/polling"]) {
        return YES;
    }
    return NO;
}

+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request {
    return request;
}

- (void)startLoading {
    NSURL *url = self.request.URL;

    NSMutableURLRequest *req = [self.request mutableCopy];
    [NSURLProtocol setProperty:@YES forKey:@"BT_handled" inRequest:req];

    self.buffer = [NSMutableData data];

    static NSURLSession *session = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSURLSessionConfiguration *cfg = [NSURLSessionConfiguration defaultSessionConfiguration];
        cfg.protocolClasses = @[];
        session = [NSURLSession sessionWithConfiguration:cfg];
    });

    __weak typeof(self) weakSelf = self;
    self.task = [session dataTaskWithRequest:req
                          completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        __strong typeof(weakSelf) self2 = weakSelf;
        if (!self2) return;

        if (error) {
            [self2.client URLProtocol:self2 didFailWithError:error];
            return;
        }

        NSData *outData = data;
        if (data && data.length > 0 && g_patchFunc) {
            @try {
                NSData *patched = g_patchFunc(url, data);
                if (patched && patched.length > 0) {
                    outData = patched;
                }
            } @catch (NSException *e) {
                BTPLOG(@"改写异常: %@", e);
            }
        }

        [self2.client URLProtocol:self2
              didReceiveResponse:response
              cacheStoragePolicy:NSURLCacheStorageNotAllowed];
        [self2.client URLProtocol:self2 didLoadData:outData];
        [self2.client URLProtocolDidFinishLoading:self2];
    }];
    [self.task resume];
}

- (void)stopLoading {
    if (self.task) {
        [self.task cancel];
        self.task = nil;
    }
}

@end

#import <objc/runtime.h>

static void btInjectProtocolIntoConfig(NSURLSessionConfiguration *cfg) {
    if (!cfg) return;
    NSArray<Class> *existing = cfg.protocolClasses ?: @[];
    if ([existing containsObject:[BTURLProtocol class]]) return;
    NSMutableArray<Class> *arr = [NSMutableArray arrayWithObject:[BTURLProtocol class]];
    [arr addObjectsFromArray:existing];
    cfg.protocolClasses = arr;
}

static void btHookSessionConfiguration(SEL sel) {
    Class cls = [NSURLSessionConfiguration class];
    Method m = class_getClassMethod(cls, sel);
    if (!m) return;
    IMP origImp = method_getImplementation(m);
    typedef NSURLSessionConfiguration *(*Fn)(id, SEL);
    Fn fn = (Fn)origImp;
    NSURLSessionConfiguration *(^blk)(id) = ^NSURLSessionConfiguration *(id self_) {
        NSURLSessionConfiguration *cfg = fn(self_, sel);
        btInjectProtocolIntoConfig(cfg);
        return cfg;
    };
    method_setImplementation(m, imp_implementationWithBlock(blk));
}

// ============================================================
void BTInstallURLProtocol(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        BOOL ok = [NSURLProtocol registerClass:[BTURLProtocol class]];
        btHookSessionConfiguration(@selector(defaultSessionConfiguration));
        btHookSessionConfiguration(@selector(ephemeralSessionConfiguration));
        BTPLOG(@"NSURLProtocol 注册%@（已注入 NSURLSessionConfiguration）", ok ? @"成功" : @"失败");
    });
}
