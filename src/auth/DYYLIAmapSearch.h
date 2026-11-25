#import <Foundation/Foundation.h>
#import <TargetConditionals.h>

#if TARGET_OS_IPHONE
#import <CoreLocation/CoreLocation.h>

NS_ASSUME_NONNULL_BEGIN

@interface DYYLIAmapSearchResult : NSObject
@property (nonatomic, assign) CLLocationCoordinate2D coordinate;
@property (nonatomic, copy) NSString *title;
@property (nonatomic, copy) NSString *subtitle;
+ (instancetype)resultWithCoordinate:(CLLocationCoordinate2D)coordinate
                               title:(nullable NSString *)title
                            subtitle:(nullable NSString *)subtitle;
@end

/// Handle that allows cancelling an in-flight multi-step AMap search or regeocode request.
@interface DYYLIAmapRequestHandle : NSObject
- (void)cancel;
@property (nonatomic, readonly, getter=isCancelled) BOOL cancelled;
@end

typedef void (^DYYLIAddressSearchCompletion)(NSArray<DYYLIAmapSearchResult *> * _Nullable results,
                                             NSError * _Nullable error);
typedef void (^DYYLIReverseGeocodeCompletion)(NSString * _Nullable address,
                                              NSError * _Nullable error);

#ifdef __cplusplus
extern "C" {
#endif

FOUNDATION_EXPORT NSString *DYYLIAmapWebServiceKey(void);
FOUNDATION_EXPORT void DYYLISetDynamicAmapWebServiceKey(NSString * _Nullable key);
FOUNDATION_EXPORT NSError *DYYLIError(NSInteger code, NSString * _Nullable message);
FOUNDATION_EXPORT NSString * _Nullable DYYLIStringValue(id _Nullable value);
FOUNDATION_EXPORT NSString *DYYLITrimmedString(NSString * _Nullable string);
FOUNDATION_EXPORT NSString *DYYLIJoinedNonEmptyStrings(NSArray<NSString *> *parts, NSString *separator);
FOUNDATION_EXPORT NSString *DYYLIDisplayAddress(NSString * _Nullable title, NSString * _Nullable subtitle);
FOUNDATION_EXPORT BOOL DYYLIParseStrictDouble(id _Nullable value, double * _Nullable outValue);
FOUNDATION_EXPORT BOOL DYYLIParseAmapLocationString(id _Nullable value, CLLocationCoordinate2D * _Nullable coord);
FOUNDATION_EXPORT CLLocationCoordinate2D DYYLIGCJ02ToWGS84(CLLocationCoordinate2D gcjCoord);

FOUNDATION_EXPORT DYYLIAmapRequestHandle *DYYLISearchAmapAddress(NSString *keyword,
                                                                 DYYLIAddressSearchCompletion completion);
FOUNDATION_EXPORT DYYLIAmapRequestHandle *DYYLIReverseGeocodeCoordinate(CLLocationCoordinate2D coord,
                                                                        DYYLIReverseGeocodeCompletion completion);

#ifdef __cplusplus
}
#endif

NS_ASSUME_NONNULL_END
#endif
