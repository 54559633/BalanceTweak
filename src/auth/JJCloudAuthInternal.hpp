#pragma once

#include <cstdint>
#include <string>

#import <Foundation/Foundation.h>
#import <TargetConditionals.h>

#if defined(JJV_AUTH_UI_TESTING) && !defined(JJV_AUTH_TESTING)
#error "UI testing requires the isolated offline authentication test build"
#endif
#if TARGET_OS_IPHONE && (!defined(JJV_AUTH_TESTING) || defined(JJV_AUTH_UI_TESTING))
#define JJV_AUTH_UI_ENABLED 1
#else
#define JJV_AUTH_UI_ENABLED 0
#endif

namespace jjcloud {

NSString *ns(const std::string& value);
std::string cpp(NSString *value);
NSString *strictString(id value);
NSString *trimmed(NSString *text);
NSDictionary *dictionaryFromJSON(const std::string& text);
NSMutableDictionary *errorResult(NSString *error, bool verified = false, long long code = 0);

double wallNow();
double steadyNow();
double currentAuthorizationExpiryWall();
bool isPermanentOfflineAuthorized();
bool isLoginInFlight();
bool isHeartbeatDue();
bool hasActiveOnlineSession();
bool isGenerationCurrent(std::uint64_t generation);
std::string currentDeviceIdPrefix();
std::string currentDeviceIdHex();
std::string authSummaryJSON();

void revokeAuthorization(bool clearPersistedLicenses = false);
std::string performHeartbeatJSON();
std::string performIniJSON();
std::string performPermanentEntitlementSyncJSON();
// 直接把当前模拟定位写进云端（"location_sync"），与 heartbeat 共用同一加密会话。
std::string performLocationSyncJSON(double latitude, double longitude, const std::string& address, bool active);
// 从云端读回定位配置（"location_get"）。
std::string performLocationFetchJSON();
std::string restoreStartupAuthorization();
void recordDiagnostic(NSString *event, NSDictionary *fields);

#if JJV_AUTH_UI_ENABLED
void initializeAuthUI();
void showAuthPopupUI();
void notifyLeaseExpiredUI();
#endif

}  // namespace jjcloud
