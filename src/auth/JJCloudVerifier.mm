#include "JJCloudVerifier.h"

#include "JJCloudAppleBridge.hpp"
#include "JJCloudAuthInternal.hpp"

#include <cstdlib>
#include <cstring>

#import <Foundation/Foundation.h>

extern "C" void dyyli_authorization_did_change(int authorized) __attribute__((weak_import));

namespace jjcloud {
void notifyAuthorizationChanged(bool authorized) {
    (void)authorized;
    void (^notify)(void) = ^{
        if (dyyli_authorization_did_change) {
            // A queued notification must reflect current state, not an older
            // network result. No authorization mutex is held during callbacks.
            dyyli_authorization_did_change(isAuthorized() ? 1 : 0);
        }
    };
    if ([NSThread isMainThread]) notify();
    else dispatch_async(dispatch_get_main_queue(), notify);
}
}  // namespace jjcloud

namespace {

char* copyCString(const std::string& value) {
    char* out = static_cast<char*>(std::malloc(value.size() + 1));
    if (!out) {
        return nullptr;
    }
    std::memcpy(out, value.c_str(), value.size() + 1);
    return out;
}

}  // namespace

#ifndef JJV_AUTH_TESTING
#include "JJVServerConfig.h"
#endif
#ifndef JJV_BUILD_VERSION
#define JJV_BUILD_VERSION "0905R10"
#endif

const char* jjv_version(void) {
    return "2.2.0";
}
const char* jjv_build_id(void) {
    return JJV_BUILD_VERSION;
}
char* jjv_startup_diagnostics_json(void) {
    return copyCString(jjcloud::startupDiagnosticsJSON());
}
char* jjv_auth_summary_json(void) {
    return copyCString(jjcloud::authSummaryJSON());
}

int jjv_configure(const char* base_url, const char* app_id, const char* app_key, int time_window_seconds) {
    jjcloud::RuntimeConfig config = jjcloud::currentRuntimeConfig();
    if (base_url && base_url[0] != '\0') {
        config.baseURL = base_url;
    }
    if (app_id && app_id[0] != '\0') {
        config.appID = app_id;
    }
    if (app_key && app_key[0] != '\0') {
        config.appKey = app_key;
    }
    if (time_window_seconds > 0) {
        config.timeWindowSeconds = time_window_seconds;
    }
    return jjcloud::setRuntimeConfig(config) ? 1 : 0;
}

char* jjv_login_json(const char* kami, const char* markcode) {
    const std::string kamiValue = kami ? kami : "";
    const std::string markcodeValue = markcode ? markcode : "";
    return copyCString(jjcloud::performLoginJSON(kamiValue, markcodeValue));
}

char* jjv_notice_json(void) {
    return copyCString(jjcloud::performNoticeJSON());
}

void jjv_show_popup(void) {
    jjcloud::showVerificationPopup();
}

int jjv_is_authorized(void) {
    return jjcloud::isAuthorized() ? 1 : 0;
}

void jjv_install_location_tweak(void) {
    jjcloud::installLocationTweak();
}

void jjv_show_location_picker(void) {
    jjcloud::showLocationPicker();
}

int jjv_set_mock_location(double latitude, double longitude, const char* address) {
    const std::string addressValue = address ? address : "";
    return jjcloud::setMockLocation(latitude, longitude, addressValue) ? 1 : 0;
}

void jjv_clear_mock_location(void) {
    jjcloud::clearMockLocation();
}

char* jjv_current_location_json(void) {
    return copyCString(jjcloud::currentLocationJSON());
}

char* jjv_sync_location_to_cloud(double latitude, double longitude, const char* address, int active) {
    const std::string addressValue = address ? address : "";
    return copyCString(jjcloud::performLocationSyncJSON(latitude, longitude, addressValue, active != 0));
}

char* jjv_fetch_location_from_cloud(void) {
    return copyCString(jjcloud::performLocationFetchJSON());
}

void jjv_free(char* text) {
    std::free(text);
}

// R9: Use priority 101 (earliest user priority) to ensure Hook installs before other plugins
__attribute__((constructor(101))) static void jjv_constructor(void) {
    @autoreleasepool {
        jjcloud::recordAuthorizationConstructor();
        jjcloud::installLocationTweak();

        jjcloud::initializeAuthorization();
    }
}
