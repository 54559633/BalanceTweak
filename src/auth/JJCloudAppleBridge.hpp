#pragma once

#include <string>

namespace jjcloud {

struct RuntimeConfig {
    std::string baseURL;
    std::string appID;
    std::string appKey;
    int timeWindowSeconds;
    bool enforceExitOnFail;
};

RuntimeConfig currentRuntimeConfig();
bool setRuntimeConfig(const RuntimeConfig& config);
bool isAuthorized();
void initializeAuthorization();
void recordAuthorizationConstructor();
std::string startupDiagnosticsJSON();
void notifyAuthorizationChanged(bool authorized);
std::string performLoginJSON(const std::string& kami, const std::string& markcode);
std::string performNoticeJSON();
void showVerificationPopup();
bool autoPopupEnabled();
void installLocationTweak();
void showLocationPicker();
bool setMockLocation(double latitude, double longitude, const std::string& address);
void clearMockLocation();
std::string currentLocationJSON();

}  // namespace jjcloud
