//
// BTLocationStubs.mm —— location-tweak 专属符号的空桩
// ============================================================
// JJCloud 模块原本是给 location-tweak 用的，里面引用了定位相关的外部符号。
// BalanceTweak 不需要定位功能，这里提供空实现让链接通过。
//
// 保留的：卡密验证（jjv_*）、网络、加密、UI 弹窗
// 桩掉的：定位设置/清除/选择器/高德 key/授权回调
// ============================================================

#import <Foundation/Foundation.h>
#include <string>

// ============================================================
// 1. 授权变更回调（原项目用 weak_import，这里给个真实实现）
// ============================================================
extern "C" void dyyli_authorization_did_change(int authorized) {
    NSLog(@"[BTStub] dyyli_authorization_did_change(%d)", authorized);
}

// ============================================================
// 2. 高德地图 Web 服务 Key（未使用）
// ============================================================
extern "C" void DYYLISetDynamicAmapWebServiceKey(const char *key) {
    (void)key;
}

// ============================================================
// 3. jjcloud 命名空间的定位相关函数
// ============================================================
namespace jjcloud {

bool setMockLocation(double latitude, double longitude, const std::string &address) {
    (void)latitude; (void)longitude; (void)address;
    NSLog(@"[BTStub] setMockLocation 忽略（BalanceTweak 不含定位功能）");
    return false;
}

void clearMockLocation(void) {
    // 空
}

void showLocationPicker(void) {
    // 空
}

std::string currentLocationJSON(void) {
    return std::string("{\"ok\":false,\"error\":\"location-not-supported\"}");
}

void installLocationTweak(void) {
    // 空
}

}  // namespace jjcloud
