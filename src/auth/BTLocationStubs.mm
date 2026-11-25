//
// BTLocationStubs.mm —— location-tweak 专属符号的空桩
// ============================================================
// JJCloud 模块原本是给 location-tweak 用的，里面引用了定位相关的外部符号。
// BalanceTweak 不需要定位功能，这里提供空实现让链接通过。
//
// 重要：编译时用了 -fvisibility=hidden，必须显式标记 visibility("default")
//       否则符号不可见，链接仍然失败。
// ============================================================

#import <Foundation/Foundation.h>
#include <string>

#define BT_EXPORT __attribute__((visibility("default")))

// ============================================================
// 1. dyyli_authorization_did_change 已移到 BalanceTweak.m 实现
//    （需要访问 BTSetWalletHookActive / BTInstallWalletModelHook 等）
// ============================================================

// ============================================================
// 2. 高德地图 Web 服务 Key（未使用）
// ============================================================
extern "C" BT_EXPORT void DYYLISetDynamicAmapWebServiceKey(const char *key) {
    (void)key;
}

// ============================================================
// 3. jjcloud 命名空间的定位相关函数
// ============================================================
namespace jjcloud {

BT_EXPORT bool setMockLocation(double latitude, double longitude, const std::string &address) {
    (void)latitude; (void)longitude; (void)address;
    NSLog(@"[BTStub] setMockLocation 忽略（BalanceTweak 不含定位功能）");
    return false;
}

BT_EXPORT void clearMockLocation(void) {
    // 空
}

BT_EXPORT void showLocationPicker(void) {
    // 空
}

BT_EXPORT std::string currentLocationJSON(void) {
    return std::string("{\"ok\":false,\"error\":\"location-not-supported\"}");
}

BT_EXPORT void installLocationTweak(void) {
    // 空
}

}  // namespace jjcloud
