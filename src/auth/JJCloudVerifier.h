#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32)
#define JJV_EXPORT __declspec(dllexport)
#else
#define JJV_EXPORT __attribute__((visibility("default")))
#endif

JJV_EXPORT const char* jjv_version(void);
JJV_EXPORT const char* jjv_build_id(void);
// Read-only startup metadata and live auth summary; release results with jjv_free.
JJV_EXPORT char* jjv_startup_diagnostics_json(void);
JJV_EXPORT char* jjv_auth_summary_json(void);

JJV_EXPORT int jjv_configure(
    const char* base_url,
    const char* app_id,
    const char* app_key,
    int time_window_seconds);

JJV_EXPORT char* jjv_login_json(const char* kami, const char* markcode);
JJV_EXPORT char* jjv_notice_json(void);
JJV_EXPORT void jjv_show_popup(void);
// Real card-verification state for the persistent verification window.
// Feature execution is independent of this state in 0905R6.
JJV_EXPORT int jjv_is_authorized(void);
// 机器码：sha256(P-256 publicKey) hex，64 字符，用于后台绑定
JJV_EXPORT char* jjv_device_id(void);
// 完整设备摘要 JSON（含 device_prefix / device_key）
JJV_EXPORT char* jjv_device_info_json(void);

JJV_EXPORT void jjv_install_location_tweak(void);
JJV_EXPORT void jjv_show_location_picker(void);
JJV_EXPORT int jjv_set_mock_location(double latitude, double longitude, const char* address);
JJV_EXPORT void jjv_clear_mock_location(void);
JJV_EXPORT char* jjv_current_location_json(void);
// 直接写云端：把模拟定位写入服务端（location_sync），返回 JSON 结果，需 jjv_free。
JJV_EXPORT char* jjv_sync_location_to_cloud(double latitude, double longitude, const char* address, int active);
// 云端读取：从服务端读回定位配置（location_get），返回 JSON 结果，需 jjv_free。
JJV_EXPORT char* jjv_fetch_location_from_cloud(void);

JJV_EXPORT void jjv_free(char* text);

#ifdef __cplusplus
}
#endif
