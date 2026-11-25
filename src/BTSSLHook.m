//
// BTSSLHook.m —— BoringSSL SSL_read 底层 hook（观察版）
// ============================================================
#import "BTSSLHook.h"
#import "BTLog.h"
#import "BTFishhook.h"
#import <dlfcn.h>
#import <objc/runtime.h>
#include <string.h>
#include <os/lock.h>
#include <mach-o/dyld.h>

// ============================================================
// 原函数指针
// ============================================================
typedef int (*SSL_read_fn)(void *ssl, void *buf, int num);
typedef int (*SSL_write_fn)(void *ssl, void *buf, int num);
typedef int (*SSL_get_error_fn)(const void *ssl, int ret);

static SSL_read_fn      g_orig_SSL_read      = NULL;
static SSL_write_fn     g_orig_SSL_write     = NULL;
static SSL_get_error_fn g_orig_SSL_get_error = NULL;

static BOOL g_patchEnabled = NO;
static BTSSLStats g_stats = {0};
static os_unfair_lock g_statsLock = OS_UNFAIR_LOCK_INIT;

void BTSetSSLHookPatchEnabled(BOOL enabled) {
    g_patchEnabled = enabled;
    BT_LOG_M(@"SSLHook", @"改写模式: %@", enabled ? @"开" : @"关");
}

void BTGetSSLStats(BTSSLStats *out) {
    if (!out) return;
    os_unfair_lock_lock(&g_statsLock);
    *out = g_stats;
    os_unfair_lock_unlock(&g_statsLock);
}

// ============================================================
// 特征检测
// ============================================================
// wallet/info 的 protobuf 响应特征：
//   0A 07 28 XX XX XX XX XX   field1 {field5: 时间戳}
//   12 XX 0A XX 10 XX...       field2 {field1 {field2: UID, field3: 余额}}
//
// 更可靠：搜 UID 前缀 / 或响应长度特征
// 实测响应 27-30 字节，极短

/// 在 buffer 里搜特征字符串
static const char *detectFeature(const uint8_t *buf, size_t len) {
    if (!buf || len < 8) return NULL;

    static const char *patterns[] = {
        "wallet/info",
        "/webcast/wallet",
        "wallet_api/recharge_page",
        "wallet/core/v1/homepage",
        "\x18\xb1\x01\x70",     // field3=177 field14 开头（可能是余额）
    };
    static const size_t plens[] = {11, 15, 24, 23, 4};

    for (int i = 0; i < 5; i++) {
        const char *p = patterns[i];
        size_t plen = plens[i];
        if (len < plen) continue;

        for (size_t j = 0; j + plen <= len; j++) {
            if (memcmp(buf + j, p, plen) == 0) {
                return p;
            }
        }
    }
    return NULL;
}

/// 判断是不是 HTTP 请求（含 URL）
static BOOL looksLikeHTTPRequest(const uint8_t *buf, size_t len) {
    if (len < 4) return NO;
    // HTTP/1.x 请求
    if (len >= 4 && (memcmp(buf, "GET ", 4) == 0 || memcmp(buf, "POST", 4) == 0)) return YES;
    // HTTP/2 preface / HEADERS 帧（难以直接识别）
    return NO;
}

// ============================================================
// SSL_read hook
// ============================================================
static int my_SSL_read(void *ssl, void *buf, int num) {
    if (!g_orig_SSL_read) return -1;

    int ret = g_orig_SSL_read(ssl, buf, num);

    if (ret > 0 && buf) {
        os_unfair_lock_lock(&g_statsLock);
        g_stats.totalReads++;
        g_stats.totalBytes += (unsigned long long)ret;
        os_unfair_lock_unlock(&g_statsLock);

        const char *hit = detectFeature((const uint8_t *)buf, (size_t)ret);
        if (hit) {
            os_unfair_lock_lock(&g_statsLock);
            g_stats.walletHits++;
            unsigned long long hits = g_stats.walletHits;
            os_unfair_lock_unlock(&g_statsLock);

            BT_LOG_M(@"SSLHook", @"★★★ 命中 #%llu  ssl=%p  %dB  特征=\"%s\"",
                     hits, ssl, ret, hit);

            // 十六进制 dump 前 64 字节
            NSMutableString *hex = [NSMutableString string];
            const uint8_t *bytes = (const uint8_t *)buf;
            size_t dumpLen = (size_t)ret > 64 ? 64 : (size_t)ret;
            for (size_t i = 0; i < dumpLen; i++) {
                [hex appendFormat:@"%02x", bytes[i]];
            }
            BT_LOG_M(@"SSLHook", @"   hex: %@", hex);
        }
    }
    return ret;
}

// ============================================================
// SSL_write hook（请求，用来识别 URL）
// ============================================================
static int my_SSL_write(void *ssl, void *buf, int num) {
    if (!g_orig_SSL_write) return -1;

    if (num > 0 && buf) {
        const char *hit = detectFeature((const uint8_t *)buf, (size_t)num);
        if (hit) {
            BT_LOG_M(@"SSLHook", @"[REQ] ssl=%p %dB 特征=\"%s\"", ssl, num, hit);
        }
    }

    return g_orig_SSL_write(ssl, buf, num);
}

// ============================================================
// 安装
// ============================================================

/// 尝试在不同路径找符号
static void *findSymbol(const char *name) {
    // 1. 全局符号（如果已加载）
    void *p = dlsym(RTLD_DEFAULT, name);
    if (p) return p;

    // 2. 显式 dlopen boringssl
    static void *hBS = NULL;
    if (!hBS) {
        const char *paths[] = {
            "@rpath/boringssl.framework/boringssl",
            "@executable_path/Frameworks/boringssl.framework/boringssl",
            "boringssl.framework/boringssl",
            NULL,
        };
        for (int i = 0; paths[i]; i++) {
            hBS = dlopen(paths[i], RTLD_NOW | RTLD_GLOBAL);
            if (hBS) {
                BT_LOG_M(@"SSLHook", @"dlopen 成功: %s", paths[i]);
                break;
            }
        }
    }
    if (hBS) {
        p = dlsym(hBS, name);
        if (p) return p;
    }

    // 3. 遍历所有已加载模块找
    int count = _dyld_image_count();
    for (int i = 0; i < count; i++) {
        const char *imgName = _dyld_get_image_name(i);
        if (!imgName) continue;
        if (!strstr(imgName, "boringssl") && !strstr(imgName, "AwemeCore")) continue;

        void *h = dlopen(imgName, RTLD_NOW | RTLD_NOLOAD);
        if (!h) continue;
        p = dlsym(h, name);
        if (p) {
            BT_LOG_M(@"SSLHook", @"从 %s 找到 %s", imgName, name);
            return p;
        }
    }

    return NULL;
}

/// 用 fishhook 风格替换 GOT 表项（简化版：直接改 __la_symbol_ptr）
/// 局限：只能改本进程内该符号的调用点
static BOOL patchSymbol(const char *name, void *replacement, void **outOrig) {
    void *orig = findSymbol(name);
    if (!orig) {
        BT_LOG_M(@"SSLHook", @"找不到符号 %s", name);
        return NO;
    }
    *outOrig = orig;
    BT_LOG_M(@"SSLHook", @"符号 %s = %p", name, orig);

    // 注意：这里不能直接改 boringssl 内部的实现
    // 因为 boringssl 是被其他模块调用的
    // 真正的 hook 需要 fishhook 改 GOT 表
    return YES;
}

void BTInstallSSLHook(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        BT_LOG_M(@"SSLHook", @"========== 开始 hook SSL ==========");

        struct bt_rebinding rebindings[] = {
            {"SSL_read",  (void *)my_SSL_read,  (void **)&g_orig_SSL_read},
            {"SSL_write", (void *)my_SSL_write, (void **)&g_orig_SSL_write},
        };

        int bound = bt_rebind_symbols(rebindings, sizeof(rebindings) / sizeof(rebindings[0]));

        BT_LOG_M(@"SSLHook", @"fishhook 完成: 绑定 %d 处", bound);
        BT_LOG_M(@"SSLHook", @"  SSL_read  原地址: %p", g_orig_SSL_read);
        BT_LOG_M(@"SSLHook", @"  SSL_write 原地址: %p", g_orig_SSL_write);

        if (bound == 0) {
            BT_LOG_M(@"SSLHook", @"✗ 没有绑定成功，boringssl 可能未加载或符号不可达");
        }
        BT_LOG_M(@"SSLHook", @"========== hook 结束 ==========");
    });
}