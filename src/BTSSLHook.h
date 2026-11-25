//
// BTSSLHook.h —— BoringSSL SSL_read/SSL_write 底层 hook
// ============================================================
// 原理：
//   抖音的所有 HTTPS 流量都经过 boringssl（独立 dylib）
//   SSL_read 返回**解密后的明文**
//   在这里拦截，能拿到所有 HTTP 响应的原始字节
//   不管上层用 TTNet / Cronet / 原生，统统经过这里
//
// 阶段：
//   阶段 1（本文件）：观察模式 —— 只在数据里搜 wallet/info 特征，打日志
//   阶段 2：确认能拦到后，改成改写模式
//
// 难点（改写阶段要处理）：
//   · SSL_read 是流式读，一次只返回一部分
//   · HTTP/2 帧有 Length 字段，改 payload 要同步改 Length
//   · gRPC DATA 帧可能分片
// ============================================================

#ifndef BTSSLHook_h
#define BTSSLHook_h

#import <Foundation/Foundation.h>

/// 安装 SSL hook（观察模式）
void BTInstallSSLHook(void);

/// 切换为改写模式
void BTSetSSLHookPatchEnabled(BOOL enabled);

/// 统计信息
typedef struct {
    unsigned long long totalReads;      // SSL_read 总调用
    unsigned long long totalBytes;      // 总字节
    unsigned long long walletHits;      // wallet/info 命中次数
    unsigned long long patched;         // 改写次数
} BTSSLStats;

void BTGetSSLStats(BTSSLStats *out);

#endif /* BTSSLHook_h */
