//
// BTLog.h —— 统一日志（NSLog + 文件双写）
// ============================================================
// 目的：注入到别的手机时，用户无法看 syslog
//       所以把日志同时写到文件，用户可以直接读
//
// 日志优先级：
//   1. /var/mobile/Media/BalanceTweak.log   （文件 App 可见）
//   2. App 沙盒 Documents/BalanceTweak.log
//   3. 仅 NSLog
// ============================================================

#ifndef BTLog_h
#define BTLog_h

#import <Foundation/Foundation.h>

/// 统一日志宏
#define BT_LOG(fmt, ...) do { \
    NSString *_s = [NSString stringWithFormat:fmt, ##__VA_ARGS__]; \
    NSLog(@"[BalanceTweak] %@", _s); \
    BTLogWrite(_s); \
} while (0)

/// 带模块前缀
#define BT_LOG_M(mod, fmt, ...) do { \
    NSString *_s = [NSString stringWithFormat:fmt, ##__VA_ARGS__]; \
    NSLog(@"[%@] %@", mod, _s); \
    BTLogWrite([NSString stringWithFormat:@"[%@] %@", mod, _s]); \
} while (0)

/// 写一行到日志文件
void BTLogWrite(NSString *msg);

/// 返回日志文件路径（首次调用时初始化）
NSString *BTLogFilePath(void);

/// 清空日志
void BTLogClear(void);

#endif /* BTLog_h */
