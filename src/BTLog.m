//
// BTLog.m —— 日志文件写入实现
// ============================================================
#import "BTLog.h"
#include <stdio.h>
#include <pthread.h>
#include <sys/stat.h>
#include <unistd.h>

static NSString *g_logPath = nil;
static pthread_mutex_t g_logLock = PTHREAD_MUTEX_INITIALIZER;

/// 尝试找可写的日志路径
static NSString *bt_find_log_path(void) {
    // 1. 优先 /var/mobile/Media/（文件 App 可见，需要 App 有权限）
    NSArray *candidates = @[
        @"/var/mobile/Media/BalanceTweak.log",
        @"/var/mobile/Documents/BalanceTweak.log",
        @"/tmp/BalanceTweak.log",
    ];

    for (NSString *p in candidates) {
        // 测试可写
        NSString *dir = [p stringByDeletingLastPathComponent];
        if (![[NSFileManager defaultManager] fileExistsAtPath:dir]) continue;

        FILE *f = fopen([p UTF8String], "a");
        if (f) {
            fclose(f);
            // 设置权限 666 让文件 App 可读
            chmod([p UTF8String], 0666);
            return p;
        }
    }

    // 2. App 沙盒 Documents
    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    if (docs) {
        return [docs stringByAppendingPathComponent:@"BalanceTweak.log"];
    }

    // 3. tmp
    return [NSTemporaryDirectory() stringByAppendingPathComponent:@"BalanceTweak.log"];
}

NSString *BTLogFilePath(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        g_logPath = bt_find_log_path();
        // 启动分隔线
        NSString *header = [NSString stringWithFormat:
            @"\n========== BalanceTweak 启动 %@ ==========\n",
            [NSDate date]];
        BTLogWrite(header);
    });
    return g_logPath;
}

void BTLogWrite(NSString *msg) {
    if (!msg) return;

    pthread_mutex_lock(&g_logLock);

    // 确保路径已初始化（注意：BTLogFilePath 内部会调 BTLogWrite，需要防递归）
    static BOOL initializing = NO;
    if (!g_logPath && !initializing) {
        initializing = YES;
        g_logPath = bt_find_log_path();
        initializing = NO;
    }

    if (g_logPath) {
        FILE *f = fopen([g_logPath UTF8String], "a");
        if (f) {
            NSString *line = [NSString stringWithFormat:@"%@\n", msg];
            fputs([line UTF8String], f);
            fclose(f);
        }
    }

    pthread_mutex_unlock(&g_logLock);
}

void BTLogClear(void) {
    pthread_mutex_lock(&g_logLock);
    if (g_logPath) {
        [[NSFileManager defaultManager] removeItemAtPath:g_logPath error:nil];
    }
    pthread_mutex_unlock(&g_logLock);
}
