//
// BTUpdateBlocker.h —— 屏蔽抖音应用内版本检查与更新弹窗
// ============================================================
// 本功能强制启用，不读取任何偏好开关，也不在界面提供关闭入口。
// ============================================================

#ifndef BTUpdateBlocker_h
#define BTUpdateBlocker_h

#import <Foundation/Foundation.h>

/// 安装版本检查屏蔽。幂等，可在任意线程调用。
/// 抖音的类可能晚于本 dylib 注册，内部已挂 dyld 镜像加载回调补装。
void BTInstallUpdateBlocking(void);

/// 已成功挂钩的目标数量（0...2），用于日志与自检。
NSInteger BTUpdateBlockingInstalledCount(void);

#endif /* BTUpdateBlocker_h */
