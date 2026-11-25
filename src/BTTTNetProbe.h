//
// BTTTNetProbe.h —— TTNet 运行时探测钩子
// ============================================================
// 目的：抖音不走 NSURLSession，走 TTNet（C++ Cronet）
//       需要在 ObjC 层找到 TTNetResponse 的数据出口
//
// 策略：
//   1. 遍历所有类，找名称含 NetResponse / Response / TTHttp / NetTask 的
//   2. 枚举它们的实例方法
//   3. hook 所有签名像 (data / response / body) 的方法
//   4. 在 hook 里打印类名+方法名+数据大小，确认哪个能拿到 wallet/info 响应
//   5. 找到后用同样的方式改写
// ============================================================

#ifndef BTTTNetProbe_h
#define BTTTNetProbe_h

#import <Foundation/Foundation.h>

/// 安装探测钩子（只打印，不改写）
void BTInstallTTNetProbe(void);

/// 停止探测（找到目标后调用，减少性能开销）
void BTStopTTNetProbe(void);

#endif /* BTTTNetProbe_h */
