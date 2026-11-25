//
// BTProtocol.h —— NSURLProtocol 拦截器（简化版，用 C 函数指针）
// ============================================================

#ifndef BTProtocol_h
#define BTProtocol_h

#import <Foundation/Foundation.h>

/// 改写回调：输入 (url, 原始数据) → 返回新数据（nil 表示不改）
typedef NSData *(*BTPatchFunc)(NSURL *url, NSData *data);

/// 注册拦截器
void BTInstallURLProtocol(void);

/// 设置改写函数
void BTSetPatchFunc(BTPatchFunc func);

#endif /* BTProtocol_h */
