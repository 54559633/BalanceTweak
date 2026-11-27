# 版本合并备份报告：`v9` · 屏蔽抖音版本检查

## 1. 备份元信息

| 项目 | 内容 |
|---|---|
| **备份时间** | 2026-11-27 |
| **版本标识** | `v9`（日志横幅 `v9+AuthGate+UpdateBlock`） |
| **合并方式** | 直接合并（`--no-ff`） |
| **合并提交 (HEAD)** | `5b2eeee`（功能提交 `3f2ec50` / `2036b57` / `56e5cb9`） |
| **上一版本基线** | `6def72b`（`feat(gate): block settings UI when unauthorized - log only`） |
| **合并前基线标签** | `backup-pre-update-block-6def72b` |
| **本次备份标签** | `backup-v9-update-block-20261127` |
| **发布标签** | `v9` |
| **CI 构建验证** | Run `45953982131`（`Build Dylib`，test + build 两个 job 全部通过） |
| **功能分支** | `feat/update-blocker`（3 个提交） |

### 成品校验和

| 文件 | 大小 | SHA-256 |
|---|---|---|
| `BalanceTweak.dylib` | 817,056 B | `574352CA299EC281D7C7F306DDF52AFFC4E0290D0745B87796D01C390297D237` |

架构：`arm64 + arm64e`（fat，两切片各 390,848 / 407,456 字节）。

---

## 2. 本次改动

### 新增

| 文件 | 行数 | 说明 |
|---|---|---|
| `src/BTUpdateBlocker.h` | 19 | 对外接口：`BTInstallUpdateBlocking()`、`BTUpdateBlockingInstalledCount()` |
| `src/BTUpdateBlocker.m` | 188 | 实现 |

### 修改

| 文件 | 改动 |
|---|---|
| `src/BalanceTweak.m` | `#import "BTUpdateBlocker.h"`；`BTInit` 中在授权判断**之前**调用 `BTInstallUpdateBlocking()` |
| `.github/workflows/build.yml` | arm64 / arm64e 的编译列表与链接列表各加一项（共 4 处） |
| `.github/workflows/build-linux.yml` | 两处编译列表 |
| `README.md` | 功能列表补充 |

### 行为

- `AWEVersionUpdateAlert -canShow` → 恒 `NO`
- `AWENewVersionAlertManager` 的 5 个检查入口 → 空实现
- **强制启用**：不读任何 `NSUserDefaults` 键，界面无关闭入口
- **独立于卡密门禁**：`BTApplyAuthGate` 只控制 `BTSetWalletHookActive` / `BTSetTTNetActive`，不影响本模块

---

## 3. 依赖变更

无新增框架。`BTUpdateBlocker.m` 只依赖 `Foundation` + `objc/runtime.h` + `string.h`，
均已由现有链接参数覆盖。

**不含任何网络请求、不含任何账号相关逻辑。**
（原包 `屏蔽抖音检测更新 1.0.2` 夹带的 `AWEOFGUser followWithUid:...` 关注逻辑完全剔除，
产物中 `AWEOFGUser` / `followWithUid` / `secUid` / `94406244690` 字符串均为 absent。）

---

## 4. 构建期发现并修复的两个问题

| # | 错误 | 原因与修正 |
|---|---|---|
| 1 | `call to undeclared function 'BTUPhookInstanceMethod'` | 定义处为 `BTUPHookInstanceMethod`（大写 H），两处调用点误写成小写 h |
| 2 | `Undefined symbols: _dyld_register_func_for_add_image` | 该符号在 iOS SDK 的 libSystem 导出表中不存在（同仓 `BTFishhook.c` 用的 `_dyld_image_count` 等则正常）。不为一个符号放宽整个链接参数（`-undefined dynamic_lookup` 会掩盖全部未定义符号），改用 0.5s / 1.5s / 3s / 6s 四次定时重试补装，效果等价 |

---

## 5. 回滚

```bash
# 回到 v8 (6def72b)
git checkout backup-pre-update-block-6def72b

# 撤销本次合并
git revert -m 1 5b2eeee

# 产物复原
git checkout backup-pre-update-block-6def72b
# 重新走 CI 构建即可
```

运行时：本模块无开关，属编译期固化。要停用它只能回退到 `6def72b` 重新构建。

---

## 6. 已知限制

1. **只挡抖音自己发起的检查**。App Store 的自动更新是 iOS 系统层行为，注入在抖音进程内的代码无法拦截，需在系统设置中关闭自动更新。
2. 5 个选择器名取自抖音实测版本。抖音改名后需在 `BTUPVersionCheckSelectors()` 追加。
3. 若某版本中 `canShow` 或检查方法的返回类型发生变化，`BTUPHookInstanceMethod` 会返回 NO 并写日志，**不崩溃** —— 表现为部分屏蔽失效，属有意降级。
4. 未在真机验证。证据链为：CI 两个 job 全绿 + 产物字符串核验 + 架构核验。
5. 晚注册兜底改为定时重试（4 次，覆盖启动后 6 秒）。若抖音把类注册推迟到更晚，会漏装；`BTUpdateBlockingInstalledCount()` 可用于自检。
