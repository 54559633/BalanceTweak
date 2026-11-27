# 更新日志

本文件是**唯一的更新记录入口**。

## 更新流程（每次改动必须遵守）

1. 改动合并到 `master` 前，先在 `backups/<日期>_<版本>_<简述>/BACKUP.md` 写备份报告
2. 同时在**本文件**顶部加一条版本记录，必须包含：
   - 变更内容（功能 / 修复 / 移除）
   - **构建过程中遇到的错误**，以及错误原文和修正方式
   - 验证结果（CI run、产物校验和、架构）
3. 打两个标签：`v<版本>`（合并提交）与 `backup-<版本>-<简述>-<YYYYMMDD>`（备份提交）
4. 推送 `master` 与标签

> 构建错误无论最终是否由我引入，都要记录。下次遇到同类问题可以直接查，不用重踩。

---

## v9 — 2026-11-27

**屏蔽抖音应用内版本检查（强制启用，不可关闭）**

### 变更

| 类型 | 内容 |
|---|---|
| 新增 | `src/BTUpdateBlocker.h` / `src/BTUpdateBlocker.m` |
| 修改 | `src/BalanceTweak.m`（import + `BTInit` 中授权判断之前调用） |
| 修改 | `.github/workflows/build.yml`（arm64 / arm64e 编译与链接列表，共 4 处） |
| 修改 | `.github/workflows/build-linux.yml`（两处编译列表） |
| 修改 | `README.md`（功能列表） |
| 修改 | 日志横幅 `v8+AuthGate` → `v9+AuthGate+UpdateBlock` |

### 功能

- `AWEVersionUpdateAlert -canShow` → 恒 `NO`
- `AWENewVersionAlertManager` 的 5 个检查入口 → 空实现：
  `checkAppNewVersion` / `checkAppNewVersionInhouse` /
  `checkAppNewVersionTestFlight` / `checkInhouseNewVersionWithDelay` /
  `checkAppNewVersionInhouseWithDelay`
- 不读任何 `NSUserDefaults` 键，界面无关闭入口，**独立于卡密授权门禁**
- 不含任何网络请求与账号相关逻辑（原包夹带的关注逻辑已剔除）

### 构建错误记录

#### 错误 1：函数名大小写不一致

```
src/BTUpdateBlocker.m:108:12: error: call to undeclared function 'BTUPhookInstanceMethod';
      ISO C99 and later do not support implicit function declarations
src/BTUpdateBlocker.m:119:13: 同上
```

**原因**：定义处写的是 `BTUPHookInstanceMethod`（大写 H），两处调用点写成了小写 h。

**修正**：调用点统一为大写 H。提交 `2036b57`。

#### 错误 2：dyld 回调符号链接不到

```
Undefined symbols for architecture arm64:
  "_dyld_register_func_for_add_image", referenced from:
      _BTInstallUpdateBlocking in BTUpdateBlocker.o
ld: symbol(s) not found for architecture arm64
```

**原因**：该符号在 iOS SDK 的 libSystem 导出表中不存在。同仓 `BTFishhook.c` 使用的
`_dyld_image_count` / `_dyld_get_image_header` 等则正常可链接。

**修正**：**没有**用 `-Wl,-undefined,dynamic_lookup` 绕过 —— 那会放过该 dylib 的全部未定义符号，
包括真实错误。改为 0.5s / 1.5s / 3s / 6s 四次递增间隔定时重试补装，覆盖启动后 6 秒内的类注册，
效果等价且不引入链接依赖。提交 `56e5cb9`。

### 验证

| 项 | 结果 |
|---|---|
| CI Run | `45953982131`，`test` + `build` 两个 job 全部通过 |
| 产物 | `BalanceTweak.dylib` 817,056 B |
| SHA-256 | `574352CA299EC281D7C7F306DDF52AFFC4E0290D0745B87796D01C390297D237` |
| 架构 | `arm64` + `arm64e`（fat，390,848 / 407,456 字节） |
| 纯净性 | `AWEOFGUser` / `followWithUid` / `secUid` / `94406244690` / `7677010391101015077` 均 absent |

### 备注

**架构判断更正**：早期曾把 `cputype = 0x0100000C` 误读为 arm64e。实际
`0x0100000C = CPU_ARCH_ABI64 | CPU_TYPE_ARM = arm64`，而 arm64e 只是 arm64 的 cpusubtype
（`0x0` = ALL，`0x2` / `0x80000002` = ARM64E）。因此不存在"只出 arm64e、A11 及更早机型装不上"的问题。

---

## 记录起点说明

本仓库此前没有变更日志。上一条 `v9` 是第一条完整记录（含构建错误）。
`6def72b`（v8+AuthGate）及更早的提交只有 `git log`，未做结构化记录。
