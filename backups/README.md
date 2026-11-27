# 版本备份索引

每次合并到 `master` 前的基线状态、合并内容与回滚方式都记录在这里。
规范与 `location-tweak-0905r10` 仓库一致。

## 规范

| 项 | 约定 |
|---|---|
| 备份目录 | `backups/<YYYY-MM-DD>_<版本>_<简述>/BACKUP.md` |
| 合并前基线标签 | `backup-pre-<简述>-<基线短SHA>` |
| 合并后备份标签 | `backup-<版本>-<简述>-<YYYYMMDD>` |
| 发布标签 | `v<版本>` |
| 报告必含 | 版本/提交元信息、成品校验和、差异清单、依赖变更、一键回滚、已知限制 |

## 索引

| 日期 | 版本 | 报告 | 基线提交 | 合并提交 | 基线标签 |
|---|---|---|---|---|---|
| 2026-11-27 | `v9` | [2026-11-27_v9_update-block/BACKUP.md](./2026-11-27_v9_update-block/BACKUP.md) | `6def72b` | `5b2eeee` (直接合并) | `backup-pre-update-block-6def72b` |

## 快速回滚

```bash
# 回到 v8
git checkout backup-pre-update-block-6def72b

# 撤销最近一次合并
git revert -m 1 HEAD
```
