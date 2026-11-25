# BalanceTweak

抖音（Aweme）钻石余额自定义显示 —— iOS 越狱插件（dylib）

## 功能

- **三指长按 1 秒** → 呼出设置界面
- 设置任意「显示数字」
- **自动追踪真实余额变化**：
  ```
  显示值 = 设置值 + (当前真实余额 - 基准真实余额)
  ```
  - 送礼（真实减少）→ 显示同步减少
  - 收礼（真实增加）→ 显示同步增加
- 配置持久化（NSUserDefaults）
- 余额接口覆盖：
  - 礼物面板（`/webcast/wallet/info/`，已实现）
  - 钱包首页（`/caijing/wallet/core/v1/homepage/index/`，待扩展）
  - 充值页（`/webcast/wallet_api/recharge_page/`，待扩展）

## 编译

GitHub Actions 自动运行单元测试并编译（`macos-14` runner，自带 Xcode + iOS SDK）：

```
Actions → Build Dylib → 下载 BalanceTweak-dylib
```

本地编译（macOS）：

```bash
SDK=$(xcrun --sdk iphoneos --show-sdk-path)

# arm64
xcrun clang -dynamiclib -target arm64-apple-ios14.0 \
  -isysroot "$SDK" -fobjc-arc -O2 -fvisibility=hidden \
  -install_name @rpath/BalanceTweak.dylib \
  -framework UIKit -framework Foundation \
  -o build-arm64.dylib src/BalanceTweak.m

# arm64e
xcrun clang -dynamiclib -target arm64e-apple-ios14.0 \
  -isysroot "$SDK" -fobjc-arc -O2 -fvisibility=hidden \
  -install_name @rpath/BalanceTweak.dylib \
  -framework UIKit -framework Foundation \
  -o build-arm64e.dylib src/BalanceTweak.m

# 合并 & 去符号
lipo -create build-arm64.dylib build-arm64e.dylib -output BalanceTweak.dylib
strip -x BalanceTweak.dylib

# 签名
ldid -S BalanceTweak.dylib
```

运行单元测试（Linux / macOS）：

```bash
gcc -std=c11 -Wall -Wextra -Werror -fsanitize=address,undefined -O2 \
  tests/test_bt_proto.c -o test_bt_proto && ./test_bt_proto
```

## 注入

### 方法 1：TrollFools（推荐）

1. 把 `BalanceTweak.dylib` 放到「文件」App 可见的位置
2. 打开 TrollFools → 选抖音 → 注入 → 选 dylib
3. 重启 App

### 方法 2：手动注入

1. 复制 `BalanceTweak.dylib` 到 `Aweme.app/Frameworks/`
2. 给 `Aweme.app/Aweme` 加 `LC_LOAD_DYLIB @rpath/BalanceTweak.dylib`
3. 重签名

```bash
# 用 insert_dylib 或 optool
insert_dylib --inplace --strip-codesig \
  '@rpath/BalanceTweak.dylib' \
  /path/to/Aweme.app/Aweme
```

### 方法 3：ElleKit tweak 目录（需要注入器工作）

```bash
# 复制 dylib
cp BalanceTweak.dylib /var/jb/usr/lib/TweakInject/

# 创建 plist
cat > /var/jb/usr/lib/TweakInject/BalanceTweak.plist <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Filter</key>
    <dict>
        <key>Bundles</key>
        <array>
            <string>com.ss.iphone.ugc.Aweme</string>
        </array>
    </dict>
</dict>
</plist>
EOF

# roothide 需要 patch 符号
ln -s /usr/lib/DynamicPatches/AutoPatches.dylib \
  /var/jb/usr/lib/TweakInject/BalanceTweak.dylib.roothidepatch
```

## 使用

1. 启动抖音
2. **三指长按屏幕 1 秒**
3. 弹出设置界面
4. 输入想显示的数字（如 `1500254`）
5. 点「应用」
6. 之后：
   - 送礼 → 显示值减少对应数量
   - 收礼 → 显示值增加对应数量

### 设置界面说明

```
真实余额:   177          ← 服务端真实值（每 2-3 秒刷新）
基准真实:   177          ← 点"应用"时的真实值
基准显示:   1500254      ← 你设置的显示值
当前显示:   1500254      ← 实时计算 = 基准显示 + (真实 - 基准真实)
改写开关:   开
```

## 技术细节

### 网络 hook

hook `NSURLSession` 的 `dataTaskWithRequest:completionHandler:`，
拦截路径包含 `/webcast/wallet/info/` 的请求，改写响应体。

### protobuf 改写

原始响应（27 字节）：

```
0a 07 [28 <ts>]            field1 {field5: 时间戳}
12 10                      field2 (16 字节)
  0a 0e                    field2.field1 (14 字节)
    10 <uid>               field 2: UID
    18 <b1 01>             field 3: 余额     177
    70 <ea 0d>             field14: 余额×10  1770
```

改写后（目标 1500254）：

```
0a 07 [28 <ts>]
12 13                      ← 长度 16→19
  0a 11                    ← 长度 14→17
    10 <uid>
    18 <de c8 5b>          field 3:  1500254   (2B→3B)
    70 <ac d7 93 07>       field14: 15002540   (2B→4B)
```

父消息长度逐层重算。

### 状态同步逻辑

```
初始：
  真实 177，用户设置 1500254
  → baseReal = 177, baseDisplay = 1500254

送礼后（真实 176）：
  显示 = 1500254 + (176 - 177) = 1500253

收礼后（真实 178）：
  显示 = 1500254 + (178 - 177) = 1500255
```

## 已知限制

- **只改显示**，不影响服务端真实余额
- 送礼 / 提现等操作仍按真实余额判断
- 抖音用 TTNet（自研网络库），如果它不走 `NSURLSession` 的 completion 路径，
  本 hook 可能不生效 —— 需要额外 hook TTNet 层
- 三指长按可能与抖音自带手势冲突（`cancelsTouchesInView = NO` 已尽量规避）

## 文件结构

```
BalanceTweak/
├─ .github/workflows/build.yml   GitHub Actions 测试与编译配置
├─ src/BTProto.h                 Protobuf 解析/改写与余额计算核心（纯 C）
├─ src/BalanceTweak.m            iOS Hook / 配置管理 / 设置界面
├─ tests/test_bt_proto.c         核心逻辑单元测试
├─ build.ps1                     Windows 本地交叉编译脚本
├─ make_fat.py                   Fat binary 合并脚本
└─ README.md
```

## License

仅用于学习研究。
