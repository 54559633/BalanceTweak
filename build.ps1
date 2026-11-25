# build.ps1 —— 编译 BalanceTweak.dylib（Python 负责合并）
$ErrorActionPreference = "Continue"

$LLVM = "C:\LLVM18\bin"
$SDK  = "C:\Users\leagu\Desktop\DEEPSEEK\dy-capture\toolchain\sdks\iPhoneOS16.5.sdk"
$SRC  = "C:\Users\leagu\Desktop\DEEPSEEK\BalanceTweak\src\BalanceTweak.m"
$OUT  = "C:\Users\leagu\Desktop\DEEPSEEK\BalanceTweak\build"

$env:PATH = "$LLVM;$env:PATH"
New-Item -ItemType Directory -Force -Path $OUT | Out-Null
Set-Location $OUT
Remove-Item "*.dylib" -ErrorAction SilentlyContinue

$clang = "$LLVM\clang.exe"

$common = @(
    "-dynamiclib"
    "-isysroot"; $SDK
    "-fobjc-arc"
    "-O2"
    "-fvisibility=hidden"
    "-install_name"; "@rpath/BalanceTweak.dylib"
    "-Wl,-undefined,dynamic_lookup"
    "-Wl,-no_fixup_chains"
)

function Build-Target {
    param([string]$Target, [string]$Output)
    $a = @("-target", $Target) + $common + @("-o", $Output, $SRC)
    Write-Host "=== $Target -> $Output ===" -ForegroundColor Cyan
    $out = & $clang @a 2>&1
    $errs = @($out | Where-Object { $_ -match ": error:" })
    if ($errs.Count -gt 0) {
        Write-Host "  错误 $($errs.Count) 个:" -ForegroundColor Red
        $errs | Select-Object -First 12 | ForEach-Object { Write-Host "    $_" -ForegroundColor Red }
        return $false
    }
    $warns = @($out | Where-Object { $_ -match ": warning:" })
    if ($warns.Count -gt 0) {
        Write-Host "  警告 $($warns.Count) 个（忽略）" -ForegroundColor DarkYellow
    }
    if (Test-Path $Output) {
        $kb = [math]::Round((Get-Item $Output).Length / 1KB, 1)
        Write-Host "  OK  $Output : $kb KB" -ForegroundColor Green
        return $true
    }
    return $false
}

$ok1 = Build-Target "arm64e-apple-ios14.0" "arm64e.dylib"
$ok2 = Build-Target "arm64-apple-ios14.0"  "arm64.dylib"

Write-Host ""
Write-Host "=== 编译结果 ===" -ForegroundColor Cyan
Get-ChildItem "*.dylib" -ErrorAction SilentlyContinue |
    Select-Object Name, @{n='KB';e={[math]::Round($_.Length/1KB,1)}} |
    Format-Table -AutoSize

if ($ok1 -and $ok2) {
    Write-Host "=== 合并 fat binary ===" -ForegroundColor Cyan
    & python "C:\Users\leagu\Desktop\DEEPSEEK\BalanceTweak\make_fat.py"
    if (Test-Path "BalanceTweak.dylib") {
        Write-Host ""
        Write-Host "=== 验证 ===" -ForegroundColor Cyan
        & "$LLVM\llvm-objdump.exe" --macho --universal-headers BalanceTweak.dylib 2>&1 | Select-Object -First 12
    }
}
