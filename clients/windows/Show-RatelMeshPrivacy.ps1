#Requires -Version 5.1

[CmdletBinding()]
param([switch]$Force)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$stateDir = Join-Path $env:LOCALAPPDATA 'RatelMesh'
$marker = Join-Path $stateDir 'geographic-privacy-v1.acknowledged'
if ((-not $Force) -and (Test-Path -LiteralPath $marker -PathType Leaf)) { exit 0 }

Add-Type -AssemblyName PresentationFramework
$isChinese = [Globalization.CultureInfo]::CurrentUICulture.Name -match '^zh'
if ($isChinese) {
    $title = 'RatelMesh - 地理位置隐私'
    $message = @'
出口设备会改变公网 IP，但不会替换 Windows 定位服务得到的物理位置。

如果不希望网站或应用获得实际位置，请检查：

• Windows 设置 > 隐私和安全性 > 位置
• 浏览器网站设置 > 位置信息：阻止或询问
• 根据风险需要检查浏览器的 WebRTC 隐私设置
• Wi-Fi/蓝牙扫描和个性化广告设置

RatelMesh 不会在未经同意时修改这些隐私权限。

现在打开 Windows 定位设置吗？
'@
} else {
    $title = 'RatelMesh - Geographic privacy'
    $message = @'
An exit device changes your public IP address, but it does not replace Windows location services.

Review these settings if you do not want websites or apps to receive your physical location:

• Windows Settings > Privacy & security > Location
• Browser site settings > Location: Block or Ask
• Browser WebRTC privacy settings when required by your threat model
• Wi-Fi/Bluetooth scanning and personalized advertising settings

RatelMesh never changes these privacy permissions without your consent.

Open Windows Location settings now?
'@
}

$result = [Windows.MessageBox]::Show(
    $message,
    $title,
    [Windows.MessageBoxButton]::YesNoCancel,
    [Windows.MessageBoxImage]::Information
)

if ($result -eq [Windows.MessageBoxResult]::Yes) {
    Start-Process 'ms-settings:privacy-location'
}
if ($result -ne [Windows.MessageBoxResult]::Cancel) {
    New-Item -ItemType Directory -Path $stateDir -Force | Out-Null
    New-Item -ItemType File -Path $marker -Force | Out-Null
}
