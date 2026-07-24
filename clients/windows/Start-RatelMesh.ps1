#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ConfigPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Unprotect-Secret {
    param([string]$ProtectedValue)
    if ([string]::IsNullOrWhiteSpace($ProtectedValue)) { return '' }
    $secure = ConvertTo-SecureString -String $ProtectedValue
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
}

if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) { throw "Client config not found: $ConfigPath" }
$config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
$configuredLanguage = if ($config.PSObject.Properties.Name -contains 'Language') { [string]$config.Language } else { 'system' }
if ($configuredLanguage -ne 'system' -and -not [string]::IsNullOrWhiteSpace($configuredLanguage)) {
    $env:RATELMESH_LANG = $configuredLanguage
}
$ratelmeshd = Join-Path ([string]$config.InstallDir) 'ratelmeshd.exe'
if (-not (Test-Path -LiteralPath $ratelmeshd -PathType Leaf)) { throw "ratelmeshd.exe not found: $ratelmeshd" }

$wireGuard = Get-Command 'wireguard.exe' -ErrorAction SilentlyContinue
if ($null -eq $wireGuard) {
    $wireGuardPath = Join-Path $env:ProgramFiles 'WireGuard\wireguard.exe'
    if (-not (Test-Path -LiteralPath $wireGuardPath -PathType Leaf)) { throw 'Official WireGuard for Windows is not installed.' }
}

$daemonArgs = @('-coord', [string]$config.Coord, '-state', [string]$config.StateDir)
if (-not [string]::IsNullOrWhiteSpace([string]$config.Hostname)) { $daemonArgs += @('-hostname', [string]$config.Hostname) }
if (-not [string]::IsNullOrWhiteSpace([string]$config.Relay)) { $daemonArgs += @('-relay', [string]$config.Relay) }
if (-not [string]::IsNullOrWhiteSpace([string]$config.VerifyKey)) { $daemonArgs += @('-verify-key', [string]$config.VerifyKey) }
if (-not [string]::IsNullOrWhiteSpace([string]$config.SplitTunnelPath)) { $daemonArgs += @('-split-tunnel', [string]$config.SplitTunnelPath) }
if ([bool]$config.AcceptRoutes) { $daemonArgs += '-accept-routes' }
if ([bool]$config.ForceRelay) { $daemonArgs += '-force-relay' }
if ([bool]$config.KillSwitch) { $daemonArgs += '-kill-switch' }
if ($config.PSObject.Properties.Name -contains 'Role' -and -not [string]::IsNullOrWhiteSpace([string]$config.Role)) {
    $daemonArgs += @('-role', [string]$config.Role)
}
if ($config.PSObject.Properties.Name -contains 'EnableNAT' -and [bool]$config.EnableNAT) { $daemonArgs += '-enable-nat' }
if ($config.PSObject.Properties.Name -contains 'MagicDNS' -and [bool]$config.MagicDNS) { $daemonArgs += '-magic-dns' }
if ($config.PSObject.Properties.Name -contains 'TunnelDNS' -and -not [string]::IsNullOrWhiteSpace([string]$config.TunnelDNS)) {
    $daemonArgs += @('-tunnel-dns', [string]$config.TunnelDNS)
}
if ([bool]$config.GuiEnabled) { $daemonArgs += @('-gui', [string]$config.GuiAddress) }

$logDir = Join-Path ([string]$config.StateDir) 'logs'
New-Item -ItemType Directory -Path $logDir -Force | Out-Null
$logPath = Join-Path $logDir 'ratelmeshd.log'
if ((Test-Path -LiteralPath $logPath) -and (Get-Item -LiteralPath $logPath).Length -gt 10MB) {
    $oldLog = Join-Path $logDir 'ratelmeshd.log.1'
    Remove-Item -LiteralPath $oldLog -Force -ErrorAction SilentlyContinue
    Move-Item -LiteralPath $logPath -Destination $oldLog
}
Add-Content -LiteralPath $logPath -Value "`r`n[$([DateTime]::Now.ToString('o'))] starting ratelmeshd"

$env:RATELMESH_AUTHKEY = Unprotect-Secret -ProtectedValue ([string]$config.AuthKeyProtected)
try {
    & $ratelmeshd @daemonArgs >> $logPath 2>&1
    $exitCode = $LASTEXITCODE
} finally {
    Remove-Item Env:RATELMESH_AUTHKEY -ErrorAction SilentlyContinue
    if ($configuredLanguage -ne 'system') { Remove-Item Env:RATELMESH_LANG -ErrorAction SilentlyContinue }
}
if ($exitCode -ne 0) { exit $exitCode }
