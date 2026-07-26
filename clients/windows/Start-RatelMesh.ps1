#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ConfigPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-ManagedPath {
    param([string]$Path, [string]$Root, [string]$Label)
    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $rootFull = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    if ($full -ine $rootFull -and -not $full.StartsWith($rootFull + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Label must stay under $rootFull"
    }
    if (Test-Path -LiteralPath $rootFull) {
        $rootItem = Get-Item -LiteralPath $rootFull -Force
        if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$Label root is a reparse point: $rootFull"
        }
    }
    $current = $rootFull
    foreach ($part in @($full.Substring($rootFull.Length).TrimStart('\').Split('\') | Where-Object { $_ })) {
        $current = Join-Path $current $part
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "$Label contains a reparse point: $current"
            }
        }
    }
    return $full
}

function Assert-RegularFile {
    param([string]$Path, [string]$Label)
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "$Label must be a regular non-reparse file: $Path"
    }
    return $item
}

function Unprotect-Secret {
    param([string]$ProtectedValue)
    if ([string]::IsNullOrWhiteSpace($ProtectedValue)) { return '' }
    $secure = ConvertTo-SecureString -String $ProtectedValue
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
}

$ConfigPath = Resolve-ManagedPath -Path $ConfigPath `
    -Root (Join-Path $env:LOCALAPPDATA 'Programs\RatelMesh') -Label 'ConfigPath'
$configItem = Assert-RegularFile -Path $ConfigPath -Label 'Client config'
if ($configItem.Length -gt 1MB) { throw "Client config is oversized: $ConfigPath" }
$config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
$coordUri = $null
if (-not [Uri]::TryCreate([string]$config.Coord, [UriKind]::Absolute, [ref]$coordUri) -or
    [string]::IsNullOrWhiteSpace($coordUri.Host) -or
    -not [string]::IsNullOrEmpty($coordUri.UserInfo) -or
    ($coordUri.Scheme -ne 'https' -and -not ($coordUri.Scheme -eq 'http' -and $coordUri.IsLoopback))) {
    throw 'Configured Coordinator URL is unsafe.'
}
$configuredLanguage = if ($config.PSObject.Properties.Name -contains 'Language') { [string]$config.Language } else { 'system' }
$allowedLanguages = @('system', 'en', 'es', 'de', 'fr', 'ja', 'ko', 'it', 'nl', 'pl', 'sv', 'pt-BR', 'zh-Hans', 'zh-Hant')
if ($configuredLanguage -notin $allowedLanguages) { throw "Unsupported configured language: $configuredLanguage" }
if ($configuredLanguage -ne 'system' -and -not [string]::IsNullOrWhiteSpace($configuredLanguage)) {
    $env:RATELMESH_LANG = $configuredLanguage
}
$installDir = Resolve-ManagedPath -Path ([string]$config.InstallDir) `
    -Root (Join-Path $env:LOCALAPPDATA 'Programs\RatelMesh') -Label 'InstallDir'
$stateDir = Resolve-ManagedPath -Path ([string]$config.StateDir) `
    -Root (Join-Path $env:LOCALAPPDATA 'RatelMesh\state') -Label 'StateDir'
$ratelmeshd = Join-Path $installDir 'ratelmeshd.exe'
[void](Assert-RegularFile -Path $ratelmeshd -Label 'ratelmeshd.exe')

$wireGuardPath = Join-Path $env:ProgramFiles 'WireGuard\wireguard.exe'
if (-not (Test-Path -LiteralPath $wireGuardPath -PathType Leaf)) {
    throw 'Official WireGuard for Windows is not installed.'
}
[void](Assert-RegularFile -Path $wireGuardPath -Label 'WireGuard executable')
$wireGuardSignature = Get-AuthenticodeSignature -LiteralPath $wireGuardPath
$wireGuardSubject = if ($null -ne $wireGuardSignature.SignerCertificate) {
    $wireGuardSignature.SignerCertificate.Subject
} else {
    '<none>'
}
if ($wireGuardSignature.Status -ne [Management.Automation.SignatureStatus]::Valid -or
    $wireGuardSubject -notmatch 'CN=WireGuard LLC(?:,|$)') {
    throw 'Installed WireGuard executable is not signed by WireGuard LLC.'
}

$daemonArgs = @('-coord', [string]$config.Coord, '-state', $stateDir)
if (-not [string]::IsNullOrWhiteSpace([string]$config.Hostname)) { $daemonArgs += @('-hostname', [string]$config.Hostname) }
if (-not [string]::IsNullOrWhiteSpace([string]$config.Relay)) { $daemonArgs += @('-relay', [string]$config.Relay) }
if (-not [string]::IsNullOrWhiteSpace([string]$config.VerifyKey)) { $daemonArgs += @('-verify-key', [string]$config.VerifyKey) }
if (-not [string]::IsNullOrWhiteSpace([string]$config.SplitTunnelPath)) { $daemonArgs += @('-split-tunnel', [string]$config.SplitTunnelPath) }
if ([bool]$config.AcceptRoutes) { $daemonArgs += '-accept-routes' }
if ([bool]$config.ForceRelay) { $daemonArgs += '-force-relay' }
if ([bool]$config.KillSwitch) { $daemonArgs += '-kill-switch' }
if ($config.PSObject.Properties.Name -contains 'Role' -and -not [string]::IsNullOrWhiteSpace([string]$config.Role)) {
    if ([string]$config.Role -notin @('plain', 'exit')) { throw "Unsupported configured role: $($config.Role)" }
    $daemonArgs += @('-role', [string]$config.Role)
}
if ($config.PSObject.Properties.Name -contains 'EnableNAT' -and [bool]$config.EnableNAT) { $daemonArgs += '-enable-nat' }
if ($config.PSObject.Properties.Name -contains 'MagicDNS' -and [bool]$config.MagicDNS) { $daemonArgs += '-magic-dns' }
if ($config.PSObject.Properties.Name -contains 'TunnelDNS' -and -not [string]::IsNullOrWhiteSpace([string]$config.TunnelDNS)) {
    $daemonArgs += @('-tunnel-dns', [string]$config.TunnelDNS)
}
if ([bool]$config.GuiEnabled) {
    $guiAddress = [string]$config.GuiAddress
    if ($guiAddress -notmatch '^(127\.0\.0\.1|\[::1\]):([0-9]{1,5})$' -or
        [int]$Matches[2] -lt 1 -or [int]$Matches[2] -gt 65535) {
        throw "Unsafe configured GUI address: $guiAddress"
    }
    $daemonArgs += @('-gui', $guiAddress)
}

$logDir = Join-Path $stateDir 'logs'
New-Item -ItemType Directory -Path $logDir -Force | Out-Null
$logItem = Get-Item -LiteralPath $logDir -Force
if (($logItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "Log directory is a reparse point: $logDir"
}
$logPath = Join-Path $logDir 'ratelmeshd.log'
if (Test-Path -LiteralPath $logPath) {
    [void](Assert-RegularFile -Path $logPath -Label 'Daemon log')
}
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
