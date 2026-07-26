#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA 'Programs\RatelMesh'),
    [string]$StateDir = (Join-Path $env:LOCALAPPDATA 'RatelMesh\state'),
    [switch]$PurgeState
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
    $current = $rootFull
    $candidates = @($rootFull)
    $relative = $full.Substring($rootFull.Length).TrimStart('\')
    foreach ($part in @($relative.Split('\') | Where-Object { $_ })) {
        $current = Join-Path $current $part
        $candidates += $current
    }
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate) {
            $item = Get-Item -LiteralPath $candidate -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "$Label is or contains a reparse point: $candidate"
            }
        }
    }
    return $full
}

function Get-TrustedWireGuardExecutable {
    $candidate = Join-Path $env:ProgramFiles 'WireGuard\wireguard.exe'
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { return $null }
    $item = Get-Item -LiteralPath $candidate -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "WireGuard executable is a reparse point: $candidate"
    }
    $signature = Get-AuthenticodeSignature -LiteralPath $candidate
    $subject = if ($null -ne $signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { '<none>' }
    if ($signature.Status -ne [Management.Automation.SignatureStatus]::Valid -or
        $subject -notmatch 'CN=WireGuard LLC(?:,|$)') {
        throw "Installed WireGuard executable is not signed by WireGuard LLC: $candidate"
    }
    return $candidate
}

function Remove-RatelMeshOwnedRoutes {
    param([Parameter(Mandatory = $true)][string]$Directory)

    $ledgerPath = Join-Path $Directory 'route-owners-v1.json'
    if (-not (Test-Path -LiteralPath $ledgerPath -PathType Leaf)) { return }
    $ledgerItem = Get-Item -LiteralPath $ledgerPath -Force
    if (($ledgerItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $ledgerItem.Length -gt 1MB) {
        throw "RatelMesh route ownership ledger is linked or oversized: $ledgerPath"
    }
    try {
        $ledger = Get-Content -LiteralPath $ledgerPath -Raw | ConvertFrom-Json
    } catch {
        throw "RatelMesh route ownership ledger is unreadable; refusing broad route cleanup: $ledgerPath"
    }
    if (-not ($ledger.PSObject.Properties.Name -contains 'Version') -or [int]$ledger.Version -ne 1) {
        throw "RatelMesh route ownership ledger has an unsupported version: $ledgerPath"
    }
    $routes = @($ledger.Routes)
    if ($routes.Count -gt 1024) {
        throw 'RatelMesh route ownership ledger contains too many entries.'
    }
    foreach ($route in $routes) {
        if (-not ($route.PSObject.Properties.Name -contains 'Windows') -or -not [bool]$route.Windows) {
            continue
        }
        foreach ($property in @('Prefix', 'InterfaceIndex', 'NextHop')) {
            if (-not ($route.PSObject.Properties.Name -contains $property) -or
                [string]::IsNullOrWhiteSpace([string]$route.$property)) {
                throw "RatelMesh route ownership ledger is missing $property; refusing broad route cleanup."
            }
        }
        $interfaceIndex = 0
        if (-not [int]::TryParse([string]$route.InterfaceIndex, [ref]$interfaceIndex) -or $interfaceIndex -le 0) {
            throw "RatelMesh route ownership ledger has an invalid interface index."
        }
        $owned = Get-NetRoute -DestinationPrefix ([string]$route.Prefix) `
            -InterfaceIndex $interfaceIndex -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
            Where-Object { $_.NextHop -eq [string]$route.NextHop }
        foreach ($entry in @($owned)) {
            Remove-NetRoute -InputObject $entry -Confirm:$false -ErrorAction Stop
        }
    }
    Remove-Item -LiteralPath $ledgerPath -Force
}

$InstallDir = Resolve-ManagedPath -Path $InstallDir `
    -Root (Join-Path $env:LOCALAPPDATA 'Programs\RatelMesh') -Label 'InstallDir'
$StateDir = Resolve-ManagedPath -Path $StateDir `
    -Root (Join-Path $env:LOCALAPPDATA 'RatelMesh\state') -Label 'StateDir'

$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$taskName = "RatelMesh-$($sid.Replace('-', '_'))"
$task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($null -ne $task) {
    Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
}

$installedHbmd = Join-Path $InstallDir 'ratelmeshd.exe'
Get-CimInstance Win32_Process -Filter "Name = 'ratelmeshd.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.ExecutablePath -ieq $installedHbmd } |
    ForEach-Object { Invoke-CimMethod -InputObject $_ -MethodName Terminate | Out-Null }
$attempt = 0
do {
    $daemonProcess = Get-CimInstance Win32_Process -Filter "Name = 'ratelmeshd.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.ExecutablePath -ieq $installedHbmd } |
        Select-Object -First 1
    if ($null -eq $daemonProcess) { break }
    Start-Sleep -Milliseconds 250
    $attempt++
} while ($attempt -lt 40)
if ($null -ne $daemonProcess) {
    if ($null -ne $task) { Start-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue }
    throw 'RatelMesh daemon did not stop; task, files, and state were retained.'
}

# A killed daemon cannot run normal teardown. Its root-owned ledger records the
# exact destination, interface and next hop of routes it created. Remove only
# those exact owners; never issue a prefix-only delete that could remove another
# VPN's route.
try {
    Remove-RatelMeshOwnedRoutes -Directory $StateDir
} catch {
    if ($null -ne $task) { Start-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue }
    throw
}

try {
    $wireGuardPath = Get-TrustedWireGuardExecutable
} catch {
    if ($null -ne $task) { Start-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue }
    throw
}
if ($null -ne $wireGuardPath) {
    & $wireGuardPath '/uninstalltunnelservice' 'ratelmesh0' 2>$null
}
$attempt = 0
do {
    $tunnelService = Get-Service -Name 'WireGuardTunnel$ratelmesh0' -ErrorAction SilentlyContinue
    $ratelmeshAdapter = Get-NetAdapter -Name 'ratelmesh0' -ErrorAction SilentlyContinue
    if ($null -eq $tunnelService -and $null -eq $ratelmeshAdapter) { break }
    Start-Sleep -Milliseconds 250
    $attempt++
} while ($attempt -lt 40)
if ($null -ne $tunnelService -or $null -ne $ratelmeshAdapter) {
    if ($null -ne $task) { Start-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue }
    throw 'RatelMesh WireGuard tunnel service or adapter is still present; installation files and state were retained for a safe retry.'
}

# A forced daemon termination cannot run its normal WinNAT teardown. Remove
# only RatelMesh's named instance and restore forwarding on its adapter.
try {
    $ownedNat = Get-NetNat -Name 'RatelMesh' -ErrorAction SilentlyContinue
    foreach ($nat in @($ownedNat)) {
        Remove-NetNat -InputObject $nat -Confirm:$false -ErrorAction Stop
    }
    if ($null -ne (Get-NetNat -Name 'RatelMesh' -ErrorAction SilentlyContinue)) {
        throw 'RatelMesh WinNAT instance is still present.'
    }
} catch {
    if ($null -ne $task) { Start-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue }
    throw 'RatelMesh WinNAT cleanup failed; installation files were retained.'
}
if ($null -ne $task) {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
}

$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
$newPath = @($userPath -split ';' | Where-Object { $_ -and $_ -ine $InstallDir }) -join ';'
[Environment]::SetEnvironmentVariable('Path', $newPath, 'User')

foreach ($name in @('ratelmeshd.exe', 'ratelmesh.exe', 'Start-RatelMesh.ps1', 'Show-RatelMeshPrivacy.ps1', 'client.json')) {
    Remove-Item -LiteralPath (Join-Path $InstallDir $name) -Force -ErrorAction SilentlyContinue
}
Remove-Item -LiteralPath $InstallDir -Force -ErrorAction SilentlyContinue
if ($PurgeState -and (Test-Path -LiteralPath $StateDir)) {
    [IO.Directory]::Delete($StateDir, $true)
}

Write-Host 'RatelMesh uninstalled for the current user.'
if (-not $PurgeState) { Write-Host "Identity and state retained at: $StateDir" }
Write-Host 'WireGuard for Windows was retained because other tunnels may use it.'
