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

$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$taskName = "RatelMesh-$($sid.Replace('-', '_'))"
$task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($null -ne $task) {
    Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
}

$installedHbmd = Join-Path $InstallDir 'ratelmeshd.exe'
Get-CimInstance Win32_Process -Filter "Name = 'ratelmeshd.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.ExecutablePath -ieq $installedHbmd } |
    ForEach-Object { Invoke-CimMethod -InputObject $_ -MethodName Terminate | Out-Null }

$wireGuard = Get-Command 'wireguard.exe' -ErrorAction SilentlyContinue
if ($null -eq $wireGuard) {
    $candidate = Join-Path $env:ProgramFiles 'WireGuard\wireguard.exe'
    if (Test-Path -LiteralPath $candidate -PathType Leaf) { $wireGuard = Get-Item -LiteralPath $candidate }
}
if ($null -ne $wireGuard) {
    if ($wireGuard -is [Management.Automation.CommandInfo]) {
        $wireGuardPath = $wireGuard.Definition
    } else {
        $wireGuardPath = $wireGuard.FullName
    }
    & $wireGuardPath '/uninstalltunnelservice' 'ratelmesh0' 2>$null
}

# A forced daemon termination cannot run its normal WinNAT teardown. Remove
# only RatelMesh's named instance and restore forwarding on its adapter.
Get-NetNat -Name 'RatelMesh' -ErrorAction SilentlyContinue |
    Remove-NetNat -Confirm:$false -ErrorAction SilentlyContinue
$ratelmeshAdapter = Get-NetAdapter -Name 'ratelmesh0' -ErrorAction SilentlyContinue
if ($null -ne $ratelmeshAdapter) {
    Set-NetIPInterface -InterfaceIndex $ratelmeshAdapter.ifIndex -AddressFamily IPv4 `
        -Forwarding Disabled -ErrorAction SilentlyContinue
}

$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
$newPath = @($userPath -split ';' | Where-Object { $_ -and $_ -ine $InstallDir }) -join ';'
[Environment]::SetEnvironmentVariable('Path', $newPath, 'User')

if (Test-Path -LiteralPath $InstallDir) { Remove-Item -LiteralPath $InstallDir -Recurse -Force }
if ($PurgeState -and (Test-Path -LiteralPath $StateDir)) { Remove-Item -LiteralPath $StateDir -Recurse -Force }

Write-Host 'RatelMesh uninstalled for the current user.'
if (-not $PurgeState) { Write-Host "Identity and state retained at: $StateDir" }
Write-Host 'WireGuard for Windows was retained because other tunnels may use it.'
