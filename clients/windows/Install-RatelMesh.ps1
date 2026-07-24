#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({
        if ($_ -match '^https://') { return $true }
        if ($_ -match '^http://(localhost|127(?:\.\d{1,3}){3}|\[::1\])(?::\d+)?(?:/|$)') { return $true }
        throw 'CoordinatorUrl must use https://; http:// is allowed only for loopback development.'
    })]
    [string]$Coord,

    [Security.SecureString]$AuthKey,
    [string]$Hostname = $env:COMPUTERNAME,
    [string]$Relay = '',
    [string]$VerifyKey = '',
    [switch]$AcceptRoutes,
    [switch]$ForceRelay,
    [switch]$KillSwitch,
    [switch]$RunAsExitNode,
    [switch]$DisableMagicDNS,
    [string]$TunnelDNS = '',
    [switch]$EnableGui,
    [ValidateSet('system', 'en', 'zh-Hans', 'ja')]
    [string]$Language = 'system',
    [ValidatePattern('^(127\.0\.0\.1|\[::1\]):[0-9]{1,5}$')]
    [string]$GuiAddress = '127.0.0.1:8088',
    [string]$SplitTunnelPath = '',

    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA 'Programs\RatelMesh'),
    [string]$StateDir = (Join-Path $env:LOCALAPPDATA 'RatelMesh\state'),
    [string]$HbmdPath = (Join-Path $PSScriptRoot 'ratelmeshd.exe'),
    [string]$HbmPath = (Join-Path $PSScriptRoot 'ratelmesh.exe'),
    [string]$WireGuardInstaller = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($DisableMagicDNS -and -not [string]::IsNullOrWhiteSpace($TunnelDNS)) {
    throw '-TunnelDNS requires MagicDNS; remove -DisableMagicDNS.'
}

function Get-WireGuardExecutable {
    $command = Get-Command 'wireguard.exe' -ErrorAction SilentlyContinue
    if ($null -ne $command) { return $command.Path }
    $candidate = Join-Path $env:ProgramFiles 'WireGuard\wireguard.exe'
    if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
    return $null
}

function Set-PrivateAcl {
    param([Parameter(Mandatory = $true)][string]$Path, [switch]$Container)

    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $userRule = "*${sid}:(F)"
    $systemRule = '*S-1-5-18:(F)'
    $adminsRule = '*S-1-5-32-544:(F)'
    if ($Container) {
        $userRule = "*${sid}:(OI)(CI)(F)"
        $systemRule = '*S-1-5-18:(OI)(CI)(F)'
        $adminsRule = '*S-1-5-32-544:(OI)(CI)(F)'
    }
    & icacls.exe $Path '/inheritance:r' '/grant:r' $userRule $systemRule $adminsRule | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Unable to secure ACL on $Path" }
}

function Get-TaskName {
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value.Replace('-', '_')
    return "RatelMesh-$sid"
}

if (-not (Test-Path -LiteralPath $HbmdPath -PathType Leaf)) { throw "ratelmeshd.exe not found: $HbmdPath" }
if (-not (Test-Path -LiteralPath $HbmPath -PathType Leaf)) { throw "ratelmesh.exe not found: $HbmPath" }

$wireGuard = Get-WireGuardExecutable
if ($null -eq $wireGuard) {
    if ([string]::IsNullOrWhiteSpace($WireGuardInstaller)) {
        throw 'WireGuard for Windows is required. Install it from wireguard.com, or pass -WireGuardInstaller with the official signed MSI/EXE.'
    }
    if (-not (Test-Path -LiteralPath $WireGuardInstaller -PathType Leaf)) {
        throw "WireGuard installer not found: $WireGuardInstaller"
    }
    $signature = Get-AuthenticodeSignature -LiteralPath $WireGuardInstaller
    if ($signature.Status -ne [Management.Automation.SignatureStatus]::Valid) {
        throw "WireGuard installer signature is not valid: $($signature.Status)"
    }
    $signerSubject = '<none>'
    if ($null -ne $signature.SignerCertificate) { $signerSubject = $signature.SignerCertificate.Subject }
    if ($signerSubject -notmatch 'CN=WireGuard LLC(?:,|$)') {
        throw "WireGuard installer has an unexpected signer: $signerSubject"
    }
    if ([IO.Path]::GetExtension($WireGuardInstaller) -ieq '.msi') {
        $installerArgs = "/i `"$WireGuardInstaller`" /qn /norestart DO_NOT_LAUNCH=1"
        $installer = Start-Process 'msiexec.exe' -ArgumentList $installerArgs -Wait -PassThru
    } else {
        $installer = Start-Process $WireGuardInstaller -ArgumentList '/noprompt' -Wait -PassThru
    }
    if ($installer.ExitCode -notin @(0, 3010)) { throw "WireGuard installation failed with exit code $($installer.ExitCode)" }
    $wireGuard = Get-WireGuardExecutable
    if ($null -eq $wireGuard) { throw 'WireGuard installation completed, but wireguard.exe was not found.' }
}

$taskName = Get-TaskName
$oldTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($null -ne $oldTask) {
    Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
}

$oldHbmd = Join-Path $InstallDir 'ratelmeshd.exe'
Get-CimInstance Win32_Process -Filter "Name = 'ratelmeshd.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.ExecutablePath -ieq $oldHbmd } |
    ForEach-Object { Invoke-CimMethod -InputObject $_ -MethodName Terminate | Out-Null }

New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
New-Item -ItemType Directory -Path $StateDir -Force | Out-Null
Set-PrivateAcl -Path $InstallDir -Container
Set-PrivateAcl -Path $StateDir -Container

$installedHbmd = Join-Path $InstallDir 'ratelmeshd.exe'
$installedHbm = Join-Path $InstallDir 'ratelmesh.exe'
$startScript = Join-Path $InstallDir 'Start-RatelMesh.ps1'
$privacyScript = Join-Path $InstallDir 'Show-RatelMeshPrivacy.ps1'
$configPath = Join-Path $InstallDir 'client.json'
Copy-Item -LiteralPath $HbmdPath -Destination $installedHbmd -Force
Copy-Item -LiteralPath $HbmPath -Destination $installedHbm -Force
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Start-RatelMesh.ps1') -Destination $startScript -Force
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Show-RatelMeshPrivacy.ps1') -Destination $privacyScript -Force

$protectedAuthKey = ''
if ($null -ne $AuthKey) {
    $protectedAuthKey = ConvertFrom-SecureString -SecureString $AuthKey
} elseif (Test-Path -LiteralPath $configPath -PathType Leaf) {
    $oldConfig = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
    if ($null -ne $oldConfig.AuthKeyProtected) { $protectedAuthKey = [string]$oldConfig.AuthKeyProtected }
}

$config = [ordered]@{
    Coord             = $Coord
    AuthKeyProtected  = $protectedAuthKey
    Hostname          = $Hostname
    Relay             = $Relay
    VerifyKey         = $VerifyKey
    AcceptRoutes      = [bool]$AcceptRoutes
    ForceRelay        = [bool]$ForceRelay
    KillSwitch        = [bool]$KillSwitch
    Role              = $(if ($RunAsExitNode) { 'exit' } else { 'plain' })
    # Permission is installed once; the signed cloud Netmap decides whether
    # EXIT is active. This makes later Tenant-admin changes command-line free.
    EnableNAT         = $true
    MagicDNS          = -not [bool]$DisableMagicDNS
    TunnelDNS         = $TunnelDNS
    GuiEnabled        = [bool]$EnableGui
    GuiAddress        = $GuiAddress
    Language          = $Language
    SplitTunnelPath   = $SplitTunnelPath
    InstallDir        = $InstallDir
    StateDir          = $StateDir
}
$config | ConvertTo-Json | Set-Content -LiteralPath $configPath -Encoding UTF8
Set-PrivateAcl -Path $configPath

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$actionArgs = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$startScript`" -ConfigPath `"$configPath`""
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $actionArgs
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $identity.Name
$principal = New-ScheduledTaskPrincipal -UserId $identity.Name -LogonType Interactive -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings `
    -Description 'RatelMesh per-user WireGuard client' -Force | Out-Null

$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
$pathParts = @($userPath -split ';' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
if ($pathParts -notcontains $InstallDir) {
    [Environment]::SetEnvironmentVariable('Path', (($pathParts + $InstallDir) -join ';'), 'User')
}
if ($Language -eq 'system') {
    [Environment]::SetEnvironmentVariable('RATELMESH_LANG', $null, 'User')
} else {
    [Environment]::SetEnvironmentVariable('RATELMESH_LANG', $Language, 'User')
}

Start-ScheduledTask -TaskName $taskName
Start-Process 'powershell.exe' -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$privacyScript`"" | Out-Null
Write-Host "RatelMesh installed for $($identity.Name)."
Write-Host "Task: $taskName"
Write-Host "State: $StateDir"
if ($EnableGui) { Write-Host "GUI: http://$GuiAddress" }
Write-Host 'Open a new terminal and run: ratelmesh status'
