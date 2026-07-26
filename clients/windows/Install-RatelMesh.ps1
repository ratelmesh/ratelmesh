#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({
        $uri = $null
        if (-not [Uri]::TryCreate($_, [UriKind]::Absolute, [ref]$uri) -or
            [string]::IsNullOrWhiteSpace($uri.Host) -or
            -not [string]::IsNullOrEmpty($uri.UserInfo)) {
            throw 'CoordinatorUrl must be an absolute URL without embedded credentials.'
        }
        if ($uri.Scheme -eq 'https') { return $true }
        if ($uri.Scheme -eq 'http' -and $uri.IsLoopback) { return $true }
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
    [ValidateSet('system', 'en', 'es', 'de', 'fr', 'ja', 'ko', 'it', 'nl', 'pl', 'sv', 'pt-BR', 'zh-Hans', 'zh-Hant')]
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

function Set-PrivateAcl {
    param([Parameter(Mandatory = $true)][string]$Path, [switch]$Container)

    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $userRule = "*${sid}:(RX)"
    $systemRule = '*S-1-5-18:(F)'
    $adminsRule = '*S-1-5-32-544:(F)'
    if ($Container) {
        $userRule = "*${sid}:(OI)(CI)(RX)"
        $systemRule = '*S-1-5-18:(OI)(CI)(F)'
        $adminsRule = '*S-1-5-32-544:(OI)(CI)(F)'
    }
    & icacls.exe $Path '/inheritance:r' '/grant:r' $userRule $systemRule $adminsRule | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Unable to secure ACL on $Path" }
}

function Assert-RegularFile {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string]$Label)
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "$Label must be a regular non-reparse file: $Path"
    }
    return $item.FullName
}

function Resolve-ManagedPath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Label
    )
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
    $relative = $full.Substring($rootFull.Length).TrimStart('\')
    foreach ($part in @($relative.Split('\') | Where-Object { $_ })) {
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

function Get-WireGuardExecutable {
    $candidate = Join-Path $env:ProgramFiles 'WireGuard\wireguard.exe'
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { return $null }
    $candidate = Assert-RegularFile -Path $candidate -Label 'WireGuard executable'
    $signature = Get-AuthenticodeSignature -LiteralPath $candidate
    $subject = if ($null -ne $signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { '<none>' }
    if ($signature.Status -ne [Management.Automation.SignatureStatus]::Valid -or
        $subject -notmatch 'CN=WireGuard LLC(?:,|$)') {
        throw "Installed WireGuard executable is not signed by WireGuard LLC: $candidate"
    }
    return $candidate
}

function Assert-BundleIntegrity {
    $checksumPath = Join-Path $PSScriptRoot 'SHA256SUMS.txt'
    [void](Assert-RegularFile -Path $checksumPath -Label 'SHA256SUMS.txt')
    $expected = @{}
    $verified = @{}
    foreach ($line in Get-Content -LiteralPath $checksumPath) {
        if ($line -notmatch '^([0-9a-f]{64})  ([^\\/]+)$') {
            throw "Invalid bundle checksum line: $line"
        }
        if ($expected.ContainsKey($Matches[2])) { throw "Duplicate bundle checksum: $($Matches[2])" }
        $expected[$Matches[2]] = $Matches[1]
    }
    foreach ($item in Get-ChildItem -LiteralPath $PSScriptRoot -File) {
        if ($item.Name -eq 'SHA256SUMS.txt') { continue }
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            -not $expected.ContainsKey($item.Name)) {
            throw "Unexpected or linked bundle file: $($item.Name)"
        }
        $actual = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -ne $expected[$item.Name]) { throw "Bundle checksum mismatch: $($item.Name)" }
        $verified[$item.Name] = $actual
        [void]$expected.Remove($item.Name)
    }
    if ($expected.Count -ne 0) {
        throw "Bundle is missing checksummed files: $(@($expected.Keys) -join ', ')"
    }
    return $verified
}

function Get-TaskName {
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value.Replace('-', '_')
    return "RatelMesh-$sid"
}

function Get-PreviousValue {
    param(
        [object]$Config,
        [Parameter(Mandatory = $true)][string]$Name,
        [object]$Default
    )
    if ($null -eq $Config -or -not ($Config.PSObject.Properties.Name -contains $Name)) {
        return $Default
    }
    return $Config.$Name
}

$bundleHashes = Assert-BundleIntegrity
$InstallDir = Resolve-ManagedPath -Path $InstallDir `
    -Root (Join-Path $env:LOCALAPPDATA 'Programs\RatelMesh') -Label 'InstallDir'
$StateDir = Resolve-ManagedPath -Path $StateDir `
    -Root (Join-Path $env:LOCALAPPDATA 'RatelMesh\state') -Label 'StateDir'
foreach ($name in @('ratelmeshd.exe', 'ratelmesh.exe', 'Start-RatelMesh.ps1', 'Show-RatelMeshPrivacy.ps1', 'client.json')) {
    $managedPath = Join-Path $InstallDir $name
    if (Test-Path -LiteralPath $managedPath) {
        [void](Assert-RegularFile -Path $managedPath -Label "managed $name")
    }
}
$HbmdPath = Assert-RegularFile -Path $HbmdPath -Label 'ratelmeshd.exe'
$HbmPath = Assert-RegularFile -Path $HbmPath -Label 'ratelmesh.exe'
foreach ($scriptName in @('Start-RatelMesh.ps1', 'Show-RatelMeshPrivacy.ps1')) {
    [void](Assert-RegularFile -Path (Join-Path $PSScriptRoot $scriptName) -Label $scriptName)
}

$configPath = Join-Path $InstallDir 'client.json'
$oldConfig = $null
if (Test-Path -LiteralPath $configPath -PathType Leaf) {
    try {
        if ((Get-Item -LiteralPath $configPath -Force).Length -gt 1MB) {
            throw 'configuration exceeds 1 MB'
        }
        $oldConfig = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
    } catch {
        throw "Existing RatelMesh configuration is unreadable; no service or file was changed: $configPath"
    }
}
if ($null -ne $oldConfig) {
    if (-not $PSBoundParameters.ContainsKey('Hostname')) {
        $Hostname = [string](Get-PreviousValue $oldConfig 'Hostname' $Hostname)
    }
    if (-not $PSBoundParameters.ContainsKey('Relay')) {
        $Relay = [string](Get-PreviousValue $oldConfig 'Relay' $Relay)
    }
    if (-not $PSBoundParameters.ContainsKey('VerifyKey')) {
        $VerifyKey = [string](Get-PreviousValue $oldConfig 'VerifyKey' $VerifyKey)
    }
    if (-not $PSBoundParameters.ContainsKey('AcceptRoutes')) {
        $AcceptRoutes = [bool](Get-PreviousValue $oldConfig 'AcceptRoutes' $false)
    }
    if (-not $PSBoundParameters.ContainsKey('ForceRelay')) {
        $ForceRelay = [bool](Get-PreviousValue $oldConfig 'ForceRelay' $false)
    }
    if (-not $PSBoundParameters.ContainsKey('KillSwitch')) {
        $KillSwitch = [bool](Get-PreviousValue $oldConfig 'KillSwitch' $false)
    }
    if (-not $PSBoundParameters.ContainsKey('RunAsExitNode')) {
        $RunAsExitNode = [string](Get-PreviousValue $oldConfig 'Role' 'plain') -eq 'exit'
    }
    if (-not $PSBoundParameters.ContainsKey('DisableMagicDNS')) {
        $DisableMagicDNS = -not [bool](Get-PreviousValue $oldConfig 'MagicDNS' $true)
    }
    if (-not $PSBoundParameters.ContainsKey('TunnelDNS') -and -not $DisableMagicDNS) {
        $TunnelDNS = [string](Get-PreviousValue $oldConfig 'TunnelDNS' $TunnelDNS)
    }
    if (-not $PSBoundParameters.ContainsKey('EnableGui')) {
        $EnableGui = [bool](Get-PreviousValue $oldConfig 'GuiEnabled' $false)
    }
    if (-not $PSBoundParameters.ContainsKey('GuiAddress')) {
        $GuiAddress = [string](Get-PreviousValue $oldConfig 'GuiAddress' $GuiAddress)
    }
    if (-not $PSBoundParameters.ContainsKey('Language')) {
        $Language = [string](Get-PreviousValue $oldConfig 'Language' $Language)
    }
    if (-not $PSBoundParameters.ContainsKey('SplitTunnelPath')) {
        $SplitTunnelPath = [string](Get-PreviousValue $oldConfig 'SplitTunnelPath' $SplitTunnelPath)
    }
    if (-not $PSBoundParameters.ContainsKey('StateDir')) {
        $StateDir = [string](Get-PreviousValue $oldConfig 'StateDir' $StateDir)
    }
}
$StateDir = Resolve-ManagedPath -Path $StateDir `
    -Root (Join-Path $env:LOCALAPPDATA 'RatelMesh\state') -Label 'StateDir'
$allowedLanguages = @('system', 'en', 'es', 'de', 'fr', 'ja', 'ko', 'it', 'nl', 'pl', 'sv', 'pt-BR', 'zh-Hans', 'zh-Hant')
if ($Language -notin $allowedLanguages) {
    throw "Existing configuration contains an unsupported language: $Language"
}
if ($GuiAddress -notmatch '^(127\.0\.0\.1|\[::1\]):([0-9]{1,5})$' -or
    [int]$Matches[2] -lt 1 -or [int]$Matches[2] -gt 65535) {
    throw "Existing configuration contains an unsafe GUI address: $GuiAddress"
}

$wireGuard = Get-WireGuardExecutable
if ($null -eq $wireGuard) {
    if ([string]::IsNullOrWhiteSpace($WireGuardInstaller)) {
        throw 'WireGuard for Windows is required. Install it from wireguard.com, or pass -WireGuardInstaller with the official signed MSI/EXE.'
    }
    if (-not (Test-Path -LiteralPath $WireGuardInstaller -PathType Leaf)) {
        throw "WireGuard installer not found: $WireGuardInstaller"
    }
    $WireGuardInstaller = Assert-RegularFile -Path $WireGuardInstaller -Label 'WireGuard installer'
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

New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
New-Item -ItemType Directory -Path $StateDir -Force | Out-Null
Set-PrivateAcl -Path $InstallDir -Container
Set-PrivateAcl -Path $StateDir -Container

$stageDir = Join-Path $InstallDir ('.install-{0}' -f [Guid]::NewGuid().ToString('N'))
$backupDir = Join-Path $InstallDir ('.rollback-{0}' -f [Guid]::NewGuid().ToString('N'))
try {
New-Item -ItemType Directory -Path $stageDir | Out-Null
New-Item -ItemType Directory -Path $backupDir | Out-Null
Set-PrivateAcl -Path $stageDir -Container
Set-PrivateAcl -Path $backupDir -Container

$sourceFiles = [ordered]@{
    'ratelmeshd.exe' = $HbmdPath
    'ratelmesh.exe' = $HbmPath
    'Start-RatelMesh.ps1' = (Join-Path $PSScriptRoot 'Start-RatelMesh.ps1')
    'Show-RatelMeshPrivacy.ps1' = (Join-Path $PSScriptRoot 'Show-RatelMeshPrivacy.ps1')
}
foreach ($entry in $sourceFiles.GetEnumerator()) {
    $sourceHash = (Get-FileHash -LiteralPath $entry.Value -Algorithm SHA256).Hash
    if ($sourceHash.ToLowerInvariant() -ne $bundleHashes[$entry.Key]) {
        throw "Bundle file changed before staging $($entry.Key)"
    }
    $stagedPath = Join-Path $stageDir $entry.Key
    Copy-Item -LiteralPath $entry.Value -Destination $stagedPath
    if ((Get-FileHash -LiteralPath $stagedPath -Algorithm SHA256).Hash -ne $sourceHash) {
        throw "Source changed while staging $($entry.Key)"
    }
}

$protectedAuthKey = ''
if ($null -ne $AuthKey) {
    $protectedAuthKey = ConvertFrom-SecureString -SecureString $AuthKey
} elseif ($null -ne $oldConfig) {
    $protectedAuthKey = [string](Get-PreviousValue $oldConfig 'AuthKeyProtected' '')
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
$config | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $stageDir 'client.json') -Encoding UTF8

$taskName = Get-TaskName
$oldTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
$oldTaskXml = if ($null -ne $oldTask) { Export-ScheduledTask -TaskName $taskName } else { $null }
if ($null -ne $oldTask) {
    Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
}

$oldHbmd = Join-Path $InstallDir 'ratelmeshd.exe'
Get-CimInstance Win32_Process -Filter "Name = 'ratelmeshd.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.ExecutablePath -ieq $oldHbmd } |
    ForEach-Object { Invoke-CimMethod -InputObject $_ -MethodName Terminate | Out-Null }
$attempt = 0
do {
    $oldProcess = Get-CimInstance Win32_Process -Filter "Name = 'ratelmeshd.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.ExecutablePath -ieq $oldHbmd } |
        Select-Object -First 1
    if ($null -eq $oldProcess) { break }
    Start-Sleep -Milliseconds 250
    $attempt++
} while ($attempt -lt 40)
if ($null -ne $oldProcess) {
    if ($null -ne $oldTask) { Start-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue }
    throw 'The previous RatelMesh daemon did not stop; existing task, binaries and configuration were retained.'
}

$installedHbmd = Join-Path $InstallDir 'ratelmeshd.exe'
$installedHbm = Join-Path $InstallDir 'ratelmesh.exe'
$startScript = Join-Path $InstallDir 'Start-RatelMesh.ps1'
$privacyScript = Join-Path $InstallDir 'Show-RatelMeshPrivacy.ps1'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$actionArgs = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$startScript`" -ConfigPath `"$configPath`""
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $actionArgs
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $identity.Name
$principal = New-ScheduledTaskPrincipal -UserId $identity.Name -LogonType Interactive -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)

$managedFiles = @('ratelmeshd.exe', 'ratelmesh.exe', 'Start-RatelMesh.ps1', 'Show-RatelMeshPrivacy.ps1', 'client.json')
foreach ($name in $managedFiles) {
    $existing = Join-Path $InstallDir $name
    if (Test-Path -LiteralPath $existing -PathType Leaf) {
        Copy-Item -LiteralPath $existing -Destination (Join-Path $backupDir $name)
    }
}
try {
    foreach ($name in $managedFiles) {
        Copy-Item -LiteralPath (Join-Path $stageDir $name) -Destination (Join-Path $InstallDir $name) -Force
        Set-PrivateAcl -Path (Join-Path $InstallDir $name)
    }
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings `
        -Description 'RatelMesh per-user WireGuard client' -Force | Out-Null
    Start-ScheduledTask -TaskName $taskName
    Start-Sleep -Seconds 1
    if ((Get-ScheduledTask -TaskName $taskName).State -ne 'Running') {
        $result = (Get-ScheduledTaskInfo -TaskName $taskName).LastTaskResult
        throw "New RatelMesh task exited during startup with result $result"
    }
} catch {
    Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    foreach ($name in $managedFiles) {
        $installed = Join-Path $InstallDir $name
        $backup = Join-Path $backupDir $name
        if (Test-Path -LiteralPath $backup -PathType Leaf) {
            Copy-Item -LiteralPath $backup -Destination $installed -Force
        } else {
            Remove-Item -LiteralPath $installed -Force -ErrorAction SilentlyContinue
        }
    }
    if ($null -ne $oldTaskXml) {
        Register-ScheduledTask -TaskName $taskName -Xml $oldTaskXml -Force | Out-Null
        Start-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    } else {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    }
    throw
} finally {
    Remove-Item -LiteralPath $stageDir -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $backupDir -Recurse -Force -ErrorAction SilentlyContinue
}

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

Start-Process 'powershell.exe' -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$privacyScript`" -Language `"$Language`"" | Out-Null
Write-Host "RatelMesh installed for $($identity.Name)."
Write-Host "Task: $taskName"
Write-Host "State: $StateDir"
if ($EnableGui) { Write-Host "GUI: http://$GuiAddress" }
Write-Host 'Open a new terminal and run: ratelmesh status'
} finally {
    Remove-Item -LiteralPath $stageDir -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $backupDir -Recurse -Force -ErrorAction SilentlyContinue
}
