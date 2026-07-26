#Requires -Version 5.1

[CmdletBinding()]
param(
    [ValidateSet('amd64', 'arm64')]
    [string]$Arch = 'amd64',
    [ValidateScript({ $_ -eq 'dev' -or $_ -match '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' })]
    [string]$Version = 'dev',
    [string]$OutputDir = (Join-Path $PSScriptRoot 'dist'),
    [string]$CodeSigningCertificateThumbprint = '',
    [string]$TimestampServer = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not [string]::IsNullOrWhiteSpace($TimestampServer)) {
    $timestampUri = $null
    if (-not [Uri]::TryCreate($TimestampServer, [UriKind]::Absolute, [ref]$timestampUri) -or
        $timestampUri.Scheme -ne 'http' -or [string]::IsNullOrWhiteSpace($timestampUri.Host) -or
        -not [string]::IsNullOrEmpty($timestampUri.UserInfo)) {
        throw '-TimestampServer must be an absolute http:// Authenticode endpoint without credentials.'
    }
}
if (-not [string]::IsNullOrWhiteSpace($CodeSigningCertificateThumbprint)) {
    $normalizedThumbprint = $CodeSigningCertificateThumbprint.Replace(' ', '').ToUpperInvariant()
    if ($normalizedThumbprint -notmatch '^[0-9A-F]{40,128}$') {
        throw '-CodeSigningCertificateThumbprint must contain only a certificate hexadecimal digest.'
    }
}

$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$OutputDir = [IO.Path]::GetFullPath($OutputDir)
$bundle = Join-Path $OutputDir "RatelMesh-windows-$Arch"
if (Test-Path -LiteralPath $bundle) {
    throw "Bundle output must not already exist: $bundle"
}
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
$stage = Join-Path $OutputDir ('.RatelMesh-windows-{0}.{1}' -f $Arch, [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $stage | Out-Null
$published = $false

try {
$oldGoos = $env:GOOS
$oldGoarch = $env:GOARCH
$oldCgo = $env:CGO_ENABLED
Push-Location $repoRoot
try {
    $env:GOOS = 'windows'
    $env:GOARCH = $Arch
    $env:CGO_ENABLED = '0'
    & go build -trimpath -tags wgreal -o (Join-Path $stage 'ratelmeshd.exe') '.\cmd\ratelmeshd'
    if ($LASTEXITCODE -ne 0) { throw 'ratelmeshd Windows build failed' }
    & go build -trimpath -ldflags "-s -w -X main.version=$Version" -o (Join-Path $stage 'ratelmesh.exe') '.\cmd\ratelmesh'
    if ($LASTEXITCODE -ne 0) { throw 'ratelmesh Windows build failed' }
} finally {
    Pop-Location
    $env:GOOS = $oldGoos
    $env:GOARCH = $oldGoarch
    $env:CGO_ENABLED = $oldCgo
}

foreach ($name in @('Install-RatelMesh.ps1', 'Start-RatelMesh.ps1', 'Show-RatelMeshPrivacy.ps1', 'Uninstall-RatelMesh.ps1', 'README.md')) {
    $source = Join-Path $PSScriptRoot $name
    $destination = Join-Path $stage $name
    if ([IO.Path]::GetExtension($name) -ieq '.ps1') {
        # Windows PowerShell 5.1 otherwise interprets UTF-8 scripts without a
        # BOM using the current ANSI code page and corrupts localized copy.
        $content = [IO.File]::ReadAllText($source, [Text.Encoding]::UTF8)
        [IO.File]::WriteAllText($destination, $content, (New-Object Text.UTF8Encoding($true)))
    } else {
        Copy-Item -LiteralPath $source -Destination $destination
    }
}

if (-not [string]::IsNullOrWhiteSpace($CodeSigningCertificateThumbprint)) {
    $thumbprint = $normalizedThumbprint
    $certificate = $null
    foreach ($store in @('Cert:\CurrentUser\My', 'Cert:\LocalMachine\My')) {
        $candidate = Get-Item -LiteralPath (Join-Path $store $thumbprint) -ErrorAction SilentlyContinue
        if ($null -ne $candidate) { $certificate = $candidate; break }
    }
    if ($null -eq $certificate) { throw "Code-signing certificate not found: $thumbprint" }
    if (-not $certificate.HasPrivateKey) { throw "Code-signing certificate has no private key: $thumbprint" }

    $signable = Get-ChildItem -LiteralPath $stage -File | Where-Object { $_.Extension -in @('.exe', '.ps1') }
    foreach ($file in $signable) {
        $arguments = @{
            FilePath = $file.FullName
            Certificate = $certificate
            HashAlgorithm = 'SHA256'
        }
        if (-not [string]::IsNullOrWhiteSpace($TimestampServer)) {
            $arguments.TimestampServer = $TimestampServer
        }
        $signature = Set-AuthenticodeSignature @arguments
        if ($signature.Status -ne [Management.Automation.SignatureStatus]::Valid) {
            throw "Authenticode signing failed for $($file.Name): $($signature.StatusMessage)"
        }
    }
}

$goVersion = (& go version).Trim()
$metadata = [ordered]@{ Version = $Version; Architecture = $Arch; Go = $goVersion }
[IO.File]::WriteAllText(
    (Join-Path $stage 'BUILD-METADATA.json'),
    ($metadata | ConvertTo-Json),
    (New-Object Text.UTF8Encoding($false))
)
foreach ($binary in @('ratelmesh.exe', 'ratelmeshd.exe')) {
    $module = (& go version -m (Join-Path $stage $binary) 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0 -or $module -notmatch "(?m)^\s*build\s+GOARCH=$([Regex]::Escape($Arch))\s*$") {
        throw "$binary does not match requested architecture $Arch"
    }
}

$hashes = Get-ChildItem -LiteralPath $stage -File | Sort-Object Name | Get-FileHash -Algorithm SHA256 |
    ForEach-Object { '{0}  {1}' -f $_.Hash.ToLowerInvariant(), (Split-Path $_.Path -Leaf) }
$hashes | Set-Content -LiteralPath (Join-Path $stage 'SHA256SUMS.txt') -Encoding ASCII
[IO.Directory]::Move($stage, $bundle)
$published = $true
} finally {
    if (-not $published -and (Test-Path -LiteralPath $stage -PathType Container)) {
        Remove-Item -LiteralPath $stage -Recurse -Force
    }
}
Write-Host "Windows bundle created: $bundle"
