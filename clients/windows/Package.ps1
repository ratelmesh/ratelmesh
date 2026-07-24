#Requires -Version 5.1

[CmdletBinding()]
param(
    [ValidateSet('amd64', 'arm64')]
    [string]$Arch = 'amd64',
    [string]$OutputDir = (Join-Path $PSScriptRoot 'dist'),
    [string]$CodeSigningCertificateThumbprint = '',
    [string]$TimestampServer = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not [string]::IsNullOrWhiteSpace($TimestampServer) -and $TimestampServer -notmatch '^http://') {
    throw '-TimestampServer must use an http:// Authenticode timestamp endpoint supported by Windows PowerShell 5.1.'
}

$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$OutputDir = [IO.Path]::GetFullPath($OutputDir)
$bundle = Join-Path $OutputDir "RatelMesh-windows-$Arch"
if (Test-Path -LiteralPath $bundle) { Remove-Item -LiteralPath $bundle -Recurse -Force }
New-Item -ItemType Directory -Path $bundle -Force | Out-Null

$oldGoos = $env:GOOS
$oldGoarch = $env:GOARCH
$oldCgo = $env:CGO_ENABLED
Push-Location $repoRoot
try {
    $env:GOOS = 'windows'
    $env:GOARCH = $Arch
    $env:CGO_ENABLED = '0'
    & go build -trimpath -tags wgreal -o (Join-Path $bundle 'ratelmeshd.exe') '.\cmd\ratelmeshd'
    if ($LASTEXITCODE -ne 0) { throw 'ratelmeshd Windows build failed' }
    & go build -trimpath -o (Join-Path $bundle 'ratelmesh.exe') '.\cmd\ratelmesh'
    if ($LASTEXITCODE -ne 0) { throw 'ratelmesh Windows build failed' }
} finally {
    Pop-Location
    $env:GOOS = $oldGoos
    $env:GOARCH = $oldGoarch
    $env:CGO_ENABLED = $oldCgo
}

foreach ($name in @('Install-RatelMesh.ps1', 'Start-RatelMesh.ps1', 'Show-RatelMeshPrivacy.ps1', 'Uninstall-RatelMesh.ps1', 'README.md')) {
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination $bundle
}

if (-not [string]::IsNullOrWhiteSpace($CodeSigningCertificateThumbprint)) {
    $thumbprint = $CodeSigningCertificateThumbprint.Replace(' ', '').ToUpperInvariant()
    $certificate = $null
    foreach ($store in @('Cert:\CurrentUser\My', 'Cert:\LocalMachine\My')) {
        $candidate = Get-Item -LiteralPath (Join-Path $store $thumbprint) -ErrorAction SilentlyContinue
        if ($null -ne $candidate) { $certificate = $candidate; break }
    }
    if ($null -eq $certificate) { throw "Code-signing certificate not found: $thumbprint" }
    if (-not $certificate.HasPrivateKey) { throw "Code-signing certificate has no private key: $thumbprint" }

    $signable = Get-ChildItem -LiteralPath $bundle -File | Where-Object { $_.Extension -in @('.exe', '.ps1') }
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

$hashes = Get-ChildItem -LiteralPath $bundle -File | Sort-Object Name | Get-FileHash -Algorithm SHA256 |
    ForEach-Object { '{0}  {1}' -f $_.Hash.ToLowerInvariant(), (Split-Path $_.Path -Leaf) }
$hashes | Set-Content -LiteralPath (Join-Path $bundle 'SHA256SUMS.txt') -Encoding ASCII
Write-Host "Windows bundle created: $bundle"
