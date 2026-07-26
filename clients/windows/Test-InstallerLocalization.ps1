#Requires -Version 5.1

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = $PSScriptRoot
$installer = Get-Content -LiteralPath (Join-Path $root 'Install-RatelMesh.ps1') -Raw
$privacy = Get-Content -LiteralPath (Join-Path $root 'Show-RatelMeshPrivacy.ps1') -Raw
$locales = @('en', 'es', 'de', 'fr', 'ja', 'ko', 'it', 'nl', 'pl', 'sv', 'pt-BR', 'zh-Hans', 'zh-Hant')

foreach ($locale in $locales) {
    if ($installer -notmatch [Regex]::Escape("'$locale'")) {
        throw "Installer language list misses $locale"
    }
    if ($privacy -notmatch [Regex]::Escape("'$locale' = @(")) {
        throw "Privacy copy misses $locale"
    }
}
if ($installer -notmatch '-Language `"\$Language`"') {
    throw 'Installer does not pass its selected language to the privacy prompt.'
}
if ($privacy -notmatch 'Resolve-RatelMeshLanguage') {
    throw 'Privacy prompt does not resolve system language safely.'
}

Write-Output 'Windows installer localization tests passed'
