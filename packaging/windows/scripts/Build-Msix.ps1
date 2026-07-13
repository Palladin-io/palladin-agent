[CmdletBinding()]
param(
  [Parameter(Mandatory)][ValidateSet('x64', 'arm64')][string] $Architecture,
  [Parameter(Mandatory)][ValidatePattern('^\d+\.\d+\.\d+\.\d+$')][string] $Version,
  [Parameter(Mandatory)][string] $Publisher,
  [Parameter(Mandatory)][string] $BrokerBinary,
  [Parameter(Mandatory)][string] $WorkerBinary,
  [Parameter(Mandatory)][string] $CompanionBinary,
  [Parameter(Mandatory)][string] $AssetsDirectory,
  [Parameter(Mandatory)][string] $OutputDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Palladin.Release.psm1') -Force
if (Test-Path -LiteralPath $OutputDirectory) { throw "output directory already exists: $OutputDirectory" }
Assert-PalladinArchitecture -Path $BrokerBinary -Architecture $Architecture
Assert-PalladinArchitecture -Path $WorkerBinary -Architecture $Architecture
Assert-PalladinArchitecture -Path $CompanionBinary -Architecture $Architecture
foreach ($asset in 'StoreLogo.png', 'Square150x150Logo.png', 'Square44x44Logo.png') {
  $null = Assert-PalladinRegularFile -Path (Join-Path $AssetsDirectory $asset) -Label 'MSIX asset'
}

$templateRoot = Join-Path $PSScriptRoot '../manifests'
$stagingRoot = Join-Path ([System.IO.Path]::GetTempPath()) "palladin-msix-build-$([guid]::NewGuid())"
New-Item -ItemType Directory -Path $OutputDirectory | Out-Null
try {
  foreach ($kind in 'Broker', 'Companion') {
    $stage = Join-Path $stagingRoot $kind
    New-Item -ItemType Directory -Path (Join-Path $stage 'bin') -Force | Out-Null
    Copy-Item -LiteralPath $AssetsDirectory -Destination (Join-Path $stage 'Assets') -Recurse
    $binary = if ($kind -eq 'Broker') { $BrokerBinary } else { $CompanionBinary }
    $name = if ($kind -eq 'Broker') { 'palladin-service.exe' } else { 'palladin-companion.exe' }
    Copy-Item -LiteralPath $binary -Destination (Join-Path $stage "bin/$name")
    if ($kind -eq 'Broker') {
      Copy-Item -LiteralPath $WorkerBinary -Destination (Join-Path $stage 'bin/palladin-worker.exe')
    }
    $manifest = Get-Content -LiteralPath (Join-Path $templateRoot "Palladin.$kind.appxmanifest.in") -Raw
    $publisherXml = [Security.SecurityElement]::Escape($Publisher)
    $manifest = $manifest.Replace('__PUBLISHER__', $publisherXml).Replace('__VERSION__', $Version).Replace('__ARCHITECTURE__', $Architecture)
    Set-Content -LiteralPath (Join-Path $stage 'AppxManifest.xml') -Value $manifest -Encoding utf8NoBOM
    $output = Join-Path $OutputDirectory "Palladin.Runtime.$kind-$Architecture-$Version.msix"
    & makeappx.exe pack /d $stage /p $output /o | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "makeappx failed for $kind" }
  }
} finally {
  Remove-Item -LiteralPath $stagingRoot -Recurse -Force -ErrorAction SilentlyContinue
}
