[CmdletBinding()]
param(
  [Parameter(Mandatory)][ValidateSet('x64', 'arm64')][string] $Architecture,
  [Parameter(Mandatory)][version] $Version,
  [Parameter(Mandatory)][string] $Publisher,
  [Parameter(Mandatory)][string] $SignerThumbprint,
  [Parameter(Mandatory)][string] $ClientBinary,
  [Parameter(Mandatory)][string] $BrokerPackage,
  [Parameter(Mandatory)][string] $CompanionPackage,
  [string] $StagedNpmDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Palladin.Release.psm1') -Force

Assert-PalladinArchitecture -Path $ClientBinary -Architecture $Architecture
foreach ($artifact in $ClientBinary, $BrokerPackage, $CompanionPackage) {
  Assert-PalladinSignature -Path $artifact -Publisher $Publisher -Thumbprint $SignerThumbprint -RequireTimestamp
}
Assert-PalladinPackageIdentity -PackagePath $BrokerPackage -ExpectedName 'Palladin.Runtime.Broker' -Publisher $Publisher -Version $Version -Architecture $Architecture
Assert-PalladinPackageIdentity -PackagePath $CompanionPackage -ExpectedName 'Palladin.Runtime.Companion' -Publisher $Publisher -Version $Version -Architecture $Architecture

$temporary = Join-Path ([System.IO.Path]::GetTempPath()) "palladin-contract-$([guid]::NewGuid())"
New-Item -ItemType Directory -Path $temporary | Out-Null
try {
  $brokerRoot = Join-Path $temporary 'broker'
  $companionRoot = Join-Path $temporary 'companion'
  & makeappx.exe unpack /p $BrokerPackage /d $brokerRoot /o | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'broker package cannot be unpacked' }
  & makeappx.exe unpack /p $CompanionPackage /d $companionRoot /o | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'companion package cannot be unpacked' }
  $brokerManifest = Get-Content -LiteralPath (Join-Path $brokerRoot 'AppxManifest.xml') -Raw
  $companionManifest = Get-Content -LiteralPath (Join-Path $companionRoot 'AppxManifest.xml') -Raw
  if ($brokerManifest -notmatch 'Name="PalladinRuntime"' -or
      $brokerManifest -notmatch 'StartAccount="localService"' -or
      $brokerManifest -notmatch 'Name="packagedServices"') {
    throw 'broker package does not declare the fixed packaged LocalService contract'
  }
  $brokerService = Join-Path $brokerRoot 'bin/palladin-service.exe'
  $brokerWorker = Join-Path $brokerRoot 'bin/palladin-worker.exe'
  $brokerExecutor = Join-Path $brokerRoot 'bin/palladin-executor.exe'
  Assert-PalladinArchitecture -Path $brokerService -Architecture $Architecture
  Assert-PalladinArchitecture -Path $brokerWorker -Architecture $Architecture
  Assert-PalladinArchitecture -Path $brokerExecutor -Architecture $Architecture
  Assert-PalladinSignature -Path $brokerExecutor -Publisher $Publisher -Thumbprint $SignerThumbprint -RequireTimestamp
  if ($companionManifest -notmatch 'uap10:TrustLevel="appContainer"' -or
      $companionManifest -notmatch 'Alias="palladin-runtime-companion.exe"' -or
      $companionManifest -match 'runFullTrust') {
    throw 'companion package is not an AppContainer-only package'
  }
  Assert-PalladinArchitecture -Path (Join-Path $companionRoot 'bin/palladin-companion.exe') -Architecture $Architecture
} finally {
  Remove-Item -LiteralPath $temporary -Recurse -Force -ErrorAction SilentlyContinue
}

if ($StagedNpmDirectory) {
  $manifestPath = Join-Path $StagedNpmDirectory 'package.json'
  $clientPath = Join-Path $StagedNpmDirectory 'bin/palladin-client.exe'
  $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
  if ($manifest.name -cne "@palladin/runtime-win32-$Architecture") { throw 'unexpected npm package name' }
  if (($manifest.os -join ',') -cne 'win32' -or ($manifest.cpu -join ',') -cne $Architecture) { throw 'unexpected npm platform selectors' }
  foreach ($field in 'private', 'scripts', 'dependencies', 'optionalDependencies') {
    if ($null -ne $manifest.PSObject.Properties[$field]) { throw "published npm package contains forbidden field: $field" }
  }
  Assert-PalladinArchitecture -Path $clientPath -Architecture $Architecture
  Assert-PalladinSignature -Path $clientPath -Publisher $Publisher -Thumbprint $SignerThumbprint -RequireTimestamp
}
