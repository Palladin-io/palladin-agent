[CmdletBinding()]
param(
  [Parameter(Mandatory)][ValidateSet('Broker', 'Companion')][string] $Kind,
  [Parameter(Mandatory)][ValidatePattern('^\d+\.\d+\.\d+\.\d+$')][string] $Version,
  [Parameter(Mandatory)][string] $X64Package,
  [Parameter(Mandatory)][string] $Arm64Package,
  [Parameter(Mandatory)][string] $OutputBundle
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Palladin.Release.psm1') -Force
if (Test-Path -LiteralPath $OutputBundle) { throw "output bundle already exists: $OutputBundle" }
$root = Join-Path ([System.IO.Path]::GetTempPath()) "palladin-bundle-$([guid]::NewGuid())"
New-Item -ItemType Directory -Path $root | Out-Null
try {
  Copy-Item -LiteralPath (Assert-PalladinRegularFile -Path $X64Package -Label 'x64 MSIX').FullName -Destination (Join-Path $root "Palladin.Runtime.$Kind-x64-$Version.msix")
  Copy-Item -LiteralPath (Assert-PalladinRegularFile -Path $Arm64Package -Label 'arm64 MSIX').FullName -Destination (Join-Path $root "Palladin.Runtime.$Kind-arm64-$Version.msix")
  & makeappx.exe bundle /d $root /p $OutputBundle /bv $Version /o | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "makeappx failed to create $Kind bundle" }
} finally {
  Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
