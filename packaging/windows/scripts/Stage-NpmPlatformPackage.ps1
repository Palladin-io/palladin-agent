[CmdletBinding()]
param(
  [Parameter(Mandatory)][ValidateSet('x64', 'arm64')][string] $Architecture,
  [Parameter(Mandatory)][string] $ClientBinary,
  [Parameter(Mandatory)][string] $OutputDirectory,
  [Parameter(Mandatory)][string] $Publisher,
  [Parameter(Mandatory)][string] $SignerThumbprint
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Palladin.Release.psm1') -Force

if (Test-Path -LiteralPath $OutputDirectory) { throw "output directory already exists: $OutputDirectory" }
Assert-PalladinArchitecture -Path $ClientBinary -Architecture $Architecture
Assert-PalladinSignature -Path $ClientBinary -Publisher $Publisher -Thumbprint $SignerThumbprint -RequireTimestamp

$root = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).Path
$source = Join-Path $root "packages/runtime-win32-$Architecture"
$manifestPath = Join-Path $source 'package.json'
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ($manifest.private -ne $true) { throw 'platform workspace must remain private' }
foreach ($field in 'scripts', 'dependencies', 'optionalDependencies') {
  if ($null -ne $manifest.PSObject.Properties[$field]) { throw "platform package must not contain $field" }
}

New-Item -ItemType Directory -Path (Join-Path $OutputDirectory 'bin') | Out-Null
Copy-Item -LiteralPath (Join-Path $source 'README.md') -Destination $OutputDirectory
Copy-Item -LiteralPath (Join-Path $source 'LICENSE') -Destination $OutputDirectory
Copy-Item -LiteralPath $ClientBinary -Destination (Join-Path $OutputDirectory 'bin/palladin-client.exe')
$manifest.PSObject.Properties.Remove('private')
$manifest | Add-Member -NotePropertyName os -NotePropertyValue @('win32')
$manifest | Add-Member -NotePropertyName cpu -NotePropertyValue @($Architecture)
$manifest | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'package.json') -Encoding utf8NoBOM
