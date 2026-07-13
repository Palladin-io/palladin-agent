[CmdletBinding()]
param(
  [Parameter(Mandatory)][ValidateSet('x64', 'arm64')][string] $Architecture,
  [Parameter(Mandatory)][version] $Version,
  [Parameter(Mandatory)][version] $SecurityFloor,
  [Parameter(Mandatory)][string] $Publisher,
  [Parameter(Mandatory)][string] $SignerThumbprint,
  [Parameter(Mandatory)][string] $BrokerPackage,
  [Parameter(Mandatory)][string] $CompanionPackage,
  [Parameter(Mandatory)][string] $OutputDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Palladin.Release.psm1') -Force
if (Test-Path -LiteralPath $OutputDirectory) { throw "output directory already exists: $OutputDirectory" }
$script = Join-Path $PSScriptRoot 'Install-SecureRuntime.ps1'
$module = Join-Path $PSScriptRoot 'Palladin.Release.psm1'
foreach ($artifact in $script, $module, $BrokerPackage, $CompanionPackage) {
  Assert-PalladinSignature -Path $artifact -Publisher $Publisher -Thumbprint $SignerThumbprint -RequireTimestamp
}
Assert-PalladinPackageIdentity -PackagePath $BrokerPackage -ExpectedName 'Palladin.Runtime.Broker' -Publisher $Publisher -Version $Version -Architecture $Architecture
Assert-PalladinPackageIdentity -PackagePath $CompanionPackage -ExpectedName 'Palladin.Runtime.Companion' -Publisher $Publisher -Version $Version -Architecture $Architecture

$sourceRoot = Join-Path $PSScriptRoot '../bootstrapper'
$temporary = Join-Path ([System.IO.Path]::GetTempPath()) "palladin-bootstrapper-$([guid]::NewGuid())"
New-Item -ItemType Directory -Path $temporary | Out-Null
try {
  Copy-Item -LiteralPath (Join-Path $sourceRoot 'Palladin.Bootstrapper.csproj') -Destination $temporary
  Copy-Item -LiteralPath (Join-Path $sourceRoot 'app.manifest') -Destination $temporary
  Copy-Item -LiteralPath $BrokerPackage -Destination (Join-Path $temporary 'Palladin.Runtime.Broker.msix')
  Copy-Item -LiteralPath $CompanionPackage -Destination (Join-Path $temporary 'Palladin.Runtime.Companion.msix')
  $moduleBase64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((Get-Content -LiteralPath $module -Raw)))
  $installText = Get-Content -LiteralPath $script -Raw
  $installText = $installText -replace "(?m)^Import-Module \(Join-Path \`$PSScriptRoot 'Palladin\.Release\.psm1'\) -Force\r?\n", ''
  if ($installText -match 'Import-Module') { throw 'embedded install script still imports a mutable module path' }
  $installBase64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($installText))
  $wrapper = @"
`$ErrorActionPreference = 'Stop'
`$moduleText = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$moduleBase64'))
`$installText = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$installBase64'))
Import-Module (New-Module -ScriptBlock ([ScriptBlock]::Create(`$moduleText))) -Force
& ([ScriptBlock]::Create(`$installText)) -Architecture `$env:PALLADIN_INSTALL_ARCHITECTURE -Version `$env:PALLADIN_INSTALL_VERSION -SecurityFloor `$env:PALLADIN_INSTALL_SECURITY_FLOOR -Publisher `$env:PALLADIN_INSTALL_PUBLISHER -SignerThumbprint `$env:PALLADIN_INSTALL_THUMBPRINT -BrokerPackage `$env:PALLADIN_INSTALL_BROKER -CompanionPackage `$env:PALLADIN_INSTALL_COMPANION
"@
  $payload = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($wrapper))
  $source = Get-Content -LiteralPath (Join-Path $sourceRoot 'Program.cs.in') -Raw
  $literal = { param([string] $Value) [System.Text.Json.JsonSerializer]::Serialize($Value) }
  $source = $source.Replace('__ARCHITECTURE_LITERAL__', (& $literal $Architecture))
  $source = $source.Replace('__VERSION_LITERAL__', (& $literal $Version.ToString()))
  $source = $source.Replace('__SECURITY_FLOOR_LITERAL__', (& $literal $SecurityFloor.ToString()))
  $source = $source.Replace('__PUBLISHER_LITERAL__', (& $literal $Publisher))
  $source = $source.Replace('__THUMBPRINT_LITERAL__', (& $literal $SignerThumbprint))
  $source = $source.Replace('__POWERSHELL_PAYLOAD_LITERAL__', (& $literal $payload))
  Set-Content -LiteralPath (Join-Path $temporary 'Program.cs') -Value $source -Encoding utf8NoBOM
  $rid = if ($Architecture -eq 'x64') { 'win-x64' } else { 'win-arm64' }
  & dotnet publish (Join-Path $temporary 'Palladin.Bootstrapper.csproj') -c Release -r $rid -o (Join-Path $temporary 'publish') --nologo
  if ($LASTEXITCODE -ne 0) { throw 'bootstrapper compilation failed' }
  New-Item -ItemType Directory -Path $OutputDirectory | Out-Null
  Copy-Item -LiteralPath (Join-Path $temporary 'publish/palladin-runtime-setup.exe') -Destination $OutputDirectory
} finally {
  Remove-Item -LiteralPath $temporary -Recurse -Force -ErrorAction SilentlyContinue
}
