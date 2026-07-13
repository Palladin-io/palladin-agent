[CmdletBinding()]
param(
  [Parameter(Mandatory)][ValidateSet('x64', 'arm64')][string] $Architecture,
  [Parameter(Mandatory)][version] $CandidateVersion,
  [Parameter(Mandatory)][version] $SecurityFloor,
  [Parameter(Mandatory)][string] $Publisher,
  [Parameter(Mandatory)][string] $SignerThumbprint,
  [Parameter(Mandatory)][string] $BrokerPackage,
  [Parameter(Mandatory)][string] $CompanionPackage
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Palladin.Release.psm1') -Force

$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'Palladin Runtime update requires an elevated administrator session'
}

$installed = Get-AppxPackage -AllUsers -Name 'Palladin.Runtime.Broker' | Sort-Object Version -Descending | Select-Object -First 1
if ($null -eq $installed) { throw 'Palladin Runtime is not installed; use the signed bootstrapper' }
$currentVersion = [version]$installed.Version
Assert-PalladinVersionPolicy -CurrentVersion $currentVersion -CandidateVersion $CandidateVersion -SecurityFloor $SecurityFloor
$stage = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)) "Palladin\UpdateCache\$([guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $stage -Force | Out-Null
$stageAcl = [Security.AccessControl.DirectorySecurity]::new()
$stageAcl.SetAccessRuleProtection($true, $false)
foreach ($sidValue in 'S-1-5-18', 'S-1-5-32-544') {
  $rule = [Security.AccessControl.FileSystemAccessRule]::new(
    [Security.Principal.SecurityIdentifier]$sidValue,
    [Security.AccessControl.FileSystemRights]::FullControl,
    [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
    [Security.AccessControl.PropagationFlags]::None,
    [Security.AccessControl.AccessControlType]::Allow
  )
  $stageAcl.AddAccessRule($rule) | Out-Null
}
Set-Acl -LiteralPath $stage -AclObject $stageAcl
$stagedBroker = Join-Path $stage 'Palladin.Runtime.Broker.msix'
$stagedCompanion = Join-Path $stage 'Palladin.Runtime.Companion.msix'
try {
  Copy-Item -LiteralPath $BrokerPackage -Destination $stagedBroker
  Copy-Item -LiteralPath $CompanionPackage -Destination $stagedCompanion
  foreach ($package in $stagedBroker, $stagedCompanion) {
    Assert-PalladinSignature -Path $package -Publisher $Publisher -Thumbprint $SignerThumbprint -RequireTimestamp
  }
  Assert-PalladinPackageIdentity -PackagePath $stagedBroker -ExpectedName 'Palladin.Runtime.Broker' -Publisher $Publisher -Version $CandidateVersion -Architecture $Architecture
  Assert-PalladinPackageIdentity -PackagePath $stagedCompanion -ExpectedName 'Palladin.Runtime.Companion' -Publisher $Publisher -Version $CandidateVersion -Architecture $Architecture

  $before = & sc.exe showsid PalladinRuntime
  if ($LASTEXITCODE -ne 0) { throw 'PalladinRuntime service SID is unavailable before update' }
  Add-AppxPackage -Path $stagedBroker -ForceApplicationShutdown -ErrorAction Stop
  Add-AppxPackage -Path $stagedCompanion -ForceApplicationShutdown -ErrorAction Stop
  $after = & sc.exe showsid PalladinRuntime
  if ($LASTEXITCODE -ne 0 -or ($before -join "`n") -cne ($after -join "`n")) { throw 'PalladinRuntime service SID changed during update' }
  $sidType = & sc.exe qsidtype PalladinRuntime
  if ($LASTEXITCODE -ne 0 -or ($sidType -join "`n") -notmatch 'SERVICE_SID_TYPE:\s+RESTRICTED') { throw 'PalladinRuntime service SID is not restricted after update' }
  $dataRoot = Join-Path $env:ProgramData 'Palladin\Runtime\v1'
  $acl = Get-Acl -LiteralPath $dataRoot
  if (-not $acl.AreAccessRulesProtected -or ($acl.Access | Where-Object AccessControlType -ne 'Allow').Count -ne 0) { throw 'broker data directory ACL is not protected after update' }
  $serviceSid = ([Security.Principal.NTAccount]'NT SERVICE\PalladinRuntime').Translate([Security.Principal.SecurityIdentifier]).Value
  $expectedSids = @('S-1-5-18', 'S-1-5-32-544', $serviceSid) | Sort-Object -Unique
  $actualSids = $acl.Access | ForEach-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } | Sort-Object -Unique
  if (($actualSids -join ',') -cne ($expectedSids -join ',')) { throw 'broker data directory ACL changed during update' }
} finally {
  Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
}
