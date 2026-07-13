# This bootstrapper is signed together with every release. It never accepts an unsigned package.
[CmdletBinding()]
param(
  [Parameter(Mandatory)][ValidateSet('x64', 'arm64')][string] $Architecture,
  [Parameter(Mandatory)][version] $Version,
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
  throw 'Palladin Runtime installation requires an elevated administrator session'
}
Assert-PalladinVersionPolicy -CurrentVersion $SecurityFloor -CandidateVersion $Version -SecurityFloor $SecurityFloor
$trustedRoot = [IO.Path]::GetFullPath([Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)).TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
foreach ($package in $BrokerPackage, $CompanionPackage) {
  $packagePath = (Assert-PalladinRegularFile -Path $package -Label 'staged installer package').FullName
  if (-not $packagePath.StartsWith($trustedRoot, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'installer packages must be staged under protected Program Files'
  }
  Assert-PalladinSignature -Path $package -Publisher $Publisher -Thumbprint $SignerThumbprint -RequireTimestamp
}
Assert-PalladinPackageIdentity -PackagePath $BrokerPackage -ExpectedName 'Palladin.Runtime.Broker' -Publisher $Publisher -Version $Version -Architecture $Architecture
Assert-PalladinPackageIdentity -PackagePath $CompanionPackage -ExpectedName 'Palladin.Runtime.Companion' -Publisher $Publisher -Version $Version -Architecture $Architecture

Add-AppxPackage -Path $BrokerPackage -ForceApplicationShutdown -ErrorAction Stop
Add-AppxPackage -Path $CompanionPackage -ForceApplicationShutdown -ErrorAction Stop
& sc.exe sidtype PalladinRuntime restricted | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'could not configure the restricted PalladinRuntime service SID' }
$sidType = & sc.exe qsidtype PalladinRuntime
if ($LASTEXITCODE -ne 0 -or ($sidType -join "`n") -notmatch 'SERVICE_SID_TYPE:\s+RESTRICTED') {
  throw 'PalladinRuntime service SID is not restricted'
}
$service = Get-CimInstance Win32_Service -Filter "Name='PalladinRuntime'"
if ($null -eq $service -or $service.StartName -notin @('NT AUTHORITY\LocalService', 'NT AUTHORITY\LOCAL SERVICE')) {
  throw 'PalladinRuntime is not registered under LocalService'
}

$dataRoot = Join-Path $env:ProgramData 'Palladin\Runtime\v1'
New-Item -ItemType Directory -Path $dataRoot -Force | Out-Null
$serviceSid = ([Security.Principal.NTAccount]'NT SERVICE\PalladinRuntime').Translate([Security.Principal.SecurityIdentifier])
$allowedSids = @(
  [Security.Principal.SecurityIdentifier]'S-1-5-18',
  [Security.Principal.SecurityIdentifier]'S-1-5-32-544',
  $serviceSid
)
$acl = [Security.AccessControl.DirectorySecurity]::new()
$acl.SetAccessRuleProtection($true, $false)
foreach ($sid in $allowedSids) {
  $rule = [Security.AccessControl.FileSystemAccessRule]::new(
    $sid,
    [Security.AccessControl.FileSystemRights]::FullControl,
    [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
    [Security.AccessControl.PropagationFlags]::None,
    [Security.AccessControl.AccessControlType]::Allow
  )
  $acl.AddAccessRule($rule) | Out-Null
}
Set-Acl -LiteralPath $dataRoot -AclObject $acl
$effectiveAcl = Get-Acl -LiteralPath $dataRoot
if (-not $effectiveAcl.AreAccessRulesProtected) { throw 'broker data directory still inherits ACL entries' }
if (($effectiveAcl.Access | Where-Object AccessControlType -ne 'Allow').Count -ne 0) { throw 'broker data directory contains a deny rule' }
$actualSids = $effectiveAcl.Access |
  Where-Object AccessControlType -eq 'Allow' |
  ForEach-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } |
  Sort-Object -Unique
$expectedSids = $allowedSids.Value | Sort-Object -Unique
if (($actualSids -join ',') -cne ($expectedSids -join ',')) {
  throw 'broker data directory ACL contains an unexpected principal'
}
