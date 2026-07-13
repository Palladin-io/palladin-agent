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

function Get-ValidatedPalladinRuntimeServiceSid {
  $sidType = & sc.exe qsidtype PalladinRuntime
  if ($LASTEXITCODE -ne 0 -or ($sidType -join "`n") -notmatch 'SERVICE_SID_TYPE:\s+RESTRICTED') {
    throw 'PalladinRuntime service SID is not restricted'
  }
  $service = Get-CimInstance Win32_Service -Filter "Name='PalladinRuntime'"
  if ($null -eq $service -or $service.StartName -notin @('NT AUTHORITY\LocalService', 'NT AUTHORITY\LOCAL SERVICE')) {
    throw 'PalladinRuntime is not registered under LocalService'
  }
  return ([Security.Principal.NTAccount]'NT SERVICE\PalladinRuntime').Translate([Security.Principal.SecurityIdentifier])
}

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

# First install denies the auto-start service until its restricted SID is
# configured. Repair/reinstall must preserve and verify the existing final ACL;
# it must never downgrade that ACL back to bootstrap permissions.
$existingService = Get-Service -Name PalladinRuntime -ErrorAction SilentlyContinue
$existingServiceSid = $null
if ($null -eq $existingService) {
  $dataRoot = Initialize-PalladinBootstrapDataRoot
} else {
  $existingServiceSid = Get-ValidatedPalladinRuntimeServiceSid
  Assert-PalladinProtectedDataRoot -ServiceSid $existingServiceSid
  $dataRoot = Join-Path (Get-PalladinCanonicalProgramDataRoot) 'Palladin\Runtime\v1'
}
Add-AppxPackage -Path $BrokerPackage -ForceApplicationShutdown -ErrorAction Stop
Add-AppxPackage -Path $CompanionPackage -ForceApplicationShutdown -ErrorAction Stop
$registeredService = Get-Service -Name PalladinRuntime -ErrorAction Stop
if ($registeredService.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
  Stop-Service -Name PalladinRuntime -Force -ErrorAction Stop
  (Get-Service -Name PalladinRuntime).WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(30))
}
& sc.exe sidtype PalladinRuntime restricted | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'could not configure the restricted PalladinRuntime service SID' }
$serviceSid = Get-ValidatedPalladinRuntimeServiceSid
if ($null -ne $existingServiceSid -and $serviceSid.Value -cne $existingServiceSid.Value) {
  throw 'PalladinRuntime service SID changed during repair'
}
$promotedRoot = Initialize-PalladinProtectedDataRoot -ServiceSid $serviceSid
if ($promotedRoot -cne $dataRoot) { throw 'canonical ProgramData root changed during installation' }
Assert-PalladinProtectedDataRoot -ServiceSid $serviceSid
Start-Service -Name PalladinRuntime -ErrorAction Stop
(Get-Service -Name PalladinRuntime).WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(30))
