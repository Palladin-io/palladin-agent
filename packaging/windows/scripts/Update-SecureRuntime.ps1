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
$serviceSid = ([Security.Principal.NTAccount]'NT SERVICE\PalladinRuntime').Translate([Security.Principal.SecurityIdentifier])
# Fail before package registration if any owner, ACE, inheritance flag, link,
# junction, or canonical ProgramData segment changed since installation.
Assert-PalladinProtectedDataRoot -ServiceSid $serviceSid
$stage = New-PalladinProtectedUpdateStage
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
  $service = Get-CimInstance Win32_Service -Filter "Name='PalladinRuntime'"
  if ($null -eq $service -or $service.StartName -notin @('NT AUTHORITY\LocalService', 'NT AUTHORITY\LOCAL SERVICE')) {
    throw 'PalladinRuntime is not registered under LocalService after update'
  }
  Assert-PalladinProtectedDataRoot -ServiceSid $serviceSid
  $controller = Get-Service -Name PalladinRuntime -ErrorAction Stop
  if ($controller.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Running) {
    Start-Service -Name PalladinRuntime -ErrorAction Stop
    (Get-Service -Name PalladinRuntime).WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(30))
  }
} finally {
  Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
}
