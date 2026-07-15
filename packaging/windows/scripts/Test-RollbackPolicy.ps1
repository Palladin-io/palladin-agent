[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Palladin.Release.psm1') -Force

Assert-PalladinVersionPolicy -CurrentVersion 1.2.0.0 -CandidateVersion 1.3.0.0 -SecurityFloor 1.1.0.0

$rejectedDowngrade = $false
try { Assert-PalladinVersionPolicy -CurrentVersion 1.3.0.0 -CandidateVersion 1.2.0.0 -SecurityFloor 1.1.0.0 } catch { $rejectedDowngrade = $true }
if (-not $rejectedDowngrade) { throw 'version downgrade was accepted' }

$rejectedBelowFloor = $false
try { Assert-PalladinVersionPolicy -CurrentVersion 1.3.0.0 -CandidateVersion 1.0.0.0 -SecurityFloor 1.1.0.0 } catch { $rejectedBelowFloor = $true }
if (-not $rejectedBelowFloor) { throw 'rollback below security floor was accepted' }
