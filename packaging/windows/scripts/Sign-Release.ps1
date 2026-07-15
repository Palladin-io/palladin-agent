[CmdletBinding()]
param(
  [Parameter(Mandatory)][string[]] $Artifacts,
  [Parameter(Mandatory)][string] $CertificateThumbprint,
  [Parameter(Mandatory)][ValidatePattern('^https://')][string] $TimestampUrl,
  [Parameter(Mandatory)][string] $Publisher
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Palladin.Release.psm1') -Force
$certificate = Get-Item -LiteralPath "Cert:\CurrentUser\My\$($CertificateThumbprint.Replace(' ', ''))" -ErrorAction Stop
foreach ($artifact in $Artifacts) {
  $null = Assert-PalladinRegularFile -Path $artifact -Label 'release artifact'
  if ([IO.Path]::GetExtension($artifact) -in @('.ps1', '.psm1')) {
    $signature = Set-AuthenticodeSignature -LiteralPath $artifact -Certificate $certificate -TimestampServer $TimestampUrl -HashAlgorithm SHA256
    if ($signature.Status -ne [Management.Automation.SignatureStatus]::Valid) { throw "PowerShell signing failed for $artifact" }
  } else {
    & signtool.exe sign /sha1 $CertificateThumbprint /fd SHA256 /tr $TimestampUrl /td SHA256 $artifact
    if ($LASTEXITCODE -ne 0) { throw "signtool failed for $artifact" }
    & signtool.exe verify /pa /all /v $artifact
    if ($LASTEXITCODE -ne 0) { throw "signtool verification failed for $artifact" }
  }
  Assert-PalladinSignature -Path $artifact -Publisher $Publisher -Thumbprint $CertificateThumbprint -RequireTimestamp
}
