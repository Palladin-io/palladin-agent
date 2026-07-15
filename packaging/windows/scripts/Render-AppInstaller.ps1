[CmdletBinding()]
param(
  [Parameter(Mandatory)][ValidatePattern('^\d+\.\d+\.\d+\.\d+$')][string] $Version,
  [Parameter(Mandatory)][string] $Publisher,
  [Parameter(Mandatory)][uri] $BaseUri,
  [Parameter(Mandatory)][string] $OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($BaseUri.Scheme -cne 'https') { throw 'App Installer release URI must use HTTPS' }
if (Test-Path -LiteralPath $OutputPath) { throw "App Installer output already exists: $OutputPath" }
$template = Get-Content -LiteralPath (Join-Path $PSScriptRoot '../manifests/Palladin.Runtime.appinstaller.in') -Raw
$base = $BaseUri.AbsoluteUri.TrimEnd('/')
$publisherXml = [Security.SecurityElement]::Escape($Publisher)
$values = @{
  '__APPINSTALLER_URI__' = [Security.SecurityElement]::Escape("$base/Palladin.Runtime.appinstaller")
  '__BROKER_URI__' = [Security.SecurityElement]::Escape("$base/Palladin.Runtime.Broker-$Version.msixbundle")
  '__COMPANION_URI__' = [Security.SecurityElement]::Escape("$base/Palladin.Runtime.Companion-$Version.msixbundle")
  '__PUBLISHER__' = $publisherXml
  '__VERSION__' = $Version
}
foreach ($entry in $values.GetEnumerator()) { $template = $template.Replace($entry.Key, $entry.Value) }
[xml]$validated = $template
Set-Content -LiteralPath $OutputPath -Value $validated.OuterXml -Encoding utf8NoBOM
