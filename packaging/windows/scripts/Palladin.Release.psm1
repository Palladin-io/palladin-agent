Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-PalladinRegularFile {
  param([Parameter(Mandatory)][string] $Path, [string] $Label = 'file')
  $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  if ($item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
    throw "$Label must be a regular non-link file: $Path"
  }
  return $item
}

function Assert-PalladinArchitecture {
  param(
    [Parameter(Mandatory)][string] $Path,
    [Parameter(Mandatory)][ValidateSet('x64', 'arm64')][string] $Architecture
  )
  $item = Assert-PalladinRegularFile -Path $Path -Label 'PE executable'
  $stream = [System.IO.File]::OpenRead($item.FullName)
  try {
    $reader = [System.IO.BinaryReader]::new($stream)
    if ($reader.ReadUInt16() -ne 0x5A4D) { throw "not a PE executable: $Path" }
    $stream.Position = 0x3C
    $peOffset = $reader.ReadUInt32()
    if ($peOffset -gt ($stream.Length - 6)) { throw "invalid PE header offset: $Path" }
    $stream.Position = $peOffset
    if ($reader.ReadUInt32() -ne 0x00004550) { throw "invalid PE signature: $Path" }
    $machine = $reader.ReadUInt16()
  } finally {
    $stream.Dispose()
  }
  $expected = if ($Architecture -eq 'x64') { 0x8664 } else { 0xAA64 }
  if ($machine -ne $expected) {
    throw "PE machine 0x$($machine.ToString('X4')) does not match $Architecture"
  }
}

function Assert-PalladinSignature {
  param(
    [Parameter(Mandatory)][string] $Path,
    [Parameter(Mandatory)][string] $Publisher,
    [Parameter(Mandatory)][string] $Thumbprint,
    [switch] $RequireTimestamp
  )
  $null = Assert-PalladinRegularFile -Path $Path -Label 'signed artifact'
  $signature = Get-AuthenticodeSignature -LiteralPath $Path
  if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
    throw "Authenticode signature is not valid for ${Path}: $($signature.Status)"
  }
  $actualThumbprint = $signature.SignerCertificate.Thumbprint.Replace(' ', '').ToUpperInvariant()
  $expectedThumbprint = $Thumbprint.Replace(' ', '').ToUpperInvariant()
  if ($actualThumbprint -cne $expectedThumbprint) { throw "unexpected signer for $Path" }
  if ($signature.SignerCertificate.Subject -cne $Publisher) { throw "unexpected publisher for $Path" }
  if ($RequireTimestamp -and $null -eq $signature.TimeStamperCertificate) {
    throw "RFC3161 timestamp is missing for $Path"
  }
}

function Assert-PalladinVersionPolicy {
  param(
    [Parameter(Mandatory)][version] $CurrentVersion,
    [Parameter(Mandatory)][version] $CandidateVersion,
    [Parameter(Mandatory)][version] $SecurityFloor
  )
  if ($CandidateVersion -lt $SecurityFloor) {
    throw "candidate $CandidateVersion is below security floor $SecurityFloor"
  }
  if ($CandidateVersion -lt $CurrentVersion) {
    throw "version downgrade from $CurrentVersion to $CandidateVersion is forbidden; rebuild the prior code with a higher version"
  }
}

function Assert-PalladinPackageIdentity {
  param(
    [Parameter(Mandatory)][string] $PackagePath,
    [Parameter(Mandatory)][string] $ExpectedName,
    [Parameter(Mandatory)][string] $Publisher,
    [Parameter(Mandatory)][version] $Version,
    [Parameter(Mandatory)][ValidateSet('x64', 'arm64')][string] $Architecture
  )
  $item = Assert-PalladinRegularFile -Path $PackagePath -Label 'MSIX package'
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  $stream = [IO.File]::Open($item.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
  $archive = $null
  $entryStream = $null
  $reader = $null
  try {
    $archive = [IO.Compression.ZipArchive]::new($stream, [IO.Compression.ZipArchiveMode]::Read, $false)
    $entries = @($archive.Entries | Where-Object FullName -CEQ 'AppxManifest.xml')
    if ($entries.Count -ne 1) { throw "MSIX contains an invalid manifest set: $PackagePath" }
    $settings = [Xml.XmlReaderSettings]::new()
    $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $entryStream = $entries[0].Open()
    $reader = [Xml.XmlReader]::Create($entryStream, $settings)
    $manifest = [Xml.XmlDocument]::new()
    $manifest.XmlResolver = $null
    $manifest.Load($reader)
    $namespace = [Xml.XmlNamespaceManager]::new($manifest.NameTable)
    $namespace.AddNamespace('f', 'http://schemas.microsoft.com/appx/manifest/foundation/windows10')
    $identity = $manifest.SelectSingleNode('/f:Package/f:Identity', $namespace)
    if ($null -eq $identity) { throw "MSIX identity is missing: $PackagePath" }
    if ($identity.GetAttribute('Name') -cne $ExpectedName -or $identity.GetAttribute('Publisher') -cne $Publisher) {
      throw "package family identity mismatch for $PackagePath"
    }
    if ([version]$identity.GetAttribute('Version') -ne $Version -or $identity.GetAttribute('ProcessorArchitecture') -cne $Architecture) {
      throw "package version or architecture mismatch for $PackagePath"
    }
  } finally {
    if ($null -ne $reader) { $reader.Dispose() }
    if ($null -ne $entryStream) { $entryStream.Dispose() }
    if ($null -ne $archive) { $archive.Dispose() }
    $stream.Dispose()
  }
}

function Get-PalladinPackageFamilyName {
  param(
    [Parameter(Mandatory)][string] $Name,
    [Parameter(Mandatory)][string] $Publisher
  )
  if ($Name -cnotmatch '^[A-Za-z0-9.-]+$' -or [string]::IsNullOrWhiteSpace($Publisher)) {
    throw 'package name or publisher is invalid'
  }
  if (-not ('Palladin.PackageIdentityNative' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace Palladin {
  [StructLayout(LayoutKind.Sequential)]
  public struct PackageId {
    public uint reserved;
    public uint processorArchitecture;
    public ulong version;
    public IntPtr name;
    public IntPtr publisher;
    public IntPtr resourceId;
    public IntPtr publisherId;
  }

  public static class PackageIdentityNative {
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    internal static extern int PackageFamilyNameFromId(
      ref PackageId packageId,
      ref uint packageFamilyNameLength,
      IntPtr packageFamilyName);

    public static string FamilyName(string name, string publisher) {
      PackageId id = new PackageId();
      id.name = Marshal.StringToHGlobalUni(name);
      id.publisher = Marshal.StringToHGlobalUni(publisher);
      IntPtr output = IntPtr.Zero;
      try {
        uint length = 0;
        int result = PackageFamilyNameFromId(ref id, ref length, IntPtr.Zero);
        const int ErrorInsufficientBuffer = 122;
        if (result != ErrorInsufficientBuffer || length == 0) {
          throw new InvalidOperationException("package family length calculation failed");
        }
        output = Marshal.AllocHGlobal(checked((int)length * sizeof(char)));
        result = PackageFamilyNameFromId(ref id, ref length, output);
        if (result != 0) throw new InvalidOperationException("package family calculation failed");
        return Marshal.PtrToStringUni(output) ?? throw new InvalidOperationException("package family is empty");
      } finally {
        if (output != IntPtr.Zero) Marshal.FreeHGlobal(output);
        Marshal.FreeHGlobal(id.publisher);
        Marshal.FreeHGlobal(id.name);
      }
    }
  }
}
'@
  }
  return [Palladin.PackageIdentityNative]::FamilyName($Name, $Publisher)
}

Export-ModuleMember -Function Assert-PalladinRegularFile, Assert-PalladinArchitecture, Assert-PalladinSignature, Assert-PalladinVersionPolicy, Assert-PalladinPackageIdentity, Get-PalladinPackageFamilyName
