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

function Initialize-PalladinDirectorySecurityType {
  if ('Palladin.WindowsDirectorySecurity' -as [type]) { return }
  Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Palladin {
  public static class WindowsDirectorySecurity {
    private const uint FileReadAttributes = 0x00000080;
    private const uint ReadControl = 0x00020000;
    private const uint WriteDac = 0x00040000;
    private const uint WriteOwner = 0x00080000;
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint FileShareDelete = 0x00000004;
    private const uint OpenExisting = 3;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint FileAttributeDirectory = 0x00000010;
    private const uint FileAttributeReparsePoint = 0x00000400;
    private const uint OwnerSecurityInformation = 0x00000001;
    private const uint DaclSecurityInformation = 0x00000004;
    private const uint ProtectedDaclSecurityInformation = 0x80000000;
    private const uint SddlRevision1 = 1;
    private const uint ErrorAlreadyExists = 183;
    private const int SeFileObject = 1;
    private static readonly Guid FolderIdProgramData = new Guid("62AB5D82-FDC1-4DC3-A9DD-070D1D495D97");

    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes {
      public int length;
      public IntPtr securityDescriptor;
      [MarshalAs(UnmanagedType.Bool)] public bool inheritHandle;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileTime {
      public uint low;
      public uint high;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation {
      public uint fileAttributes;
      public FileTime creationTime;
      public FileTime lastAccessTime;
      public FileTime lastWriteTime;
      public uint volumeSerialNumber;
      public uint fileSizeHigh;
      public uint fileSizeLow;
      public uint numberOfLinks;
      public uint fileIndexHigh;
      public uint fileIndexLow;
    }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int SHGetKnownFolderPath(
      ref Guid folderId,
      uint flags,
      IntPtr token,
      out IntPtr path);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateDirectoryW(string path, ref SecurityAttributes attributes);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(
      string fileName,
      uint desiredAccess,
      uint shareMode,
      IntPtr securityAttributes,
      uint creationDisposition,
      uint flagsAndAttributes,
      IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(
      SafeFileHandle file,
      out ByHandleFileInformation information);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern uint GetSecurityInfo(
      SafeFileHandle handle,
      int objectType,
      uint securityInformation,
      out IntPtr owner,
      out IntPtr group,
      out IntPtr dacl,
      out IntPtr sacl,
      out IntPtr securityDescriptor);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern uint SetSecurityInfo(
      SafeFileHandle handle,
      int objectType,
      uint securityInformation,
      IntPtr owner,
      IntPtr group,
      IntPtr dacl,
      IntPtr sacl);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetSecurityDescriptorOwner(
      IntPtr securityDescriptor,
      out IntPtr owner,
      [MarshalAs(UnmanagedType.Bool)] out bool ownerDefaulted);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetSecurityDescriptorDacl(
      IntPtr securityDescriptor,
      [MarshalAs(UnmanagedType.Bool)] out bool daclPresent,
      out IntPtr dacl,
      [MarshalAs(UnmanagedType.Bool)] out bool daclDefaulted);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(
      string stringSecurityDescriptor,
      uint stringSdRevision,
      out IntPtr securityDescriptor,
      out uint securityDescriptorSize);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ConvertSecurityDescriptorToStringSecurityDescriptorW(
      IntPtr securityDescriptor,
      uint requestedStringSdRevision,
      uint securityInformation,
      out IntPtr stringSecurityDescriptor,
      out uint stringSecurityDescriptorLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr LocalFree(IntPtr memory);

    public static string ProgramDataRoot() {
      IntPtr raw = IntPtr.Zero;
      Guid folder = FolderIdProgramData;
      int result = SHGetKnownFolderPath(ref folder, 0, IntPtr.Zero, out raw);
      if (result < 0 || raw == IntPtr.Zero) {
        throw new Win32Exception(result, "FOLDERID_ProgramData resolution failed");
      }
      try {
        string value = Marshal.PtrToStringUni(raw);
        if (String.IsNullOrWhiteSpace(value) || !Path.IsPathRooted(value)) {
          throw new InvalidOperationException("FOLDERID_ProgramData returned an invalid path");
        }
        return Path.GetFullPath(value).TrimEnd(Path.DirectorySeparatorChar);
      } finally {
        Marshal.FreeCoTaskMem(raw);
      }
    }

    public static string EnsureBootstrapTree() {
      return ProcessTree(null, true, false);
    }

    public static string EnsureProtectedTree(string serviceSid) {
      ValidateServiceSid(serviceSid);
      return ProcessTree(serviceSid, false, false);
    }

    public static string PromoteProtectedTree(string serviceSid) {
      ValidateServiceSid(serviceSid);
      return ProcessTree(serviceSid, false, true);
    }

    public static string CreateAdministratorStagingDirectory(string programFilesRoot) {
      if (String.IsNullOrWhiteSpace(programFilesRoot) || !Path.IsPathRooted(programFilesRoot)) {
        throw new ArgumentException("Program Files root is invalid", "programFilesRoot");
      }
      string root = Path.GetFullPath(programFilesRoot).TrimEnd(Path.DirectorySeparatorChar);
      string expected = CanonicalSecurityDescriptor(BootstrapSddl());
      List<SafeFileHandle> handles = new List<SafeFileHandle>();
      try {
        handles.Add(OpenDirectory(root, false));
        string current = root;
        foreach (string segment in new[] {
          "PalladinRuntimeInstaller",
          "UpdateCache",
          Guid.NewGuid().ToString("N")
        }) {
          current = Path.Combine(current, segment);
          TryCreateDirectory(current, expected);
          SafeFileHandle handle = OpenDirectory(current, false);
          handles.Add(handle);
          if (!String.Equals(SecurityDescriptorForHandle(handle), expected, StringComparison.Ordinal)) {
            throw new InvalidOperationException("installer staging owner or DACL is not exact: " + current);
          }
        }
        return current;
      } finally {
        for (int index = handles.Count - 1; index >= 0; index--) handles[index].Dispose();
      }
    }

    private static string ProcessTree(string serviceSid, bool createMissing, bool promote) {
      string root = ProgramDataRoot();
      string bootstrap = CanonicalSecurityDescriptor(BootstrapSddl());
      string expected = serviceSid == null
        ? bootstrap
        : CanonicalSecurityDescriptor(ProtectedSddl(serviceSid));
      List<SafeFileHandle> handles = new List<SafeFileHandle>();
      try {
        handles.Add(OpenDirectory(root, false));
        string current = root;
        foreach (string segment in new[] { "Palladin", "Runtime", "v1" }) {
          current = Path.Combine(current, segment);
          if (createMissing) TryCreateDirectory(current, expected);
          SafeFileHandle handle = OpenDirectory(current, promote);
          handles.Add(handle);
          string actual = SecurityDescriptorForHandle(handle);
          if (promote) {
            if (!String.Equals(actual, bootstrap, StringComparison.Ordinal) &&
                !String.Equals(actual, expected, StringComparison.Ordinal)) {
              throw new InvalidOperationException("pre-existing protected directory owner or DACL is not exact: " + current);
            }
            if (!String.Equals(actual, expected, StringComparison.Ordinal)) {
              SetSecurityDescriptorForHandle(handle, expected);
              actual = SecurityDescriptorForHandle(handle);
            }
          }
          if (!String.Equals(actual, expected, StringComparison.Ordinal)) {
            throw new InvalidOperationException("protected directory owner or DACL is not exact: " + current);
          }
        }
        return current;
      } finally {
        for (int index = handles.Count - 1; index >= 0; index--) handles[index].Dispose();
      }
    }

    private static void ValidateServiceSid(string value) {
      if (String.IsNullOrWhiteSpace(value) || !value.StartsWith("S-1-5-80-", StringComparison.Ordinal)) {
        throw new ArgumentException("service SID is invalid", "value");
      }
      for (int index = 0; index < value.Length; index++) {
        char character = value[index];
        if ((character < '0' || character > '9') && character != 'S' && character != '-') {
          throw new ArgumentException("service SID is invalid", "value");
        }
      }
    }

    private static string BootstrapSddl() {
      return "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
    }

    private static string ProtectedSddl(string serviceSid) {
      return "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + serviceSid + ")";
    }

    private static void TryCreateDirectory(string path, string expectedSddl) {
      IntPtr descriptor = IntPtr.Zero;
      uint descriptorSize;
      if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
        expectedSddl,
        SddlRevision1,
        out descriptor,
        out descriptorSize)) {
        throw new Win32Exception(Marshal.GetLastWin32Error(), "directory security descriptor creation failed");
      }
      try {
        SecurityAttributes attributes = new SecurityAttributes();
        attributes.length = Marshal.SizeOf(typeof(SecurityAttributes));
        attributes.securityDescriptor = descriptor;
        attributes.inheritHandle = false;
        if (!CreateDirectoryW(path, ref attributes)) {
          uint error = unchecked((uint)Marshal.GetLastWin32Error());
          if (error != ErrorAlreadyExists) {
            throw new Win32Exception(unchecked((int)error), "protected directory creation failed: " + path);
          }
        }
      } finally {
        if (descriptor != IntPtr.Zero) LocalFree(descriptor);
      }
    }

    private static SafeFileHandle OpenDirectory(string path, bool writeSecurity) {
      uint desiredAccess = ReadControl | FileReadAttributes;
      if (writeSecurity) desiredAccess |= WriteDac | WriteOwner;
      SafeFileHandle handle = CreateFileW(
        path,
        desiredAccess,
        FileShareRead | FileShareWrite | FileShareDelete,
        IntPtr.Zero,
        OpenExisting,
        FileFlagBackupSemantics | FileFlagOpenReparsePoint,
        IntPtr.Zero);
      if (handle.IsInvalid) {
        int error = Marshal.GetLastWin32Error();
        handle.Dispose();
        throw new Win32Exception(error, "protected directory could not be opened without following links: " + path);
      }
      ByHandleFileInformation information;
      if (!GetFileInformationByHandle(handle, out information)) {
        int error = Marshal.GetLastWin32Error();
        handle.Dispose();
        throw new Win32Exception(error, "protected directory attributes could not be read: " + path);
      }
      if ((information.fileAttributes & FileAttributeDirectory) == 0 ||
          (information.fileAttributes & FileAttributeReparsePoint) != 0) {
        handle.Dispose();
        throw new InvalidOperationException("protected directory is a link or reparse point: " + path);
      }
      return handle;
    }

    private static string SecurityDescriptorForHandle(SafeFileHandle handle) {
      IntPtr owner;
      IntPtr group;
      IntPtr dacl;
      IntPtr sacl;
      IntPtr descriptor;
      uint result = GetSecurityInfo(
        handle,
        SeFileObject,
        OwnerSecurityInformation | DaclSecurityInformation,
        out owner,
        out group,
        out dacl,
        out sacl,
        out descriptor);
      if (result != 0 || descriptor == IntPtr.Zero) {
        throw new Win32Exception(unchecked((int)result), "directory security descriptor read failed");
      }
      try {
        return SecurityDescriptorToString(descriptor);
      } finally {
        LocalFree(descriptor);
      }
    }

    private static void SetSecurityDescriptorForHandle(SafeFileHandle handle, string expectedSddl) {
      IntPtr descriptor = IntPtr.Zero;
      uint size;
      if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
        expectedSddl,
        SddlRevision1,
        out descriptor,
        out size)) {
        throw new Win32Exception(Marshal.GetLastWin32Error(), "protected directory descriptor conversion failed");
      }
      try {
        IntPtr owner;
        bool ownerDefaulted;
        if (!GetSecurityDescriptorOwner(descriptor, out owner, out ownerDefaulted) || owner == IntPtr.Zero) {
          throw new Win32Exception(Marshal.GetLastWin32Error(), "protected directory owner extraction failed");
        }
        bool daclPresent;
        IntPtr dacl;
        bool daclDefaulted;
        if (!GetSecurityDescriptorDacl(descriptor, out daclPresent, out dacl, out daclDefaulted) ||
            !daclPresent || dacl == IntPtr.Zero) {
          throw new Win32Exception(Marshal.GetLastWin32Error(), "protected directory DACL extraction failed");
        }
        uint result = SetSecurityInfo(
          handle,
          SeFileObject,
          OwnerSecurityInformation | DaclSecurityInformation | ProtectedDaclSecurityInformation,
          owner,
          IntPtr.Zero,
          dacl,
          IntPtr.Zero);
        if (result != 0) {
          throw new Win32Exception(unchecked((int)result), "protected directory descriptor update failed");
        }
      } finally {
        if (descriptor != IntPtr.Zero) LocalFree(descriptor);
      }
    }

    private static string CanonicalSecurityDescriptor(string sddl) {
      IntPtr descriptor = IntPtr.Zero;
      uint size;
      if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl,
        SddlRevision1,
        out descriptor,
        out size)) {
        throw new Win32Exception(Marshal.GetLastWin32Error(), "expected security descriptor is invalid");
      }
      try {
        return SecurityDescriptorToString(descriptor);
      } finally {
        LocalFree(descriptor);
      }
    }

    private static string SecurityDescriptorToString(IntPtr descriptor) {
      IntPtr raw = IntPtr.Zero;
      uint length;
      if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(
        descriptor,
        SddlRevision1,
        OwnerSecurityInformation | DaclSecurityInformation,
        out raw,
        out length)) {
        throw new Win32Exception(Marshal.GetLastWin32Error(), "security descriptor normalization failed");
      }
      try {
        string value = Marshal.PtrToStringUni(raw);
        if (value == null) throw new InvalidOperationException("security descriptor normalization returned null");
        return value;
      } finally {
        if (raw != IntPtr.Zero) LocalFree(raw);
      }
    }
  }
}
'@
}

function Get-PalladinCanonicalProgramDataRoot {
  Initialize-PalladinDirectorySecurityType
  return [Palladin.WindowsDirectorySecurity]::ProgramDataRoot()
}

function Initialize-PalladinProtectedDataRoot {
  param([Parameter(Mandatory)][Security.Principal.SecurityIdentifier] $ServiceSid)
  Initialize-PalladinDirectorySecurityType
  return [Palladin.WindowsDirectorySecurity]::PromoteProtectedTree($ServiceSid.Value)
}

function Initialize-PalladinBootstrapDataRoot {
  Initialize-PalladinDirectorySecurityType
  return [Palladin.WindowsDirectorySecurity]::EnsureBootstrapTree()
}

function Assert-PalladinProtectedDataRoot {
  param([Parameter(Mandatory)][Security.Principal.SecurityIdentifier] $ServiceSid)
  Initialize-PalladinDirectorySecurityType
  $null = [Palladin.WindowsDirectorySecurity]::EnsureProtectedTree($ServiceSid.Value)
}

function New-PalladinProtectedUpdateStage {
  Initialize-PalladinDirectorySecurityType
  $programFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
  return [Palladin.WindowsDirectorySecurity]::CreateAdministratorStagingDirectory($programFiles)
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
        string familyName = Marshal.PtrToStringUni(output);
        if (familyName == null) throw new InvalidOperationException("package family is empty");
        return familyName;
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

Export-ModuleMember -Function Assert-PalladinRegularFile, Assert-PalladinArchitecture, Assert-PalladinSignature, Assert-PalladinVersionPolicy, Assert-PalladinPackageIdentity, Get-PalladinPackageFamilyName, Get-PalladinCanonicalProgramDataRoot, Initialize-PalladinBootstrapDataRoot, Initialize-PalladinProtectedDataRoot, Assert-PalladinProtectedDataRoot, New-PalladinProtectedUpdateStage
