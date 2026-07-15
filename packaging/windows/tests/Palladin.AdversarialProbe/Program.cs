using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;
using System.Text;

namespace Palladin.AdversarialProbe;

[SupportedOSPlatform("windows")]
internal static class Program
{
    private const uint ProcessVmRead = 0x0010;
    private const uint ProcessDupHandle = 0x0040;
    private const uint ProcessQueryInformation = 0x0400;
    private const uint ProcessQueryLimitedInformation = 0x1000;
    private const uint CreateSuspended = 0x00000004;
    private const uint TokenQuery = 0x0008;
    private const uint CredentialTypeGeneric = 1;
    private const int ErrorAccessDenied = 5;
    private const int ErrorInsufficientBuffer = 122;
    private const int ErrorNotFound = 1168;
    private const uint StillActive = 259;
    private const int TokenUserInformationClass = 1;
    private const int TokenIsAppContainerInformationClass = 29;

    private static readonly string[] RequiredSecretRoles = ["service", "companion", "worker"];
    private static readonly IReadOnlyDictionary<string, RoleExpectation> RoleExpectations =
        new Dictionary<string, RoleExpectation>(StringComparer.Ordinal)
        {
            ["service"] = new("palladin-service.exe", "Palladin.Runtime.Broker_", "S-1-5-19", false),
            ["companion"] = new("palladin-companion.exe", "Palladin.Runtime.Companion_", null, true),
            ["worker"] = new("palladin-worker.exe", "Palladin.Runtime.Broker_", "S-1-5-19", false),
        };

    public static int Main(string[] args)
    {
        try
        {
            if (!OperatingSystem.IsWindows())
            {
                throw new PlatformNotSupportedException();
            }
            return Run(args);
        }
        catch
        {
            Console.Error.WriteLine("Windows adversarial probe failed without emitting captured data.");
            return 1;
        }
    }

    [SupportedOSPlatform("windows")]
    private static int Run(string[] args)
    {
        string? client = null;
        string mode = "hosted";
        var targets = new Dictionary<string, int>(StringComparer.Ordinal);
        for (var index = 0; index < args.Length; index++)
        {
            if (args[index] == "--client" && index + 1 < args.Length)
            {
                client = Path.GetFullPath(args[++index]);
            }
            else if (args[index] == "--mode" && index + 1 < args.Length)
            {
                mode = args[++index];
            }
            else if (args[index] == "--target" && index + 1 < args.Length)
            {
                var parts = args[++index].Split(':', 2, StringSplitOptions.None);
                if (parts.Length != 2 || !RequiredSecretRoles.Contains(parts[0], StringComparer.Ordinal)
                    || !int.TryParse(parts[1], out var processId) || processId <= 0)
                {
                    throw new ArgumentException("invalid target");
                }
                targets[parts[0]] = processId;
            }
            else
            {
                throw new ArgumentException("invalid argument");
            }
        }

        if (client is null || !File.Exists(client) || (mode != "hosted" && mode != "dedicated-hardware"))
        {
            throw new ArgumentException("missing input");
        }

        AssertKnownCredentialManagerSlotsAreAbsent();

        var elevated = IsProcessElevated();
        if (mode == "dedicated-hardware" && elevated)
        {
            throw new InvalidOperationException("dedicated evidence must use a non-elevated attacker");
        }
        if (elevated)
        {
            Console.WriteLine("hosted-limitation: elevated token prevents honest same-user process evidence");
            Console.WriteLine("dedicated-hardware-required: non-elevated x64 and ARM64 process cells remain mandatory");
            Console.WriteLine("evidence-status: incomplete-hosted-elevated");
            return 0;
        }

        AssertPublicClientVmReadHandleIsObtainable(client);

        var validatedTargets = new List<ValidatedTarget>();
        try
        {
            foreach (var (role, processId) in targets)
            {
                validatedTargets.Add(ValidateTarget(role, processId));
            }
            foreach (var target in validatedTargets)
            {
                AssertSecretProcessRejectsAttackPrerequisites(target);
            }
        }
        finally
        {
            foreach (var target in validatedTargets)
            {
                target.Dispose();
            }
        }

        var missing = RequiredSecretRoles.Where(role => !targets.ContainsKey(role)).ToArray();
        if (mode == "dedicated-hardware" && missing.Length != 0)
        {
            throw new InvalidOperationException("dedicated evidence omitted a secret-bearing process");
        }
        if (missing.Length != 0)
        {
            Console.WriteLine("hosted-limitation: companion and worker require a live operator-approved operation");
            Console.WriteLine("dedicated-hardware-required: complete all three non-elevated process roles");
            Console.WriteLine("evidence-status: incomplete-hosted-partial");
            return 0;
        }

        Console.WriteLine("evidence-status: complete-dedicated-hardware");
        return 0;
    }

    private static void AssertKnownCredentialManagerSlotsAreAbsent()
    {
        foreach (var service in new[] { "palladin", "claw-vault" })
        {
            foreach (var account in new[] { "default:private-key", "default:signing-key" })
            {
                var target = $"{account}.{service}";
                if (CredRead(target, CredentialTypeGeneric, 0, out var credential))
                {
                    if (credential != IntPtr.Zero) CredFree(credential);
                    throw new InvalidOperationException("Hardened runtime exposed a known Credential Manager slot");
                }
                if (Marshal.GetLastWin32Error() != ErrorNotFound)
                {
                    throw new Win32Exception();
                }
            }
        }
        Console.WriteLine("credential-manager: known legacy slots absent; no credential blob was dereferenced or printed");
    }

    [SupportedOSPlatform("windows")]
    private static bool IsProcessElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static void AssertPublicClientVmReadHandleIsObtainable(string client)
    {
        var startup = new StartupInfo { Size = Marshal.SizeOf<StartupInfo>() };
        var commandLine = $"\"{client}\" doctor";
        if (!CreateProcess(client, commandLine, IntPtr.Zero, IntPtr.Zero, false, CreateSuspended,
                IntPtr.Zero, null, ref startup, out var created))
        {
            throw new Win32Exception();
        }

        try
        {
            var opened = OpenProcess(ProcessQueryInformation | ProcessVmRead, false, created.ProcessId);
            if (opened == IntPtr.Zero)
            {
                throw new InvalidOperationException("public client VM_READ handle was unexpectedly denied");
            }
            CloseHandle(opened);
        }
        finally
        {
            TerminateProcess(created.Process, 1);
            CloseHandle(created.Thread);
            CloseHandle(created.Process);
        }
        Console.WriteLine("public-client: VM_READ handle obtainable for the non-secret public control");
    }

    private static ValidatedTarget ValidateTarget(string role, int processId)
    {
        var expectation = RoleExpectations[role];
        var queryHandle = OpenProcess(ProcessQueryLimitedInformation, false, processId);
        if (queryHandle == IntPtr.Zero)
        {
            throw new Win32Exception();
        }

        try
        {
            AssertStillActive(queryHandle);
            var imagePath = QueryImagePath(queryHandle);
            AssertExpectedPackagedImage(imagePath, expectation);
            AssertExpectedToken(queryHandle, expectation);
            return new ValidatedTarget(role, processId, queryHandle);
        }
        catch
        {
            CloseHandle(queryHandle);
            throw;
        }
    }

    private static void AssertExpectedPackagedImage(string imagePath, RoleExpectation expectation)
    {
        var canonical = Path.GetFullPath(imagePath);
        var windowsApps = Path.GetFullPath(Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            "WindowsApps"));
        var relative = Path.GetRelativePath(windowsApps, canonical);
        var parts = relative.Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries);
        if (relative.StartsWith("..", StringComparison.Ordinal)
            || parts.Length < 3
            || !parts[0].StartsWith(expectation.PackageDirectoryPrefix, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(parts[^2], "bin", StringComparison.OrdinalIgnoreCase)
            || !string.Equals(parts[^1], expectation.FileName, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("target image does not match its protected package role");
        }
    }

    private static string QueryImagePath(IntPtr process)
    {
        var capacity = 32_768U;
        var buffer = new StringBuilder((int)capacity);
        if (!QueryFullProcessImageName(process, 0, buffer, ref capacity) || capacity == 0)
        {
            throw new Win32Exception();
        }
        return buffer.ToString();
    }

    private static void AssertExpectedToken(IntPtr process, RoleExpectation expectation)
    {
        if (!OpenProcessToken(process, TokenQuery, out var token) || token == IntPtr.Zero)
        {
            throw new Win32Exception();
        }

        try
        {
            var userSid = ReadTokenUserSid(token);
            var isAppContainer = ReadTokenInt32(token, TokenIsAppContainerInformationClass) != 0;
            if ((expectation.UserSid is not null
                    && !string.Equals(userSid, expectation.UserSid, StringComparison.Ordinal))
                || isAppContainer != expectation.RequiresAppContainer)
            {
                throw new InvalidOperationException("target token does not match its protected role");
            }
        }
        finally
        {
            CloseHandle(token);
        }
    }

    [SupportedOSPlatform("windows")]
    private static string ReadTokenUserSid(IntPtr token)
    {
        _ = GetTokenInformation(token, TokenUserInformationClass, IntPtr.Zero, 0, out var required);
        if (Marshal.GetLastWin32Error() != ErrorInsufficientBuffer || required == 0)
        {
            throw new Win32Exception();
        }
        var buffer = Marshal.AllocHGlobal((int)required);
        try
        {
            if (!GetTokenInformation(token, TokenUserInformationClass, buffer, required, out _))
            {
                throw new Win32Exception();
            }
            var tokenUser = Marshal.PtrToStructure<TokenUser>(buffer);
            return new SecurityIdentifier(tokenUser.User.Sid).Value;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static int ReadTokenInt32(IntPtr token, int informationClass)
    {
        var buffer = Marshal.AllocHGlobal(sizeof(int));
        try
        {
            if (!GetTokenInformation(token, informationClass, buffer, sizeof(int), out var returned)
                || returned != sizeof(int))
            {
                throw new Win32Exception();
            }
            return Marshal.ReadInt32(buffer);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static void AssertStillActive(IntPtr process)
    {
        if (!GetExitCodeProcess(process, out var exitCode) || exitCode != StillActive)
        {
            throw new InvalidOperationException("target process is not live");
        }
    }

    private static void AssertSecretProcessRejectsAttackPrerequisites(ValidatedTarget target)
    {
        AssertStillActive(target.QueryHandle);
        AssertOpenProcessDenied(
            target.Role,
            target.ProcessId,
            ProcessQueryInformation | ProcessVmRead,
            "VM_READ prerequisite");
        AssertOpenProcessDenied(
            target.Role,
            target.ProcessId,
            ProcessQueryInformation | ProcessDupHandle,
            "handle-duplication prerequisite");

        if (DebugActiveProcess(target.ProcessId))
        {
            DebugActiveProcessStop(target.ProcessId);
            throw new InvalidOperationException($"{target.Role} accepted debugger attachment");
        }
        RequireAccessDenied("debugger attachment");

        AssertOpenProcessDenied(
            target.Role,
            target.ProcessId,
            ProcessQueryInformation | ProcessVmRead | ProcessDupHandle,
            "full-memory-dump prerequisite");
        AssertStillActive(target.QueryHandle);
        Console.WriteLine($"process-evidence: {target.Role} attack prerequisites denied with ERROR_ACCESS_DENIED");
    }

    private static void AssertOpenProcessDenied(string role, int processId, uint access, string operation)
    {
        var handle = OpenProcess(access, false, processId);
        if (handle != IntPtr.Zero)
        {
            CloseHandle(handle);
            throw new InvalidOperationException($"{role} granted {operation}");
        }
        RequireAccessDenied(operation);
    }

    private static void RequireAccessDenied(string operation)
    {
        if (Marshal.GetLastWin32Error() != ErrorAccessDenied)
        {
            throw new InvalidOperationException($"{operation} failed for a reason other than access denial");
        }
    }

    private sealed record RoleExpectation(
        string FileName,
        string PackageDirectoryPrefix,
        string? UserSid,
        bool RequiresAppContainer);

    private sealed class ValidatedTarget(string role, int processId, IntPtr queryHandle) : IDisposable
    {
        public string Role { get; } = role;
        public int ProcessId { get; } = processId;
        public IntPtr QueryHandle { get; } = queryHandle;

        public void Dispose()
        {
            if (QueryHandle != IntPtr.Zero) CloseHandle(QueryHandle);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SidAndAttributes
    {
        public IntPtr Sid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TokenUser
    {
        public SidAndAttributes User;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct StartupInfo
    {
        public int Size;
        public string? Reserved;
        public string? Desktop;
        public string? Title;
        public int X;
        public int Y;
        public int XSize;
        public int YSize;
        public int XCountChars;
        public int YCountChars;
        public int FillAttribute;
        public int Flags;
        public short ShowWindow;
        public short Reserved2;
        public IntPtr Reserved2Pointer;
        public IntPtr StandardInput;
        public IntPtr StandardOutput;
        public IntPtr StandardError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInformation
    {
        public IntPtr Process;
        public IntPtr Thread;
        public int ProcessId;
        public int ThreadId;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CreateProcess(
        string applicationName,
        string commandLine,
        IntPtr processAttributes,
        IntPtr threadAttributes,
        bool inheritHandles,
        uint creationFlags,
        IntPtr environment,
        string? currentDirectory,
        ref StartupInfo startupInfo,
        out ProcessInformation processInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint desiredAccess, bool inheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageName(
        IntPtr process,
        uint flags,
        StringBuilder executableName,
        ref uint size);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr process, uint desiredAccess, out IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(
        IntPtr token,
        int tokenInformationClass,
        IntPtr tokenInformation,
        uint tokenInformationLength,
        out uint returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DebugActiveProcess(int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DebugActiveProcessStop(int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateProcess(IntPtr process, uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CredRead(string target, uint type, uint flags, out IntPtr credential);

    [DllImport("advapi32.dll")]
    private static extern void CredFree(IntPtr credential);
}
