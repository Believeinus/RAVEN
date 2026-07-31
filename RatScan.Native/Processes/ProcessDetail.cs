using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using Windows.Win32;
using Windows.Win32.Security;
using Windows.Win32.System.Threading;

namespace RatScan.Native.Processes;

/// <summary>Windows integrity level, derived from the token's mandatory label SID.</summary>
public enum IntegrityLevel
{
    Unknown = 0,
    Untrusted,
    Low,
    Medium,
    High,
    System,
    ProtectedProcess,
}

/// <summary>
/// Everything worth knowing about one process that requires opening a handle to it.
/// Any field may be null: a great deal of this is unreachable without elevation, and
/// silently substituting a default would be a lie the verdict is built on.
/// </summary>
public sealed record ProcessDetail
{
    public required uint Pid { get; init; }
    public string? ImagePath { get; init; }
    public uint? SessionId { get; init; }
    public bool? IsElevated { get; init; }
    public IntegrityLevel Integrity { get; init; } = IntegrityLevel.Unknown;

    /// <summary>
    /// Whether the process holds a UIAccess token — it can drive the UI of processes
    /// at higher integrity, which is exactly the capability an input-control implant
    /// wants. Legitimate accessibility software also has it, so this is a signal, not
    /// a verdict.
    /// </summary>
    public bool? HasUiAccess { get; init; }

    /// <summary>True when the process could not be opened at all (protected or gone).</summary>
    public bool Inaccessible { get; init; }

    public string? Error { get; init; }
}

/// <summary>Opens processes and reads the properties that need a handle.</summary>
public static class ProcessInspector
{
    private const uint TokenIntegrityLevelClass = 25;
    private const uint TokenUiAccessClass = 26;

    // Mandatory-label RIDs (winnt.h SECURITY_MANDATORY_*_RID).
    private const uint RidUntrusted = 0x00000000;
    private const uint RidLow = 0x00001000;
    private const uint RidMedium = 0x00002000;
    private const uint RidHigh = 0x00003000;
    private const uint RidSystem = 0x00004000;
    private const uint RidProtected = 0x00005000;

    public static ProcessDetail Inspect(uint pid)
    {
        using var process = PInvoke.OpenProcess_SafeHandle(
            PROCESS_ACCESS_RIGHTS.PROCESS_QUERY_LIMITED_INFORMATION, false, pid);

        if (process.IsInvalid)
        {
            return new ProcessDetail
            {
                Pid = pid,
                Inaccessible = true,
                Error = $"OpenProcess denied (win32 {Marshal.GetLastWin32Error()})",
            };
        }

        uint? sessionId = PInvoke.ProcessIdToSessionId(pid, out var session) ? session : null;

        return new ProcessDetail
        {
            Pid = pid,
            ImagePath = TryGetImagePath(process),
            SessionId = sessionId,
            IsElevated = TryGetElevation(process),
            Integrity = TryGetIntegrity(process),
            HasUiAccess = TryGetUiAccess(process),
        };
    }

    /// <summary>
    /// Reads the image path via <c>QueryFullProcessImageName</c> rather than the
    /// module list, because the module list is trivially spoofable from inside the
    /// target process while this comes from the kernel's own record.
    /// </summary>
    private static string? TryGetImagePath(SafeHandle process)
    {
        // Long paths are enabled in the manifest, and hostile binaries like deep ones.
        Span<char> buffer = new char[4096];
        var size = (uint)buffer.Length;

        return PInvoke.QueryFullProcessImageName(process, PROCESS_NAME_FORMAT.PROCESS_NAME_WIN32, buffer, ref size)
            ? new string(buffer[..(int)size])
            : null;
    }

    private static bool? TryGetElevation(SafeHandle process)
    {
        using var token = OpenToken(process);
        if (token is null)
        {
            return null;
        }

        Span<byte> buffer = stackalloc byte[sizeof(uint)];
        return PInvoke.GetTokenInformation(
            token, TOKEN_INFORMATION_CLASS.TokenElevation, buffer, out _)
            ? BitConverter.ToUInt32(buffer) != 0
            : null;
    }

    private static bool? TryGetUiAccess(SafeHandle process)
    {
        using var token = OpenToken(process);
        if (token is null)
        {
            return null;
        }

        Span<byte> buffer = stackalloc byte[sizeof(uint)];
        return PInvoke.GetTokenInformation(
            token, (TOKEN_INFORMATION_CLASS)TokenUiAccessClass, buffer, out _)
            ? BitConverter.ToUInt32(buffer) != 0
            : null;
    }

    /// <summary>
    /// Integrity level lives in the last sub-authority of the token's mandatory
    /// label SID.
    /// </summary>
    private static unsafe IntegrityLevel TryGetIntegrity(SafeHandle process)
    {
        using var token = OpenToken(process);
        if (token is null)
        {
            return IntegrityLevel.Unknown;
        }

        // Query the size first — TOKEN_MANDATORY_LABEL trails a variable-length SID.
        // An empty span drives the size query; the SafeHandle overload is required,
        // since passing null binds to the raw HANDLE overload instead.
        PInvoke.GetTokenInformation(
            token, (TOKEN_INFORMATION_CLASS)TokenIntegrityLevelClass, Span<byte>.Empty, out var needed);

        if (needed == 0)
        {
            return IntegrityLevel.Unknown;
        }

        var buffer = new byte[needed];
        if (!PInvoke.GetTokenInformation(
                token, (TOKEN_INFORMATION_CLASS)TokenIntegrityLevelClass, buffer, out _))
        {
            return IntegrityLevel.Unknown;
        }

        fixed (byte* raw = buffer)
        {
            var label = (TOKEN_MANDATORY_LABEL*)raw;
            var sid = (PSID)label->Label.Sid;

            var countPtr = PInvoke.GetSidSubAuthorityCount(sid);
            if (countPtr is null || *countPtr == 0)
            {
                return IntegrityLevel.Unknown;
            }

            var rid = *PInvoke.GetSidSubAuthority(sid, (uint)(*countPtr - 1));

            return rid switch
            {
                >= RidProtected => IntegrityLevel.ProtectedProcess,
                >= RidSystem => IntegrityLevel.System,
                >= RidHigh => IntegrityLevel.High,
                >= RidMedium => IntegrityLevel.Medium,
                >= RidLow => IntegrityLevel.Low,
                RidUntrusted => IntegrityLevel.Untrusted,
                _ => IntegrityLevel.Unknown,
            };
        }
    }

    private static SafeFileHandle? OpenToken(SafeHandle process) =>
        PInvoke.OpenProcessToken(process, TOKEN_ACCESS_MASK.TOKEN_QUERY, out var token) ? token : null;
}
