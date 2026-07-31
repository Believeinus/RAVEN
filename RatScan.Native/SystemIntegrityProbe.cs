using System.Runtime.InteropServices;
using Windows.Wdk;
using Windows.Wdk.System.SystemInformation;

namespace RatScan.Native;

/// <summary>
/// Low-level conditions that determine how much a scan's result is worth.
/// <para>
/// None of these detect malware. They establish whether the machine is in a state
/// where detection can be trusted at all — kernel debugging, unsigned driver loading
/// and disabled code integrity each mean a user-mode scanner can be lied to freely.
/// </para>
/// </summary>
public static unsafe class SystemIntegrityProbe
{
    // Documented but absent from the generated enum; cast explicitly.
    private const SYSTEM_INFORMATION_CLASS SystemKernelDebuggerInformation = (SYSTEM_INFORMATION_CLASS)35;

    private const uint CodeIntegrityEnabled = 0x0001;
    private const uint CodeIntegrityTestSign = 0x0002;
    private const uint CodeIntegrityDebugModeEnabled = 0x0004;

    [StructLayout(LayoutKind.Sequential)]
    private struct SystemCodeIntegrityInformation
    {
        public uint Length;
        public uint CodeIntegrityOptions;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SystemKernelDebuggerInfo
    {
        public byte KernelDebuggerEnabled;
        public byte KernelDebuggerNotPresent;
    }

    /// <summary>
    /// Whether Windows is enforcing driver signing.
    /// <para>
    /// Returns null when the query fails rather than guessing. Test-signing mode or
    /// disabled code integrity means unsigned kernel drivers can load, which puts
    /// every result this tool produces within reach of tampering.
    /// </para>
    /// </summary>
    public static (bool? Enforced, bool? TestSigning, bool? DebugMode) ReadCodeIntegrity()
    {
        var info = new SystemCodeIntegrityInformation
        {
            Length = (uint)sizeof(SystemCodeIntegrityInformation),
        };

        uint returned = 0;
        var status = PInvoke.NtQuerySystemInformation(
            SYSTEM_INFORMATION_CLASS.SystemCodeIntegrityInformation,
            &info,
            info.Length,
            ref returned);

        if (status.Value < 0)
        {
            return (null, null, null);
        }

        return (
            (info.CodeIntegrityOptions & CodeIntegrityEnabled) != 0,
            (info.CodeIntegrityOptions & CodeIntegrityTestSign) != 0,
            (info.CodeIntegrityOptions & CodeIntegrityDebugModeEnabled) != 0);
    }

    /// <summary>
    /// Whether a kernel debugger is attached. An attached debugger can read and modify
    /// anything, so a scan performed under one proves very little.
    /// </summary>
    public static bool? IsKernelDebuggerPresent()
    {
        var info = default(SystemKernelDebuggerInfo);
        uint returned = 0;

        var status = PInvoke.NtQuerySystemInformation(
            SystemKernelDebuggerInformation,
            &info,
            (uint)sizeof(SystemKernelDebuggerInfo),
            ref returned);

        if (status.Value < 0)
        {
            return null;
        }

        return info.KernelDebuggerEnabled != 0 && info.KernelDebuggerNotPresent == 0;
    }
}
