using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using Windows.Win32;
using Windows.Win32.System.Threading;

namespace RatScan.Native.Processes;

/// <summary>
/// View 4 — probe the PID space directly with OpenProcess.
/// <para>
/// This source asks no API to <em>list</em> anything, so there is no list for a
/// rootkit to filter. It is the strongest of the four views for that reason: a PID
/// that answers here but appears in none of the enumerating sources is, by
/// definition, hidden.
/// </para>
/// <para>
/// The discrimination that makes it work is in the error code. Windows distinguishes
/// "you may not touch this process" from "there is no such process":
/// </para>
/// <list type="bullet">
///   <item>success — the process exists and we could open it;</item>
///   <item><c>ERROR_ACCESS_DENIED</c> — it exists and is protected (PPL, System, or
///         another user's). Still proof of existence, which is all we need;</item>
///   <item><c>ERROR_INVALID_PARAMETER</c> — no process holds this ID.</item>
/// </list>
/// </summary>
public sealed class BruteForceProcessSource : IProcessSource
{
    private const int ErrorAccessDenied = 5;

    /// <summary>WAIT_TIMEOUT — the wait expired, so the process object is not signalled.</summary>
    private const uint WaitTimeout = 0x00000102;

    /// <summary>Standard SYNCHRONIZE right, not exposed on PROCESS_ACCESS_RIGHTS.</summary>
    private const uint Synchronize = 0x00100000;

    /// <summary>
    /// The minimum access this probe needs. SYNCHRONIZE is essential and easy to miss:
    /// PROCESS_QUERY_LIMITED_INFORMATION alone opens the handle fine but makes
    /// WaitForSingleObject fail with WAIT_FAILED, which reads identically to "this
    /// process is dead" and silently blanks most of the results.
    /// </summary>
    private const PROCESS_ACCESS_RIGHTS ProbeAccess =
        (PROCESS_ACCESS_RIGHTS)((uint)PROCESS_ACCESS_RIGHTS.PROCESS_QUERY_LIMITED_INFORMATION | Synchronize);

    /// <summary>
    /// Windows allocates PIDs in multiples of four.
    /// </summary>
    private const uint PidStride = 4;

    /// <summary>
    /// Highest PID probed. Windows can allocate above this (the ceiling is tunable
    /// system-wide and defaults far higher), so this bound is a real, if narrow,
    /// blind spot — it is reported in <see cref="ProcessSourceResult.Partial"/> so the
    /// Scan Integrity panel can name it rather than quietly ignore it.
    /// </summary>
    public const uint DefaultCeiling = 0x10000;

    private readonly uint _ceiling;

    public BruteForceProcessSource(uint ceiling = DefaultCeiling) => _ceiling = ceiling;

    public ProcessSourceKind Kind => ProcessSourceKind.BruteForceOpen;
    public string SourceName => $"OpenProcess probe (PID < {_ceiling})";

    public ProcessSourceResult Enumerate(CancellationToken cancellationToken = default)
    {
        var live = new ConcurrentBag<(uint Pid, bool? VerifiedAlive)>();

        try
        {
            var candidates = new List<uint>((int)(_ceiling / PidStride));
            for (var pid = PidStride; pid < _ceiling; pid += PidStride)
            {
                candidates.Add(pid);
            }

            Parallel.ForEach(
                candidates,
                new ParallelOptions { CancellationToken = cancellationToken },
                pid =>
                {
                    var probed = Probe(pid);
                    if (probed is not false)
                    {
                        live.Add((pid, probed));
                    }
                });
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            return ProcessSourceResult.Fail(Kind, SourceName, ex.Message);
        }

        var found = live
            .OrderBy(entry => entry.Pid)
            .Select(entry => new RawProcess { Pid = entry.Pid, VerifiedAlive = entry.VerifiedAlive })
            .ToList();

        // PID 0 (System Idle) never opens; it is real but not probeable, so it is
        // added unconditionally rather than left to look like a discrepancy.
        found.Insert(0, new RawProcess { Pid = 0, Name = "System Idle Process", VerifiedAlive = true });

        return ProcessSourceResult.Ok(Kind, SourceName, found, partial: true);
    }

    /// <summary>
    /// Probes one PID. Returns <c>null</c> when nothing live is there.
    /// </summary>
    private static bool? Probe(uint pid)
    {
        // Deliberately the raw import, not OpenProcess_SafeHandle: that overload is a
        // managed wrapper which calls Marshal.InitHandle after the syscall and
        // clobbers the thread's last-error value. The technique depends on the error
        // code, so it has to be captured immediately.
        var handle = PInvoke.OpenProcess(ProbeAccess, false, pid);
        var error = Marshal.GetLastWin32Error();

        if (handle.IsNull)
        {
            // Access denied proves a process object exists, but says nothing about
            // whether it is still running — report it as unverified rather than alive.
            return error == ErrorAccessDenied ? null : (bool?)false;
        }

        try
        {
            // A successful OpenProcess is NOT proof the process is running.
            //
            // When a process exits, its kernel object survives as long as anything
            // still holds a handle to it, and OpenProcess keeps succeeding on that PID
            // the whole time. On this development machine that accounted for ~327
            // "processes" that no enumeration API listed and .NET denied existed —
            // which the cross-view engine would have reported as hidden processes.
            //
            // A terminated process object is signalled; a running one is not. So a
            // zero-timeout wait is the discriminator: WAIT_TIMEOUT means still alive.
            var wait = (uint)PInvoke.WaitForSingleObject(handle, 0);
            return wait == WaitTimeout ? true : (bool?)false;
        }
        finally
        {
            PInvoke.CloseHandle(handle);
        }
    }
}
