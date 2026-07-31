namespace RatScan.Native.Processes;

/// <summary>
/// One process as reported by a single enumeration source. Fields are nullable
/// because the sources genuinely disagree about what they can tell us — Toolhelp
/// knows the parent PID, PSAPI knows only the PID, and the brute-force prober may
/// know nothing but that something exists at this ID.
/// </summary>
public sealed record RawProcess
{
    public required uint Pid { get; init; }
    public uint? ParentPid { get; init; }
    public string? Name { get; init; }
    public uint? SessionId { get; init; }
    public uint? ThreadCount { get; init; }
    public DateTime? CreatedUtc { get; init; }

    /// <summary>
    /// Whether the source could confirm this process is actually <em>running</em>.
    /// <para>
    /// Only the PID probe sets this. <c>true</c> means confirmed alive; <c>null</c>
    /// means the process object exists but was too protected to interrogate. The
    /// distinction matters because a probe-only PID that is confirmed alive is a
    /// serious concealment signal, whereas one that merely refused access is not.
    /// </para>
    /// </summary>
    public bool? VerifiedAlive { get; init; }
}

/// <summary>Which kernel interface produced a view of the process list.</summary>
public enum ProcessSourceKind
{
    /// <summary>CreateToolhelp32Snapshot — the classic, most-hooked interface.</summary>
    Toolhelp,

    /// <summary>NtQuerySystemInformation(SystemProcessInformation) — closest to the kernel.</summary>
    NtQuerySystemInformation,

    /// <summary>EnumProcesses (PSAPI).</summary>
    Psapi,

    /// <summary>OpenProcess probed across the PID space — sees what no list API returns.</summary>
    BruteForceOpen,

    /// <summary>WMI Win32_Process — a different code path again (WMI service, not the caller).</summary>
    Wmi,

    /// <summary>ETW kernel rundown — the kernel's own record of live processes.</summary>
    EtwRundown,
}

/// <summary>
/// The outcome of one source's enumeration.
/// <para>
/// <see cref="Succeeded"/> exists for a specific correctness reason: a source that
/// <em>failed</em> must never be diffed as though it returned an empty list, or the
/// cross-view engine would report every running process as "hidden". A failed source
/// degrades coverage; it does not manufacture findings.
/// </para>
/// </summary>
public sealed record ProcessSourceResult
{
    public required ProcessSourceKind Kind { get; init; }
    public required string SourceName { get; init; }
    public required bool Succeeded { get; init; }
    public IReadOnlyList<RawProcess> Processes { get; init; } = [];
    public string? Error { get; init; }

    /// <summary>True when this source could not see the whole system (e.g. no elevation).</summary>
    public bool Partial { get; init; }

    public static ProcessSourceResult Ok(
        ProcessSourceKind kind, string name, IReadOnlyList<RawProcess> processes, bool partial = false) =>
        new() { Kind = kind, SourceName = name, Succeeded = true, Processes = processes, Partial = partial };

    public static ProcessSourceResult Fail(ProcessSourceKind kind, string name, string error) =>
        new() { Kind = kind, SourceName = name, Succeeded = false, Error = error };
}

/// <summary>
/// An independent view of the running process list.
/// <para>
/// INVARIANT: implementations must reach the kernel by genuinely different routes.
/// If two sources collapse onto the same underlying syscall, the cross-view diff
/// silently stops detecting concealment while still appearing to work.
/// </para>
/// </summary>
public interface IProcessSource
{
    ProcessSourceKind Kind { get; }
    string SourceName { get; }
    ProcessSourceResult Enumerate(CancellationToken cancellationToken = default);
}
