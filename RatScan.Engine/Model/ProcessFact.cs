using RatScan.Native.Network;
using RatScan.Native.Processes;
using RatScan.Native.Signing;
using RatScan.Native.Windowing;

namespace RatScan.Engine.Model;

/// <summary>
/// Everything known about one running process, merged from every source that saw it.
/// <para>
/// This is a statement of observation, not of judgement. Nothing here is scored or
/// classified — detectors do that. Keeping the split strict is what lets detection
/// logic be tested against synthetic facts instead of a live infected machine.
/// </para>
/// </summary>
public sealed record ProcessFact
{
    public required uint Pid { get; init; }
    public uint? ParentPid { get; init; }
    public string? Name { get; init; }
    public string? ImagePath { get; init; }
    public uint? SessionId { get; init; }
    public uint? ThreadCount { get; init; }
    public DateTime? CreatedUtc { get; init; }

    public bool? IsElevated { get; init; }
    public IntegrityLevel Integrity { get; init; } = IntegrityLevel.Unknown;
    public bool? HasUiAccess { get; init; }

    public SignatureInfo? Signature { get; init; }
    public string? Sha256 { get; init; }

    public WindowPresence? Windows { get; init; }
    public IReadOnlyList<Connection> Connections { get; init; } = [];

    /// <summary>
    /// DLLs loaded into this process. Empty when module collection was disabled or
    /// the process could not be opened — <see cref="ModulesReadable"/> distinguishes
    /// the two, since "loaded nothing" and "we could not look" are different facts.
    /// </summary>
    public IReadOnlyList<LoadedModule> Modules { get; init; } = [];

    public bool ModulesReadable { get; init; }

    /// <summary>
    /// Which enumeration sources reported this process. The heart of concealment
    /// detection: a process seen by some interfaces and not others is hiding.
    /// </summary>
    public IReadOnlyList<ProcessSourceKind> SeenBy { get; init; } = [];

    /// <summary>
    /// Tri-state, from the PID probe. <c>true</c> = confirmed running, <c>null</c> =
    /// exists but too protected to interrogate, <c>false</c>/absent = not established.
    /// Only <c>true</c> combined with absence from the listing sources is concealment.
    /// </summary>
    public bool? VerifiedAlive { get; init; }

    /// <summary>True when a handle could not be opened, so most fields are unknown.</summary>
    public bool Inaccessible { get; init; }

    /// <summary>
    /// Set only after a second, independent confirmation pass established that this
    /// process is alive and still absent from every enumeration interface.
    /// <para>
    /// The confirmation exists to defeat the one benign explanation for a probe-only
    /// PID: ordinary process churn. A process that starts midway through a scan can
    /// legitimately appear in the probe but not in a list captured moments earlier.
    /// Re-running the listing sources against the specific candidate removes that
    /// explanation, so anything still absent afterwards is concealment.
    /// </para>
    /// </summary>
    public bool ConfirmedHidden { get; init; }

    /// <summary>Enumeration sources that ran successfully but did not report this process.</summary>
    public IReadOnlyList<ProcessSourceKind> MissingFrom { get; init; } = [];

    public bool HasNetworkActivity => Connections.Count > 0;

    public bool IsListening => Connections.Any(c => c.IsListener);
}

/// <summary>Per-source outcome, so coverage can be reported rather than assumed.</summary>
public sealed record SourceCoverage
{
    public required string Source { get; init; }
    public required bool Succeeded { get; init; }
    public int Reported { get; init; }
    public string? Error { get; init; }
    public bool Partial { get; init; }
}

public sealed record ProcessCollectionResult
{
    public IReadOnlyList<ProcessFact> Processes { get; init; } = [];
    public IReadOnlyList<SourceCoverage> Coverage { get; init; } = [];
    public IReadOnlyList<Blindspot> Blindspots { get; init; } = [];

    /// <summary>True when at least one enumeration source produced a usable list.</summary>
    public bool UsableForCrossView =>
        Coverage.Count(c => c.Succeeded) >= 2;

    public TimeSpan Duration { get; init; }
}
