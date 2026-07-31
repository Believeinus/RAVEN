namespace RatScan.Etw;

public enum LiveEventKind
{
    ProcessStarted,
    ProcessStopped,
    ImageLoaded,
    NetworkConnect,
    NetworkAccept,
    DnsQuery,
}

/// <summary>
/// One thing that happened on the machine, observed as it happened.
/// <para>
/// This is what a scan cannot give you. A scan describes the machine at an instant; a
/// RAT that beacons for thirty seconds every ten minutes, or that spawns, captures a
/// screenshot and exits, is absent from every instant a scan happens to sample.
/// </para>
/// </summary>
public sealed record LiveEvent
{
    public required DateTime TimeUtc { get; init; }
    public required LiveEventKind Kind { get; init; }
    public required uint Pid { get; init; }
    public string? ProcessName { get; init; }

    /// <summary>Image path, remote endpoint, or queried domain, depending on kind.</summary>
    public string? Subject { get; init; }

    public string? Detail { get; init; }
}

/// <summary>An observation the watcher considered worth interrupting the user for.</summary>
public sealed record LiveAlert
{
    public required DateTime TimeUtc { get; init; }
    public required string RuleId { get; init; }
    public required string Title { get; init; }
    public required string Explanation { get; init; }
    public required LiveEvent Trigger { get; init; }
    public bool IsHighPriority { get; init; }
}
