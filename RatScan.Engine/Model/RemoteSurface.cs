namespace RatScan.Engine.Model;

public enum SurfaceState
{
    /// <summary>Could not be determined — treat as a blind spot, not as "off".</summary>
    Unknown = 0,

    /// <summary>Present but turned off.</summary>
    Disabled,

    /// <summary>On, but constrained (loopback-only, NLA required, policy-limited).</summary>
    Restricted,

    /// <summary>On and reachable.</summary>
    Enabled,
}

/// <summary>
/// One of Windows' own remote-access mechanisms, audited.
/// <para>
/// These matter as much as third-party tools and get overlooked more: nobody
/// "installs" RDP shadowing or WinRM, so nobody remembers to check them. An attacker
/// with one-time admin access prefers them precisely because they leave no new
/// binary behind.
/// </para>
/// </summary>
public sealed record RemoteSurface
{
    public required string Id { get; init; }
    public required string Name { get; init; }
    public required SurfaceState State { get; init; }

    /// <summary>What this grants a remote party if it is on.</summary>
    public required string Capability { get; init; }

    /// <summary>One-line summary of the observed configuration.</summary>
    public string? Detail { get; init; }

    public IReadOnlyList<Evidence> EvidenceChain { get; init; } = [];

    /// <summary>Ports found listening that belong to this surface.</summary>
    public IReadOnlyList<int> ListeningPorts { get; init; } = [];

    /// <summary>How to turn it off, shown to the user before anything is executed.</summary>
    public string? DisableCommand { get; init; }

    /// <summary>
    /// True when the surface is on <em>and</em> reachable from off-box. Something
    /// enabled but bound to loopback is a different proposition from something
    /// listening on every interface.
    /// </summary>
    public bool IsExposed => State == SurfaceState.Enabled && ListeningPorts.Count > 0;
}

/// <summary>Evidence that somebody has actually connected, drawn from the event logs.</summary>
public sealed record RemoteLogonEvent
{
    public required DateTime TimeUtc { get; init; }
    public required string Kind { get; init; }
    public string? Account { get; init; }
    public string? SourceAddress { get; init; }
    public string? Detail { get; init; }
}

public sealed record RemoteSurfaceResult
{
    public IReadOnlyList<RemoteSurface> Surfaces { get; init; } = [];
    public IReadOnlyList<RemoteLogonEvent> RecentRemoteLogons { get; init; } = [];
    public IReadOnlyList<Blindspot> Blindspots { get; init; } = [];

    public IEnumerable<RemoteSurface> Exposed => Surfaces.Where(s => s.IsExposed);
}
