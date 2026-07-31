using RatScan.Native.Signing;

namespace RatScan.Engine.Model;

/// <summary>
/// The auto-start extensibility point a persistence entry occupies.
/// <para>
/// Ordered roughly by how often each is abused relative to how often anyone checks
/// it. <see cref="WmiEventSubscription"/> sits at the far end of that scale: it is
/// entirely fileless, survives reboots, and almost no consumer security tool
/// enumerates it.
/// </para>
/// </summary>
public enum PersistenceSurface
{
    RunKey,
    RunOnceKey,
    StartupFolder,
    ScheduledTask,
    Service,
    WmiEventSubscription,
    WinlogonShell,
    WinlogonUserinit,
    AppInitDll,
    AppCertDll,
    ImageFileExecutionOptions,
    ComHijack,
    LsaPackage,
    PrintMonitor,
    NetshHelper,
    ActiveSetup,
    PowerShellProfile,
}

public enum PersistenceScope
{
    /// <summary>Applies to every user (HKLM).</summary>
    Machine,

    /// <summary>Applies to the current user only (HKCU).</summary>
    User,
}

/// <summary>
/// One thing configured to run automatically. A statement of observation only —
/// whether an entry is suspicious is the detector's call, since the overwhelming
/// majority of these are legitimate.
/// </summary>
public sealed record PersistenceEntry
{
    public required PersistenceSurface Surface { get; init; }
    public required PersistenceScope Scope { get; init; }

    /// <summary>Value name, task name, or subscription name.</summary>
    public required string Name { get; init; }

    /// <summary>The raw configured command line, exactly as stored.</summary>
    public string? Command { get; init; }

    /// <summary>Executable resolved out of <see cref="Command"/>, where one could be.</summary>
    public string? ImagePath { get; init; }

    public SignatureInfo? Signature { get; init; }

    /// <summary>Where this was read from — registry path, folder, or WMI namespace.</summary>
    public required string Location { get; init; }

    public IReadOnlyList<Evidence> EvidenceChain { get; init; } = [];

    /// <summary>
    /// True when the entry runs code with no file on disk — a script body stored in
    /// the registry or in WMI. Nothing legitimate needs to be invisible to a file scan.
    /// </summary>
    public bool IsFileless { get; init; }
}

/// <summary>A loaded or registered kernel driver, merged across sources.</summary>
public sealed record DriverEntry
{
    public required string Name { get; init; }
    public string? ImagePath { get; init; }
    public SignatureInfo? Signature { get; init; }

    /// <summary>Currently loaded in kernel memory.</summary>
    public bool IsLoaded { get; init; }

    /// <summary>Registered as a driver service in the registry.</summary>
    public bool IsRegistered { get; init; }

    /// <summary>Start type from the service registration, when known.</summary>
    public uint? StartType { get; init; }

    /// <summary>
    /// Loaded but with no service registration behind it. Unusual: the normal way to
    /// get a driver into the kernel leaves a registry trace.
    /// </summary>
    public bool LoadedWithoutRegistration => IsLoaded && !IsRegistered;
}

public sealed record PersistenceResult
{
    public IReadOnlyList<PersistenceEntry> Entries { get; init; } = [];
    public IReadOnlyList<Blindspot> Blindspots { get; init; } = [];

    public IEnumerable<PersistenceEntry> Fileless => Entries.Where(e => e.IsFileless);
}

public sealed record DriverCensusResult
{
    public IReadOnlyList<DriverEntry> Drivers { get; init; } = [];
    public IReadOnlyList<Blindspot> Blindspots { get; init; } = [];

    /// <summary>True when the OS withheld kernel image bases (running unelevated).</summary>
    public bool AddressesWithheld { get; init; }
}
