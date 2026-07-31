namespace RatScan.Engine.Model;

public enum Severity
{
    /// <summary>Worth knowing, not worth acting on.</summary>
    Info = 0,

    /// <summary>Legitimate but exposed, or unusual enough to review.</summary>
    Low,

    /// <summary>A real remote-access capability, or a meaningful anomaly.</summary>
    Medium,

    /// <summary>An active remote-access surface, or strong evidence of surveillance.</summary>
    High,

    /// <summary>Evidence of active concealment. Nothing benign looks like this.</summary>
    Critical,
}

/// <summary>
/// How sure the engine is that the finding means what it says.
/// <para>
/// Kept separate from <see cref="Severity"/> on purpose. "A hidden process exists" is
/// catastrophic if true but may be low-confidence; "TightVNC is installed" is certain
/// but only moderately severe. Collapsing the two into one number is how scanners end
/// up either crying wolf or burying the one thing that mattered.
/// </para>
/// </summary>
public enum Confidence
{
    /// <summary>Consistent with the finding, but with benign explanations.</summary>
    Possible = 0,

    /// <summary>More consistent with the finding than not.</summary>
    Likely,

    /// <summary>Directly observed; no reasonable benign explanation.</summary>
    Confirmed,
}

public enum FindingCategory
{
    RemoteAccessSoftware,
    WindowsRemoteSurface,
    ScreenOrInputSurveillance,
    Persistence,
    Concealment,
    UntrustedBinary,
    NetworkExposure,
    ScanIntegrity,
}

/// <summary>
/// One observed fact supporting a finding. Findings are never presented bare — the
/// user must be able to see what was actually observed and reach their own view.
/// </summary>
public sealed record Evidence
{
    public required string Label { get; init; }
    public required string Value { get; init; }

    /// <summary>Where the observation came from, e.g. "GetExtendedTcpTable", "SCM".</summary>
    public string? Source { get; init; }

    public static Evidence Of(string label, string value, string? source = null) =>
        new() { Label = label, Value = value, Source = source };
}

/// <summary>
/// Something the engine concluded, with the observations that led there.
/// </summary>
public sealed record Finding
{
    public required string RuleId { get; init; }
    public required string Title { get; init; }
    public required Severity Severity { get; init; }
    public required Confidence Confidence { get; init; }
    public required FindingCategory Category { get; init; }

    /// <summary>What this is about — a process, a service, a registry key, a port.</summary>
    public string? Subject { get; init; }

    public uint? Pid { get; init; }

    /// <summary>Plain-language explanation of why this was flagged.</summary>
    public required string Explanation { get; init; }

    /// <summary>What the user can actually do about it.</summary>
    public string? Recommendation { get; init; }

    public IReadOnlyList<Evidence> EvidenceChain { get; init; } = [];

    /// <summary>MITRE ATT&amp;CK technique, where one applies.</summary>
    public string? MitreTechnique { get; init; }
}

/// <summary>
/// Something the scan could <em>not</em> see, and why.
/// <para>
/// First-class rather than an afterthought. A verdict is only meaningful alongside its
/// coverage, and the product commitment is that blind spots are named rather than
/// silently folded into a clean result.
/// </para>
/// </summary>
public sealed record Blindspot
{
    public required string Area { get; init; }
    public required string Reason { get; init; }

    /// <summary>What the user could do to close it, e.g. "run as Administrator".</summary>
    public string? Remedy { get; init; }
}
