namespace RatScan.Engine.Model;

/// <summary>
/// The headline result.
/// <para>
/// Note what is absent: there is no <c>Clean</c>. No user-mode scanner can establish
/// that a machine is unmonitored — a kernel rootkit, a hypervisor implant or a
/// hardware KVM can answer every API this tool calls with clean lies. The best
/// available outcome is <see cref="NoEvidenceFound"/>, which is a statement about what
/// was looked at, not about what is true.
/// </para>
/// </summary>
public enum VerdictLevel
{
    /// <summary>Nothing above informational, within the coverage achieved.</summary>
    NoEvidenceFound = 0,

    /// <summary>Remote-access capability present that the user should confirm is theirs.</summary>
    ReviewRecommended,

    /// <summary>A remote-access surface is active and reachable right now.</summary>
    RemoteAccessActive,

    /// <summary>Evidence of concealment or an untrusted impostor binary.</summary>
    CompromiseIndicated,
}

/// <summary>One condition affecting how much the verdict is worth.</summary>
public sealed record IntegritySignal
{
    public required string Name { get; init; }

    /// <summary>Null when the condition could not be determined — never guessed.</summary>
    public required bool? Satisfied { get; init; }

    public required string Detail { get; init; }

    /// <summary>
    /// True when failing this condition means a user-mode scan can be actively
    /// deceived, as opposed to merely being less complete.
    /// </summary>
    public bool UnderminesResult { get; init; }
}

/// <summary>
/// The conditions the scan ran under. Shown with every verdict, not on request.
/// </summary>
public sealed record IntegrityReport
{
    public required bool Elevated { get; init; }
    public IReadOnlyList<IntegritySignal> Signals { get; init; } = [];

    /// <summary>Signals that were checked and failed in a way that undermines trust.</summary>
    public IEnumerable<IntegritySignal> Undermining =>
        Signals.Where(s => s.UnderminesResult && s.Satisfied == false);

    /// <summary>Signals that could not be determined at all.</summary>
    public IEnumerable<IntegritySignal> Indeterminate => Signals.Where(s => s.Satisfied is null);

    /// <summary>
    /// True when nothing observed suggests the scan itself could have been deceived.
    /// Deliberately not called "trustworthy" — it is the absence of known problems.
    /// </summary>
    public bool NoKnownUnderminingConditions => !Undermining.Any();
}

/// <summary>The complete outcome of one scan.</summary>
public sealed record ScanResult
{
    public required VerdictLevel Verdict { get; init; }

    /// <summary>The one-line result, always qualified by coverage.</summary>
    public required string Headline { get; init; }

    /// <summary>The paragraph under the headline, in plain language.</summary>
    public required string Summary { get; init; }

    public required IntegrityReport Integrity { get; init; }
    public IReadOnlyList<Finding> Findings { get; init; } = [];
    public IReadOnlyList<Blindspot> Blindspots { get; init; } = [];

    /// <summary>
    /// Findings the user's allowlist withheld from <see cref="Findings"/> and from the
    /// verdict. Carried on the result rather than discarded: a muted finding is still
    /// something this machine is doing, and the user has to be able to see what they
    /// have decided not to be told about.
    /// </summary>
    public IReadOnlyList<Allowlist.SuppressedFinding> Suppressed { get; init; } = [];

    /// <summary>Allowlist entries that no longer applied, with the reason each failed.</summary>
    public IReadOnlyList<Allowlist.StaleAllowlistEntry> StaleAllowlistEntries { get; init; } = [];

    /// <summary>
    /// What the verdict would have been with nothing muted.
    /// <para>
    /// The counterfactual exists so the product can never quietly downgrade itself.
    /// An allowlist that can turn "remote access is active" into "no evidence found"
    /// without saying so is a worse failure than not having one.
    /// </para>
    /// </summary>
    public VerdictLevel VerdictIfNothingMuted { get; init; }

    public bool MutingChangedVerdict => VerdictIfNothingMuted != Verdict;

    /// <summary>Named areas that were successfully examined.</summary>
    public IReadOnlyList<string> SurfacesExamined { get; init; } = [];

    public DateTime StartedUtc { get; init; }
    public TimeSpan Duration { get; init; }

    public int CountOf(Severity severity) => Findings.Count(f => f.Severity == severity);
}
