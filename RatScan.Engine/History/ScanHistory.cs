using RatScan.Engine.Model;

namespace RatScan.Engine.History;

/// <summary>One finding as it was recorded at the time of a scan.</summary>
public sealed record RecordedFinding
{
    public required string RuleId { get; init; }
    public string? IdentityKey { get; init; }
    public string? Subject { get; init; }
    public required string Title { get; init; }
    public required Severity Severity { get; init; }
    public required Confidence Confidence { get; init; }
    public required FindingCategory Category { get; init; }

    /// <summary>
    /// What makes two findings across scans "the same thing". Rule plus identity where
    /// there is one, falling back to the subject — never the title, which carries counts
    /// that shift between scans and would report every scan as entirely new.
    /// </summary>
    public string Key => $"{RuleId}|{IdentityKey ?? Subject ?? string.Empty}";

    public static RecordedFinding From(Finding finding)
    {
        ArgumentNullException.ThrowIfNull(finding);

        return new RecordedFinding
        {
            RuleId = finding.RuleId,
            IdentityKey = finding.IdentityKey,
            Subject = finding.Subject,
            Title = finding.Title,
            Severity = finding.Severity,
            Confidence = finding.Confidence,
            Category = finding.Category,
        };
    }
}

/// <summary>A scan as it is remembered afterwards: the verdict, its coverage, its findings.</summary>
public sealed record ScanRecord
{
    public long Id { get; init; }
    public required DateTime StartedUtc { get; init; }
    public required TimeSpan Duration { get; init; }
    public required VerdictLevel Verdict { get; init; }
    public required string Headline { get; init; }

    /// <summary>
    /// Recorded because it decides what a comparison is worth. An unelevated scan cannot
    /// see what an elevated one can, so a finding that "went away" between the two may
    /// only have gone out of view.
    /// </summary>
    public required bool Elevated { get; init; }

    public int SurfacesExamined { get; init; }
    public int Blindspots { get; init; }
    public int Muted { get; init; }

    public IReadOnlyList<RecordedFinding> Findings { get; init; } = [];
}

/// <summary>What changed between two scans.</summary>
public sealed record ScanDiff
{
    public required ScanRecord Previous { get; init; }

    /// <summary>Findings present now that were not there last time.</summary>
    public IReadOnlyList<RecordedFinding> Appeared { get; init; } = [];

    /// <summary>Findings present last time and absent now — see <see cref="ComparabilityCaveat"/>.</summary>
    public IReadOnlyList<RecordedFinding> Gone { get; init; } = [];

    /// <summary>Findings present in both, where the severity moved.</summary>
    public IReadOnlyList<(RecordedFinding Was, RecordedFinding Now)> Changed { get; init; } = [];

    public bool VerdictChanged { get; init; }
    public VerdictLevel PreviousVerdict => Previous.Verdict;

    /// <summary>
    /// Why this comparison may be misleading, or null when the two scans saw comparably
    /// much.
    /// <para>
    /// The load-bearing part of the whole feature. "Three findings went away" reads as
    /// good news, and it is indistinguishable from "this scan could see less than the
    /// last one" unless somebody says so.
    /// </para>
    /// </summary>
    public string? ComparabilityCaveat { get; init; }

    public bool NothingChanged =>
        Appeared.Count == 0 && Gone.Count == 0 && Changed.Count == 0 && !VerdictChanged;
}

/// <summary>
/// Compares a scan against the one before it.
/// <para>
/// Pure, and separate from the store, because the judgements worth testing are about
/// what a difference <em>means</em> — particularly the refusal to read a disappearance
/// as an improvement when the second scan simply looked at less.
/// </para>
/// </summary>
public static class ScanDiffer
{
    public static ScanDiff Compare(ScanRecord previous, ScanResult current)
    {
        ArgumentNullException.ThrowIfNull(previous);
        ArgumentNullException.ThrowIfNull(current);

        var now = current.Findings.Select(RecordedFinding.From).ToList();

        var before = previous.Findings
            .GroupBy(f => f.Key, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);

        var after = now
            .GroupBy(f => f.Key, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);

        var appeared = after.Where(kv => !before.ContainsKey(kv.Key)).Select(kv => kv.Value).ToList();
        var gone = before.Where(kv => !after.ContainsKey(kv.Key)).Select(kv => kv.Value).ToList();

        var changed = after
            .Where(kv => before.ContainsKey(kv.Key))
            .Select(kv => (Was: before[kv.Key], Now: kv.Value))
            .Where(pair => pair.Was.Severity != pair.Now.Severity)
            .ToList();

        return new ScanDiff
        {
            Previous = previous,
            Appeared = [.. appeared.OrderByDescending(f => f.Severity)],
            Gone = [.. gone.OrderByDescending(f => f.Severity)],
            Changed = changed,
            VerdictChanged = previous.Verdict != current.Verdict,
            ComparabilityCaveat = Caveat(previous, current, gone.Count),
        };
    }

    /// <summary>
    /// Names the reasons this comparison is weaker than it looks. Only raised when
    /// something actually disappeared, because that is the direction in which a
    /// difference in coverage is mistaken for good news.
    /// </summary>
    private static string? Caveat(ScanRecord previous, ScanResult current, int goneCount)
    {
        if (goneCount == 0)
        {
            return null;
        }

        var reasons = new List<string>();

        if (previous.Elevated && !current.Integrity.Elevated)
        {
            reasons.Add("the earlier scan ran as Administrator and this one did not, so parts of "
                        + "the machine that were visible then are not visible now");
        }

        if (current.Blindspots.Count > previous.Blindspots)
        {
            reasons.Add($"this scan has {current.Blindspots.Count} blind spots against "
                        + $"{previous.Blindspots} last time, so it examined less");
        }

        if (current.Suppressed.Count > previous.Muted)
        {
            reasons.Add($"{current.Suppressed.Count - previous.Muted} more finding"
                        + $"{(current.Suppressed.Count - previous.Muted == 1 ? " is" : "s are")} "
                        + "muted by your allowlist than last time, which removes them from this "
                        + "list without anything having changed on the machine");
        }

        if (reasons.Count == 0)
        {
            return null;
        }

        return "Treat what disappeared with care: " + string.Join("; ", reasons) + ".";
    }
}
