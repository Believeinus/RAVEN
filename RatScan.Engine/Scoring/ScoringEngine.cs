using System.Globalization;
using System.Text;
using RatScan.Engine.Allowlist;
using RatScan.Engine.Model;

namespace RatScan.Engine.Scoring;

public interface IScoringEngine
{
    /// <param name="findings">Findings that count — the allowlist has already been applied.</param>
    /// <param name="allowlist">
    /// What the allowlist withheld, or null when nothing was muted. Passed in rather
    /// than applied here so the verdict and its counterfactual are computed from the
    /// same place.
    /// </param>
    ScanResult Score(
        IReadOnlyList<Finding> findings,
        IReadOnlyList<Blindspot> blindspots,
        IReadOnlyList<string> surfacesExamined,
        IntegrityReport integrity,
        DateTime startedUtc,
        TimeSpan duration,
        AllowlistApplication? allowlist = null);
}

/// <summary>
/// Turns findings into the headline the user actually reads.
/// <para>
/// The governing rule, and the reason this class exists rather than a severity max():
/// <b>the verdict is never "clean"</b>. It states what was examined, what was found,
/// and what could not be seen — in that order — so a quiet result reads as a bounded
/// observation instead of a guarantee nobody can make.
/// </para>
/// </summary>
public sealed class ScoringEngine : IScoringEngine
{
    public ScanResult Score(
        IReadOnlyList<Finding> findings,
        IReadOnlyList<Blindspot> blindspots,
        IReadOnlyList<string> surfacesExamined,
        IntegrityReport integrity,
        DateTime startedUtc,
        TimeSpan duration,
        AllowlistApplication? allowlist = null)
    {
        var suppressed = allowlist?.Suppressed ?? [];
        var verdict = DecideVerdict(findings);

        // The verdict the machine would have got with nothing muted. Computed here,
        // beside the real one, so the two can never drift out of step.
        var unmuted = suppressed.Count == 0
            ? verdict
            : DecideVerdict([.. findings, .. suppressed.Select(s => s.Finding)]);

        return new ScanResult
        {
            Verdict = verdict,
            Headline = BuildHeadline(verdict, findings, surfacesExamined, blindspots, suppressed.Count),
            Summary = BuildSummary(verdict, findings, blindspots, integrity, suppressed, unmuted),
            Integrity = integrity,
            Findings = findings.OrderByDescending(f => f.Severity).ThenByDescending(f => f.Confidence).ToList(),
            Blindspots = blindspots,
            Suppressed = suppressed,
            StaleAllowlistEntries = allowlist?.Stale ?? [],
            VerdictIfNothingMuted = unmuted,
            SurfacesExamined = surfacesExamined,
            StartedUtc = startedUtc,
            Duration = duration,
        };
    }

    private static VerdictLevel DecideVerdict(IReadOnlyList<Finding> findings)
    {
        // Concealment outranks everything. A machine actively hiding something is a
        // different situation from one merely running remote-access software.
        if (findings.Any(f => f.Category == FindingCategory.Concealment
                              && f.Severity == Severity.Critical))
        {
            return VerdictLevel.CompromiseIndicated;
        }

        if (findings.Any(f => f.Severity == Severity.Critical))
        {
            return VerdictLevel.CompromiseIndicated;
        }

        if (findings.Any(f => f.Severity == Severity.High))
        {
            return VerdictLevel.RemoteAccessActive;
        }

        return findings.Any(f => f.Severity is Severity.Medium or Severity.Low)
            ? VerdictLevel.ReviewRecommended
            : VerdictLevel.NoEvidenceFound;
    }

    private static string BuildHeadline(
        VerdictLevel verdict,
        IReadOnlyList<Finding> findings,
        IReadOnlyList<string> surfaces,
        IReadOnlyList<Blindspot> blindspots,
        int mutedCount)
    {
        var coverage = $"across {surfaces.Count} surface{(surfaces.Count == 1 ? "" : "s")}"
                       + (blindspots.Count > 0
                           ? $", with {blindspots.Count} blind spot{(blindspots.Count == 1 ? "" : "s")}"
                           : ", with no blind spots recorded")

                       // Muting belongs in the headline, not in a panel further down.
                       // The quiet verdict is the one people stop reading after, and it
                       // is the one a mute is most likely to have produced.
                       + (mutedCount > 0
                           ? $", and {mutedCount} finding{(mutedCount == 1 ? "" : "s")} you have muted"
                           : "");

        return verdict switch
        {
            VerdictLevel.CompromiseIndicated =>
                $"Evidence of compromise found — {Count(findings, Severity.Critical)} critical "
                + $"finding{(Count(findings, Severity.Critical) == 1 ? "" : "s")} {coverage}",

            VerdictLevel.RemoteAccessActive =>
                $"Active remote-access surface found — {Count(findings, Severity.High)} high-severity "
                + $"finding{(Count(findings, Severity.High) == 1 ? "" : "s")} {coverage}",

            VerdictLevel.ReviewRecommended =>
                $"Remote-access capability present — {findings.Count} finding"
                + $"{(findings.Count == 1 ? "" : "s")} to review {coverage}",

            // The most important string in the product. Not "you are clean".
            _ => $"No evidence of remote access found — {coverage}",
        };
    }

    private static string BuildSummary(
        VerdictLevel verdict,
        IReadOnlyList<Finding> findings,
        IReadOnlyList<Blindspot> blindspots,
        IntegrityReport integrity,
        IReadOnlyList<SuppressedFinding> suppressed,
        VerdictLevel unmutedVerdict)
    {
        var text = new StringBuilder();

        switch (verdict)
        {
            case VerdictLevel.CompromiseIndicated:
                text.Append("Something on this machine is either concealing itself or impersonating "
                            + "trusted software. Treat the machine as compromised until you have "
                            + "identified what was found. Avoid signing in to anything sensitive from it.");
                break;

            case VerdictLevel.RemoteAccessActive:
                text.Append("Software or a Windows feature on this machine is currently accepting "
                            + "remote connections. That is not automatically wrong — it is wrong if you "
                            + "did not set it up. Work through the high-severity findings and confirm "
                            + "each one is yours.");
                break;

            case VerdictLevel.ReviewRecommended:
                text.Append("Remote-access capability exists here but nothing was observed actively "
                            + "listening or hiding. Confirm each item below is software you installed "
                            + "and still want.");
                break;

            default:
                text.Append("Nothing examined in this scan showed signs of remote access, "
                            + "surveillance software, or concealment.");
                break;
        }

        // The honesty clause. Appended to every verdict, including the quiet one —
        // especially the quiet one, because that is where a false sense of safety does
        // the most damage.
        text.Append(' ');
        text.Append("This is a statement about what was examined, not a guarantee. RAVEN runs in "
                    + "user mode: code running in the kernel, in a hypervisor beneath Windows, or in "
                    + "hardware attached to this machine can return clean answers to every check "
                    + "performed here.");

        if (blindspots.Count > 0)
        {
            text.Append($" {blindspots.Count} area"
                        + $"{(blindspots.Count == 1 ? " was" : "s were")} not fully examined; "
                        + "these are listed individually.");
        }

        if (suppressed.Count > 0)
        {
            text.Append($" {suppressed.Count} finding{(suppressed.Count == 1 ? " is" : "s are")} "
                        + "muted by your allowlist and not counted above; "
                        + $"{(suppressed.Count == 1 ? "it is" : "they are")} listed with the reason "
                        + "you gave.");

            // The counterfactual is stated only when it is load-bearing — when the
            // user's own decision is the reason this verdict reads as calmly as it does.
            if (unmutedVerdict != verdict)
            {
                text.Append(CultureInfo.InvariantCulture,
                    $" Without {(suppressed.Count == 1 ? "it" : "them")} this scan would "
                    + $"read: {Describe(unmutedVerdict)}.");
            }
        }

        var undermining = integrity.Undermining.ToList();
        if (undermining.Count > 0)
        {
            text.Append(" Conditions on this machine actively reduce how much this result is worth: ");
            text.Append(string.Join("; ", undermining.Select(s => s.Name.ToLowerInvariant())));
            text.Append('.');
        }

        if (!integrity.Elevated)
        {
            text.Append(" The scan ran without Administrator rights, so a substantial part of the "
                        + "machine could not be inspected at all.");
        }

        return text.ToString();
    }

    private static int Count(IReadOnlyList<Finding> findings, Severity severity) =>
        findings.Count(f => f.Severity == severity);

    /// <summary>Verdict as a phrase that fits mid-sentence, for the muting counterfactual.</summary>
    private static string Describe(VerdictLevel verdict) => verdict switch
    {
        VerdictLevel.CompromiseIndicated => "evidence of compromise found",
        VerdictLevel.RemoteAccessActive => "an active remote-access surface was found",
        VerdictLevel.ReviewRecommended => "remote-access capability present, review recommended",
        _ => "no evidence of remote access found",
    };
}
