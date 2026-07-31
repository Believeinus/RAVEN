using System.Text;
using RatScan.Engine.Model;

namespace RatScan.Engine.Scoring;

public interface IScoringEngine
{
    ScanResult Score(
        IReadOnlyList<Finding> findings,
        IReadOnlyList<Blindspot> blindspots,
        IReadOnlyList<string> surfacesExamined,
        IntegrityReport integrity,
        DateTime startedUtc,
        TimeSpan duration);
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
        TimeSpan duration)
    {
        var verdict = DecideVerdict(findings);

        return new ScanResult
        {
            Verdict = verdict,
            Headline = BuildHeadline(verdict, findings, surfacesExamined, blindspots),
            Summary = BuildSummary(verdict, findings, blindspots, integrity),
            Integrity = integrity,
            Findings = findings.OrderByDescending(f => f.Severity).ThenByDescending(f => f.Confidence).ToList(),
            Blindspots = blindspots,
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
        IReadOnlyList<Blindspot> blindspots)
    {
        var coverage = $"across {surfaces.Count} surface{(surfaces.Count == 1 ? "" : "s")}"
                       + (blindspots.Count > 0
                           ? $", with {blindspots.Count} blind spot{(blindspots.Count == 1 ? "" : "s")}"
                           : ", with no blind spots recorded");

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
        IntegrityReport integrity)
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
        text.Append("This is a statement about what was examined, not a guarantee. RatScan runs in "
                    + "user mode: code running in the kernel, in a hypervisor beneath Windows, or in "
                    + "hardware attached to this machine can return clean answers to every check "
                    + "performed here.");

        if (blindspots.Count > 0)
        {
            text.Append($" {blindspots.Count} area"
                        + $"{(blindspots.Count == 1 ? " was" : "s were")} not fully examined; "
                        + "these are listed individually.");
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
}
