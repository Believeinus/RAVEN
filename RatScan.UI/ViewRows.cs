using System.Globalization;
using System.Windows;
using System.Windows.Media;
using RatScan.Engine.Allowlist;
using RatScan.Engine.History;
using RatScan.Engine.Model;
using RatScan.Engine.Remediation;
using RatScan.Etw;

namespace RatScan.UI;

/// <summary>
/// The presentation rows every view binds to.
/// <para>
/// Lifted out of the window's code-behind when the dashboard became a navigation shell:
/// findings are rendered on the Scan view, alerts and events on Live Watch, and both
/// needed the same types. They convert engine records into something bindable and do no
/// judging of their own — severity, confidence and coverage were decided long before
/// anything reached here.
/// </para>
/// </summary>
internal static class Palette
{
    // Severity and state colours stay explicit rather than tracking theme brushes. They
    // carry meaning: amber is "this narrows what was seen", red is "this could have been
    // deceived". A neutral text brush that shifted with the theme would quietly change
    // what the colour says.
    public static readonly Color Critical = Color.FromRgb(0xE5, 0x5C, 0x5C);
    public static readonly Color High = Color.FromRgb(0xE8, 0x8B, 0x39);
    public static readonly Color Medium = Color.FromRgb(0xE8, 0xC9, 0x39);
    public static readonly Color Low = Color.FromRgb(0x8B, 0xB8, 0xE8);
    public static readonly Color Good = Color.FromRgb(0x6E, 0xD0, 0x8A);
    public static readonly Color Caution = Color.FromRgb(0xE8, 0xB3, 0x39);
    public static readonly Color Neutral = Color.FromRgb(0x8B, 0x93, 0xA1);
    public static readonly Color Urgent = Color.FromRgb(0xFF, 0x6B, 0x6B);

    public static Color ForVerdict(VerdictLevel verdict) => verdict switch
    {
        VerdictLevel.CompromiseIndicated => Critical,
        VerdictLevel.RemoteAccessActive => High,
        VerdictLevel.ReviewRecommended => Medium,
        _ => Good,
    };

    public static string RiskText(RemediationRisk risk) => risk switch
    {
        RemediationRisk.Reversible => "reversible — you can undo this",
        RemediationRisk.Disruptive => "disruptive — unsaved work in that program may be lost",
        _ => "consequential — this may affect how Windows or other software behaves",
    };
}

/// <summary>Presentation row for one finding. No judgement happens here.</summary>
public sealed record FindingRow
{
    public required string SeverityLabel { get; init; }
    public required Brush SeverityBrush { get; init; }
    public required string ConfidenceLabel { get; init; }
    public required string Title { get; init; }
    public required string Explanation { get; init; }
    public string? Recommendation { get; init; }
    public required IReadOnlyList<string> Evidence { get; init; }
    public required IReadOnlyList<RemediationAction> Actions { get; init; }

    /// <summary>The finding itself, so the mute button knows what it is muting.</summary>
    public required Finding Finding { get; init; }

    public required Visibility MuteVisibility { get; init; }

    public Visibility RecommendationVisibility =>
        string.IsNullOrWhiteSpace(Recommendation) ? Visibility.Collapsed : Visibility.Visible;

    public static FindingRow From(Finding finding, bool allowlistAvailable)
    {
        ArgumentNullException.ThrowIfNull(finding);

        return new FindingRow
        {
            Finding = finding,

            // Concealment and coverage findings never offer this — see Finding.CanBeMuted.
            MuteVisibility = allowlistAvailable && finding.CanBeMuted
                ? Visibility.Visible
                : Visibility.Collapsed,

            SeverityLabel = finding.Severity.ToString().ToUpperInvariant(),
            SeverityBrush = new SolidColorBrush(finding.Severity switch
            {
                Severity.Critical => Palette.Critical,
                Severity.High => Palette.High,
                Severity.Medium => Palette.Medium,
                Severity.Low => Palette.Low,
                _ => Palette.Neutral,
            }),

            // Confidence is spelled out rather than shown as a bare word: "possible" on its
            // own reads as an accusation to someone who is already worried.
            ConfidenceLabel = finding.Confidence switch
            {
                Confidence.Confirmed => "confirmed",
                Confidence.Likely => "likely",
                _ => "possible — may have a benign explanation",
            },
            Title = finding.Title,
            Explanation = finding.Explanation,
            Recommendation = finding.Recommendation,
            Evidence = finding.EvidenceChain
                .Select(e => $"{e.Label}: {e.Value}" + (e.Source is null ? string.Empty : $"   [{e.Source}]"))
                .ToList(),
            Actions = finding.Actions,
        };
    }
}

public sealed record IntegrityRow
{
    public required string Name { get; init; }
    public required string Detail { get; init; }
    public required Brush StateBrush { get; init; }

    public static IntegrityRow From(IntegritySignal signal)
    {
        ArgumentNullException.ThrowIfNull(signal);

        return new IntegrityRow
        {
            Name = signal.Name,
            Detail = signal.Detail,
            StateBrush = new SolidColorBrush(signal.Satisfied switch
            {
                true => Palette.Good,

                // Red where a failure means the scan could have been deceived; amber where
                // it only narrows coverage. That distinction is the point of this panel.
                false when signal.UnderminesResult => Palette.Critical,
                false => Palette.Medium,
                null => Palette.Neutral,
            }),
        };
    }
}

/// <summary>An alert the live watcher decided was worth interrupting for.</summary>
public sealed record WatchAlertRow
{
    public required string Title { get; init; }
    public required string Explanation { get; init; }
    public required string When { get; init; }
    public required Brush AccentBrush { get; init; }

    public static WatchAlertRow From(LiveAlert alert)
    {
        ArgumentNullException.ThrowIfNull(alert);

        return new WatchAlertRow
        {
            Title = alert.Title,
            Explanation = alert.Explanation,
            When = alert.TimeUtc.ToLocalTime().ToString("HH:mm:ss", CultureInfo.CurrentCulture),

            // High priority is red; everything else is amber. The distinction matches
            // the integrity panel: red means something may be acting against you.
            AccentBrush = new SolidColorBrush(alert.IsHighPriority ? Palette.Urgent : Palette.Caution),
        };
    }
}

/// <summary>One observed event in the live feed.</summary>
public sealed record FeedRow
{
    public required string When { get; init; }
    public required string Marker { get; init; }
    public required Brush MarkerBrush { get; init; }
    public required string Text { get; init; }

    private static readonly Brush Started = new SolidColorBrush(Palette.High);
    private static readonly Brush Outbound = new SolidColorBrush(Color.FromRgb(0x6E, 0xA8, 0xD0));
    private static readonly Brush Inbound = new SolidColorBrush(Palette.Medium);

    public static FeedRow From(LiveEvent observed)
    {
        ArgumentNullException.ThrowIfNull(observed);

        var name = observed.ProcessName ?? $"pid {observed.Pid}";

        var (marker, brush, text) = observed.Kind switch
        {
            LiveEventKind.ProcessStarted => ("+", Started, $"{name} started"),
            LiveEventKind.NetworkConnect => ("→", Outbound, $"{name} connected to {observed.Subject}"),

            // Inbound is the one that matters most here: something on this machine
            // accepted a connection from somewhere else.
            LiveEventKind.NetworkAccept => ("←", Inbound, $"{name} accepted a connection from {observed.Subject}"),
            _ => ("·", Outbound, $"{name} {observed.Kind}"),
        };

        return new FeedRow
        {
            When = observed.TimeUtc.ToLocalTime().ToString("HH:mm:ss", CultureInfo.CurrentCulture),
            Marker = marker,
            MarkerBrush = brush,
            Text = text,
        };
    }
}

/// <summary>One line in the "since your last scan" panel.</summary>
public sealed record ChangeRow
{
    public required string Marker { get; init; }
    public required Brush MarkerBrush { get; init; }
    public required string Text { get; init; }

    private static readonly Brush Appeared = new SolidColorBrush(Palette.High);
    private static readonly Brush Gone = new SolidColorBrush(Palette.Good);
    private static readonly Brush Moved = new SolidColorBrush(Palette.Medium);

    public static IEnumerable<ChangeRow> From(ScanDiff diff)
    {
        ArgumentNullException.ThrowIfNull(diff);

        if (diff.VerdictChanged)
        {
            yield return new ChangeRow
            {
                Marker = "!",
                MarkerBrush = Moved,
                Text = $"The verdict changed from {diff.PreviousVerdict} to a different result.",
            };
        }

        // New things first. Something that appeared since the last scan is the reason
        // anyone reads this panel.
        foreach (var finding in diff.Appeared)
        {
            yield return new ChangeRow
            {
                Marker = "+",
                MarkerBrush = Appeared,
                Text = $"New ({finding.Severity}): {finding.Title}",
            };
        }

        foreach (var pair in diff.Changed)
        {
            yield return new ChangeRow
            {
                Marker = "~",
                MarkerBrush = Moved,
                Text = $"{pair.Was.Severity} → {pair.Now.Severity}: {pair.Now.Title}",
            };
        }

        foreach (var finding in diff.Gone)
        {
            yield return new ChangeRow
            {
                Marker = "-",
                MarkerBrush = Gone,
                Text = $"No longer reported: {finding.Title}",
            };
        }
    }
}

/// <summary>
/// One allowlist entry as it stands during this scan: applying, not applying because
/// the file changed, or matching nothing at all.
/// </summary>
public sealed record MutedRow
{
    public required string Title { get; init; }
    public required string Reason { get; init; }
    public required string Pin { get; init; }
    public required Brush PinBrush { get; init; }
    public required AllowlistEntry Entry { get; init; }

    public static MutedRow From(AllowlistEntry entry, ScanResult result)
    {
        ArgumentNullException.ThrowIfNull(entry);
        ArgumentNullException.ThrowIfNull(result);

        var suppressed = result.Suppressed.FirstOrDefault(s => s.Entry.Id == entry.Id);
        var stale = result.StaleAllowlistEntries.FirstOrDefault(s => s.Entry.Id == entry.Id);

        var (pin, colour) = (suppressed, stale) switch
        {
            // Applying, and pinned to the bytes that were approved.
            (not null, _) when entry.IsPinnedToFileContents =>
                ($"Muting “{suppressed.Finding.Title}”. The file is unchanged since you muted it.",
                    Palette.Good),

            // Applying, but there is nothing to pin to — a weaker promise, said as one.
            (not null, _) =>
                ($"Muting “{suppressed.Finding.Title}”. This entry is not pinned to a file, so it "
                 + "applies whenever the rule matches.", Palette.Medium),

            // The dangerous case, and the one worth colouring like a warning.
            (_, not null) => ($"Not applied — {stale.Reason}.", Palette.High),

            _ => ("Nothing in this scan matched this entry. The program may have been removed, "
                  + "moved, or renamed.", Palette.Neutral),
        };

        return new MutedRow
        {
            Title = entry.Label ?? entry.IdentityKey,
            Reason = $"“{entry.Reason}” — muted {entry.CreatedUtc.ToLocalTime():d MMM yyyy}",
            Pin = pin,
            PinBrush = new SolidColorBrush(colour),
            Entry = entry,
        };
    }
}

public sealed record BlindspotRow
{
    public required string Area { get; init; }
    public required string Reason { get; init; }
    public string? Remedy { get; init; }

    public Visibility RemedyVisibility =>
        string.IsNullOrWhiteSpace(Remedy) ? Visibility.Collapsed : Visibility.Visible;

    public static BlindspotRow From(Blindspot blindspot)
    {
        ArgumentNullException.ThrowIfNull(blindspot);

        return new BlindspotRow
        {
            Area = blindspot.Area,
            Reason = blindspot.Reason,
            Remedy = blindspot.Remedy is null ? null : $"→ {blindspot.Remedy}",
        };
    }
}

/// <summary>One recorded scan in the history view.</summary>
public sealed record HistoryRow
{
    public required string When { get; init; }
    public required string Verdict { get; init; }
    public required string Headline { get; init; }
    public required string Coverage { get; init; }
    public required Brush VerdictBrush { get; init; }

    public static HistoryRow From(ScanRecord record)
    {
        ArgumentNullException.ThrowIfNull(record);

        // Elevation is stated on every row because it decides what the row could see.
        // Two scans with different coverage are not two readings of the same thing, and
        // a history that hides that invites exactly the comparison it should prevent.
        var coverage = record.Elevated
            ? $"as Administrator · {record.Blindspots} blind spot{(record.Blindspots == 1 ? string.Empty : "s")}"
            : $"not elevated · {record.Blindspots} blind spot{(record.Blindspots == 1 ? string.Empty : "s")}";

        return new HistoryRow
        {
            When = record.StartedUtc.ToLocalTime().ToString("d MMM yyyy, HH:mm", CultureInfo.CurrentCulture),
            Verdict = record.Verdict.ToString(),
            Headline = record.Headline,
            Coverage = record.Muted > 0 ? $"{coverage} · {record.Muted} muted" : coverage,
            VerdictBrush = new SolidColorBrush(Palette.ForVerdict(record.Verdict)),
        };
    }
}
