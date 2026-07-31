using System.Security.Principal;
using System.Windows;
using System.Windows.Media;
using RatScan.Engine;
using RatScan.Engine.Collectors;
using RatScan.Engine.Model;

namespace RatScan.UI;

public partial class MainWindow : Window
{
    private readonly ScanOrchestrator _orchestrator = new();

    public MainWindow()
    {
        InitializeComponent();
        ShowElevationState();
    }

    private void ShowElevationState()
    {
        var elevated = IsElevated();

        ElevationText.Text = elevated
            ? "Running as Administrator"
            : "Not elevated — coverage is reduced";

        ElevationText.Foreground = new SolidColorBrush(elevated
            ? Color.FromRgb(0x6E, 0xD0, 0x8A)
            : Color.FromRgb(0xE8, 0xB3, 0x39));
    }

    private static bool IsElevated()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    private async void OnScanClick(object sender, RoutedEventArgs e)
    {
        ScanButton.IsEnabled = false;
        ScanButton.Content = "Scanning…";
        ScanProgress.Visibility = Visibility.Visible;
        HeadlineText.Text = "Scanning…";
        SummaryText.Text = "Enumerating processes across four independent kernel interfaces, reading "
                           + "network listeners, auditing Windows' remote-access features, sweeping "
                           + "auto-start entries and verifying signatures.";
        FindingsList.ItemsSource = null;
        IntegrityList.ItemsSource = null;
        BlindspotList.ItemsSource = null;

        try
        {
            // Off the UI thread: a full scan verifies signatures on several hundred
            // binaries and probes the PID space, which takes seconds.
            var result = await Task.Run(() => _orchestrator.Run(ScanOptions.Full)).ConfigureAwait(true);
            Render(result);
        }
        catch (Exception ex)
        {
            // A failed scan must never look like a quiet one.
            HeadlineText.Text = "The scan did not complete";
            SummaryText.Text = $"{ex.GetType().Name}: {ex.Message}\n\n"
                               + "Nothing was established about this machine. Do not read this as a "
                               + "clean result.";
            VerdictStripe.Background = new SolidColorBrush(Color.FromRgb(0xE8, 0xB3, 0x39));
        }
        finally
        {
            ScanProgress.Visibility = Visibility.Collapsed;
            ScanButton.IsEnabled = true;
            ScanButton.Content = "Run full scan";
        }
    }

    private void Render(ScanResult result)
    {
        HeadlineText.Text = result.Headline;
        SummaryText.Text = result.Summary;
        VerdictStripe.Background = new SolidColorBrush(VerdictColour(result.Verdict));

        FindingsHeader.Text = result.Findings.Count == 0
            ? "FINDINGS — NONE"
            : $"FINDINGS — {result.Findings.Count}";

        FindingsList.ItemsSource = result.Findings.Select(FindingRow.From).ToList();
        IntegrityList.ItemsSource = result.Integrity.Signals.Select(IntegrityRow.From).ToList();

        BlindspotHeader.Text = $"WHAT THIS SCAN COULD NOT SEE — {result.Blindspots.Count}";
        BlindspotList.ItemsSource = result.Blindspots.Select(BlindspotRow.From).ToList();

        Title = $"RatScan — {result.Verdict} ({result.Duration.TotalSeconds:F1}s)";
    }

    private static Color VerdictColour(VerdictLevel verdict) => verdict switch
    {
        VerdictLevel.CompromiseIndicated => Color.FromRgb(0xE5, 0x5C, 0x5C),
        VerdictLevel.RemoteAccessActive => Color.FromRgb(0xE8, 0x8B, 0x39),
        VerdictLevel.ReviewRecommended => Color.FromRgb(0xE8, 0xC9, 0x39),
        _ => Color.FromRgb(0x6E, 0xD0, 0x8A),
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

    public Visibility RecommendationVisibility =>
        string.IsNullOrWhiteSpace(Recommendation) ? Visibility.Collapsed : Visibility.Visible;

    public static FindingRow From(Finding finding) => new()
    {
        SeverityLabel = finding.Severity.ToString().ToUpperInvariant(),
        SeverityBrush = new SolidColorBrush(finding.Severity switch
        {
            Severity.Critical => Color.FromRgb(0xE5, 0x5C, 0x5C),
            Severity.High => Color.FromRgb(0xE8, 0x8B, 0x39),
            Severity.Medium => Color.FromRgb(0xE8, 0xC9, 0x39),
            Severity.Low => Color.FromRgb(0x8B, 0xB8, 0xE8),
            _ => Color.FromRgb(0x8B, 0x93, 0xA1),
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
    };
}

public sealed record IntegrityRow
{
    public required string Name { get; init; }
    public required string Detail { get; init; }
    public required Brush StateBrush { get; init; }

    public static IntegrityRow From(IntegritySignal signal) => new()
    {
        Name = signal.Name,
        Detail = signal.Detail,
        StateBrush = new SolidColorBrush(signal.Satisfied switch
        {
            true => Color.FromRgb(0x6E, 0xD0, 0x8A),

            // Red where a failure means the scan could have been deceived; amber where
            // it only narrows coverage. That distinction is the point of this panel.
            false when signal.UnderminesResult => Color.FromRgb(0xE5, 0x5C, 0x5C),
            false => Color.FromRgb(0xE8, 0xC9, 0x39),
            null => Color.FromRgb(0x8B, 0x93, 0xA1),
        }),
    };
}

public sealed record BlindspotRow
{
    public required string Area { get; init; }
    public required string Reason { get; init; }
    public string? Remedy { get; init; }

    public Visibility RemedyVisibility =>
        string.IsNullOrWhiteSpace(Remedy) ? Visibility.Collapsed : Visibility.Visible;

    public static BlindspotRow From(Blindspot blindspot) => new()
    {
        Area = blindspot.Area,
        Reason = blindspot.Reason,
        Remedy = blindspot.Remedy is null ? null : $"→ {blindspot.Remedy}",
    };
}
