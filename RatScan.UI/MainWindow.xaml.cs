using System.IO;
using System.Security.Principal;
using System.Windows;
using System.Windows.Media;
using RatScan.Engine;
using RatScan.Engine.Allowlist;
using RatScan.Engine.Collectors;
using RatScan.Engine.Export;
using RatScan.Engine.History;
using RatScan.Engine.Model;
using RatScan.Engine.Remediation;

namespace RatScan.UI;

/// <summary>
/// Disposable because it owns the allowlist database connection. WPF closes the window
/// rather than disposing it, so <see cref="OnClosed"/> is where that actually happens —
/// <see cref="Dispose"/> exists so the ownership is declared rather than implied.
/// </summary>
public partial class MainWindow : Window, IDisposable
{
    private readonly ScanOrchestrator _orchestrator;
    private readonly RemediationExecutor _remediation = new();

    /// <summary>Null when the allowlist database could not be opened — see the constructor.</summary>
    private readonly SqliteAllowlistStore? _allowlist;

    private readonly string? _allowlistError;

    /// <summary>Null when history could not be opened; scans still run, they just are not kept.</summary>
    private readonly SqliteScanHistoryStore? _history;

    /// <summary>The last rendered scan, kept so muting can re-score it without re-scanning.</summary>
    private ScanResult? _lastResult;

    /// <summary>The comparison shown for that scan, so an export can carry it too.</summary>
    private ScanDiff? _lastDiff;

    public MainWindow()
    {
        InitializeComponent();

        // A broken allowlist store must not stop the tool scanning. It degrades to
        // muting nothing — which shows the user more, not less — and says so where the
        // muted list would otherwise be.
        try
        {
            _allowlist = new SqliteAllowlistStore();
            _history = new SqliteScanHistoryStore();
        }
        catch (Exception ex)
        {
            _allowlistError = $"Your allowlist could not be opened ({ex.GetType().Name}: "
                              + $"{ex.Message}). Nothing is being muted, and muting is unavailable "
                              + "until this is fixed.";
        }

        _orchestrator = new ScanOrchestrator(allowlist: _allowlist);

        FitToScreen();
        ShowElevationState();
    }

    /// <summary>
    /// Sizes and places the window inside the usable desktop.
    /// <para>
    /// The XAML size is a preference, not a demand. <c>CenterScreen</c> centres on the
    /// whole monitor including the taskbar, so on a shorter or scaled display the title
    /// bar ends up above the top edge with no way to move the window back.
    /// </para>
    /// </summary>
    private void FitToScreen()
    {
        var work = SystemParameters.WorkArea;

        Width = Math.Min(Width, work.Width - DesktopMargin);
        Height = Math.Min(Height, work.Height - DesktopMargin);

        Left = work.Left + ((work.Width - Width) / 2);
        Top = work.Top + ((work.Height - Height) / 2);
    }

    /// <summary>Breathing room left around the window when the desktop is tight.</summary>
    private const double DesktopMargin = 32;

    protected override void OnClosed(EventArgs e)
    {
        Dispose();
        base.OnClosed(e);
    }

    public void Dispose()
    {
        _allowlist?.Dispose();
        _history?.Dispose();
        GC.SuppressFinalize(this);
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
        ChangePanel.Visibility = Visibility.Collapsed;
        ExportButton.IsEnabled = false;
        _lastDiff = null;

        try
        {
            // Off the UI thread: a full scan verifies signatures on several hundred
            // binaries and probes the PID space, which takes seconds.
            var result = await Task.Run(() => _orchestrator.Run(ScanOptions.Full)).ConfigureAwait(true);

            // Read the previous scan before recording this one, or the diff compares
            // this scan against itself and reports that nothing ever changes.
            var previous = TryLatestScan();

            Render(result);
            RenderChanges(previous, result);
            TryRecord(result);
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
        _lastResult = result;
        ExportButton.IsEnabled = true;

        HeadlineText.Text = result.Headline;
        SummaryText.Text = result.Summary;
        VerdictStripe.Background = new SolidColorBrush(VerdictColour(result.Verdict));

        FindingsHeader.Text = result.Findings.Count == 0
            ? "FINDINGS — NONE"
            : $"FINDINGS — {result.Findings.Count}";

        FindingsList.ItemsSource = result.Findings
            .Select(f => FindingRow.From(f, _allowlist is not null))
            .ToList();

        IntegrityList.ItemsSource = result.Integrity.Signals.Select(IntegrityRow.From).ToList();

        BlindspotHeader.Text = $"WHAT THIS SCAN COULD NOT SEE — {result.Blindspots.Count}";
        BlindspotList.ItemsSource = result.Blindspots.Select(BlindspotRow.From).ToList();

        RenderAllowlist(result);

        Title = $"RatScan — {result.Verdict} ({result.Duration.TotalSeconds:F1}s)";
    }

    /// <summary>
    /// Writes the current scan to a file the user chooses.
    /// <para>
    /// Deliberate, never automatic, and it says what is in the file before writing it.
    /// A report contains program paths, ports and file hashes from this machine — it is
    /// a record of the user's computer, and they should know that at the moment they
    /// decide where to put it, not afterwards.
    /// </para>
    /// </summary>
    private void OnExportClick(object sender, RoutedEventArgs e)
    {
        if (_lastResult is null)
        {
            return;
        }

        var dialog = new Microsoft.Win32.SaveFileDialog
        {
            Title = "Export this scan",
            FileName = ScanExporter.SuggestedFileName(_lastResult, ExportFormat.Html),
            DefaultExt = ".html",

            // HTML first: the report is meant to be read by a person.
            Filter = "Report to read (*.html)|*.html|Scan data (*.json)|*.json",
            AddExtension = true,
        };

        if (dialog.ShowDialog(this) != true)
        {
            return;
        }

        var format = dialog.FileName.EndsWith(".json", StringComparison.OrdinalIgnoreCase)
            ? ExportFormat.Json
            : ExportFormat.Html;

        var confirm = MessageBox.Show(
            this,
            "This file will describe what is running on this machine — program paths, "
            + "listening ports, file hashes and your allowlist notes.\n\n"
            + "It also records what the scan could not see, so it cannot be read as a "
            + "clean bill of health.\n\n"
            + $"Write it to:\n{dialog.FileName}",
            "Export this scan",
            MessageBoxButton.OKCancel,
            MessageBoxImage.Information,
            MessageBoxResult.OK);

        if (confirm != MessageBoxResult.OK)
        {
            return;
        }

        try
        {
            var content = ScanExporter.Export(
                _lastResult, format, _lastDiff, Environment.MachineName);

            File.WriteAllText(dialog.FileName, content, System.Text.Encoding.UTF8);
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                this,
                $"The report was not written.\n\n{ex.GetType().Name}: {ex.Message}",
                "Export failed", MessageBoxButton.OK, MessageBoxImage.Error);

            return;
        }

        MessageBox.Show(
            this,
            $"Written to:\n{dialog.FileName}",
            "Exported", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private ScanRecord? TryLatestScan()
    {
        try
        {
            return _history?.Latest();
        }
        catch (Exception)
        {
            // History is a convenience. Losing it must never cost the user a scan.
            return null;
        }
    }

    private void TryRecord(ScanResult result)
    {
        try
        {
            _history?.Record(result);
        }
        catch (Exception)
        {
            // Same: a scan that ran and was not filed is still a scan that ran.
        }
    }

    /// <summary>
    /// Shows what moved since the previous scan.
    /// <para>
    /// The rule this panel exists to respect: a finding that disappeared is not
    /// automatically good news. If this scan saw less than the last one — unelevated,
    /// more blind spots, more muted — that is stated in amber next to the list, because
    /// "3 findings gone" and "3 findings out of view" look identical otherwise.
    /// </para>
    /// </summary>
    private void RenderChanges(ScanRecord? previous, ScanResult current)
    {
        if (previous is null)
        {
            ChangePanel.Visibility = Visibility.Collapsed;
            return;
        }

        var diff = ScanDiffer.Compare(previous, current);
        var rows = ChangeRow.From(diff).ToList();

        _lastDiff = diff;

        ChangePanel.Visibility = Visibility.Visible;

        var when = previous.StartedUtc.ToLocalTime();
        var header = $"SINCE YOUR LAST SCAN — {when:d MMM yyyy, HH:mm}";

        ChangeHeader.Text = diff.NothingChanged
            ? $"{header}: nothing changed. That is not the same as nothing being there — "
              + "the findings above are still present."
            : header;

        ChangeList.ItemsSource = rows;

        ChangeCaveat.Text = diff.ComparabilityCaveat ?? string.Empty;
        ChangeCaveat.Visibility = diff.ComparabilityCaveat is null
            ? Visibility.Collapsed
            : Visibility.Visible;
    }

    /// <summary>
    /// Lists the whole allowlist, not just the part that fired. An entry that matched
    /// nothing this scan still says something — the program may have been uninstalled,
    /// or moved, or renamed — and an allowlist the user cannot see in full is one they
    /// cannot audit.
    /// </summary>
    private void RenderAllowlist(ScanResult result)
    {
        if (_allowlistError is not null)
        {
            MutedSection.Visibility = Visibility.Visible;
            MutedHeader.Text = "MUTED BY YOU — UNAVAILABLE";
            MutedNote.Text = _allowlistError;
            MutedList.ItemsSource = null;
            return;
        }

        var entries = _allowlist?.All() ?? [];

        if (entries.Count == 0)
        {
            MutedSection.Visibility = Visibility.Collapsed;
            MutedList.ItemsSource = null;
            return;
        }

        var rows = entries.Select(entry => MutedRow.From(entry, result)).ToList();
        var applied = result.Suppressed.Count;

        MutedSection.Visibility = Visibility.Visible;
        MutedHeader.Text = $"MUTED BY YOU — {applied} OF {entries.Count} "
                           + $"ENTR{(entries.Count == 1 ? "Y" : "IES")} APPLIED";

        MutedNote.Text = result.MutingChangedVerdict
            ? "These are findings you told RatScan not to report. Your allowlist is the reason "
              + $"this scan reads as it does: without it the verdict would be "
              + $"{result.VerdictIfNothingMuted}."
            : "These are findings you told RatScan not to report. They were still detected — they "
              + "are only withheld from the count and the verdict.";

        MutedList.ItemsSource = rows;
    }

    /// <summary>
    /// Every action passes through here, and every action shows the exact command
    /// before it runs. The dialog is not a formality: RatScan can be wrong, and the
    /// person at the keyboard is the one who knows whether a program is theirs.
    /// </summary>
    private void OnFixClick(object sender, RoutedEventArgs e)
    {
        if (sender is not FrameworkElement { Tag: RemediationAction action })
        {
            return;
        }

        var elevationWarning = action.RequiresElevation && !IsElevated()
            ? "\n\nThis needs Administrator rights and RatScan is not elevated, so it will "
              + "probably fail. Restart as Administrator first."
            : string.Empty;

        var prompt =
            $"{action.Description}\n\n"
            + $"This will run:\n{action.PreviewCommand}\n\n"
            + $"Risk: {RiskText(action.Risk)}"
            + (action.Caveat is null ? string.Empty : $"\n\nNote: {action.Caveat}")
            + elevationWarning
            + "\n\nGo ahead?";

        var answer = MessageBox.Show(
            this, prompt, action.Title, MessageBoxButton.YesNo, MessageBoxImage.Warning,
            MessageBoxResult.No);

        if (answer != MessageBoxResult.Yes)
        {
            return;
        }

        var outcome = _remediation.Execute(action, confirmed: true);

        MessageBox.Show(
            this,
            outcome.Message + (outcome.Detail is null ? string.Empty : $"\n\n{outcome.Detail}"),
            outcome.Succeeded ? "Done" : "Did not complete",
            MessageBoxButton.OK,
            outcome.Succeeded ? MessageBoxImage.Information : MessageBoxImage.Error);

        if (outcome.Succeeded)
        {
            HeadlineText.Text = "Run the scan again to see the current state.";
            SummaryText.Text = "The findings above are from before that change and are now out of "
                               + "date.";
        }
    }

    /// <summary>
    /// Muting is the one control here that makes RatScan report less, so it goes
    /// through the same shape as remediation: state plainly what it will do, require a
    /// reason, and change nothing until the user commits.
    /// </summary>
    private void OnMuteClick(object sender, RoutedEventArgs e)
    {
        if (sender is not FrameworkElement { Tag: Finding finding } || _allowlist is null)
        {
            return;
        }

        var entry = MuteDialog.Ask(this, finding);
        if (entry is null)
        {
            return;
        }

        try
        {
            _allowlist.Add(entry);
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                this,
                $"The entry was not saved: {ex.Message}\n\nNothing has been muted.",
                "Could not save", MessageBoxButton.OK, MessageBoxImage.Error);

            return;
        }

        Refresh();
    }

    private void OnUnmuteClick(object sender, RoutedEventArgs e)
    {
        if (sender is not FrameworkElement { Tag: AllowlistEntry entry } || _allowlist is null)
        {
            return;
        }

        _allowlist.Remove(entry.Id);
        Refresh();
    }

    /// <summary>
    /// Re-scores the last scan against the current allowlist. Cheaper than re-scanning
    /// and, more importantly, honest about what it is: the same observations, judged
    /// again — not a fresh look at the machine.
    /// </summary>
    private void Refresh()
    {
        if (_lastResult is null)
        {
            return;
        }

        Render(_orchestrator.ReapplyAllowlist(_lastResult));
    }

    private static string RiskText(RemediationRisk risk) => risk switch
    {
        RemediationRisk.Reversible => "reversible — you can undo this",
        RemediationRisk.Disruptive => "disruptive — unsaved work in that program may be lost",
        _ => "consequential — this may affect how Windows or other software behaves",
    };

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
    public required IReadOnlyList<RatScan.Engine.Remediation.RemediationAction> Actions { get; init; }

    /// <summary>The finding itself, so the mute button knows what it is muting.</summary>
    public required Finding Finding { get; init; }

    public required Visibility MuteVisibility { get; init; }

    public Visibility RecommendationVisibility =>
        string.IsNullOrWhiteSpace(Recommendation) ? Visibility.Collapsed : Visibility.Visible;

    public static FindingRow From(Finding finding, bool allowlistAvailable) => new()
    {
        Finding = finding,

        // Concealment and coverage findings never offer this — see Finding.CanBeMuted.
        MuteVisibility = allowlistAvailable && finding.CanBeMuted
            ? Visibility.Visible
            : Visibility.Collapsed,

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
        Actions = finding.Actions,
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

/// <summary>One line in the "since your last scan" panel.</summary>
public sealed record ChangeRow
{
    public required string Marker { get; init; }
    public required Brush MarkerBrush { get; init; }
    public required string Text { get; init; }

    private static readonly Brush Appeared = new SolidColorBrush(Color.FromRgb(0xE8, 0x8B, 0x39));
    private static readonly Brush Gone = new SolidColorBrush(Color.FromRgb(0x6E, 0xD0, 0x8A));
    private static readonly Brush Moved = new SolidColorBrush(Color.FromRgb(0xE8, 0xC9, 0x39));

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
                    Color.FromRgb(0x6E, 0xD0, 0x8A)),

            // Applying, but there is nothing to pin to — a weaker promise, said as one.
            (not null, _) =>
                ($"Muting “{suppressed.Finding.Title}”. This entry is not pinned to a file, so it "
                 + "applies whenever the rule matches.", Color.FromRgb(0xE8, 0xC9, 0x39)),

            // The dangerous case, and the one worth colouring like a warning.
            (_, not null) => ($"Not applied — {stale.Reason}.", Color.FromRgb(0xE8, 0x8B, 0x39)),

            _ => ("Nothing in this scan matched this entry. The program may have been removed, "
                  + "moved, or renamed.", Color.FromRgb(0x8B, 0x93, 0xA1)),
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

    public static BlindspotRow From(Blindspot blindspot) => new()
    {
        Area = blindspot.Area,
        Reason = blindspot.Reason,
        Remedy = blindspot.Remedy is null ? null : $"→ {blindspot.Remedy}",
    };
}
