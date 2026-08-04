using System.IO;
using System.Security.Principal;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using RatScan.Engine.Collectors;
using RatScan.Engine.Export;
using RatScan.Engine.History;
using RatScan.Engine.Model;
using RatScan.Engine.Remediation;

namespace RatScan.UI.Pages;

/// <summary>
/// The scan view: run it, read the verdict, work the findings, see what was not covered.
/// <para>
/// Holds no services of its own — the orchestrator, the allowlist and the history store
/// all come from the shared <see cref="RavenSession"/>, because a second connection to
/// either store would be a lock waiting to happen and a second orchestrator would score
/// against a different allowlist than the one on screen.
/// </para>
/// </summary>
public partial class ScanPage : Page
{
    private readonly RavenSession _session;

    public ScanPage(RavenSession session)
    {
        ArgumentNullException.ThrowIfNull(session);

        _session = session;
        InitializeComponent();

        SizeChanged += (_, _) => UpdateChangeListCap();
        Loaded += (_, _) => UpdateChangeListCap();
    }

    /// <summary>The window this page is inside, for dialog ownership.</summary>
    private Window? Owner => Window.GetWindow(this);

    /// <summary>
    /// Keeps the "since your last scan" list from pushing the rest of the view off-screen.
    /// <para>
    /// The list has no natural size limit. The first scan taken after this machine's
    /// coverage changes produces one diff entry per kernel driver the previous scan could
    /// see and this one cannot — around a hundred rows. Uncapped, that drove the findings
    /// and coverage cards a thousand pixels below the bottom of the window.
    /// </para>
    /// <para>
    /// The cap lands on the list, which scrolls, rather than on the card, which would clip
    /// the verdict itself — the one thing here that has to stay readable.
    /// </para>
    /// </summary>
    private void UpdateChangeListCap() =>
        ChangeScroll.MaxHeight = Math.Max(120, ActualHeight * 0.22);

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
        _session.LastDiff = null;

        try
        {
            // Off the UI thread: a full scan verifies signatures on several hundred
            // binaries and probes the PID space, which takes seconds.
            var result = await Task.Run(() => _session.Orchestrator.Run(ScanOptions.Full))
                .ConfigureAwait(true);

            // Read the previous scan before recording this one, or the diff compares this
            // scan against itself and reports that nothing ever changes.
            var previous = TryLatestScan();

            Render(result);
            RenderChanges(previous, result);
            TryRecord(result);

            _session.NotifyScanCompleted();
        }
        catch (Exception ex)
        {
            // A failed scan must never look like a quiet one.
            HeadlineText.Text = "The scan did not complete";
            SummaryText.Text = $"{ex.GetType().Name}: {ex.Message}\n\n"
                               + "Nothing was established about this machine. Do not read this as a "
                               + "clean result.";
            VerdictStripe.Background = new SolidColorBrush(Palette.Caution);
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
        _session.LastResult = result;
        ExportButton.IsEnabled = true;

        HeadlineText.Text = result.Headline;
        SummaryText.Text = result.Summary;
        VerdictStripe.Background = new SolidColorBrush(Palette.ForVerdict(result.Verdict));

        FindingsHeader.Text = result.Findings.Count == 0
            ? "FINDINGS — NONE"
            : $"FINDINGS — {result.Findings.Count}";

        FindingsList.ItemsSource = result.Findings
            .Select(f => FindingRow.From(f, _session.Allowlist is not null))
            .ToList();

        IntegrityList.ItemsSource = result.Integrity.Signals.Select(IntegrityRow.From).ToList();

        BlindspotHeader.Text = $"WHAT THIS SCAN COULD NOT SEE — {result.Blindspots.Count}";
        BlindspotList.ItemsSource = result.Blindspots.Select(BlindspotRow.From).ToList();

        RenderAllowlist(result);

        if (Owner is { } window)
        {
            window.Title = $"RAVEN — {result.Verdict} ({result.Duration.TotalSeconds:F1}s)";
        }
    }

    /// <summary>
    /// Writes the current scan to a file the user chooses.
    /// <para>
    /// Deliberate, never automatic, and it says what is in the file before writing it. A
    /// report contains program paths, ports and file hashes from this machine — it is a
    /// record of the user's computer, and they should know that at the moment they decide
    /// where to put it, not afterwards.
    /// </para>
    /// </summary>
    private void OnExportClick(object sender, RoutedEventArgs e)
    {
        if (_session.LastResult is not { } last)
        {
            return;
        }

        var dialog = new Microsoft.Win32.SaveFileDialog
        {
            Title = "Export this scan",
            FileName = ScanExporter.SuggestedFileName(last, ExportFormat.Html),
            DefaultExt = ".html",

            // HTML first: the report is meant to be read by a person.
            Filter = "Report to read (*.html)|*.html|Scan data (*.json)|*.json",
            AddExtension = true,
        };

        if (dialog.ShowDialog(Owner) != true)
        {
            return;
        }

        var format = dialog.FileName.EndsWith(".json", StringComparison.OrdinalIgnoreCase)
            ? ExportFormat.Json
            : ExportFormat.Html;

        var confirm = MessageBox.Show(
            Owner!,
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
            var content = ScanExporter.Export(last, format, _session.LastDiff, Environment.MachineName);
            File.WriteAllText(dialog.FileName, content, System.Text.Encoding.UTF8);
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                Owner!,
                $"The report was not written.\n\n{ex.GetType().Name}: {ex.Message}",
                "Export failed", MessageBoxButton.OK, MessageBoxImage.Error);

            return;
        }

        MessageBox.Show(
            Owner!, $"Written to:\n{dialog.FileName}",
            "Exported", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private ScanRecord? TryLatestScan()
    {
        try
        {
            return _session.History?.Latest();
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
            _session.History?.Record(result);
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
    /// automatically good news. If this scan saw less than the last one — unelevated, more
    /// blind spots, more muted — that is stated in amber next to the list, because
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

        _session.LastDiff = diff;

        ChangePanel.Visibility = Visibility.Visible;

        var when = previous.StartedUtc.ToLocalTime();
        var header = $"SINCE YOUR LAST SCAN — {when:d MMM yyyy, HH:mm}";

        // The count goes in the header because the list scrolls. Showing six rows out of a
        // hundred with no total is the same failure as a quiet verdict: what is on screen
        // reads like all there is.
        ChangeHeader.Text = diff.NothingChanged
            ? $"{header}: nothing changed. That is not the same as nothing being there — "
              + "the findings below are still present."
            : $"{header} — {rows.Count} change{(rows.Count == 1 ? string.Empty : "s")}";

        ChangeList.ItemsSource = rows;

        ChangeCaveat.Text = diff.ComparabilityCaveat ?? string.Empty;
        ChangeCaveat.Visibility = diff.ComparabilityCaveat is null
            ? Visibility.Collapsed
            : Visibility.Visible;
    }

    /// <summary>
    /// Lists the whole allowlist, not just the part that fired. An entry that matched
    /// nothing this scan still says something — the program may have been uninstalled, or
    /// moved, or renamed — and an allowlist the user cannot see in full is one they cannot
    /// audit.
    /// </summary>
    private void RenderAllowlist(ScanResult result)
    {
        if (_session.StoreError is { } error)
        {
            MutedSection.Visibility = Visibility.Visible;
            MutedHeader.Text = "MUTED BY YOU — UNAVAILABLE";
            MutedNote.Text = error;
            MutedList.ItemsSource = null;
            return;
        }

        var entries = _session.Allowlist?.All() ?? [];

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
            ? "These are findings you told RAVEN not to report. Your allowlist is the reason "
              + $"this scan reads as it does: without it the verdict would be "
              + $"{result.VerdictIfNothingMuted}."
            : "These are findings you told RAVEN not to report. They were still detected — they "
              + "are only withheld from the count and the verdict.";

        MutedList.ItemsSource = rows;
    }

    /// <summary>
    /// Every action passes through here, and every action shows the exact command before it
    /// runs. The dialog is not a formality: RAVEN can be wrong, and the person at the
    /// keyboard is the one who knows whether a program is theirs.
    /// </summary>
    private void OnFixClick(object sender, RoutedEventArgs e)
    {
        if (sender is not FrameworkElement { Tag: RemediationAction action })
        {
            return;
        }

        var elevationWarning = action.RequiresElevation && !IsElevated()
            ? "\n\nThis needs Administrator rights and RAVEN is not elevated, so it will "
              + "probably fail. Restart as Administrator first."
            : string.Empty;

        var prompt =
            $"{action.Description}\n\n"
            + $"This will run:\n{action.PreviewCommand}\n\n"
            + $"Risk: {Palette.RiskText(action.Risk)}"
            + (action.Caveat is null ? string.Empty : $"\n\nNote: {action.Caveat}")
            + elevationWarning
            + "\n\nGo ahead?";

        var answer = MessageBox.Show(
            Owner!, prompt, action.Title, MessageBoxButton.YesNo, MessageBoxImage.Warning,
            MessageBoxResult.No);

        if (answer != MessageBoxResult.Yes)
        {
            return;
        }

        var outcome = _session.Remediation.Execute(action, confirmed: true);

        MessageBox.Show(
            Owner!,
            outcome.Message + (outcome.Detail is null ? string.Empty : $"\n\n{outcome.Detail}"),
            outcome.Succeeded ? "Done" : "Did not complete",
            MessageBoxButton.OK,
            outcome.Succeeded ? MessageBoxImage.Information : MessageBoxImage.Error);

        if (outcome.Succeeded)
        {
            HeadlineText.Text = "Run the scan again to see the current state.";
            SummaryText.Text = "The findings below are from before that change and are now out of "
                               + "date.";
        }
    }

    /// <summary>
    /// Muting is the one control here that makes RAVEN report less, so it goes through the
    /// same shape as remediation: state plainly what it will do, require a reason, and
    /// change nothing until the user commits.
    /// </summary>
    private void OnMuteClick(object sender, RoutedEventArgs e)
    {
        if (sender is not FrameworkElement { Tag: Finding finding }
            || _session.Allowlist is not { } allowlist
            || Owner is not { } owner)
        {
            return;
        }

        var entry = MuteDialog.Ask(owner, finding);
        if (entry is null)
        {
            return;
        }

        try
        {
            allowlist.Add(entry);
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                owner,
                $"The entry was not saved: {ex.Message}\n\nNothing has been muted.",
                "Could not save", MessageBoxButton.OK, MessageBoxImage.Error);

            return;
        }

        Refresh();
    }

    private void OnUnmuteClick(object sender, RoutedEventArgs e)
    {
        if (sender is not FrameworkElement { Tag: RatScan.Engine.Allowlist.AllowlistEntry entry }
            || _session.Allowlist is not { } allowlist)
        {
            return;
        }

        allowlist.Remove(entry.Id);
        Refresh();
    }

    /// <summary>
    /// Re-scores the last scan against the current allowlist. Cheaper than re-scanning and,
    /// more importantly, honest about what it is: the same observations, judged again — not
    /// a fresh look at the machine.
    /// </summary>
    private void Refresh()
    {
        if (_session.LastResult is not { } last)
        {
            return;
        }

        Render(_session.Orchestrator.ReapplyAllowlist(last));
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
}
