using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Security.Principal;
using System.Windows;
using System.Windows.Media;
using System.Windows.Threading;
using Hardcodet.Wpf.TaskbarNotification;
using RatScan.Engine;
using RatScan.Engine.Allowlist;
using RatScan.Engine.Collectors;
using RatScan.Engine.Export;
using RatScan.Engine.History;
using RatScan.Engine.Model;
using RatScan.Engine.Remediation;
using RatScan.Etw;

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

    /// <summary>Live ETW watch. Constructed here, started only when the user asks.</summary>
    private readonly LiveWatcher _watcher = new();

    private readonly DispatcherTimer _feedTimer = new() { Interval = TimeSpan.FromSeconds(1) };

    private readonly List<WatchAlertRow> _alerts = [];

    private DateTime _watchStartedUtc;

    /// <summary>
    /// Set only by "Quit RAVEN". Closing the window while a watch is running hides it
    /// instead, so the close path needs to know which of the two it is serving.
    /// </summary>
    private bool _quitting;

    /// <summary>
    /// The hide-to-tray explanation is shown once per run. Repeating it every time turns
    /// a disclosure into an irritation, and an irritation is something people click past.
    /// </summary>
    private bool _explainedHiding;

    /// <summary>How many process/network events the feed shows at once.</summary>
    private const int FeedLength = 60;

    /// <summary>Mirrors <c>LiveWatcher</c>'s ring size, for the disclosure line only.</summary>
    private const int RingCapacityForDisplay = 5000;

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

        _watcher.Alerted += OnAlerted;
        _feedTimer.Tick += (_, _) => RefreshFeed();

        SizeChanged += (_, _) => UpdateChangeListCap();
        Loaded += (_, _) => UpdateChangeListCap();

        FitToScreen();
        ShowElevationState();
    }

    /// <summary>
    /// Keeps the "since your last scan" list from pushing the rest of the window off-screen.
    /// <para>
    /// The list has no natural size limit. The first scan taken after this machine's
    /// coverage changes produces one diff entry per kernel driver the previous scan could
    /// see and this one cannot — around a hundred rows. Uncapped, in an Auto-height row,
    /// that drove the findings, integrity and blind-spot cards a thousand pixels below the
    /// bottom of the window, and with no outer scrollbar the only way to get them back was
    /// to run a second scan.
    /// </para>
    /// <para>
    /// The cap lands on the list, which scrolls, rather than on the card, which would clip
    /// the verdict itself — the one thing on this window that has to stay readable.
    /// </para>
    /// </summary>
    /// <para>
    /// The fraction is small on purpose. Every pixel this panel takes comes out of the
    /// cards below it, and those hold the findings themselves — the change list is a
    /// summary of what moved, not the evidence, and it scrolls with its total stated in
    /// the header.
    /// </para>
    private void UpdateChangeListCap() =>
        ChangeScroll.MaxHeight = Math.Max(120, ActualHeight * 0.17);

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

    /// <summary>
    /// Closing the window ends RAVEN — unless a live watch is running, in which case it
    /// hides to the tray and says so.
    /// <para>
    /// The asymmetry is the point. A watcher that dies with its window cannot catch a
    /// beacon that fires every thirty seconds, which is the whole reason the panel exists.
    /// But an application that silently outlives its own window, whenever it feels like
    /// it, is behaving exactly like the software this tool flags — so it only happens
    /// while there is something to watch, it is announced the first time, and stopping the
    /// watch from the tray closes the process for good.
    /// </para>
    /// </summary>
    protected override void OnClosing(CancelEventArgs e)
    {
        ArgumentNullException.ThrowIfNull(e);

        if (_quitting || !_watcher.IsRunning)
        {
            base.OnClosing(e);
            return;
        }

        e.Cancel = true;
        Hide();
        Tray.Visibility = Visibility.Visible;

        if (!_explainedHiding)
        {
            _explainedHiding = true;

            Tray.ShowBalloonTip(
                "RAVEN is still watching",
                "The window is closed but the live watch is still running. Right-click the "
                + "tray icon to stop watching or quit.",
                BalloonIcon.Info);
        }

        base.OnClosing(e);
    }

    protected override void OnClosed(EventArgs e)
    {
        Dispose();
        base.OnClosed(e);
    }

    private void OnTrayShowClick(object sender, RoutedEventArgs e) => RestoreFromTray();

    private void RestoreFromTray()
    {
        Show();
        WindowState = WindowState.Normal;
        Activate();
    }

    /// <summary>
    /// Stops the watch from the tray and brings the window back, rather than stopping it
    /// invisibly. The state that changed is one the user has to be able to see.
    /// </summary>
    private void OnTrayStopWatchingClick(object sender, RoutedEventArgs e)
    {
        if (_watcher.IsRunning)
        {
            StopWatching("Stopped from the tray. Nothing is being observed between scans.");
        }

        RestoreFromTray();
        UpdateTrayState();
    }

    private void OnTrayQuitClick(object sender, RoutedEventArgs e)
    {
        _quitting = true;
        Close();
    }

    /// <summary>
    /// Keeps the tray icon telling the truth about whether anything is being observed.
    /// A green indicator over a dead watcher would be worse than no indicator at all.
    /// </summary>
    private void UpdateTrayState()
    {
        var watching = _watcher.IsRunning;

        var colour = watching
            ? Color.FromRgb(0x6E, 0xD0, 0x8A)
            : Color.FromRgb(0x8B, 0x93, 0xA1);

        TrayDot.Fill = new SolidColorBrush(colour);

        Tray.ToolTipText = watching
            ? "RAVEN — watching for remote-access software starting"
            : "RAVEN — not watching";

        TrayStopItem.IsEnabled = watching;

        // The icon is only shown while it means something: a watch is running, or the
        // window is hidden and the tray is the only way back to it.
        Tray.Visibility = watching || !IsVisible ? Visibility.Visible : Visibility.Collapsed;
    }

    public void Dispose()
    {
        // The ETW session outlives the process that created it, so failing to dispose
        // leaves a running kernel session behind and blocks the next start.
        _feedTimer.Stop();
        _watcher.Dispose();

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

        ElevateButton.Visibility = elevated ? Visibility.Collapsed : Visibility.Visible;
    }

    /// <summary>
    /// Relaunches elevated, at the user's request rather than by manifest.
    /// <para>
    /// Deliberately a button and not a <c>requireAdministrator</c> manifest. Forcing
    /// elevation would make the degraded-coverage path unreachable, and that path is a
    /// first-class product behaviour: RAVEN has to be able to show a user what it
    /// cannot see. Declining the UAC prompt is a normal outcome, not an error.
    /// </para>
    /// </summary>
    private void OnElevateClick(object sender, RoutedEventArgs e)
    {
        var exe = Environment.ProcessPath;

        if (exe is null)
        {
            MessageBox.Show(
                this,
                "RAVEN could not determine its own executable path, so it cannot restart itself.",
                "Cannot restart", MessageBoxButton.OK, MessageBoxImage.Error);

            return;
        }

        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = exe,
                UseShellExecute = true,
                Verb = "runas",
            });
        }
        catch (System.ComponentModel.Win32Exception)
        {
            // The user dismissed the UAC prompt. Nothing has changed and nothing is
            // wrong; saying so beats an error dialog for a decision they just made.
            ElevationText.Text = "Not elevated — restart declined";
            return;
        }

        Close();
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

        Title = $"RAVEN — {result.Verdict} ({result.Duration.TotalSeconds:F1}s)";
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

        // The count goes in the header because the list scrolls. Showing six rows out of a
        // hundred with no total is the same failure as a quiet verdict: what is on screen
        // reads like all there is.
        ChangeHeader.Text = diff.NothingChanged
            ? $"{header}: nothing changed. That is not the same as nothing being there — "
              + "the findings above are still present."
            : $"{header} — {rows.Count} change{(rows.Count == 1 ? string.Empty : "s")}";

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
            ? "These are findings you told RAVEN not to report. Your allowlist is the reason "
              + $"this scan reads as it does: without it the verdict would be "
              + $"{result.VerdictIfNothingMuted}."
            : "These are findings you told RAVEN not to report. They were still detected — they "
              + "are only withheld from the count and the verdict.";

        MutedList.ItemsSource = rows;
    }

    /// <summary>
    /// Every action passes through here, and every action shows the exact command
    /// before it runs. The dialog is not a formality: RAVEN can be wrong, and the
    /// person at the keyboard is the one who knows whether a program is theirs.
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
    /// Muting is the one control here that makes RAVEN report less, so it goes
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

    // ---- live watch ---------------------------------------------------------------

    /// <summary>
    /// Starts or stops the ETW watcher.
    /// <para>
    /// Off until asked for. It needs Administrator, and a failure to start is shown as a
    /// named condition with its remedy rather than a silent no-op — the whole value of
    /// this panel is that the user can tell watching from not-watching at a glance.
    /// </para>
    /// </summary>
    private void OnWatchClick(object sender, RoutedEventArgs e)
    {
        if (_watcher.IsRunning)
        {
            StopWatching("Stopped. Nothing is being observed between scans.");
            return;
        }

        var start = _watcher.Start();

        if (!start.Started)
        {
            WatchHeader.Text = "LIVE WATCH — CANNOT START";
            WatchStatus.Foreground = new SolidColorBrush(Color.FromRgb(0xE8, 0xB3, 0x39));
            WatchStatus.Text = start.Remedy is null
                ? start.Error ?? "The watcher could not be started."
                : $"{start.Error}\n{start.Remedy}";

            return;
        }

        _watchStartedUtc = DateTime.UtcNow;
        _alerts.Clear();
        AlertList.ItemsSource = null;

        WatchHeader.Text = "LIVE WATCH — ON";
        WatchButton.Content = "Stop watching";
        WatchStatus.Foreground = new SolidColorBrush(Color.FromRgb(0x6E, 0xD0, 0x8A));
        // Kept to two lines. This card has to fit a status, a counts line, the alerts and
        // the event feed into one column; three lines of standing explanation is three
        // lines the live data does not get, and the user reads this once.
        WatchStatus.Text = "Watching process starts, image loads and TCP connections. Alerts fire "
                           + "once per tool for catalogued remote-access software; everything else "
                           + "is listed below.";

        WatchCounts.Visibility = Visibility.Visible;
        _feedTimer.Start();
        UpdateTrayState();
        RefreshFeed();
    }

    private void StopWatching(string status)
    {
        _feedTimer.Stop();
        _watcher.Stop();

        WatchHeader.Text = "LIVE WATCH — OFF";
        WatchButton.Content = "Start watching";
        WatchStatus.Foreground = new SolidColorBrush(Color.FromRgb(0x8B, 0x93, 0xA1));
        WatchStatus.Text = status;

        UpdateTrayState();
    }

    /// <summary>
    /// Redraws the feed on a timer rather than per event.
    /// <para>
    /// Image-load events arrive in the thousands per second on an ordinary desktop.
    /// Marshalling each one to the UI thread would wedge the window, and a watcher that
    /// freezes the app is a watcher the user turns off.
    /// </para>
    /// </summary>
    private void RefreshFeed()
    {
        // The pump can die underneath us — the session is torn down, or another process
        // takes the ETW session name. Reporting that is the whole point of the panel.
        if (!_watcher.IsRunning)
        {
            StopWatching("The watcher stopped on its own. The ETW session was closed or taken over — "
                         + "nothing has been observed since. Start it again to resume.");

            return;
        }

        var events = _watcher.RecentEvents;

        var shown = events
            .Where(Interesting)
            .TakeLast(FeedLength)
            .Reverse()
            .Select(FeedRow.From)
            .ToList();

        FeedList.ItemsSource = shown;

        // The feed hides image loads because they would bury everything else. Hiding
        // them silently would be the same move this tool refuses to make elsewhere, so
        // the count says what is not on screen.
        var hidden = events.Count - events.Count(Interesting);
        var elapsed = DateTime.UtcNow - _watchStartedUtc;

        WatchCounts.Text =
            $"{events.Count} events in {elapsed.TotalMinutes:F0} min · showing the last "
            + $"{shown.Count} process and network events · {hidden} image loads not shown · "
            + $"buffer holds the most recent {RingCapacityForDisplay}";
    }

    private static bool Interesting(LiveEvent observed) =>
        observed.Kind is LiveEventKind.ProcessStarted
            or LiveEventKind.NetworkConnect
            or LiveEventKind.NetworkAccept;

    /// <summary>
    /// Called from the ETW pump thread — every touch of the UI has to be marshalled.
    /// </summary>
    private void OnAlerted(LiveAlert alert) =>
        Dispatcher.BeginInvoke(() =>
        {
            var row = WatchAlertRow.From(alert);

            _alerts.Insert(0, row);
            AlertList.ItemsSource = null;
            AlertList.ItemsSource = _alerts;

            // The alerts this raises are already rare by design — a catalogued
            // remote-access tool starting, once per tool per session. An alert nobody is
            // looking at is the case the tray exists for, so it is pushed rather than
            // left sitting in a list behind a hidden window. When the window is up and
            // in front, the list is the notification and a balloon would be noise.
            if (IsVisible && IsActive)
            {
                return;
            }

            Tray.Visibility = Visibility.Visible;
            Tray.ShowBalloonTip(row.Title, row.Explanation, BalloonIcon.Warning);
        });

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
            AccentBrush = new SolidColorBrush(alert.IsHighPriority
                ? Color.FromRgb(0xFF, 0x6B, 0x6B)
                : Color.FromRgb(0xE8, 0xB3, 0x39)),
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

    private static readonly Brush Started = new SolidColorBrush(Color.FromRgb(0xE8, 0x8B, 0x39));
    private static readonly Brush Outbound = new SolidColorBrush(Color.FromRgb(0x6E, 0xA8, 0xD0));
    private static readonly Brush Inbound = new SolidColorBrush(Color.FromRgb(0xE8, 0xC9, 0x39));

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
