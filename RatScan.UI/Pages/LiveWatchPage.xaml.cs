using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using RatScan.Etw;

namespace RatScan.UI.Pages;

/// <summary>
/// The live ETW watch: start it, see what it observes, and be told plainly when it is not
/// running or has stopped on its own.
/// </summary>
public partial class LiveWatchPage : Page
{
    private readonly RavenSession _session;
    private readonly DispatcherTimer _feedTimer = new() { Interval = TimeSpan.FromSeconds(1) };
    private readonly List<WatchAlertRow> _alerts = [];

    private DateTime _watchStartedUtc;

    /// <summary>How many process/network events the feed shows at once.</summary>
    private const int FeedLength = 120;

    /// <summary>Mirrors <c>LiveWatcher</c>'s ring size, for the disclosure line only.</summary>
    private const int RingCapacityForDisplay = 5000;

    public LiveWatchPage(RavenSession session)
    {
        ArgumentNullException.ThrowIfNull(session);

        _session = session;
        InitializeComponent();

        _feedTimer.Tick += (_, _) => RefreshFeed();
        _session.Watcher.Alerted += OnAlerted;
    }

    /// <summary>
    /// Starts or stops the ETW watcher.
    /// <para>
    /// Off until asked for. It needs Administrator, and a failure to start is shown as a
    /// named condition with its remedy rather than a silent no-op — the whole value of this
    /// view is that the user can tell watching from not-watching at a glance.
    /// </para>
    /// </summary>
    private void OnWatchClick(object sender, RoutedEventArgs e)
    {
        if (_session.Watcher.IsRunning)
        {
            StopWatching("Stopped. Nothing is being observed between scans.");
            return;
        }

        var start = _session.Watcher.Start();

        if (!start.Started)
        {
            WatchHeader.Text = "Live watch — cannot start";
            WatchDot.Fill = new SolidColorBrush(Palette.Caution);
            WatchStatus.Foreground = new SolidColorBrush(Palette.Caution);
            WatchStatus.Text = start.Remedy is null
                ? start.Error ?? "The watcher could not be started."
                : $"{start.Error}\n{start.Remedy}";

            return;
        }

        _watchStartedUtc = DateTime.UtcNow;
        _alerts.Clear();
        AlertList.ItemsSource = null;
        AlertSection.Visibility = Visibility.Collapsed;

        WatchHeader.Text = "Live watch — on";
        WatchDot.Fill = new SolidColorBrush(Palette.Good);
        WatchButton.Content = "Stop watching";
        WatchStatus.Foreground = new SolidColorBrush(Palette.Good);
        WatchStatus.Text = "Watching process starts, image loads and TCP connections. Alerts fire "
                           + "once per tool for catalogued remote-access software; everything else "
                           + "is listed below.";

        WatchCounts.Visibility = Visibility.Visible;
        _feedTimer.Start();
        _session.NotifyWatchStateChanged();
        RefreshFeed();
    }

    private void StopWatching(string status)
    {
        _feedTimer.Stop();
        _session.Watcher.Stop();

        WatchHeader.Text = "Live watch — off";
        WatchDot.Fill = new SolidColorBrush(Palette.Neutral);
        WatchButton.Content = "Start watching";
        WatchStatus.Foreground = new SolidColorBrush(Palette.Neutral);
        WatchStatus.Text = status;

        _session.NotifyWatchStateChanged();
    }

    /// <summary>
    /// Stops the watch from somewhere other than this view — the tray menu — and leaves the
    /// view telling the truth about it.
    /// </summary>
    public void StopFromElsewhere(string status)
    {
        if (_session.Watcher.IsRunning)
        {
            StopWatching(status);
        }
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
        // takes the ETW session name. Reporting that is the whole point of this view.
        if (!_session.Watcher.IsRunning)
        {
            StopWatching("The watcher stopped on its own. The ETW session was closed or taken over — "
                         + "nothing has been observed since. Start it again to resume.");

            return;
        }

        var events = _session.Watcher.RecentEvents;

        var shown = events
            .Where(Interesting)
            .TakeLast(FeedLength)
            .Reverse()
            .Select(FeedRow.From)
            .ToList();

        FeedList.ItemsSource = shown;

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
    /// Called from the ETW pump thread — every touch of the UI has to be marshalled. The
    /// tray balloon is raised separately by the shell window, which knows whether anyone is
    /// looking at this view.
    /// </summary>
    private void OnAlerted(LiveAlert alert) =>
        Dispatcher.BeginInvoke(() =>
        {
            _alerts.Insert(0, WatchAlertRow.From(alert));

            AlertSection.Visibility = Visibility.Visible;
            AlertHeader.Text = $"ALERTS — {_alerts.Count}";
            AlertList.ItemsSource = null;
            AlertList.ItemsSource = _alerts;
        });
}
