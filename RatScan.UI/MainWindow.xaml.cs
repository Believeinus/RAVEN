using System.ComponentModel;
using System.Security.Principal;
using System.Windows;
using System.Windows.Media;
using Hardcodet.Wpf.TaskbarNotification;
using RatScan.Etw;
using RatScan.UI.Pages;

// Aliased rather than importing Wpf.Ui.Controls wholesale. That namespace redeclares
// MessageBox, MessageBoxButton, MessageBoxResult, TextBox and Button, so a blanket using
// makes existing calls ambiguous — and the compiler points at the call sites rather than
// at the import that caused it.
using FluentWindow = Wpf.Ui.Controls.FluentWindow;

namespace RatScan.UI;

/// <summary>
/// The shell. Owns the window, the navigation, the tray icon and the one
/// <see cref="RavenSession"/> every page shares.
/// <para>
/// It deliberately holds no scanning logic. When this was a single dashboard the same
/// code-behind ran the scan, drew the findings, drove the watcher and answered the tray;
/// splitting the views apart without splitting that up would have moved the file, not the
/// problem.
/// </para>
/// </summary>
public partial class MainWindow : FluentWindow, IDisposable
{
    private readonly RavenSession _session = new();
    private readonly LiveWatchPage _liveWatch;

    /// <summary>
    /// Set only by "Quit RAVEN". Closing the window while a watch is running hides it
    /// instead, so the close path needs to know which of the two it is serving.
    /// </summary>
    private bool _quitting;

    /// <summary>
    /// The hide-to-tray explanation is shown once per run. Repeating it every time turns a
    /// disclosure into an irritation, and an irritation is something people click past.
    /// </summary>
    private bool _explainedHiding;

    public MainWindow()
    {
        InitializeComponent();

        _liveWatch = new LiveWatchPage(_session);

        // Built once and handed to the navigation view, rather than constructed per
        // navigation. Rebuilding would reset scroll position, throw away the rendered scan
        // and restart the event feed every time the user looked at another view.
        RootNavigation.SetPageProviderService(new RavenPageProvider(
            new Dictionary<Type, object>
            {
                [typeof(ScanPage)] = new ScanPage(_session),
                [typeof(LiveWatchPage)] = _liveWatch,
                [typeof(HistoryPage)] = new HistoryPage(_session),
                [typeof(SettingsPage)] = new SettingsPage(_session),
            }));

        _session.WatchStateChanged += UpdateTrayState;
        _session.Watcher.Alerted += OnAlerted;

        FitToScreen();
        ShowElevationState();

        Loaded += (_, _) => RootNavigation.Navigate(typeof(ScanPage));
    }

    /// <summary>
    /// Sizes and places the window inside the usable desktop.
    /// <para>
    /// The XAML size is a preference, not a demand. <c>CenterScreen</c> centres on the whole
    /// monitor including the taskbar, so on a shorter or scaled display the title bar ends
    /// up above the top edge with no way to move the window back.
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

    private void ShowElevationState() => ElevationBar.IsOpen = !IsElevated();

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

    /// <summary>
    /// Closing the window ends RAVEN — unless a live watch is running, in which case it
    /// hides to the tray and says so.
    /// <para>
    /// The asymmetry is the point. A watcher that dies with its window cannot catch a beacon
    /// that fires every thirty seconds, which is the whole reason the watch exists. But an
    /// application that silently outlives its own window, whenever it feels like it, is
    /// behaving exactly like the software this tool flags — so it only happens while there
    /// is something to watch, it is announced the first time, and stopping the watch from
    /// the tray closes the process for good.
    /// </para>
    /// </summary>
    protected override void OnClosing(CancelEventArgs e)
    {
        ArgumentNullException.ThrowIfNull(e);

        if (_quitting || !_session.Watcher.IsRunning)
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
    /// Stops the watch from the tray and brings the window back to the view that owns it,
    /// rather than stopping it invisibly. The state that changed is one the user has to be
    /// able to see.
    /// </summary>
    private void OnTrayStopWatchingClick(object sender, RoutedEventArgs e)
    {
        _liveWatch.StopFromElsewhere("Stopped from the tray. Nothing is being observed between scans.");

        RestoreFromTray();
        RootNavigation.Navigate(typeof(LiveWatchPage));
        UpdateTrayState();
    }

    private void OnTrayQuitClick(object sender, RoutedEventArgs e)
    {
        _quitting = true;
        Close();
    }

    /// <summary>
    /// Keeps the tray icon telling the truth about whether anything is being observed. A
    /// green indicator over a dead watcher would be worse than no indicator at all.
    /// </summary>
    private void UpdateTrayState()
    {
        var watching = _session.Watcher.IsRunning;

        TrayDot.Fill = new SolidColorBrush(watching ? Palette.Good : Palette.Neutral);

        Tray.ToolTipText = watching
            ? "RAVEN — watching for remote-access software starting"
            : "RAVEN — not watching";

        TrayStopItem.IsEnabled = watching;

        // The icon is only shown while it means something: a watch is running, or the
        // window is hidden and the tray is the only way back to it.
        Tray.Visibility = watching || !IsVisible ? Visibility.Visible : Visibility.Collapsed;
    }

    /// <summary>
    /// Raises the tray balloon for an alert nobody is looking at.
    /// <para>
    /// The Live Watch view keeps its own list; this only adds the push. Alerts are already
    /// rare by design — a catalogued remote-access tool starting, once per tool per session
    /// — and an alert behind a hidden window is exactly the case the tray exists for. When
    /// the window is up and in front, the list is the notification and a balloon is noise.
    /// </para>
    /// </summary>
    private void OnAlerted(LiveAlert alert) =>
        Dispatcher.BeginInvoke(() =>
        {
            if (IsVisible && IsActive)
            {
                return;
            }

            var row = WatchAlertRow.From(alert);

            Tray.Visibility = Visibility.Visible;
            Tray.ShowBalloonTip(row.Title, row.Explanation, BalloonIcon.Warning);
        });

    public void Dispose()
    {
        _session.Dispose();
        GC.SuppressFinalize(this);
    }
}
