using RatScan.Engine;
using RatScan.Engine.Allowlist;
using RatScan.Engine.History;
using RatScan.Engine.Model;
using RatScan.Engine.Remediation;
using RatScan.Etw;

namespace RatScan.UI;

/// <summary>
/// The state every view shares: the stores, the watcher, and the last scan.
/// <para>
/// Introduced when the single dashboard became a navigation shell. Each page owns its own
/// XAML and handlers, but there is exactly one allowlist connection, one history
/// connection and one ETW session for the process — a second <see cref="LiveWatcher"/>
/// would fail to start against its own session name and report the failure as though the
/// machine were at fault, and a second SQLite writer would be a lock waiting to happen.
/// </para>
/// <para>
/// Deliberately a plain object handed to page constructors rather than a container. There
/// is still no view-model layer here and no host; adding one to pass four references
/// would be the same dead architecture the dependency list was cleaned of.
/// </para>
/// </summary>
public sealed class RavenSession : IDisposable
{
    public RavenSession()
    {
        // A broken store must not stop the tool scanning. It degrades to muting nothing —
        // which shows the user more, not less — and the reason is carried so the view can
        // say it where the muted list would otherwise be.
        try
        {
            Allowlist = new SqliteAllowlistStore();
            History = new SqliteScanHistoryStore();
        }
        catch (Exception ex)
        {
            StoreError = $"Your allowlist could not be opened ({ex.GetType().Name}: "
                         + $"{ex.Message}). Nothing is being muted, and muting is unavailable "
                         + "until this is fixed.";
        }

        Orchestrator = new ScanOrchestrator(allowlist: Allowlist);
    }

    public ScanOrchestrator Orchestrator { get; }

    public RemediationExecutor Remediation { get; } = new();

    /// <summary>Null when the allowlist database could not be opened.</summary>
    public SqliteAllowlistStore? Allowlist { get; }

    /// <summary>Null when history could not be opened; scans still run, they are not kept.</summary>
    public SqliteScanHistoryStore? History { get; }

    /// <summary>Why the stores are unavailable, when they are. Shown, never swallowed.</summary>
    public string? StoreError { get; }

    /// <summary>Live ETW watch. Constructed here, started only when the user asks.</summary>
    public LiveWatcher Watcher { get; } = new();

    /// <summary>The last rendered scan, kept so muting can re-score without re-scanning.</summary>
    public ScanResult? LastResult { get; set; }

    /// <summary>The comparison shown for that scan, so an export can carry it too.</summary>
    public ScanDiff? LastDiff { get; set; }

    /// <summary>Raised when a scan completes, so views other than Scan can refresh.</summary>
    public event Action? ScanCompleted;

    public void NotifyScanCompleted() => ScanCompleted?.Invoke();

    /// <summary>
    /// Raised when the watch starts or stops. The tray icon lives on the shell window and
    /// the start/stop button lives on the Live Watch view, so the indicator would otherwise
    /// keep showing green over a watcher that had been stopped from another screen — worse
    /// than having no indicator at all.
    /// </summary>
    public event Action? WatchStateChanged;

    public void NotifyWatchStateChanged() => WatchStateChanged?.Invoke();

    public void Dispose()
    {
        // The ETW session outlives the process that created it, so failing to dispose
        // leaves a running kernel session behind and blocks the next start.
        Watcher.Dispose();
        Allowlist?.Dispose();
        History?.Dispose();
        GC.SuppressFinalize(this);
    }
}

/// <summary>
/// Hands the navigation shell the page instances it asks for by type.
/// <para>
/// WPF-UI resolves <c>TargetPageType</c> through a provider so that pages can come from a
/// DI container. This project has no container, so the provider is a lookup over
/// instances built once with the shared <see cref="RavenSession"/>. Building them per
/// navigation would reset scroll position, lose the rendered scan and restart the feed
/// every time the user looked at another view.
/// </para>
/// </summary>
public sealed class RavenPageProvider(IReadOnlyDictionary<Type, object> pages)
    : Wpf.Ui.Abstractions.INavigationViewPageProvider
{
    public object? GetPage(Type pageType) =>
        pages.TryGetValue(pageType, out var page) ? page : null;
}
