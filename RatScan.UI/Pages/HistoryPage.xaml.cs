using System.Windows;
using System.Windows.Controls;

namespace RatScan.UI.Pages;

/// <summary>
/// Recorded scans, newest first, each stating the coverage it had.
/// </summary>
public partial class HistoryPage : Page
{
    private readonly RavenSession _session;

    public HistoryPage(RavenSession session)
    {
        ArgumentNullException.ThrowIfNull(session);

        _session = session;
        InitializeComponent();

        // Refreshed when a scan finishes rather than only when the view is opened, so
        // switching to History after a scan never shows a list missing the scan the user
        // just watched run.
        _session.ScanCompleted += Reload;
        Loaded += (_, _) => Reload();
    }

    private void Reload()
    {
        if (_session.History is not { } history)
        {
            ShowEmpty(_session.StoreError
                      ?? "Scan history is unavailable, so nothing can be compared against a "
                      + "previous run. Scans still work; they are just not being kept.");
            return;
        }

        IReadOnlyList<HistoryRow> rows;

        try
        {
            rows = history.Recent(50).Select(HistoryRow.From).ToList();
        }
        catch (Exception ex)
        {
            // History is a convenience. Failing to read it is worth saying, not worth
            // throwing away the rest of the view for.
            ShowEmpty($"The history could not be read ({ex.GetType().Name}: {ex.Message}).");
            return;
        }

        if (rows.Count == 0)
        {
            ShowEmpty("No scans have been recorded yet. Run one from the Scan view and it will "
                      + "appear here, along with what it was able to examine.");
            return;
        }

        HistoryEmpty.Visibility = Visibility.Collapsed;
        HistoryHeader.Text = $"RECORDED SCANS — {rows.Count}";
        HistoryList.ItemsSource = rows;
    }

    private void ShowEmpty(string message)
    {
        HistoryHeader.Text = "RECORDED SCANS — NONE";
        HistoryEmpty.Text = message;
        HistoryEmpty.Visibility = Visibility.Visible;
        HistoryList.ItemsSource = null;
    }
}
