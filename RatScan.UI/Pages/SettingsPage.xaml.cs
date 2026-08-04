using System.Security.Principal;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using RatScan.Engine.Storage;

namespace RatScan.UI.Pages;

/// <summary>
/// Coverage, the allowlist, where the data lives, and what the tool does not claim.
/// </summary>
public partial class SettingsPage : Page
{
    private readonly RavenSession _session;

    public SettingsPage(RavenSession session)
    {
        ArgumentNullException.ThrowIfNull(session);

        _session = session;
        InitializeComponent();

        _session.ScanCompleted += ShowAllowlist;
        Loaded += (_, _) =>
        {
            ShowElevationState();
            ShowAllowlist();
        };

        DataPathText.Text = RavenPathsSafe();
    }

    private Window? Owner => Window.GetWindow(this);

    private void ShowElevationState()
    {
        var elevated = IsElevated();

        ElevationText.Text = elevated
            ? "Running as Administrator"
            : "Not elevated — coverage is reduced";

        ElevationText.Foreground = new SolidColorBrush(elevated ? Palette.Good : Palette.Caution);

        ElevationDetail.Text = elevated
            ? "Process image paths, kernel driver identities, the object-manager driver "
              + "directory, the Security event log and SMB session data are all readable, and "
              + "the live watch can start."
            : "Without Administrator, RAVEN cannot read kernel driver identities, the "
              + "object-manager driver directory, the Security event log or SMB session data, "
              + "and the live watch cannot start. Those gaps are listed on every scan rather "
              + "than passed over.";

        ElevateButton.Visibility = elevated ? Visibility.Collapsed : Visibility.Visible;
    }

    private void ShowAllowlist()
    {
        if (_session.StoreError is { } error)
        {
            AllowlistHeader.Text = "ALLOWLIST — UNAVAILABLE";
            AllowlistNote.Text = error;
            return;
        }

        var entries = _session.Allowlist?.All() ?? [];

        AllowlistHeader.Text = entries.Count == 0
            ? "ALLOWLIST — EMPTY"
            : $"ALLOWLIST — {entries.Count} ENTR{(entries.Count == 1 ? "Y" : "IES")}";

        AllowlistNote.Text = entries.Count == 0
            ? "Nothing is being muted. Every finding a scan produces is being shown to you."
            : $"{entries.Count} finding{(entries.Count == 1 ? " is" : "s are")} being withheld from "
              + "the count and the verdict. Each entry is pinned to the SHA-256 of the file it "
              + "excuses, so replacing that file brings the finding straight back. The full list, "
              + "and whether each entry actually applied, is shown under the findings on the Scan "
              + "view — muted items are listed there, never hidden.";
    }

    /// <summary>
    /// Relaunches elevated, at the user's request rather than by manifest.
    /// <para>
    /// Deliberately a button and not a <c>requireAdministrator</c> manifest. Forcing
    /// elevation would make the degraded-coverage path unreachable, and that path is a
    /// first-class product behaviour: RAVEN has to be able to show a user what it cannot
    /// see. Declining the UAC prompt is a normal outcome, not an error.
    /// </para>
    /// </summary>
    private void OnElevateClick(object sender, RoutedEventArgs e)
    {
        var exe = Environment.ProcessPath;

        if (exe is null)
        {
            MessageBox.Show(
                Owner!,
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
            // The user dismissed the UAC prompt. Nothing has changed and nothing is wrong;
            // saying so beats an error dialog for a decision they just made.
            ElevationText.Text = "Not elevated — restart declined";
            return;
        }

        Owner?.Close();
    }

    private static string RavenPathsSafe()
    {
        try
        {
            return RatScanPaths.Database;
        }
        catch (Exception)
        {
            return "The database location could not be resolved.";
        }
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
