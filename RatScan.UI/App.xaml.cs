using System.ComponentModel;
using System.Diagnostics;
using System.Security.Principal;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;

namespace RatScan.UI;

/// <summary>
/// Application entry point. Beyond starting the window, its one job is deciding whether
/// this process is the one that should run.
/// </summary>
public partial class App : Application
{
    /// <summary>
    /// Run without asking for Administrator.
    /// <para>
    /// Not a convenience switch. Reduced coverage is a product behaviour RatScan has to
    /// be able to demonstrate, and it cannot be exercised — by a user or by a test — if
    /// elevation is unconditional. The manifest stays <c>asInvoker</c> for the same
    /// reason: elevation is requested here, where it can be declined, rather than
    /// demanded by Windows before the process exists.
    /// </para>
    /// </summary>
    public const string StayUnelevatedSwitch = "--no-elevate";

    protected override void OnStartup(StartupEventArgs e)
    {
        ArgumentNullException.ThrowIfNull(e);

        if (ShouldRelaunchElevated(e.Args) && RelaunchElevated(e.Args))
        {
            // The elevated copy owns the session now. Shutting down before the window
            // exists keeps two RatScans off the same SQLite file.
            Shutdown();
            return;
        }

        base.OnStartup(e);
    }

    private static bool ShouldRelaunchElevated(string[] args) =>
        !IsElevated()
        && !args.Contains(StayUnelevatedSwitch, StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Asks Windows for a second, elevated copy of this application.
    /// </summary>
    /// <returns>
    /// True when the elevated copy started and this one should exit. False when the user
    /// declined the prompt or the relaunch failed — in which case RatScan carries on
    /// unelevated rather than refusing to run, and the window reports the reduced
    /// coverage and offers to try again.
    /// </returns>
    private static bool RelaunchElevated(string[] args)
    {
        var exe = Environment.ProcessPath;

        if (exe is null)
        {
            return false;
        }

        var info = new ProcessStartInfo
        {
            FileName = exe,
            UseShellExecute = true,
            Verb = "runas",
        };

        // Carry the original arguments across, minus anything that would send the new
        // process straight back down the unelevated path.
        foreach (var arg in args.Where(a =>
            !string.Equals(a, StayUnelevatedSwitch, StringComparison.OrdinalIgnoreCase)))
        {
            info.ArgumentList.Add(arg);
        }

        try
        {
            return Process.Start(info) is not null;
        }
        catch (Win32Exception)
        {
            // The user dismissed the UAC prompt. That is a decision, not a failure.
            return false;
        }
        catch (InvalidOperationException)
        {
            return false;
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

    /// <summary>
    /// Pixels moved for one full wheel notch (a delta of 120). The single number worth
    /// tuning if scrolling feels wrong: lower is slower.
    /// </summary>
    private const double PixelsPerNotch = 42;

    /// <summary>
    /// Scrolls by the size of the gesture rather than in fixed jumps.
    /// <para>
    /// WPF turns any wheel event into the same fixed movement, so a precision touchpad -
    /// which reports a stream of small deltas across one swipe - produces a full jump for
    /// every one of them, and the content outruns the finger. Scaling by
    /// <c>Delta / 120</c> keeps small movements small and leaves a real notch feeling
    /// like a notch.
    /// </para>
    /// </summary>
    private void OnScrollViewerPreviewMouseWheel(object sender, MouseWheelEventArgs e)
    {
        if (sender is not ScrollViewer viewer || e.Handled)
        {
            return;
        }

        // Nothing to scroll: let the event bubble to a parent that might scroll instead
        // of swallowing it, or the outer panel stops responding to the wheel.
        if (viewer.ScrollableHeight <= 0)
        {
            return;
        }

        var offset = viewer.VerticalOffset - (e.Delta / 120.0 * PixelsPerNotch);

        viewer.ScrollToVerticalOffset(Math.Clamp(offset, 0, viewer.ScrollableHeight));
        e.Handled = true;
    }
}
