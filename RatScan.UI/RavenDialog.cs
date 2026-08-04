using System.Windows;
using ContentDialog = Wpf.Ui.Controls.ContentDialog;
using ContentDialogButton = Wpf.Ui.Controls.ContentDialogButton;
using ContentDialogHost = Wpf.Ui.Controls.ContentDialogHost;
using ContentDialogResult = Wpf.Ui.Controls.ContentDialogResult;
using ControlAppearance = Wpf.Ui.Controls.ControlAppearance;

namespace RatScan.UI;

/// <summary>
/// The two prompts every view needs: ask before doing something, and say what happened.
/// <para>
/// These were <c>MessageBox</c> calls. The change is not cosmetic. A MessageBox is a
/// separate top-level window with the system title bar and OS button labels, so the one
/// dialog in this product that has to be read carefully — the one naming the exact command
/// about to run — arrived looking like every "are you sure?" the user has ever clicked
/// through. A <see cref="ContentDialog"/> renders inside the window, in this app's own
/// typography, and its primary button carries the name of the action instead of "OK".
/// </para>
/// </summary>
internal static class RavenDialog
{
    /// <summary>
    /// Wide enough for a command line to sit on one line where it can be read, narrow
    /// enough that prose does not run past a comfortable measure.
    /// </summary>
    private const double DialogWidth = 620;

    /// <summary>
    /// Asks, and returns true only if the user pressed the button that names the action.
    /// <para>
    /// Every caller is a guard in front of something that changes the machine or writes a
    /// file describing it, so the answer is deliberately narrow: the primary button is
    /// consent, and Cancel, Escape and a dismissed dialog are all the same "no".
    /// </para>
    /// </summary>
    public static async Task<bool> ConfirmAsync(
        FrameworkElement anchor,
        string title,
        string body,
        string primaryText,
        ControlAppearance primaryAppearance = ControlAppearance.Primary)
    {
        ArgumentNullException.ThrowIfNull(anchor);

        if (HostFor(anchor) is not { } host)
        {
            // A confirmation is the only thing standing in front of a remediation command.
            // If the host is somehow missing, the action still has to be asked about — a
            // failure to render the guard must never be read as consent.
            return MessageBox.Show(
                Window.GetWindow(anchor)!, body, title,
                MessageBoxButton.OKCancel, MessageBoxImage.Warning,
                MessageBoxResult.Cancel) == MessageBoxResult.OK;
        }

        var dialog = new ContentDialog(host)
        {
            Title = title,
            Content = Prose(body),
            PrimaryButtonText = primaryText,
            PrimaryButtonAppearance = primaryAppearance,
            CloseButtonText = "Cancel",

            // Cancel is the default so that Enter or Space on a dialog the user has not
            // read yet does nothing. Nothing here is worth defaulting to yes.
            DefaultButton = ContentDialogButton.Close,
            DialogMaxWidth = DialogWidth,
        };

        return await dialog.ShowAsync().ConfigureAwait(true) == ContentDialogResult.Primary;
    }

    /// <summary>States an outcome. One button, and nothing is decided by pressing it.</summary>
    public static async Task TellAsync(
        FrameworkElement anchor,
        string title,
        string body,
        string closeText = "Close")
    {
        ArgumentNullException.ThrowIfNull(anchor);

        if (HostFor(anchor) is not { } host)
        {
            MessageBox.Show(
                Window.GetWindow(anchor)!, body, title,
                MessageBoxButton.OK, MessageBoxImage.Information);

            return;
        }

        var dialog = new ContentDialog(host)
        {
            Title = title,
            Content = Prose(body),
            CloseButtonText = closeText,
            DefaultButton = ContentDialogButton.Close,
            DialogMaxWidth = DialogWidth,
        };

        await dialog.ShowAsync().ConfigureAwait(true);
    }

    /// <summary>The window's one dialog host, or null if this element is not in a window yet.</summary>
    public static ContentDialogHost? HostFor(FrameworkElement anchor) =>
        Window.GetWindow(anchor) is { } window ? ContentDialogHost.GetForWindow(window) : null;

    /// <summary>
    /// A bare string handed to a ContentDialog does not wrap, and these bodies are
    /// paragraphs — one of them is a file path that has to stay readable.
    /// </summary>
    private static System.Windows.Controls.TextBlock Prose(string body) => new()
    {
        Text = body,
        TextWrapping = TextWrapping.Wrap,
    };
}
