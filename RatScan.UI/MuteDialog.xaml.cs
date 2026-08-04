using System.Windows;
using System.Windows.Media;
using RatScan.Engine.Allowlist;
using RatScan.Engine.Model;
using ContentDialog = Wpf.Ui.Controls.ContentDialog;
using ContentDialogClosingEventArgs = Wpf.Ui.Controls.ContentDialogClosingEventArgs;
using ContentDialogHost = Wpf.Ui.Controls.ContentDialogHost;
using ContentDialogResult = Wpf.Ui.Controls.ContentDialogResult;

namespace RatScan.UI;

/// <summary>
/// Asks for the one thing an allowlist entry cannot be created without: why.
/// <para>
/// It also states, before the user commits, exactly how strong the mute they are about
/// to create is — pinned to this file's current contents, or not pinned at all. Those
/// are materially different promises, and the difference is only knowable at this
/// moment, so it is shown here rather than left for the user to discover later.
/// </para>
/// </summary>
public partial class MuteDialog : ContentDialog
{
    /// <summary>
    /// Short enough that a real answer always clears it, long enough that "ok" and a
    /// stray keystroke do not.
    /// </summary>
    private const int MinimumReason = 4;

    public MuteDialog(ContentDialogHost host, Finding finding, bool pinnable)
        : base(host)
    {
        ArgumentNullException.ThrowIfNull(finding);

        InitializeComponent();

        Title = finding.Title;

        PinText.Text = pinnable
            ? "This finding will stop appearing for this exact file, as it is right now. RAVEN "
              + $"records a fingerprint of {finding.IdentityKey}. If that file is ever replaced or "
              + "modified, the fingerprint stops matching and the finding comes back — so muting "
              + "cannot become a place for something to hide.\n\n"
              + "Everything else about this rule keeps being reported. Muted findings stay listed, "
              + "with your reason, and the scan says so in its result."
            : "This finding is about a Windows feature rather than a file, so there is nothing to "
              + "fingerprint. The mute applies whenever this feature is enabled, and it will not "
              + "notice if the feature is later turned on by someone else.\n\n"
              + "Muted findings stay listed, with your reason, and the scan says so in its result.";

        Loaded += (_, _) => ReasonBox.Focus();
        Closing += OnClosing;
    }

    /// <summary>The reason as typed, trimmed. Empty until there is enough of one to accept.</summary>
    public string Reason => ReasonBox.Text.Trim();

    /// <summary>
    /// An entry with no reason is a hole in the scan that nobody can explain later,
    /// including the person who made it. The close is refused rather than the reason
    /// defaulted to something like "muted", so there is no path to an unexplained mute.
    /// </summary>
    private void OnClosing(ContentDialog sender, ContentDialogClosingEventArgs e)
    {
        if (e.Result != ContentDialogResult.Primary || Reason.Length >= MinimumReason)
        {
            return;
        }

        e.Cancel = true;
        ValidationText.Text = "Say why — you will want to know later.";
        ValidationText.Foreground = new SolidColorBrush(Palette.Caution);
        ReasonBox.Focus();
    }

    /// <summary>Puts the refusal back to a plain note as soon as it stops applying.</summary>
    private void OnReasonChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
    {
        if (Reason.Length < MinimumReason)
        {
            return;
        }

        ValidationText.SetResourceReference(
            System.Windows.Controls.TextBlock.ForegroundProperty, "TextFillColorSecondaryBrush");
    }

    /// <summary>Runs the dialog and returns the entry to store, or null if cancelled.</summary>
    public static async Task<AllowlistEntry?> AskAsync(FrameworkElement anchor, Finding finding)
    {
        ArgumentNullException.ThrowIfNull(anchor);
        ArgumentNullException.ThrowIfNull(finding);

        if (RavenDialog.HostFor(anchor) is not { } host)
        {
            await RavenDialog.TellAsync(
                anchor,
                "Nothing was muted",
                "The mute dialog could not be opened, so no allowlist entry was created. The "
                + "finding is still being reported.").ConfigureAwait(true);

            return null;
        }

        // Hash first so the dialog can state honestly whether the mute will be pinned.
        var hasher = new FileHasher();
        var pinnable = hasher.Sha256(finding.IdentityKey!) is not null;

        var dialog = new MuteDialog(host, finding, pinnable);

        return await dialog.ShowAsync().ConfigureAwait(true) == ContentDialogResult.Primary
            ? AllowlistEntry.For(finding, dialog.Reason, hasher)
            : null;
    }
}
