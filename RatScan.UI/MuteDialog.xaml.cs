using System.Windows;
using RatScan.Engine.Allowlist;
using RatScan.Engine.Model;

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
public partial class MuteDialog : Window
{
    public string? Reason { get; private set; }

    public MuteDialog(Finding finding, bool pinnable)
    {
        ArgumentNullException.ThrowIfNull(finding);

        InitializeComponent();

        TitleText.Text = finding.Title;

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
    }

    private void OnConfirm(object sender, RoutedEventArgs e)
    {
        var reason = ReasonBox.Text.Trim();

        // An entry with no reason is a hole in the scan that nobody can explain later,
        // including the person who made it. Refuse rather than default it to "muted".
        if (reason.Length < 4)
        {
            ValidationText.Text = "Say why — you will want to know later.";
            ValidationText.Visibility = Visibility.Visible;
            ReasonBox.Focus();
            return;
        }

        Reason = reason;
        DialogResult = true;
    }

    private void OnCancel(object sender, RoutedEventArgs e) => DialogResult = false;

    /// <summary>Runs the dialog and returns the entry to store, or null if cancelled.</summary>
    public static AllowlistEntry? Ask(Window owner, Finding finding)
    {
        ArgumentNullException.ThrowIfNull(finding);

        // Hash first so the dialog can state honestly whether the mute will be pinned.
        var hasher = new FileHasher();
        var pinnable = hasher.Sha256(finding.IdentityKey!) is not null;

        var dialog = new MuteDialog(finding, pinnable) { Owner = owner };

        return dialog.ShowDialog() == true
            ? AllowlistEntry.For(finding, dialog.Reason!, hasher)
            : null;
    }
}
