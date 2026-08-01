using RatScan.Engine.Model;

namespace RatScan.Engine.Allowlist;

/// <summary>
/// One thing the user has decided they do not want to be told about again.
/// <para>
/// An allowlist is the one feature in a detection tool that exists to make it say
/// <em>less</em>, so it is built to be the opposite of a silencer. Every entry is pinned
/// to a specific rule and a specific file, records why it was created and when, is
/// listed back to the user on every scan, and — where the target is a real file — is
/// pinned to that file's bytes, so replacing the file brings the finding straight back.
/// </para>
/// </summary>
public sealed record AllowlistEntry
{
    public required string Id { get; init; }

    /// <summary>The rule this silences. An entry never silences a whole category.</summary>
    public required string RuleId { get; init; }

    /// <summary>The <see cref="Finding.IdentityKey"/> this was created against.</summary>
    public required string IdentityKey { get; init; }

    /// <summary>Why the user decided this was theirs. Required — an unexplained mute is a hole.</summary>
    public required string Reason { get; init; }

    public required DateTime CreatedUtc { get; init; }

    /// <summary>
    /// SHA-256 of the file at <see cref="IdentityKey"/> as it was when the entry was
    /// created, where that path was a readable file.
    /// <para>
    /// This is what stops an allowlist from becoming a hiding place. "I trust
    /// <c>MpOav.dll</c>" is not a decision anyone can actually make; "I trust the
    /// <c>MpOav.dll</c> that was on this machine on this date, with these bytes" is.
    /// If the file is replaced, the pin stops matching and the finding returns.
    /// </para>
    /// Null when the entry is not about a file — a Windows feature, for instance — in
    /// which case the entry is disclosed as unpinned.
    /// </summary>
    public string? PinnedSha256 { get; init; }

    /// <summary>Short label captured when muted, so the muted list is readable.</summary>
    public string? Label { get; init; }

    public bool IsPinnedToFileContents => PinnedSha256 is not null;

    /// <summary>
    /// Builds the entry that would mute this finding, pinning it to the current bytes
    /// of the file it identifies.
    /// </summary>
    /// <exception cref="ArgumentException">
    /// The finding may not be muted. Callers are expected to have checked
    /// <see cref="Finding.CanBeMuted"/> and hidden the option; reaching here means a
    /// path exists that could silence a concealment or coverage finding, which must
    /// fail loudly rather than quietly succeed.
    /// </exception>
    public static AllowlistEntry For(Finding finding, string reason, IFileHasher? hasher = null)
    {
        ArgumentNullException.ThrowIfNull(finding);

        if (!finding.CanBeMuted)
        {
            throw new ArgumentException(
                $"Finding '{finding.RuleId}' cannot be muted.", nameof(finding));
        }

        if (string.IsNullOrWhiteSpace(reason))
        {
            throw new ArgumentException("An allowlist entry must record why.", nameof(reason));
        }

        return new AllowlistEntry
        {
            Id = Guid.NewGuid().ToString("n"),
            RuleId = finding.RuleId,
            IdentityKey = finding.IdentityKey!,
            Reason = reason.Trim(),
            CreatedUtc = DateTime.UtcNow,
            PinnedSha256 = (hasher ?? new FileHasher()).Sha256(finding.IdentityKey!),
            Label = finding.Subject ?? finding.Title,
        };
    }
}

/// <summary>A finding that was found, then withheld from the verdict by an allowlist entry.</summary>
public sealed record SuppressedFinding
{
    public required Finding Finding { get; init; }
    public required AllowlistEntry Entry { get; init; }
}

/// <summary>
/// An entry that matched a finding's rule and identity but whose file pin no longer
/// holds, so the finding was <em>not</em> muted.
/// <para>
/// Reported rather than discarded. Silently failing to apply a mute would be merely
/// annoying; silently applying one to a file that had been swapped underneath it would
/// be the failure that matters, and the user needs to see which of the two happened.
/// </para>
/// </summary>
public sealed record StaleAllowlistEntry
{
    public required AllowlistEntry Entry { get; init; }

    /// <summary>Plain-language account of why the pin no longer holds.</summary>
    public required string Reason { get; init; }
}
