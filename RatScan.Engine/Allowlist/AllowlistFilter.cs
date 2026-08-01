using RatScan.Engine.Model;

namespace RatScan.Engine.Allowlist;

/// <summary>The outcome of applying the allowlist to one scan's findings.</summary>
public sealed record AllowlistApplication
{
    /// <summary>Findings that survived and count towards the verdict.</summary>
    public IReadOnlyList<Finding> Active { get; init; } = [];

    /// <summary>Findings withheld from the verdict, each with the entry responsible.</summary>
    public IReadOnlyList<SuppressedFinding> Suppressed { get; init; } = [];

    /// <summary>Entries that matched but did not apply, because their file pin no longer holds.</summary>
    public IReadOnlyList<StaleAllowlistEntry> Stale { get; init; } = [];
}

/// <summary>
/// Decides which findings the user's allowlist withholds from the verdict.
/// <para>
/// Kept as a pure function over findings and entries, with file hashing behind
/// <see cref="IFileHasher"/>, for the same reason detectors are separate from
/// collectors: the decisions worth testing here are the refusals — a rule that does not
/// match, a category that may not be muted, a pin that no longer holds — and none of
/// them should need a staged filesystem to exercise.
/// </para>
/// </summary>
public sealed class AllowlistFilter(IFileHasher? hasher = null)
{
    /// <summary>Marks evidence this filter added, so a re-run can strip its own notes.</summary>
    public const string EvidenceSource = "your allowlist";

    private readonly IFileHasher _hasher = hasher ?? new FileHasher();

    public AllowlistApplication Apply(
        IReadOnlyList<Finding> findings, IReadOnlyList<AllowlistEntry> entries)
    {
        if (entries.Count == 0)
        {
            return new AllowlistApplication { Active = findings };
        }

        var active = new List<Finding>();
        var suppressed = new List<SuppressedFinding>();
        var stale = new List<StaleAllowlistEntry>();

        // One hash per distinct file per scan, however many entries point at it.
        var hashes = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);

        foreach (var finding in findings)
        {
            var candidate = finding.CanBeMuted
                ? entries.FirstOrDefault(e => Matches(e, finding))
                : null;

            if (candidate is null)
            {
                active.Add(finding);
                continue;
            }

            var (applies, reason) = PinHolds(candidate, hashes);

            if (applies)
            {
                suppressed.Add(new SuppressedFinding { Finding = finding, Entry = candidate });
                continue;
            }

            // The mute did not apply, so the finding is shown — but the user muted this
            // once and would otherwise reasonably assume it had stopped working. Say
            // what happened, on the finding itself, where they are already looking.
            active.Add(finding with
            {
                EvidenceChain =
                [
                    .. finding.EvidenceChain,
                    Evidence.Of("Allowlist", reason, EvidenceSource),
                ],
            });

            if (stale.All(s => s.Entry.Id != candidate.Id))
            {
                stale.Add(new StaleAllowlistEntry { Entry = candidate, Reason = reason });
            }
        }

        return new AllowlistApplication
        {
            Active = active,
            Suppressed = suppressed,
            Stale = stale,
        };
    }

    private static bool Matches(AllowlistEntry entry, Finding finding) =>
        string.Equals(entry.RuleId, finding.RuleId, StringComparison.Ordinal)
        && string.Equals(entry.IdentityKey, finding.IdentityKey, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Whether an entry's file pin still holds. Anything other than a confirmed match
    /// fails open — the finding is shown — because an unverifiable pin is exactly the
    /// state a swapped file produces, and the whole point of pinning is that this case
    /// must not be mistaken for agreement.
    /// </summary>
    private (bool Applies, string Reason) PinHolds(
        AllowlistEntry entry, Dictionary<string, string?> hashes)
    {
        if (!entry.IsPinnedToFileContents)
        {
            return (true, "muted by an entry that is not pinned to file contents");
        }

        if (!hashes.TryGetValue(entry.IdentityKey, out var current))
        {
            current = _hasher.Sha256(entry.IdentityKey);
            hashes[entry.IdentityKey] = current;
        }

        if (current is null)
        {
            return (false,
                $"you muted this on {entry.CreatedUtc.ToLocalTime():d MMM yyyy}, but the file could "
                + "not be read to confirm it is the same one, so the finding is shown");
        }

        return string.Equals(current, entry.PinnedSha256, StringComparison.OrdinalIgnoreCase)
            ? (true, "muted, and the file is unchanged since you muted it")
            : (false,
                $"you muted this on {entry.CreatedUtc.ToLocalTime():d MMM yyyy}, but the file has "
                + "changed since — it is not the one you approved, so the finding is shown");
    }
}
