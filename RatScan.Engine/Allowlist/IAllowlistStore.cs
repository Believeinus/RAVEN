namespace RatScan.Engine.Allowlist;

/// <summary>
/// Where allowlist entries live between scans.
/// <para>
/// An interface rather than a concrete store because the engine must stay runnable
/// with no database at all: a scan with no store simply mutes nothing, which is the
/// safe direction to fail in.
/// </para>
/// </summary>
public interface IAllowlistStore
{
    IReadOnlyList<AllowlistEntry> All();

    void Add(AllowlistEntry entry);

    /// <summary>Removes an entry by id. Returns false when there was nothing to remove.</summary>
    bool Remove(string id);
}

/// <summary>Store with no persistence, for tests and for running without a database.</summary>
public sealed class InMemoryAllowlistStore : IAllowlistStore
{
    private readonly List<AllowlistEntry> _entries = [];

    public InMemoryAllowlistStore(IEnumerable<AllowlistEntry>? seed = null)
    {
        if (seed is not null)
        {
            _entries.AddRange(seed);
        }
    }

    public IReadOnlyList<AllowlistEntry> All() => _entries.ToList();

    public void Add(AllowlistEntry entry) => _entries.Add(entry);

    public bool Remove(string id) => _entries.RemoveAll(e => e.Id == id) > 0;
}
