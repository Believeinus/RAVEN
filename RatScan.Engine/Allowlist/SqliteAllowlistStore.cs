using System.Globalization;
using Microsoft.Data.Sqlite;
using RatScan.Engine.Storage;

namespace RatScan.Engine.Allowlist;

/// <summary>
/// The allowlist as it survives a restart. SQLite, single file, no server.
/// <para>
/// The schema itself lives in <see cref="RatScanDatabase"/>, shared with scan history,
/// so no store has to guess what shape the file it opened is in.
/// </para>
/// </summary>
public sealed class SqliteAllowlistStore : IAllowlistStore, IDisposable
{
    private readonly SqliteConnection _connection;

    public SqliteAllowlistStore(string? databasePath = null)
    {
        _connection = RatScanDatabase.Open(databasePath);
    }

    public IReadOnlyList<AllowlistEntry> All()
    {
        using var command = _connection.CreateCommand();
        command.CommandText =
            """
            SELECT id, rule_id, identity_key, reason, created_utc, pinned_sha256, label
            FROM allowlist
            ORDER BY created_utc DESC
            """;

        var entries = new List<AllowlistEntry>();
        using var reader = command.ExecuteReader();

        while (reader.Read())
        {
            entries.Add(new AllowlistEntry
            {
                Id = reader.GetString(0),
                RuleId = reader.GetString(1),
                IdentityKey = reader.GetString(2),
                Reason = reader.GetString(3),
                CreatedUtc = DateTime.Parse(
                    reader.GetString(4), CultureInfo.InvariantCulture,
                    DateTimeStyles.RoundtripKind),
                PinnedSha256 = reader.IsDBNull(5) ? null : reader.GetString(5),
                Label = reader.IsDBNull(6) ? null : reader.GetString(6),
            });
        }

        return entries;
    }

    /// <summary>
    /// Adds the entry, replacing any existing mute for the same rule and file. Muting
    /// the same thing twice is a re-approval of whatever it is now, so the newer pin
    /// wins rather than leaving two entries disagreeing about which bytes were trusted.
    /// </summary>
    public void Add(AllowlistEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);

        using var command = _connection.CreateCommand();
        command.CommandText =
            """
            INSERT INTO allowlist (id, rule_id, identity_key, reason, created_utc, pinned_sha256, label)
            VALUES ($id, $rule, $identity, $reason, $created, $sha, $label)
            ON CONFLICT (rule_id, identity_key) DO UPDATE SET
                id            = excluded.id,
                reason        = excluded.reason,
                created_utc   = excluded.created_utc,
                pinned_sha256 = excluded.pinned_sha256,
                label         = excluded.label
            """;

        command.Parameters.AddWithValue("$id", entry.Id);
        command.Parameters.AddWithValue("$rule", entry.RuleId);
        command.Parameters.AddWithValue("$identity", entry.IdentityKey);
        command.Parameters.AddWithValue("$reason", entry.Reason);
        command.Parameters.AddWithValue(
            "$created", entry.CreatedUtc.ToString("o", CultureInfo.InvariantCulture));
        command.Parameters.AddWithValue("$sha", (object?)entry.PinnedSha256 ?? DBNull.Value);
        command.Parameters.AddWithValue("$label", (object?)entry.Label ?? DBNull.Value);

        command.ExecuteNonQuery();
    }

    public bool Remove(string id)
    {
        using var command = _connection.CreateCommand();
        command.CommandText = "DELETE FROM allowlist WHERE id = $id";
        command.Parameters.AddWithValue("$id", id);

        return command.ExecuteNonQuery() > 0;
    }

    public void Dispose()
    {
        _connection.Dispose();
        SqliteConnection.ClearPool(_connection);
    }
}
