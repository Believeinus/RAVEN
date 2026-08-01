using System.Globalization;
using Microsoft.Data.Sqlite;
using RatScan.Engine.Model;
using RatScan.Engine.Storage;

namespace RatScan.Engine.History;

/// <summary>Scan history as it survives a restart.</summary>
public interface IScanHistoryStore
{
    /// <summary>The most recent scans, newest first, with their findings.</summary>
    IReadOnlyList<ScanRecord> Recent(int limit = 20);

    /// <summary>The most recent scan, or null when this is the first one.</summary>
    ScanRecord? Latest();

    /// <summary>Records a completed scan and returns it as stored.</summary>
    ScanRecord Record(ScanResult result);
}

/// <summary>
/// Keeps every completed scan so the next one can say what changed.
/// <para>
/// History exists because a scan describes an instant and the useful question is
/// usually comparative: not "is TightVNC running" but "was it running yesterday". The
/// muted count and elevation are stored alongside the findings precisely so a later
/// comparison can tell a real change from a change in what the tool could see.
/// </para>
/// </summary>
public sealed class SqliteScanHistoryStore : IScanHistoryStore, IDisposable
{
    private readonly SqliteConnection _connection;

    public SqliteScanHistoryStore(string? databasePath = null)
    {
        _connection = RatScanDatabase.Open(databasePath);
    }

    public ScanRecord Record(ScanResult result)
    {
        ArgumentNullException.ThrowIfNull(result);

        using var transaction = _connection.BeginTransaction();

        long id;

        using (var insert = _connection.CreateCommand())
        {
            insert.Transaction = transaction;
            insert.CommandText =
                """
                INSERT INTO scan
                    (started_utc, duration_ms, verdict, headline, elevated, surfaces, blindspots, muted)
                VALUES
                    ($started, $duration, $verdict, $headline, $elevated, $surfaces, $blindspots, $muted);
                SELECT last_insert_rowid();
                """;

            insert.Parameters.AddWithValue(
                "$started", result.StartedUtc.ToString("o", CultureInfo.InvariantCulture));
            insert.Parameters.AddWithValue("$duration", (long)result.Duration.TotalMilliseconds);
            insert.Parameters.AddWithValue("$verdict", result.Verdict.ToString());
            insert.Parameters.AddWithValue("$headline", result.Headline);
            insert.Parameters.AddWithValue("$elevated", result.Integrity.Elevated ? 1 : 0);
            insert.Parameters.AddWithValue("$surfaces", result.SurfacesExamined.Count);
            insert.Parameters.AddWithValue("$blindspots", result.Blindspots.Count);
            insert.Parameters.AddWithValue("$muted", result.Suppressed.Count);

            id = (long)insert.ExecuteScalar()!;
        }

        foreach (var finding in result.Findings)
        {
            using var insert = _connection.CreateCommand();
            insert.Transaction = transaction;
            insert.CommandText =
                """
                INSERT INTO scan_finding
                    (scan_id, rule_id, identity_key, subject, title, severity, confidence, category)
                VALUES
                    ($scan, $rule, $identity, $subject, $title, $severity, $confidence, $category)
                """;

            insert.Parameters.AddWithValue("$scan", id);
            insert.Parameters.AddWithValue("$rule", finding.RuleId);
            insert.Parameters.AddWithValue("$identity", (object?)finding.IdentityKey ?? DBNull.Value);
            insert.Parameters.AddWithValue("$subject", (object?)finding.Subject ?? DBNull.Value);
            insert.Parameters.AddWithValue("$title", finding.Title);
            insert.Parameters.AddWithValue("$severity", finding.Severity.ToString());
            insert.Parameters.AddWithValue("$confidence", finding.Confidence.ToString());
            insert.Parameters.AddWithValue("$category", finding.Category.ToString());

            insert.ExecuteNonQuery();
        }

        transaction.Commit();

        return Load(id)!;
    }

    public ScanRecord? Latest()
    {
        var recent = Recent(1);
        return recent.Count > 0 ? recent[0] : null;
    }

    public IReadOnlyList<ScanRecord> Recent(int limit = 20)
    {
        var ids = new List<long>();

        using (var command = _connection.CreateCommand())
        {
            command.CommandText = "SELECT id FROM scan ORDER BY id DESC LIMIT $limit";
            command.Parameters.AddWithValue("$limit", limit);

            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                ids.Add(reader.GetInt64(0));
            }
        }

        return ids.Select(Load).OfType<ScanRecord>().ToList();
    }

    private ScanRecord? Load(long id)
    {
        ScanRecord? record;

        using (var command = _connection.CreateCommand())
        {
            command.CommandText =
                """
                SELECT id, started_utc, duration_ms, verdict, headline, elevated,
                       surfaces, blindspots, muted
                FROM scan WHERE id = $id
                """;

            command.Parameters.AddWithValue("$id", id);

            using var reader = command.ExecuteReader();
            if (!reader.Read())
            {
                return null;
            }

            record = new ScanRecord
            {
                Id = reader.GetInt64(0),
                StartedUtc = DateTime.Parse(
                    reader.GetString(1), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind),
                Duration = TimeSpan.FromMilliseconds(reader.GetInt64(2)),
                Verdict = Enum.Parse<VerdictLevel>(reader.GetString(3)),
                Headline = reader.GetString(4),
                Elevated = reader.GetInt32(5) == 1,
                SurfacesExamined = reader.GetInt32(6),
                Blindspots = reader.GetInt32(7),
                Muted = reader.GetInt32(8),
            };
        }

        var findings = new List<RecordedFinding>();

        using (var command = _connection.CreateCommand())
        {
            command.CommandText =
                """
                SELECT rule_id, identity_key, subject, title, severity, confidence, category
                FROM scan_finding WHERE scan_id = $id
                """;

            command.Parameters.AddWithValue("$id", id);

            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                findings.Add(new RecordedFinding
                {
                    RuleId = reader.GetString(0),
                    IdentityKey = reader.IsDBNull(1) ? null : reader.GetString(1),
                    Subject = reader.IsDBNull(2) ? null : reader.GetString(2),
                    Title = reader.GetString(3),
                    Severity = Enum.Parse<Severity>(reader.GetString(4)),
                    Confidence = Enum.Parse<Confidence>(reader.GetString(5)),
                    Category = Enum.Parse<FindingCategory>(reader.GetString(6)),
                });
            }
        }

        return record with { Findings = findings };
    }

    public void Dispose()
    {
        _connection.Dispose();
        SqliteConnection.ClearPool(_connection);
    }
}
