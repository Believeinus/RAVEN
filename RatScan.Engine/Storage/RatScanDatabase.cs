using Microsoft.Data.Sqlite;

namespace RatScan.Engine.Storage;

/// <summary>
/// Where RatScan keeps its local state: <c>%LOCALAPPDATA%\RatScan</c>.
/// <para>
/// Per-user by design. The database records process paths, file hashes, scan history
/// and the user's own notes about what runs on their machine. That is host telemetry —
/// it belongs under the user's profile, not somewhere shared or roaming.
/// </para>
/// </summary>
public static class RatScanPaths
{
    public static string DataDirectory =>
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            // Deliberately still "RatScan" after the rename to RAVEN. This folder holds
            // the user's scan history, allowlist and baselines; renaming it would leave
            // all of that behind on disk while the app came up looking like a fresh
            // install, which is data loss dressed up as a rebrand. Changing it needs a
            // migration, not a new string.
            "RatScan");

    public static string Database => Path.Combine(DataDirectory, "ratscan.db");

    public static string EnsureDataDirectory()
    {
        Directory.CreateDirectory(DataDirectory);
        return DataDirectory;
    }
}

/// <summary>
/// Opens the local database and brings its schema up to date.
/// <para>
/// One place owns the schema even though several stores read from it. Two stores each
/// migrating the file independently is how local state quietly diverges — one of them
/// eventually creates a table the other assumes a different shape for, and the failure
/// surfaces as missing history rather than as an error.
/// </para>
/// </summary>
public static class RatScanDatabase
{
    /// <summary>
    /// 1 — allowlist. 2 — scan history and per-scan findings.
    /// </summary>
    public const int SchemaVersion = 2;

    public static SqliteConnection Open(string? databasePath = null)
    {
        var path = databasePath ?? RatScanPaths.Database;

        var directory = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var connection = new SqliteConnection(
            new SqliteConnectionStringBuilder { DataSource = path }.ToString());

        connection.Open();
        Migrate(connection);

        return connection;
    }

    /// <summary>
    /// Creates everything the current version needs.
    /// <para>
    /// Every statement here is a compile-time constant, and every value written by the
    /// stores goes in as a parameter. Nothing observed on a scanned machine — a process
    /// path, a signer name, a user's own note — may ever reach this database as syntax.
    /// </para>
    /// </summary>
    private static void Migrate(SqliteConnection connection)
    {
        using (var schema = connection.CreateCommand())
        {
            schema.CommandText =
                """
                CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);

                CREATE TABLE IF NOT EXISTS allowlist (
                    id            TEXT PRIMARY KEY,
                    rule_id       TEXT NOT NULL,
                    identity_key  TEXT NOT NULL,
                    reason        TEXT NOT NULL,
                    created_utc   TEXT NOT NULL,
                    pinned_sha256 TEXT NULL,
                    label         TEXT NULL
                );

                CREATE UNIQUE INDEX IF NOT EXISTS ix_allowlist_target
                    ON allowlist (rule_id, identity_key);

                CREATE TABLE IF NOT EXISTS scan (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    started_utc     TEXT NOT NULL,
                    duration_ms     INTEGER NOT NULL,
                    verdict         TEXT NOT NULL,
                    headline        TEXT NOT NULL,
                    elevated        INTEGER NOT NULL,
                    surfaces        INTEGER NOT NULL,
                    blindspots      INTEGER NOT NULL,
                    muted           INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS scan_finding (
                    scan_id      INTEGER NOT NULL REFERENCES scan (id) ON DELETE CASCADE,
                    rule_id      TEXT NOT NULL,
                    identity_key TEXT NULL,
                    subject      TEXT NULL,
                    title        TEXT NOT NULL,
                    severity     TEXT NOT NULL,
                    confidence   TEXT NOT NULL,
                    category     TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS ix_scan_finding_scan ON scan_finding (scan_id);
                CREATE INDEX IF NOT EXISTS ix_scan_started ON scan (started_utc DESC);
                """;

            schema.ExecuteNonQuery();
        }

        using var read = connection.CreateCommand();
        read.CommandText = "SELECT version FROM schema_version LIMIT 1";
        var current = read.ExecuteScalar();

        // Two literal statements rather than one chosen at runtime: keeping every
        // CommandText a compile-time constant is what makes it impossible for anything
        // observed on the machine to arrive here as SQL.
        if (current is null)
        {
            using var insert = connection.CreateCommand();
            insert.CommandText = "INSERT INTO schema_version (version) VALUES ($version)";
            insert.Parameters.AddWithValue("$version", SchemaVersion);
            insert.ExecuteNonQuery();

            return;
        }

        using var update = connection.CreateCommand();
        update.CommandText = "UPDATE schema_version SET version = $version";
        update.Parameters.AddWithValue("$version", SchemaVersion);
        update.ExecuteNonQuery();
    }
}
