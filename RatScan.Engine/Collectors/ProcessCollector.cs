using System.Collections.Concurrent;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Principal;
using RatScan.Engine.Model;
using RatScan.Native.Network;
using RatScan.Native.Processes;
using RatScan.Native.Signing;
using RatScan.Native.Windowing;

namespace RatScan.Engine.Collectors;

public sealed record ScanOptions
{
    /// <summary>Verify Authenticode signatures. The single most expensive step.</summary>
    public bool VerifySignatures { get; init; } = true;

    /// <summary>SHA-256 every distinct image. Needed for hash-based rules and VT lookups.</summary>
    public bool ComputeHashes { get; init; } = true;

    /// <summary>
    /// Probe the PID space with OpenProcess. Slower than the listing sources but the
    /// only one a process-hiding rootkit cannot filter, so it is on by default.
    /// </summary>
    public bool ProbePidSpace { get; init; } = true;

    public static ScanOptions Quick => new()
    {
        VerifySignatures = false,
        ComputeHashes = false,
        ProbePidSpace = false,
    };

    public static ScanOptions Full => new();
}

/// <summary>
/// Gathers the process fact set. Behind an interface so detectors and the UI can be
/// exercised against synthetic facts without touching the real machine.
/// </summary>
public interface IProcessCollector
{
    ProcessCollectionResult Collect(ScanOptions? options = null, CancellationToken cancellationToken = default);
}

/// <summary>
/// Merges every process-facing source into one fact set.
/// <para>
/// Judgement-free by design: it records what each source saw, including what each
/// source <em>failed</em> to see, and leaves every conclusion to the detectors.
/// </para>
/// </summary>
public sealed class ProcessCollector : IProcessCollector
{
    public ProcessCollectionResult Collect(ScanOptions? options = null, CancellationToken cancellationToken = default)
    {
        options ??= ScanOptions.Full;
        var started = Stopwatch.GetTimestamp();

        var elevated = IsCurrentProcessElevated();
        var blindspots = new List<Blindspot>();

        var sources = BuildSources(options);
        var results = sources.Select(s => s.Enumerate(cancellationToken)).ToList();

        var coverage = results
            .Select(r => new SourceCoverage
            {
                Source = r.SourceName,
                Succeeded = r.Succeeded,
                Reported = r.Processes.Count,
                Error = r.Error,
                Partial = r.Partial,
            })
            .ToList();

        foreach (var failed in results.Where(r => !r.Succeeded))
        {
            blindspots.Add(new Blindspot
            {
                Area = $"Process enumeration via {failed.SourceName}",
                Reason = failed.Error ?? "source failed for an unrecorded reason",
                Remedy = elevated ? null : "Run as Administrator",
            });
        }

        if (!elevated)
        {
            blindspots.Add(new Blindspot
            {
                Area = "Protected and other-user processes",
                Reason = "Running without Administrator: image paths, tokens and integrity "
                         + "levels cannot be read for processes outside this session.",
                Remedy = "Run as Administrator",
            });
        }

        if (options.ProbePidSpace)
        {
            blindspots.Add(new Blindspot
            {
                Area = $"Process IDs at or above {BruteForceProcessSource.DefaultCeiling}",
                Reason = "The PID probe stops at a fixed ceiling; Windows can allocate above it.",
                Remedy = "Raise the probe ceiling in Settings (slower scan)",
            });
        }
        else
        {
            blindspots.Add(new Blindspot
            {
                Area = "Processes hidden from all listing APIs",
                Reason = "The PID-space probe is disabled, so a process concealed from every "
                         + "enumeration interface would not be detected.",
                Remedy = "Enable the PID-space probe (Full scan)",
            });
        }

        var merged = Merge(results, cancellationToken);

        Enrich(merged, options, cancellationToken);

        return new ProcessCollectionResult
        {
            Processes = merged.Values.OrderBy(p => p.Pid).ToList(),
            Coverage = coverage,
            Blindspots = blindspots,
            Duration = Stopwatch.GetElapsedTime(started),
        };
    }

    private static List<IProcessSource> BuildSources(ScanOptions options)
    {
        var sources = new List<IProcessSource>
        {
            new ToolhelpProcessSource(),
            new NtProcessSource(),
            new PsapiProcessSource(),
        };

        if (options.ProbePidSpace)
        {
            sources.Add(new BruteForceProcessSource());
        }

        return sources;
    }

    /// <summary>
    /// Folds the per-source lists into one record per PID, preserving which sources
    /// saw it. Only successful sources contribute — a failed source must not make
    /// every process look absent from it.
    /// </summary>
    private static Dictionary<uint, ProcessFact> Merge(
        IReadOnlyList<ProcessSourceResult> results, CancellationToken cancellationToken)
    {
        var merged = new Dictionary<uint, ProcessFact>();
        var seenBy = new Dictionary<uint, List<ProcessSourceKind>>();

        foreach (var result in results.Where(r => r.Succeeded))
        {
            foreach (var raw in result.Processes)
            {
                cancellationToken.ThrowIfCancellationRequested();

                if (!seenBy.TryGetValue(raw.Pid, out var sources))
                {
                    seenBy[raw.Pid] = sources = [];
                }

                sources.Add(result.Kind);

                if (merged.TryGetValue(raw.Pid, out var existing))
                {
                    // Later sources fill gaps but never overwrite an existing value:
                    // the first source to report a field is as authoritative as any.
                    merged[raw.Pid] = existing with
                    {
                        ParentPid = existing.ParentPid ?? raw.ParentPid,
                        Name = existing.Name ?? raw.Name,
                        SessionId = existing.SessionId ?? raw.SessionId,
                        ThreadCount = existing.ThreadCount ?? raw.ThreadCount,
                        CreatedUtc = existing.CreatedUtc ?? raw.CreatedUtc,
                        VerifiedAlive = existing.VerifiedAlive ?? raw.VerifiedAlive,
                    };
                }
                else
                {
                    merged[raw.Pid] = new ProcessFact
                    {
                        Pid = raw.Pid,
                        ParentPid = raw.ParentPid,
                        Name = raw.Name,
                        SessionId = raw.SessionId,
                        ThreadCount = raw.ThreadCount,
                        CreatedUtc = raw.CreatedUtc,
                        VerifiedAlive = raw.VerifiedAlive,
                    };
                }
            }
        }

        foreach (var (pid, sources) in seenBy)
        {
            merged[pid] = merged[pid] with { SeenBy = sources.Distinct().ToList() };
        }

        return merged;
    }

    private static void Enrich(
        Dictionary<uint, ProcessFact> merged, ScanOptions options, CancellationToken cancellationToken)
    {
        var connections = ConnectionTables.ReadAll(cancellationToken);
        var byPid = connections.Succeeded
            ? connections.Connections.GroupBy(c => c.OwningPid).ToDictionary(g => g.Key, g => (IReadOnlyList<Connection>)g.ToList())
            : [];

        var windows = WindowInventory.ReadAll();

        // Signature verification and hashing are per-image, not per-process: dozens of
        // svchost instances share one binary, and verifying it once instead of forty
        // times is the difference between a fast scan and a slow one.
        var signatures = new ConcurrentDictionary<string, SignatureInfo>(StringComparer.OrdinalIgnoreCase);
        var hashes = new ConcurrentDictionary<string, string?>(StringComparer.OrdinalIgnoreCase);

        foreach (var pid in merged.Keys.ToList())
        {
            cancellationToken.ThrowIfCancellationRequested();

            var detail = ProcessInspector.Inspect(pid);

            merged[pid] = merged[pid] with
            {
                ImagePath = detail.ImagePath,
                SessionId = merged[pid].SessionId ?? detail.SessionId,
                IsElevated = detail.IsElevated,
                Integrity = detail.Integrity,
                HasUiAccess = detail.HasUiAccess,
                Inaccessible = detail.Inaccessible,
                Connections = byPid.GetValueOrDefault(pid, []),
                Windows = windows.GetValueOrDefault(pid),
            };
        }

        var distinctImages = merged.Values
            .Select(p => p.ImagePath)
            .Where(p => !string.IsNullOrEmpty(p))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        Parallel.ForEach(
            distinctImages,
            new ParallelOptions { CancellationToken = cancellationToken },
            path =>
            {
                if (options.VerifySignatures)
                {
                    signatures[path!] = AuthenticodeVerifier.Verify(path!);
                }

                if (options.ComputeHashes)
                {
                    hashes[path!] = TryHash(path!);
                }
            });

        foreach (var pid in merged.Keys.ToList())
        {
            var fact = merged[pid];
            if (string.IsNullOrEmpty(fact.ImagePath))
            {
                continue;
            }

            merged[pid] = fact with
            {
                Signature = signatures.GetValueOrDefault(fact.ImagePath),
                Sha256 = hashes.GetValueOrDefault(fact.ImagePath),
            };
        }
    }

    private static string? TryHash(string path)
    {
        try
        {
            using var stream = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            return Convert.ToHexString(SHA256.HashData(stream));
        }
        catch
        {
            // Locked, denied, or gone between enumeration and hashing. Absent hash is
            // reported as absent rather than substituted with anything.
            return null;
        }
    }

    private static bool IsCurrentProcessElevated()
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
}
