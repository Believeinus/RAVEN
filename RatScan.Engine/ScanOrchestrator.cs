using System.Diagnostics;
using RatScan.Engine.Allowlist;
using RatScan.Engine.Collectors;
using RatScan.Engine.Detection;
using RatScan.Engine.Model;
using RatScan.Engine.Scoring;

namespace RatScan.Engine;

public interface IScanOrchestrator
{
    ScanResult Run(ScanOptions? options = null, CancellationToken cancellationToken = default);
}

/// <summary>
/// Runs a complete scan: collect facts, apply detectors, score the result.
/// <para>
/// Collector failures are deliberately non-fatal. A scan that aborts because one
/// surface was unreadable tells the user nothing, whereas a scan that completes and
/// names what it could not reach tells them exactly where they stand.
/// </para>
/// </summary>
public sealed class ScanOrchestrator : IScanOrchestrator
{
    private const string AllowlistBlindspot = "Allowlist";
    private const string AllowlistEvidenceSource = AllowlistFilter.EvidenceSource;

    private readonly IProcessCollector _processes;
    private readonly IRemoteSurfaceCollector _surfaces;
    private readonly IPersistenceCollector _persistence;
    private readonly IDriverCollector _drivers;
    private readonly IIntegrityAssessor _integrity;
    private readonly IScoringEngine _scoring;
    private readonly IReadOnlyList<IDetector> _detectors;
    private readonly IAllowlistStore? _allowlist;
    private readonly AllowlistFilter _allowlistFilter;

    public ScanOrchestrator(
        IProcessCollector? processes = null,
        IRemoteSurfaceCollector? surfaces = null,
        IPersistenceCollector? persistence = null,
        IDriverCollector? drivers = null,
        IIntegrityAssessor? integrity = null,
        IScoringEngine? scoring = null,
        IReadOnlyList<IDetector>? detectors = null,
        IAllowlistStore? allowlist = null,
        IFileHasher? hasher = null)
    {
        // No store means nothing is muted. Detection has to work with no local state
        // at all, and the direction to fail in is "show everything".
        _allowlist = allowlist;
        _allowlistFilter = new AllowlistFilter(hasher);

        _processes = processes ?? new ProcessCollector();
        _surfaces = surfaces ?? new RemoteSurfaceCollector();
        _persistence = persistence ?? new PersistenceCollector();
        _drivers = drivers ?? new DriverCollector();
        _integrity = integrity ?? new IntegrityAssessor();
        _scoring = scoring ?? new ScoringEngine();
        _detectors = detectors ??
        [
            new ConcealmentDetector(),
            new RemoteAccessToolDetector(),
            new SurveillanceDetector(),
            new PersistenceDetector(),
        ];
    }

    public ScanResult Run(ScanOptions? options = null, CancellationToken cancellationToken = default)
    {
        options ??= ScanOptions.Full;
        var startedUtc = DateTime.UtcNow;
        var clock = Stopwatch.GetTimestamp();

        var blindspots = new List<Blindspot>();
        var examined = new List<string>();

        var integrity = _integrity.Assess();

        var processes = Attempt(
            "Running processes", () => _processes.Collect(options, cancellationToken),
            examined, blindspots)
            ?? new ProcessCollectionResult();

        blindspots.AddRange(processes.Blindspots);

        var surfaces = Attempt(
            "Windows remote-access surfaces", () => _surfaces.Collect(cancellationToken),
            examined, blindspots);

        if (surfaces is not null)
        {
            blindspots.AddRange(surfaces.Blindspots);
        }

        var persistence = Attempt(
            "Auto-start persistence", () => _persistence.Collect(options.VerifySignatures, cancellationToken),
            examined, blindspots);

        if (persistence is not null)
        {
            blindspots.AddRange(persistence.Blindspots);
        }

        var drivers = Attempt(
            "Kernel drivers", () => _drivers.Collect(options.VerifySignatures, cancellationToken),
            examined, blindspots);

        if (drivers is not null)
        {
            blindspots.AddRange(drivers.Blindspots);
        }

        var context = new DetectionContext
        {
            Processes = processes,
            Surfaces = surfaces,
            Persistence = persistence,
            Drivers = drivers,
            IsElevated = integrity.Elevated,
        };

        var findings = new List<Finding>();

        foreach (var detector in _detectors)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                findings.AddRange(detector.Detect(context, cancellationToken));
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                // A detector that throws must not silently vanish — its absence is a
                // gap in coverage and has to be reported as one.
                blindspots.Add(new Blindspot
                {
                    Area = $"Detector: {detector.Name}",
                    Reason = $"Failed with {ex.GetType().Name}: {ex.Message}",
                });
            }
        }

        findings.AddRange(SurfaceFindings(surfaces));

        // Muting happens after detection and before scoring, deliberately. Detectors
        // must not know the allowlist exists — a detector that skips work because
        // something is muted would stop noticing when the muted thing changed.
        var allowlist = ApplyAllowlist(findings, blindspots);

        return _scoring.Score(
            allowlist.Active, blindspots, examined, integrity, startedUtc,
            Stopwatch.GetElapsedTime(clock), allowlist);
    }

    /// <summary>
    /// Re-applies the allowlist to a scan that has already run, so muting something
    /// takes effect immediately instead of after another few seconds of scanning.
    /// <para>
    /// Re-scoring rather than editing the previous result: the verdict, the headline and
    /// the muting counterfactual all have to be recomputed together, and a result whose
    /// findings no longer match its own headline is worse than a slow refresh.
    /// </para>
    /// </summary>
    public ScanResult ReapplyAllowlist(ScanResult previous)
    {
        ArgumentNullException.ThrowIfNull(previous);

        // Findings come back from both lists — what is muted is a question for the
        // allowlist to answer again from scratch, not a state carried forward.
        var findings = previous.Findings
            .Concat(previous.Suppressed.Select(s => s.Finding))
            .Select(Unannotated)
            .ToList();

        var blindspots = previous.Blindspots.Where(b => b.Area != AllowlistBlindspot).ToList();
        var allowlist = ApplyAllowlist(findings, blindspots);

        return _scoring.Score(
            allowlist.Active, blindspots, previous.SurfacesExamined, previous.Integrity,
            previous.StartedUtc, previous.Duration, allowlist);
    }

    /// <summary>
    /// Strips the note a previous pass may have attached about a stale allowlist entry,
    /// so re-applying cannot stack the same explanation twice.
    /// </summary>
    private static Finding Unannotated(Finding finding) =>
        finding.EvidenceChain.Any(e => e.Source == AllowlistEvidenceSource)
            ? finding with
            {
                EvidenceChain = finding.EvidenceChain
                    .Where(e => e.Source != AllowlistEvidenceSource)
                    .ToList(),
            }
            : finding;

    /// <summary>
    /// Applies the user's allowlist. A store that cannot be read mutes nothing and
    /// records a blind spot: the user believes some findings are suppressed, and a scan
    /// that silently stopped honouring that is a different scan from the one they think
    /// they are reading.
    /// </summary>
    private AllowlistApplication ApplyAllowlist(
        IReadOnlyList<Finding> findings, List<Blindspot> blindspots)
    {
        if (_allowlist is null)
        {
            return new AllowlistApplication { Active = findings };
        }

        try
        {
            return _allowlistFilter.Apply(findings, _allowlist.All());
        }
        catch (Exception ex)
        {
            blindspots.Add(new Blindspot
            {
                Area = AllowlistBlindspot,
                Reason = $"Your allowlist could not be read ({ex.GetType().Name}: {ex.Message}), so "
                         + "nothing was muted. Findings you previously silenced are shown again.",
                Remedy = "Check that %LOCALAPPDATA%\\RatScan is readable.",
            });

            return new AllowlistApplication { Active = findings };
        }
    }

    /// <summary>
    /// Turns enabled built-in remote surfaces into findings. Only exposed ones — a
    /// disabled feature is configuration, not a finding.
    /// </summary>
    private static IEnumerable<Finding> SurfaceFindings(RemoteSurfaceResult? surfaces)
    {
        if (surfaces is null)
        {
            yield break;
        }

        foreach (var surface in surfaces.Surfaces.Where(s => s.State == SurfaceState.Enabled))
        {
            yield return new Finding
            {
                RuleId = $"surface.{surface.Id}",
                Title = $"{surface.Name} is enabled",
                Severity = surface.IsExposed ? Severity.Medium : Severity.Low,
                Confidence = Confidence.Confirmed,
                Category = FindingCategory.WindowsRemoteSurface,
                Subject = surface.Name,

                // A Windows feature is not a file, so this entry cannot be pinned to
                // bytes. The allowlist says so on the entry rather than implying a
                // stronger guarantee than it has.
                IdentityKey = $"windows-surface:{surface.Id}",
                Explanation = $"{surface.Capability}. Observed state: {surface.Detail}",
                Recommendation = surface.DisableCommand is not null
                    ? $"If you do not use this, it can be turned off:\n{surface.DisableCommand}"
                    : "Confirm this is something you rely on.",
                EvidenceChain = surface.EvidenceChain,
                MitreTechnique = "T1021",
                Actions = surface.DisableCommand is null
                    ? []
                    :
                    [
                        new Remediation.RemediationAction
                        {
                            Kind = Remediation.RemediationKind.DisableWindowsSurface,
                            Title = $"Turn off {surface.Name}",
                            Description = $"Disables this Windows feature. {surface.Capability} — "
                                          + "that capability goes away.",
                            PreviewCommand = surface.DisableCommand,
                            Risk = Remediation.RemediationRisk.Consequential,
                            Caveat = "If you or someone who supports this machine relies on this "
                                     + "feature, turning it off will break that.",
                            RequiresElevation = true,
                        },
                    ],
            };
        }
    }

    private static T? Attempt<T>(
        string surfaceName, Func<T> collect, List<string> examined, List<Blindspot> blindspots)
        where T : class
    {
        try
        {
            var result = collect();
            examined.Add(surfaceName);
            return result;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            blindspots.Add(new Blindspot
            {
                Area = surfaceName,
                Reason = $"Collection failed with {ex.GetType().Name}: {ex.Message}",
            });

            return null;
        }
    }
}
