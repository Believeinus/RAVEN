using System.Diagnostics;
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
    private readonly IProcessCollector _processes;
    private readonly IRemoteSurfaceCollector _surfaces;
    private readonly IPersistenceCollector _persistence;
    private readonly IDriverCollector _drivers;
    private readonly IIntegrityAssessor _integrity;
    private readonly IScoringEngine _scoring;
    private readonly IReadOnlyList<IDetector> _detectors;

    public ScanOrchestrator(
        IProcessCollector? processes = null,
        IRemoteSurfaceCollector? surfaces = null,
        IPersistenceCollector? persistence = null,
        IDriverCollector? drivers = null,
        IIntegrityAssessor? integrity = null,
        IScoringEngine? scoring = null,
        IReadOnlyList<IDetector>? detectors = null)
    {
        _processes = processes ?? new ProcessCollector();
        _surfaces = surfaces ?? new RemoteSurfaceCollector();
        _persistence = persistence ?? new PersistenceCollector();
        _drivers = drivers ?? new DriverCollector();
        _integrity = integrity ?? new IntegrityAssessor();
        _scoring = scoring ?? new ScoringEngine();
        _detectors = detectors ?? [new ConcealmentDetector(), new RemoteAccessToolDetector()];
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
            "Auto-start persistence", () => _persistence.Collect(cancellationToken),
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

        return _scoring.Score(
            findings, blindspots, examined, integrity, startedUtc, Stopwatch.GetElapsedTime(clock));
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
                Explanation = $"{surface.Capability}. Observed state: {surface.Detail}",
                Recommendation = surface.DisableCommand is not null
                    ? $"If you do not use this, it can be turned off:\n{surface.DisableCommand}"
                    : "Confirm this is something you rely on.",
                EvidenceChain = surface.EvidenceChain,
                MitreTechnique = "T1021",
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
