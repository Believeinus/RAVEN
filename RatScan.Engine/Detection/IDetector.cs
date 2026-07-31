using RatScan.Engine.Model;

namespace RatScan.Engine.Detection;

/// <summary>
/// Everything the detectors are allowed to reason over.
/// <para>
/// Deliberately a plain data bundle: detectors must not touch the operating system.
/// That is what lets every rule be exercised against synthetic facts, including the
/// compromise scenarios nobody can reproduce on demand.
/// </para>
/// </summary>
public sealed record DetectionContext
{
    public required ProcessCollectionResult Processes { get; init; }
    public RemoteSurfaceResult? Surfaces { get; init; }
    public PersistenceResult? Persistence { get; init; }
    public DriverCensusResult? Drivers { get; init; }

    /// <summary>Whether the scan itself ran with Administrator rights.</summary>
    public bool IsElevated { get; init; }
}

/// <summary>Turns facts into findings. Never reads the machine directly.</summary>
public interface IDetector
{
    string Name { get; }

    IEnumerable<Finding> Detect(DetectionContext context, CancellationToken cancellationToken = default);
}
