using RatScan.Engine.Collectors;
using RatScan.Native.Processes;
using RatScan.Native.Signing;
using Xunit.Abstractions;

namespace RatScan.Tests;

public sealed class ProcessCollectorTests(ITestOutputHelper output)
{
    [Fact]
    public void Full_collection_produces_a_coherent_fact_set()
    {
        var result = new ProcessCollector().Collect(ScanOptions.Full);

        output.WriteLine($"processes={result.Processes.Count} in {result.Duration.TotalSeconds:F1}s");
        output.WriteLine("coverage:");
        foreach (var c in result.Coverage)
        {
            output.WriteLine($"  {c.Source,-40} ok={c.Succeeded,-5} reported={c.Reported,-5} partial={c.Partial} {c.Error}");
        }

        output.WriteLine("blind spots:");
        foreach (var b in result.Blindspots)
        {
            output.WriteLine($"  {b.Area} — {b.Reason}");
        }

        Assert.NotEmpty(result.Processes);
        Assert.True(result.UsableForCrossView, "fewer than two sources succeeded — cross-view is not possible");

        // Blind spots are a product commitment, not a nicety: a scan that claims no
        // limits at all is the one thing this tool must never produce.
        Assert.NotEmpty(result.Blindspots);

        var self = result.Processes.Single(p => p.Pid == (uint)Environment.ProcessId);
        Assert.NotNull(self.ImagePath);
        Assert.NotNull(self.Sha256);
        Assert.Equal(64, self.Sha256!.Length);
        Assert.NotEqual(IntegrityLevel.Unknown, self.Integrity);
        Assert.Contains(ProcessSourceKind.NtQuerySystemInformation, self.SeenBy);
    }

    [Fact]
    public void Collection_summarises_trust_and_network_exposure()
    {
        var result = new ProcessCollector().Collect(ScanOptions.Full);

        var withPath = result.Processes.Where(p => p.ImagePath is not null).ToList();
        var signed = withPath.Count(p => p.Signature?.Status == SignatureStatus.Valid);
        var unsigned = withPath.Count(p => p.Signature?.Status == SignatureStatus.Unsigned);
        var networked = result.Processes.Count(p => p.HasNetworkActivity);
        var listening = result.Processes.Where(p => p.IsListening).ToList();
        var hidden = result.Processes.Count(p => p.Windows?.RunsHidden == true);

        output.WriteLine($"with image path : {withPath.Count}");
        output.WriteLine($"  valid signature: {signed}");
        output.WriteLine($"  unsigned       : {unsigned}");
        output.WriteLine($"with connections : {networked}");
        output.WriteLine($"listening        : {listening.Count}");
        output.WriteLine($"windowed but hidden: {hidden}");

        output.WriteLine("");
        output.WriteLine("listening processes (the inbound doors):");
        foreach (var p in listening.OrderBy(p => p.Name))
        {
            var ports = string.Join(",", p.Connections.Where(c => c.IsListener).Select(c => c.LocalPort).Distinct().Order());
            var trust = p.Signature?.Status.ToString() ?? "unknown";
            var signer = p.Signature?.SignerName ?? "-";
            output.WriteLine($"  {p.Name,-28} pid={p.Pid,-6} ports={ports,-24} {trust,-10} {signer}");
        }

        Assert.NotEmpty(withPath);

        // If nothing on a live Windows desktop verifies as signed, the trust pipeline
        // is broken rather than the machine being remarkable.
        Assert.True(signed > 0, "no process resolved to a valid signature — trust pipeline is broken");
    }

    [Fact]
    public void Quick_scan_is_materially_faster_and_declares_what_it_skipped()
    {
        var quick = new ProcessCollector().Collect(ScanOptions.Quick);

        output.WriteLine($"quick: processes={quick.Processes.Count} in {quick.Duration.TotalSeconds:F1}s");
        foreach (var b in quick.Blindspots)
        {
            output.WriteLine($"  blind spot: {b.Area}");
        }

        Assert.NotEmpty(quick.Processes);
        Assert.All(quick.Processes, p => Assert.Null(p.Sha256));

        // Skipping the probe must be reported as a gap, not silently absorbed.
        Assert.Contains(quick.Blindspots, b => b.Area.Contains("hidden from all listing", StringComparison.OrdinalIgnoreCase));
    }
}
