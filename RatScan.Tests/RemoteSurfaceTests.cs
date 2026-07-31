using RatScan.Engine.Collectors;
using RatScan.Engine.Model;
using Xunit.Abstractions;

namespace RatScan.Tests;

public sealed class RemoteSurfaceTests(ITestOutputHelper output)
{
    [Fact]
    public void Audits_every_builtin_surface_on_this_machine()
    {
        var result = new RemoteSurfaceCollector().Collect();

        Assert.NotEmpty(result.Surfaces);

        output.WriteLine($"{"surface",-34} {"state",-11} detail");
        output.WriteLine(new string('-', 100));
        foreach (var s in result.Surfaces)
        {
            var ports = s.ListeningPorts.Count > 0 ? $" [{string.Join(",", s.ListeningPorts)}]" : "";
            output.WriteLine($"{s.Name,-34} {s.State,-11} {s.Detail}{ports}");
        }

        output.WriteLine("");
        output.WriteLine($"exposed surfaces: {result.Exposed.Count()}");
        foreach (var s in result.Exposed)
        {
            output.WriteLine($"  EXPOSED: {s.Name} — {s.Capability}");
        }

        output.WriteLine("");
        output.WriteLine($"recent remote logons: {result.RecentRemoteLogons.Count}");
        foreach (var e in result.RecentRemoteLogons.Take(5))
        {
            output.WriteLine($"  {e.TimeUtc:u} {e.Account} from {e.SourceAddress}");
        }

        output.WriteLine("");
        foreach (var b in result.Blindspots)
        {
            output.WriteLine($"  blind spot: {b.Area} — {b.Reason}");
        }

        // Every surface must resolve to a definite reading or be explicitly Unknown.
        // Silently defaulting an unreadable surface to Disabled is the failure mode.
        Assert.All(result.Surfaces, s => Assert.False(string.IsNullOrWhiteSpace(s.Capability)));
        Assert.All(result.Surfaces, s => Assert.NotEmpty(s.EvidenceChain));

        Assert.Contains(result.Surfaces, s => s.Id == "windows.rdp");
        Assert.Contains(result.Surfaces, s => s.Id == "windows.rdp.shadow");
        Assert.Contains(result.Surfaces, s => s.Id == "windows.winrm");
    }

    /// <summary>
    /// SMB is running on essentially every Windows desktop, so it doubles as proof the
    /// service and port correlation actually works rather than returning defaults.
    /// </summary>
    [Fact]
    public void Smb_surface_reflects_real_listener_state()
    {
        var result = new RemoteSurfaceCollector().Collect();
        var smb = result.Surfaces.Single(s => s.Id == "windows.smb");

        output.WriteLine($"SMB: {smb.State} — {smb.Detail}");
        foreach (var e in smb.EvidenceChain)
        {
            output.WriteLine($"  {e.Label} = {e.Value} ({e.Source})");
        }

        Assert.NotEqual(SurfaceState.Unknown, smb.State);

        if (smb.ListeningPorts.Count > 0)
        {
            Assert.Equal(SurfaceState.Enabled, smb.State);
            Assert.True(smb.IsExposed);
        }
    }

    /// <summary>
    /// Regression: the surface state must come from real configuration, never from the
    /// size of the evidence list. Adding a "we checked and found nothing" evidence
    /// entry once flipped portproxy to Enabled on a machine with no forwarding rules.
    /// </summary>
    [Fact]
    public void Portproxy_with_no_rules_reads_as_disabled_despite_carrying_evidence()
    {
        var result = new RemoteSurfaceCollector().Collect();
        var portproxy = result.Surfaces.Single(s => s.Id == "windows.portproxy");

        output.WriteLine($"portproxy: {portproxy.State} — {portproxy.Detail}");
        foreach (var e in portproxy.EvidenceChain)
        {
            output.WriteLine($"  {e.Label} = {e.Value}");
        }

        Assert.NotEmpty(portproxy.EvidenceChain);

        if (portproxy.Detail is not null && portproxy.Detail.Contains("No forwarding rules"))
        {
            Assert.Equal(SurfaceState.Disabled, portproxy.State);
        }
    }

    [Fact]
    public void Shadow_policy_absence_is_not_reported_as_enabled()
    {
        var result = new RemoteSurfaceCollector().Collect();
        var shadow = result.Surfaces.Single(s => s.Id == "windows.rdp.shadow");

        output.WriteLine($"shadow: {shadow.State} — {shadow.Detail}");

        // The dangerous misreading would be treating a missing policy value as
        // "silent shadowing permitted". Absent means Windows' consent-prompting
        // default, which is not an exposed surface.
        Assert.NotEqual(SurfaceState.Enabled, shadow.State);
    }
}
