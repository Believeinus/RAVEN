using RatScan.Engine;
using RatScan.Engine.Collectors;
using RatScan.Engine.Detection;
using RatScan.Engine.Model;
using RatScan.Native.Network;
using RatScan.Native.Processes;
using RatScan.Native.Signing;
using RatScan.Native.Windowing;
using Xunit.Abstractions;

namespace RatScan.Tests;

public sealed class SurveillanceDetectorTests(ITestOutputHelper output)
{
    private static LoadedModule Dll(string name, string? path = null) =>
        new() { Name = name, Path = path ?? $@"C:\Program Files\Thing\{name}" };

    private static DetectionContext ContextWith(params ProcessFact[] processes) => new()
    {
        Processes = new ProcessCollectionResult
        {
            Processes = processes,
            Coverage = [new SourceCoverage { Source = "a", Succeeded = true }],
        },
    };

    private static Connection Outbound(uint pid) => new()
    {
        Protocol = TransportProtocol.Tcp,
        OwningPid = pid,
        LocalAddress = System.Net.IPAddress.Loopback,
        LocalPort = 50000,
        RemoteAddress = System.Net.IPAddress.Parse("203.0.113.10"),
        RemotePort = 443,
        State = TcpConnectionState.Established,
    };

    /// <summary>
    /// The full surveillance shape: can read the screen, shows no window, is talking to
    /// the internet, and nobody vouches for it.
    /// </summary>
    [Fact]
    public void Fires_when_capture_capability_coincides_with_hiding_and_network_activity()
    {
        var suspect = new ProcessFact
        {
            Pid = 4321,
            Name = "svhost32.exe",
            ModulesReadable = true,
            Modules = [Dll("dxgi.dll"), Dll("d3d11.dll")],
            Windows = new WindowPresence { Pid = 4321, TotalWindows = 1, VisibleWindows = 0 },
            Connections = [Outbound(4321)],
            Signature = new SignatureInfo { FilePath = "x", Status = SignatureStatus.Unsigned },
        };

        var finding = Assert.Single(
            new SurveillanceDetector().Detect(ContextWith(suspect))
                .Where(f => f.RuleId == "surveillance.screen-capture-correlation"));

        output.WriteLine($"{finding.Severity}/{finding.Confidence}: {finding.Title}");
        output.WriteLine(finding.Explanation);

        Assert.Equal(Severity.High, finding.Severity);
        Assert.Equal("T1113", finding.MitreTechnique);

        // Must present itself as a correlation, not as proof.
        Assert.Contains("correlation, not proof", finding.Explanation, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Chrome can capture the screen and always could. Flagging every browser would
    /// bury every real finding, which is the practical way this detector fails.
    /// </summary>
    [Fact]
    public void Stays_silent_for_a_browser_holding_the_same_modules()
    {
        var chrome = new ProcessFact
        {
            Pid = 1000,
            Name = "chrome.exe",
            ModulesReadable = true,
            Modules = [Dll("dxgi.dll"), Dll("d3d11.dll")],
            Windows = new WindowPresence { Pid = 1000, TotalWindows = 3, VisibleWindows = 0 },
            Connections = [Outbound(1000)],
            Signature = new SignatureInfo { FilePath = "x", Status = SignatureStatus.Unsigned },
        };

        Assert.Empty(new SurveillanceDetector().Detect(ContextWith(chrome))
            .Where(f => f.Category == FindingCategory.ScreenOrInputSurveillance));
    }

    /// <summary>
    /// Capability on its own means nothing — a signed, visible, offline program that
    /// can capture the screen is just a program.
    /// </summary>
    [Fact]
    public void Stays_silent_when_only_one_factor_is_present()
    {
        var benign = new ProcessFact
        {
            Pid = 2000,
            Name = "screenshot-tool.exe",
            ModulesReadable = true,
            Modules = [Dll("dxgi.dll")],
            Windows = new WindowPresence { Pid = 2000, TotalWindows = 2, VisibleWindows = 2 },
            Signature = new SignatureInfo
            {
                FilePath = "x",
                Status = SignatureStatus.Valid,
                SignerName = "Reputable Software Ltd",
            },
        };

        Assert.Empty(new SurveillanceDetector().Detect(ContextWith(benign))
            .Where(f => f.Category == FindingCategory.ScreenOrInputSurveillance));
    }

    /// <summary>
    /// The keylogger footprint: one DLL from outside the Windows directory resident
    /// across many unrelated processes.
    /// </summary>
    [Fact]
    public void Detects_a_dll_injected_across_many_processes()
    {
        var hook = Dll("hooklib.dll", @"C:\Users\x\AppData\Roaming\hooklib.dll");

        var processes = Enumerable.Range(1, 30)
            .Select(i => new ProcessFact
            {
                Pid = (uint)(1000 + i),
                Name = $"app{i}.exe",
                ModulesReadable = true,
                Modules = [Dll("kernel32.dll", @"C:\Windows\System32\kernel32.dll"), hook],
            })
            .ToArray();

        var finding = Assert.Single(
            new SurveillanceDetector().Detect(ContextWith(processes))
                .Where(f => f.RuleId == "surveillance.broad-dll-injection"));

        output.WriteLine($"{finding.Severity}: {finding.Title}");

        Assert.Contains("hooklib.dll", finding.Title);
        Assert.Equal("T1056.004", finding.MitreTechnique);

        // Legitimate causes must be acknowledged, or the user cannot judge it.
        Assert.Contains("accessibility", finding.Explanation, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// System DLLs are in every process by design and must never trigger the breadth
    /// rule, or the finding list becomes pure noise.
    /// </summary>
    [Fact]
    public void System_dlls_do_not_trigger_the_injection_rule()
    {
        var processes = Enumerable.Range(1, 30)
            .Select(i => new ProcessFact
            {
                Pid = (uint)(2000 + i),
                Name = $"app{i}.exe",
                ModulesReadable = true,
                Modules =
                [
                    Dll("kernel32.dll", @"C:\Windows\System32\kernel32.dll"),
                    Dll("user32.dll", @"C:\Windows\System32\user32.dll"),
                ],
            })
            .ToArray();

        Assert.Empty(new SurveillanceDetector().Detect(ContextWith(processes))
            .Where(f => f.RuleId == "surveillance.broad-dll-injection"));
    }

    [Fact]
    public void Reports_scan_integrity_when_no_module_lists_were_readable()
    {
        var blind = new ProcessFact { Pid = 1, Name = "x.exe", ModulesReadable = false };

        var finding = Assert.Single(new SurveillanceDetector().Detect(ContextWith(blind)));

        // Silence would imply the checks ran and found nothing.
        Assert.Equal("surveillance.unavailable", finding.RuleId);
        Assert.Equal(FindingCategory.ScanIntegrity, finding.Category);
    }
}

public sealed class SurveillanceOnThisMachineTests(ITestOutputHelper output)
{
    [Fact]
    public void Reports_surveillance_correlations_for_this_machine()
    {
        var result = new ScanOrchestrator().Run(ScanOptions.Full);

        var surveillance = result.Findings
            .Where(f => f.Category == FindingCategory.ScreenOrInputSurveillance)
            .ToList();

        output.WriteLine($"surveillance findings: {surveillance.Count}");
        foreach (var f in surveillance)
        {
            output.WriteLine("");
            output.WriteLine($"[{f.Severity}/{f.Confidence}] {f.Title}");
            foreach (var e in f.EvidenceChain)
            {
                output.WriteLine($"    {e.Label}: {e.Value}");
            }
        }

        output.WriteLine("");
        output.WriteLine($"VERDICT: {result.Headline}");

        // No count assertion — this surfaces what the machine actually looks like.
        Assert.All(surveillance, f => Assert.NotEmpty(f.EvidenceChain));
    }
}
