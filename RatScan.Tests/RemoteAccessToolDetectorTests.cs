using RatScan.Engine.Collectors;
using RatScan.Engine.Detection;
using RatScan.Engine.Model;
using RatScan.Rules;
using Xunit.Abstractions;

namespace RatScan.Tests;

public sealed class CatalogueTests(ITestOutputHelper output)
{
    [Fact]
    public void Catalogue_loads_and_is_internally_consistent()
    {
        var tools = KnownToolCatalogue.Tools;

        output.WriteLine($"tools={tools.Count}");
        foreach (var group in tools.GroupBy(t => t.ParsedCategory).OrderByDescending(g => g.Count()))
        {
            output.WriteLine($"  {group.Key,-16} {group.Count()}");
        }

        Assert.NotEmpty(tools);

        // A tool with no identifiers can never match, so it is dead weight that makes
        // the catalogue look bigger than its real coverage.
        Assert.All(tools, t => Assert.True(
            t.Processes.Count > 0 || t.Services.Count > 0 || t.Drivers.Count > 0,
            $"{t.Id} has no matchable identifier"));

        Assert.All(tools, t => Assert.False(string.IsNullOrWhiteSpace(t.Name)));
        Assert.All(tools, t => Assert.NotEqual(ToolCategory.Unknown, t.ParsedCategory));

        // Duplicate ids would silently produce duplicate findings.
        var duplicates = tools.GroupBy(t => t.Id).Where(g => g.Count() > 1).Select(g => g.Key).ToList();
        Assert.Empty(duplicates);

        // Process names are matched case-insensitively against enumeration output, so
        // they must be bare file names rather than paths.
        Assert.All(tools, t => Assert.All(t.Processes, p =>
            Assert.DoesNotContain('\\', p)));
    }
}

public sealed class RemoteAccessToolDetectorTests(ITestOutputHelper output)
{
    private static DetectionContext ContextWith(params ProcessFact[] processes) => new()
    {
        Processes = new ProcessCollectionResult
        {
            Processes = processes,
            Coverage =
            [
                new SourceCoverage { Source = "a", Succeeded = true },
                new SourceCoverage { Source = "b", Succeeded = true },
            ],
        },
    };

    [Fact]
    public void Identifies_a_vnc_server_by_name_and_port()
    {
        var fact = new ProcessFact
        {
            Pid = 6124,
            Name = "tvnserver.exe",
            ImagePath = @"C:\Program Files\TightVNC\tvnserver.exe",
            Connections =
            [
                new RatScan.Native.Network.Connection
                {
                    Protocol = RatScan.Native.Network.TransportProtocol.Tcp,
                    OwningPid = 6124,
                    LocalAddress = System.Net.IPAddress.Any,
                    LocalPort = 5900,
                    State = RatScan.Native.Network.TcpConnectionState.Listen,
                },
            ],
        };

        var finding = Assert.Single(new RemoteAccessToolDetector().Detect(ContextWith(fact)));

        output.WriteLine($"{finding.Severity}/{finding.Confidence}: {finding.Title}");
        output.WriteLine(finding.Explanation);

        Assert.Equal("remote-tool.tightvnc", finding.RuleId);
        Assert.Equal(FindingCategory.RemoteAccessSoftware, finding.Category);

        // The explanation must say what someone can do to the user, in plain words.
        Assert.Contains("see your screen", finding.Explanation, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("keyboard and mouse", finding.Explanation, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("5900", finding.Explanation);
    }

    /// <summary>
    /// A binary wearing a known product's name that fails signature verification is
    /// not that product.
    /// </summary>
    [Fact]
    public void Flags_a_binary_using_a_known_name_that_is_unsigned()
    {
        var fact = new ProcessFact
        {
            Pid = 1337,
            Name = "anydesk.exe",
            ImagePath = @"C:\Users\x\Downloads\anydesk.exe",
            Signature = new RatScan.Native.Signing.SignatureInfo
            {
                FilePath = @"C:\Users\x\Downloads\anydesk.exe",
                Status = RatScan.Native.Signing.SignatureStatus.Unsigned,
            },
        };

        var finding = Assert.Single(new RemoteAccessToolDetector().Detect(ContextWith(fact)));

        output.WriteLine($"{finding.Severity}/{finding.Confidence}: {finding.Title}");

        Assert.Equal("remote-tool.unsigned-impostor", finding.RuleId);
        Assert.Equal(Severity.Critical, finding.Severity);
    }

    /// <summary>
    /// Regression for a real false positive. The catalogue listed TightVNC's publisher
    /// as "GlavSoft LLC"; the installed copy is signed "OOO GlavSoft". A validly signed,
    /// entirely legitimate product was accused of impersonation at Critical severity.
    /// <para>
    /// An unrecognised signer means our data may be stale — it must lower confidence
    /// and be surfaced as a caveat, never escalate severity.
    /// </para>
    /// </summary>
    [Fact]
    public void Validly_signed_tool_with_an_unrecognised_signer_is_not_accused()
    {
        var fact = new ProcessFact
        {
            Pid = 6124,
            Name = "tvnserver.exe",
            ImagePath = @"C:\Program Files\TightVNC\tvnserver.exe",
            Signature = new RatScan.Native.Signing.SignatureInfo
            {
                FilePath = @"C:\Program Files\TightVNC\tvnserver.exe",
                Status = RatScan.Native.Signing.SignatureStatus.Valid,
                SignerName = "Some Publisher We Have Not Catalogued",
            },
        };

        var finding = Assert.Single(new RemoteAccessToolDetector().Detect(ContextWith(fact)));

        output.WriteLine($"{finding.Severity}/{finding.Confidence}: {finding.Title}");
        output.WriteLine(finding.Explanation);

        Assert.NotEqual("remote-tool.unsigned-impostor", finding.RuleId);
        Assert.NotEqual(Severity.Critical, finding.Severity);
        Assert.Equal(Confidence.Possible, finding.Confidence);

        // The discrepancy is still disclosed, framed as a limit of our own data.
        Assert.Contains("catalogue is out of date", finding.Explanation, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Confidence_rises_with_the_number_of_agreeing_signals()
    {
        var nameOnly = new ProcessFact { Pid = 1, Name = "rustdesk.exe" };

        var nameAndPort = new ProcessFact
        {
            Pid = 2,
            Name = "rustdesk.exe",
            Connections =
            [
                new RatScan.Native.Network.Connection
                {
                    Protocol = RatScan.Native.Network.TransportProtocol.Tcp,
                    OwningPid = 2,
                    LocalAddress = System.Net.IPAddress.Any,
                    LocalPort = 21116,
                    State = RatScan.Native.Network.TcpConnectionState.Listen,
                },
            ],
        };

        var weak = Assert.Single(new RemoteAccessToolDetector().Detect(ContextWith(nameOnly)));
        var stronger = Assert.Single(new RemoteAccessToolDetector().Detect(ContextWith(nameAndPort)));

        output.WriteLine($"name only      -> {weak.Confidence}");
        output.WriteLine($"name + port    -> {stronger.Confidence}");

        // A rename is trivial, so a lone name hit must never read as certain.
        Assert.Equal(Confidence.Possible, weak.Confidence);
        Assert.True(stronger.Confidence > weak.Confidence);
    }

    [Fact]
    public void Ignores_processes_that_match_nothing()
    {
        var fact = new ProcessFact { Pid = 500, Name = "notepad.exe" };
        Assert.Empty(new RemoteAccessToolDetector().Detect(ContextWith(fact)));
    }
}

public sealed class RemoteAccessOnThisMachineTests(ITestOutputHelper output)
{
    [Fact]
    public void Reports_what_is_actually_installed_here()
    {
        var processes = new ProcessCollector().Collect(ScanOptions.Full);
        var findings = new RemoteAccessToolDetector()
            .Detect(new DetectionContext { Processes = processes })
            .ToList();

        output.WriteLine($"remote-access findings: {findings.Count}");
        foreach (var f in findings.OrderByDescending(f => f.Severity))
        {
            output.WriteLine("");
            output.WriteLine($"[{f.Severity}/{f.Confidence}] {f.Title}");
            output.WriteLine($"  {f.Explanation}");
        }

        // No assertion on count: a machine with none is a valid result. This test
        // exists to surface what the catalogue actually recognises here.
        Assert.All(findings, f => Assert.False(string.IsNullOrWhiteSpace(f.Explanation)));
    }
}
