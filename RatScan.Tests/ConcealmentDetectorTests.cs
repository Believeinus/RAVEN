using RatScan.Engine.Collectors;
using RatScan.Engine.Detection;
using RatScan.Engine.Model;
using RatScan.Native.Processes;
using Xunit.Abstractions;

namespace RatScan.Tests;

/// <summary>
/// Synthetic facts throughout, on purpose. A rootkit cannot be installed on demand to
/// test against, and a detector that has only ever been observed staying silent has
/// not been shown to work at all — silence is also what a broken detector produces.
/// </summary>
public sealed class ConcealmentDetectorTests(ITestOutputHelper output)
{
    private static readonly SourceCoverage[] HealthyCoverage =
    [
        new() { Source = "CreateToolhelp32Snapshot", Succeeded = true, Reported = 400 },
        new() { Source = "NtQuerySystemInformation", Succeeded = true, Reported = 400 },
        new() { Source = "EnumProcesses", Succeeded = true, Reported = 400 },
        new() { Source = "OpenProcess probe", Succeeded = true, Reported = 400, Partial = true },
    ];

    private static DetectionContext ContextWith(params ProcessFact[] processes) => new()
    {
        Processes = new ProcessCollectionResult
        {
            Processes = processes,
            Coverage = HealthyCoverage,
        },
        IsElevated = true,
    };

    [Fact]
    public void Fires_critical_when_a_confirmed_live_process_is_absent_from_every_listing()
    {
        var hidden = new ProcessFact
        {
            Pid = 6666,
            VerifiedAlive = true,
            ConfirmedHidden = true,
            SeenBy = [ProcessSourceKind.BruteForceOpen],
            MissingFrom =
            [
                ProcessSourceKind.Toolhelp,
                ProcessSourceKind.NtQuerySystemInformation,
                ProcessSourceKind.Psapi,
            ],
        };

        var findings = new ConcealmentDetector().Detect(ContextWith(hidden)).ToList();

        var finding = Assert.Single(findings.Where(f => f.RuleId == "concealment.hidden-process"));
        output.WriteLine($"{finding.Severity}/{finding.Confidence}: {finding.Title}");
        foreach (var e in finding.EvidenceChain)
        {
            output.WriteLine($"  {e.Label}: {e.Value}");
        }

        Assert.Equal(Severity.Critical, finding.Severity);
        Assert.Equal(Confidence.Confirmed, finding.Confidence);
        Assert.Equal(FindingCategory.Concealment, finding.Category);
        Assert.Equal(6666u, finding.Pid);

        // The finding must carry enough evidence for the user to judge it themselves.
        Assert.True(finding.EvidenceChain.Count >= 4);
        Assert.NotNull(finding.Recommendation);
    }

    [Fact]
    public void Fires_when_a_process_is_visible_to_some_interfaces_but_not_others()
    {
        var selective = new ProcessFact
        {
            Pid = 4242,
            Name = "sneaky.exe",
            SeenBy = [ProcessSourceKind.NtQuerySystemInformation, ProcessSourceKind.BruteForceOpen],
            MissingFrom = [ProcessSourceKind.Toolhelp, ProcessSourceKind.Psapi],
        };

        var findings = new ConcealmentDetector().Detect(ContextWith(selective)).ToList();

        var finding = Assert.Single(findings.Where(f => f.RuleId == "concealment.selective-hiding"));
        output.WriteLine($"{finding.Severity}/{finding.Confidence}: {finding.Title}");

        Assert.Equal(Severity.Critical, finding.Severity);

        // Not Confirmed: a process exiting mid-scan produces the same shape.
        Assert.Equal(Confidence.Likely, finding.Confidence);
    }

    [Fact]
    public void Stays_silent_for_a_process_seen_by_everything()
    {
        var normal = new ProcessFact
        {
            Pid = 1234,
            Name = "explorer.exe",
            SeenBy =
            [
                ProcessSourceKind.Toolhelp,
                ProcessSourceKind.NtQuerySystemInformation,
                ProcessSourceKind.Psapi,
                ProcessSourceKind.BruteForceOpen,
            ],
            MissingFrom = [],
        };

        Assert.Empty(new ConcealmentDetector().Detect(ContextWith(normal)));
    }

    /// <summary>
    /// The regression that matters most. A probe-only PID that was NOT confirmed by the
    /// second pass is ordinary process churn, and must produce nothing — this is the
    /// exact shape that generated 327 phantom findings during phase 1.
    /// </summary>
    [Fact]
    public void Stays_silent_for_an_unconfirmed_probe_only_process()
    {
        var churn = new ProcessFact
        {
            Pid = 9999,
            VerifiedAlive = true,
            ConfirmedHidden = false,
            SeenBy = [ProcessSourceKind.BruteForceOpen],
            MissingFrom =
            [
                ProcessSourceKind.Toolhelp,
                ProcessSourceKind.NtQuerySystemInformation,
                ProcessSourceKind.Psapi,
            ],
        };

        Assert.Empty(new ConcealmentDetector().Detect(ContextWith(churn)));
    }

    /// <summary>
    /// An access-denied PID is unverifiable, not hidden. Reporting it would mean
    /// turning "I could not check" into "something is concealed".
    /// </summary>
    [Fact]
    public void Stays_silent_for_an_unverifiable_process()
    {
        var unverifiable = new ProcessFact
        {
            Pid = 8888,
            VerifiedAlive = null,
            ConfirmedHidden = false,
            SeenBy = [ProcessSourceKind.BruteForceOpen],
            MissingFrom = [ProcessSourceKind.Toolhelp],
        };

        Assert.Empty(new ConcealmentDetector().Detect(ContextWith(unverifiable)));
    }

    [Fact]
    public void Reports_scan_integrity_when_too_few_sources_succeeded()
    {
        var context = new DetectionContext
        {
            Processes = new ProcessCollectionResult
            {
                Processes = [],
                Coverage =
                [
                    new SourceCoverage { Source = "CreateToolhelp32Snapshot", Succeeded = true, Reported = 400 },
                    new SourceCoverage { Source = "NtQuerySystemInformation", Succeeded = false, Error = "denied" },
                ],
            },
        };

        var finding = Assert.Single(new ConcealmentDetector().Detect(context));

        // Silence would falsely imply "checked and clean".
        Assert.Equal("concealment.unavailable", finding.RuleId);
        Assert.Equal(FindingCategory.ScanIntegrity, finding.Category);
    }

    [Fact]
    public void Does_not_report_unregistered_drivers_when_addresses_were_withheld()
    {
        var context = new DetectionContext
        {
            Processes = new ProcessCollectionResult { Processes = [], Coverage = HealthyCoverage },
            Drivers = new DriverCensusResult
            {
                AddressesWithheld = true,
                Drivers = [new DriverEntry { Name = "straggler.sys", IsLoaded = true, IsRegistered = false }],
            },
        };

        // Unelevated, the loaded view is an artefact — it must not become a finding.
        Assert.Empty(new ConcealmentDetector().Detect(context));
    }

    [Fact]
    public void Reports_unregistered_drivers_when_the_census_is_trustworthy()
    {
        var context = new DetectionContext
        {
            Processes = new ProcessCollectionResult { Processes = [], Coverage = HealthyCoverage },
            Drivers = new DriverCensusResult
            {
                AddressesWithheld = false,
                Drivers =
                [
                    new DriverEntry { Name = "manual.sys", IsLoaded = true, IsRegistered = false },
                    new DriverEntry { Name = "normal.sys", IsLoaded = true, IsRegistered = true },
                ],
            },
        };

        var finding = Assert.Single(new ConcealmentDetector().Detect(context));
        output.WriteLine($"{finding.Severity}: {finding.Title}");

        Assert.Equal("concealment.unregistered-driver", finding.RuleId);
        Assert.Equal("manual.sys", finding.Subject);
    }
}

public sealed class ConcealmentOnThisMachineTests(ITestOutputHelper output)
{
    /// <summary>
    /// The live counterpart: on a healthy machine the detector must find nothing. A
    /// detector that fires here would be worse than useless, since a permanent
    /// "rootkit detected" trains the user to ignore it.
    /// </summary>
    [Fact]
    public void No_concealment_findings_on_this_machine()
    {
        var processes = new ProcessCollector().Collect(ScanOptions.Quick with { ProbePidSpace = true });
        var context = new DetectionContext { Processes = processes };

        var findings = new ConcealmentDetector().Detect(context)
            .Where(f => f.Category == FindingCategory.Concealment)
            .ToList();

        foreach (var f in findings)
        {
            output.WriteLine($"{f.Severity}: {f.Title}");
            foreach (var e in f.EvidenceChain)
            {
                output.WriteLine($"    {e.Label}: {e.Value}");
            }
        }

        var confirmed = processes.Processes.Count(p => p.ConfirmedHidden);
        output.WriteLine($"processes={processes.Processes.Count} confirmedHidden={confirmed} findings={findings.Count}");

        Assert.Empty(findings);
    }
}
