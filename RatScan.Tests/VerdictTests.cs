using RatScan.Engine;
using RatScan.Engine.Collectors;
using RatScan.Engine.Model;
using RatScan.Engine.Scoring;
using Xunit.Abstractions;

namespace RatScan.Tests;

public sealed class ScoringEngineTests(ITestOutputHelper output)
{
    private static IntegrityReport HealthyIntegrity => new()
    {
        Elevated = true,
        Signals =
        [
            new IntegritySignal { Name = "Driver signature enforcement", Satisfied = true, Detail = "on", UnderminesResult = true },
        ],
    };

    private static ScanResult Score(
        IReadOnlyList<Finding> findings,
        IReadOnlyList<Blindspot>? blindspots = null,
        IntegrityReport? integrity = null) =>
        new ScoringEngine().Score(
            findings,
            blindspots ?? [],
            ["Running processes", "Windows remote-access surfaces"],
            integrity ?? HealthyIntegrity,
            DateTime.UtcNow,
            TimeSpan.FromSeconds(2));

    private static Finding At(Severity severity, FindingCategory category = FindingCategory.RemoteAccessSoftware) =>
        new()
        {
            RuleId = "test",
            Title = "test",
            Severity = severity,
            Confidence = Confidence.Confirmed,
            Category = category,
            Explanation = "test",
        };

    /// <summary>
    /// The single most important assertion in the product. RatScan must never tell a
    /// user they are clean, because no user-mode scanner can establish that.
    /// </summary>
    [Fact]
    public void Quiet_result_never_claims_the_machine_is_clean()
    {
        var result = Score([]);

        output.WriteLine(result.Headline);
        output.WriteLine("");
        output.WriteLine(result.Summary);

        Assert.Equal(VerdictLevel.NoEvidenceFound, result.Verdict);

        var text = $"{result.Headline} {result.Summary}";
        foreach (var forbidden in new[] { "you are clean", "no threats", "you're safe", "guaranteed", "nothing is spying" })
        {
            Assert.DoesNotContain(forbidden, text, StringComparison.OrdinalIgnoreCase);
        }

        Assert.Contains("No evidence of remote access found", result.Headline);

        // The honesty clause must be present precisely when the result is quiet.
        Assert.Contains("not a guarantee", result.Summary, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("kernel", result.Summary, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Headline_states_coverage_and_blind_spots()
    {
        var result = Score([], [
            new Blindspot { Area = "Security event log", Reason = "needs elevation" },
            new Blindspot { Area = "WMI subscriptions", Reason = "denied" },
        ]);

        output.WriteLine(result.Headline);

        Assert.Contains("2 surfaces", result.Headline);
        Assert.Contains("2 blind spots", result.Headline);
    }

    [Fact]
    public void Concealment_outranks_everything_else()
    {
        var result = Score([
            At(Severity.Critical, FindingCategory.Concealment),
            At(Severity.High),
        ]);

        output.WriteLine(result.Headline);

        Assert.Equal(VerdictLevel.CompromiseIndicated, result.Verdict);
        Assert.Contains("compromise", result.Headline, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(Severity.High, VerdictLevel.RemoteAccessActive)]
    [InlineData(Severity.Medium, VerdictLevel.ReviewRecommended)]
    [InlineData(Severity.Low, VerdictLevel.ReviewRecommended)]
    [InlineData(Severity.Info, VerdictLevel.NoEvidenceFound)]
    public void Verdict_follows_the_highest_severity_present(Severity severity, VerdictLevel expected)
    {
        Assert.Equal(expected, Score([At(severity)]).Verdict);
    }

    [Fact]
    public void Undermining_conditions_are_stated_in_the_summary()
    {
        var compromisedIntegrity = new IntegrityReport
        {
            Elevated = false,
            Signals =
            [
                new IntegritySignal
                {
                    Name = "Kernel debugger",
                    Satisfied = false,
                    UnderminesResult = true,
                    Detail = "attached",
                },
            ],
        };

        var result = Score([], integrity: compromisedIntegrity);

        output.WriteLine(result.Summary);

        // A quiet verdict produced under a kernel debugger must say so in the same
        // breath, not bury it in a panel the user might not open.
        Assert.Contains("kernel debugger", result.Summary, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("without Administrator", result.Summary, StringComparison.OrdinalIgnoreCase);
        Assert.False(compromisedIntegrity.NoKnownUnderminingConditions);
    }

    [Fact]
    public void Findings_are_ordered_most_severe_first()
    {
        var result = Score([At(Severity.Low), At(Severity.Critical), At(Severity.Medium)]);

        Assert.Equal(Severity.Critical, result.Findings[0].Severity);
        Assert.Equal(Severity.Low, result.Findings[^1].Severity);
    }
}

public sealed class IntegrityAssessorTests(ITestOutputHelper output)
{
    [Fact]
    public void Reports_real_conditions_on_this_machine()
    {
        var report = new IntegrityAssessor().Assess();

        output.WriteLine($"elevated: {report.Elevated}");
        foreach (var s in report.Signals)
        {
            var state = s.Satisfied switch { true => "OK", false => "FAIL", null => "UNKNOWN" };
            output.WriteLine($"  [{state,-7}] {s.Name}: {s.Detail}");
        }

        Assert.NotEmpty(report.Signals);

        // Every signal must carry an explanation; a bare pass/fail is not actionable.
        Assert.All(report.Signals, s => Assert.False(string.IsNullOrWhiteSpace(s.Detail)));

        // Indeterminate must stay indeterminate rather than defaulting to "fine".
        Assert.All(report.Signals, s => Assert.True(
            s.Satisfied is not null || s.Detail.Contains("Could not be determined", StringComparison.OrdinalIgnoreCase)));
    }
}

public sealed class EndToEndScanTests(ITestOutputHelper output)
{
    [Fact]
    public void Full_scan_produces_a_complete_result_for_this_machine()
    {
        var result = new ScanOrchestrator().Run(ScanOptions.Full);

        output.WriteLine("================ RATSCAN RESULT ================");
        output.WriteLine(result.Headline);
        output.WriteLine("");
        output.WriteLine(result.Summary);
        output.WriteLine("");
        output.WriteLine($"verdict={result.Verdict}  duration={result.Duration.TotalSeconds:F1}s");
        output.WriteLine($"examined: {string.Join(", ", result.SurfacesExamined)}");
        output.WriteLine("");
        output.WriteLine($"findings ({result.Findings.Count}):");
        foreach (var f in result.Findings)
        {
            output.WriteLine($"  [{f.Severity}/{f.Confidence}] {f.Title}");
        }

        output.WriteLine("");
        output.WriteLine($"blind spots ({result.Blindspots.Count}):");
        foreach (var b in result.Blindspots)
        {
            output.WriteLine($"  {b.Area}");
        }

        Assert.NotEmpty(result.SurfacesExamined);
        Assert.False(string.IsNullOrWhiteSpace(result.Headline));

        // The honesty clause is unconditional — it must appear on every verdict.
        Assert.Contains("not a guarantee", result.Summary, StringComparison.OrdinalIgnoreCase);
    }
}
