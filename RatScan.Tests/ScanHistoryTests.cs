using RatScan.Engine.History;
using RatScan.Engine.Model;
using RatScan.Engine.Scoring;
using Xunit.Abstractions;

namespace RatScan.Tests;

/// <summary>
/// History exists so a scan can say what changed. The tests that matter are about what
/// a difference is allowed to <em>mean</em> — above all, the refusal to read a finding
/// disappearing as good news when this scan simply saw less than the last one.
/// </summary>
public sealed class ScanHistoryTests(ITestOutputHelper output)
{
    private static Finding Finding(
        string ruleId,
        Severity severity = Severity.Medium,
        string? identity = null,
        string title = "something") =>
        new()
        {
            RuleId = ruleId,
            Title = title,
            Severity = severity,
            Confidence = Confidence.Likely,
            Category = FindingCategory.RemoteAccessSoftware,
            Subject = ruleId,
            IdentityKey = identity,
            Explanation = "test",
        };

    private static ScanResult Result(
        IReadOnlyList<Finding> findings,
        bool elevated = true,
        int blindspots = 0,
        IReadOnlyList<RatScan.Engine.Allowlist.SuppressedFinding>? suppressed = null)
    {
        var result = new ScoringEngine().Score(
            findings,
            [.. Enumerable.Range(0, blindspots).Select(i =>
                new Blindspot { Area = $"area{i}", Reason = "test" })],
            ["Running processes"],
            new IntegrityReport { Elevated = elevated },
            DateTime.UtcNow,
            TimeSpan.FromSeconds(2));

        return suppressed is null ? result : result with { Suppressed = suppressed };
    }

    private static ScanRecord Record(ScanResult result, bool elevated = true, int blindspots = 0) =>
        new()
        {
            StartedUtc = result.StartedUtc.AddHours(-1),
            Duration = result.Duration,
            Verdict = result.Verdict,
            Headline = result.Headline,
            Elevated = elevated,
            SurfacesExamined = 1,
            Blindspots = blindspots,
            Muted = result.Suppressed.Count,
            Findings = [.. result.Findings.Select(RecordedFinding.From)],
        };

    [Fact]
    public void A_new_finding_is_reported_as_new()
    {
        var before = Record(Result([Finding("remote-tool.tightvnc")]));
        var now = Result([Finding("remote-tool.tightvnc"), Finding("remote-tool.anydesk")]);

        var diff = ScanDiffer.Compare(before, now);

        Assert.Equal("remote-tool.anydesk", Assert.Single(diff.Appeared).RuleId);
        Assert.Empty(diff.Gone);
        Assert.Null(diff.ComparabilityCaveat);
    }

    /// <summary>
    /// Titles carry counts — "loaded into 9 unrelated programs" becomes 10 — so matching
    /// on them would report every scan as entirely new and make the panel worthless.
    /// </summary>
    [Fact]
    public void Identity_not_the_title_decides_whether_a_finding_is_the_same_one()
    {
        var before = Record(Result([
            Finding("surveillance.broad-dll-injection", identity: @"C:\x\hook.dll",
                title: "'hook.dll' is loaded into 9 unrelated programs"),
        ]));

        var now = Result([
            Finding("surveillance.broad-dll-injection", identity: @"C:\x\hook.dll",
                title: "'hook.dll' is loaded into 14 unrelated programs"),
        ]);

        var diff = ScanDiffer.Compare(before, now);

        Assert.Empty(diff.Appeared);
        Assert.Empty(diff.Gone);
        Assert.True(diff.NothingChanged);
    }

    [Fact]
    public void A_severity_change_on_the_same_finding_is_reported_as_a_change()
    {
        var before = Record(Result([Finding("remote-tool.tightvnc", Severity.Medium)]));
        var now = Result([Finding("remote-tool.tightvnc", Severity.High)]);

        var diff = ScanDiffer.Compare(before, now);

        var (was, current) = Assert.Single(diff.Changed);
        Assert.Equal(Severity.Medium, was.Severity);
        Assert.Equal(Severity.High, current.Severity);
        Assert.True(diff.VerdictChanged);
    }

    /// <summary>
    /// The point of the whole feature. Three findings vanishing because this scan ran
    /// unelevated looks exactly like three problems being solved, and only one of those
    /// is true.
    /// </summary>
    [Fact]
    public void Losing_elevation_qualifies_everything_that_disappeared()
    {
        var before = Record(Result([Finding("remote-tool.tightvnc")]), elevated: true);
        var now = Result([], elevated: false);

        var diff = ScanDiffer.Compare(before, now);

        Assert.Single(diff.Gone);
        Assert.NotNull(diff.ComparabilityCaveat);
        output.WriteLine(diff.ComparabilityCaveat);

        Assert.Contains("Administrator", diff.ComparabilityCaveat, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void More_blind_spots_than_last_time_qualifies_what_disappeared()
    {
        var before = Record(Result([Finding("remote-tool.tightvnc")]), blindspots: 1);
        var now = Result([], blindspots: 5);

        var diff = ScanDiffer.Compare(before, now);

        Assert.NotNull(diff.ComparabilityCaveat);
        Assert.Contains("examined less", diff.ComparabilityCaveat, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Muting something removes it from the findings list. Without this, the next scan
    /// would report the user's own allowlist decision as the machine getting better.
    /// </summary>
    [Fact]
    public void Newly_muted_findings_are_named_rather_than_shown_as_an_improvement()
    {
        var muted = Finding("remote-tool.tightvnc");

        var before = Record(Result([muted]));
        var now = Result(
            [],
            suppressed:
            [
                new RatScan.Engine.Allowlist.SuppressedFinding
                {
                    Finding = muted,
                    Entry = new RatScan.Engine.Allowlist.AllowlistEntry
                    {
                        Id = "e1",
                        RuleId = muted.RuleId,
                        IdentityKey = "x",
                        Reason = "mine",
                        CreatedUtc = DateTime.UtcNow,
                    },
                },
            ]);

        var diff = ScanDiffer.Compare(before, now);

        Assert.Single(diff.Gone);
        Assert.NotNull(diff.ComparabilityCaveat);
        output.WriteLine(diff.ComparabilityCaveat);

        Assert.Contains("muted", diff.ComparabilityCaveat, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// A caveat on every diff would be noise, and noise is how a real warning gets
    /// ignored. It is raised only when something disappeared.
    /// </summary>
    [Fact]
    public void No_caveat_when_nothing_disappeared()
    {
        var before = Record(Result([Finding("remote-tool.tightvnc")]), elevated: true);
        var now = Result([Finding("remote-tool.tightvnc"), Finding("remote-tool.anydesk")],
            elevated: false, blindspots: 9);

        Assert.Null(ScanDiffer.Compare(before, now).ComparabilityCaveat);
    }

    [Fact]
    public void Sqlite_history_round_trips_a_scan_and_returns_the_latest()
    {
        var path = Path.Combine(Path.GetTempPath(), $"ratscan-hist-{Guid.NewGuid():n}.db");

        try
        {
            var first = Result([Finding("remote-tool.tightvnc", Severity.High, @"C:\x\vnc.exe")]);
            var second = Result([Finding("remote-tool.anydesk")]);

            using (var store = new SqliteScanHistoryStore(path))
            {
                Assert.Null(store.Latest());

                store.Record(first);
                store.Record(second with { StartedUtc = second.StartedUtc.AddMinutes(1) });
            }

            using (var reopened = new SqliteScanHistoryStore(path))
            {
                var latest = reopened.Latest();
                Assert.NotNull(latest);
                Assert.Equal("remote-tool.anydesk", Assert.Single(latest!.Findings).RuleId);

                var all = reopened.Recent();
                Assert.Equal(2, all.Count);

                var oldest = all[1];
                var finding = Assert.Single(oldest.Findings);

                Assert.Equal(Severity.High, finding.Severity);
                Assert.Equal(@"C:\x\vnc.exe", finding.IdentityKey);
                Assert.Equal(DateTimeKind.Utc, oldest.StartedUtc.Kind);
                Assert.True(oldest.Elevated);
            }
        }
        finally
        {
            File.Delete(path);
        }
    }

    /// <summary>
    /// Both stores open the same file. If they migrated it independently they would
    /// eventually disagree about its shape, so this asserts they coexist.
    /// </summary>
    [Fact]
    public void Allowlist_and_history_share_one_database_file()
    {
        var path = Path.Combine(Path.GetTempPath(), $"ratscan-both-{Guid.NewGuid():n}.db");

        try
        {
            using var history = new SqliteScanHistoryStore(path);
            using var allowlist = new RatScan.Engine.Allowlist.SqliteAllowlistStore(path);

            history.Record(Result([Finding("remote-tool.tightvnc")]));

            allowlist.Add(new RatScan.Engine.Allowlist.AllowlistEntry
            {
                Id = "e1",
                RuleId = "remote-tool.tightvnc",
                IdentityKey = @"C:\x\vnc.exe",
                Reason = "mine",
                CreatedUtc = DateTime.UtcNow,
            });

            Assert.NotNull(history.Latest());
            Assert.Single(allowlist.All());
        }
        finally
        {
            File.Delete(path);
        }
    }
}
