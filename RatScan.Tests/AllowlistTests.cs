using RatScan.Engine;
using RatScan.Engine.Allowlist;
using RatScan.Engine.Collectors;
using RatScan.Engine.Model;
using RatScan.Engine.Scoring;
using Xunit.Abstractions;

namespace RatScan.Tests;

/// <summary>
/// The allowlist is the only feature in RatScan whose purpose is to make it say less,
/// so most of these tests assert what it refuses to do rather than what it does.
/// </summary>
public sealed class AllowlistTests(ITestOutputHelper output)
{
    /// <summary>Hasher with a fixed table, so "the file changed" is a one-line setup.</summary>
    private sealed class StubHasher(Dictionary<string, string?> hashes) : IFileHasher
    {
        public string? Sha256(string path) =>
            hashes.TryGetValue(path, out var hash) ? hash : null;
    }

    private static Finding Finding(
        string ruleId = "surveillance.broad-dll-injection",
        string? identity = @"C:\Program Files\Bonjour\mdnsNSP.dll",
        Severity severity = Severity.Medium,
        FindingCategory category = FindingCategory.ScreenOrInputSurveillance) =>
        new()
        {
            RuleId = ruleId,
            Title = "test finding",
            Severity = severity,
            Confidence = Confidence.Possible,
            Category = category,
            Subject = "mdnsNSP.dll",
            IdentityKey = identity,
            Explanation = "test",
            EvidenceChain = [Evidence.Of("Path", identity ?? "none")],
        };

    private static AllowlistEntry Entry(
        Finding finding, string? pin = "AA11", DateTime? created = null) =>
        new()
        {
            Id = Guid.NewGuid().ToString("n"),
            RuleId = finding.RuleId,
            IdentityKey = finding.IdentityKey!,
            Reason = "Bonjour, installed with iTunes years ago",
            CreatedUtc = created ?? DateTime.UtcNow.AddDays(-3),
            PinnedSha256 = pin,
            Label = finding.Subject,
        };

    [Fact]
    public void Muted_finding_is_withheld_from_the_active_list()
    {
        var finding = Finding();
        var entry = Entry(finding);

        var result = new AllowlistFilter(
            new StubHasher(new() { [finding.IdentityKey!] = "AA11" }))
            .Apply([finding], [entry]);

        Assert.Empty(result.Active);
        Assert.Equal(entry.Id, Assert.Single(result.Suppressed).Entry.Id);
        Assert.Empty(result.Stale);
    }

    /// <summary>
    /// The property that stops an allowlist becoming a hiding place. An entry approves
    /// specific bytes, not a path — swapping the file must bring the finding back.
    /// </summary>
    [Fact]
    public void Replacing_the_pinned_file_un_mutes_the_finding()
    {
        var finding = Finding();
        var entry = Entry(finding, pin: "AA11");

        var result = new AllowlistFilter(
            new StubHasher(new() { [finding.IdentityKey!] = "BB22" }))
            .Apply([finding], [entry]);

        var active = Assert.Single(result.Active);
        Assert.Empty(result.Suppressed);

        var stale = Assert.Single(result.Stale);
        output.WriteLine(stale.Reason);
        Assert.Contains("changed", stale.Reason, StringComparison.OrdinalIgnoreCase);

        // The user muted this once and would otherwise assume it was still muted, so
        // the reason has to travel on the finding itself.
        Assert.Contains(active.EvidenceChain, e => e.Label == "Allowlist");
    }

    /// <summary>
    /// Invariant 10, applied to the allowlist: a file that cannot be hashed is missing
    /// data, and missing data must never be read as agreement.
    /// </summary>
    [Fact]
    public void Unreadable_file_does_not_satisfy_a_pin()
    {
        var finding = Finding();

        var result = new AllowlistFilter(new StubHasher([]))
            .Apply([finding], [Entry(finding, pin: "AA11")]);

        Assert.Single(result.Active);
        Assert.Empty(result.Suppressed);
        Assert.Single(result.Stale);
    }

    [Fact]
    public void Entry_only_mutes_its_own_rule_and_its_own_file()
    {
        var muted = Finding();
        var entry = Entry(muted);
        var hasher = new StubHasher(new()
        {
            [muted.IdentityKey!] = "AA11",
            [@"C:\Other\mdnsNSP.dll"] = "AA11",
        });

        var otherRule = Finding(ruleId: "surveillance.uiaccess-unsigned");
        var otherFile = Finding(identity: @"C:\Other\mdnsNSP.dll");

        var result = new AllowlistFilter(hasher).Apply([muted, otherRule, otherFile], [entry]);

        Assert.Single(result.Suppressed);
        Assert.Equal(2, result.Active.Count);
    }

    /// <summary>
    /// Concealment findings are the reason this tool exists. Offering a button that
    /// silences "something on this machine is hiding" would hand the user a way to
    /// disable the product's whole point.
    /// </summary>
    [Theory]
    [InlineData(FindingCategory.Concealment)]
    [InlineData(FindingCategory.ScanIntegrity)]
    public void Concealment_and_coverage_findings_can_never_be_muted(FindingCategory category)
    {
        var finding = Finding(category: category, severity: Severity.Critical);

        Assert.False(finding.CanBeMuted);
        Assert.Throws<ArgumentException>(() => AllowlistEntry.For(finding, "I am sure it is fine"));

        // Even a hand-written entry aimed straight at it does not apply.
        var forced = new AllowlistEntry
        {
            Id = "forced",
            RuleId = finding.RuleId,
            IdentityKey = finding.IdentityKey!,
            Reason = "forced",
            CreatedUtc = DateTime.UtcNow,
            PinnedSha256 = null,
        };

        var result = new AllowlistFilter(new StubHasher([])).Apply([finding], [forced]);

        Assert.Single(result.Active);
        Assert.Empty(result.Suppressed);
    }

    [Fact]
    public void A_finding_with_no_stable_identity_cannot_be_muted()
    {
        Assert.False(Finding(identity: null).CanBeMuted);
    }

    [Fact]
    public void An_entry_must_record_a_reason()
    {
        Assert.Throws<ArgumentException>(() => AllowlistEntry.For(Finding(), "   "));
    }

    /// <summary>
    /// Not a file, so not pinnable. The entry is created rather than refused — muting
    /// "RDP is enabled" is a legitimate decision — but it records no pin, and the UI
    /// discloses that it is weaker than a file-pinned entry.
    /// </summary>
    [Fact]
    public void A_non_file_target_produces_an_unpinned_entry()
    {
        var surface = Finding(
            ruleId: "surface.rdp",
            identity: "windows-surface:rdp",
            category: FindingCategory.WindowsRemoteSurface);

        var entry = AllowlistEntry.For(surface, "I use RDP to reach this machine from work");

        Assert.False(entry.IsPinnedToFileContents);

        var result = new AllowlistFilter(new StubHasher([])).Apply([surface], [entry]);
        Assert.Single(result.Suppressed);
    }

    // ---- what the verdict says about muting -------------------------------------

    private static ScanResult Score(AllowlistApplication allowlist) =>
        new ScoringEngine().Score(
            allowlist.Active,
            [],
            ["Running processes"],
            new IntegrityReport { Elevated = true },
            DateTime.UtcNow,
            TimeSpan.FromSeconds(1),
            allowlist);

    [Fact]
    public void Muted_findings_are_disclosed_in_the_headline()
    {
        var high = Finding(severity: Severity.High);
        var entry = Entry(high);

        var result = Score(new AllowlistFilter(
            new StubHasher(new() { [high.IdentityKey!] = "AA11" }))
            .Apply([high], [entry]));

        output.WriteLine(result.Headline);
        output.WriteLine("");
        output.WriteLine(result.Summary);

        Assert.Contains("muted", result.Headline, StringComparison.OrdinalIgnoreCase);
        Assert.Single(result.Suppressed);
    }

    /// <summary>
    /// The one that matters most. If the user's own allowlist is the only reason this
    /// scan reads quietly, the scan has to say so — silently downgrading a verdict is
    /// the same lie as claiming the machine is clean.
    /// </summary>
    [Fact]
    public void A_verdict_lowered_by_muting_states_what_it_would_otherwise_have_been()
    {
        var high = Finding(severity: Severity.High);

        var result = Score(new AllowlistFilter(
            new StubHasher(new() { [high.IdentityKey!] = "AA11" }))
            .Apply([high], [Entry(high)]));

        output.WriteLine(result.Summary);

        Assert.Equal(VerdictLevel.NoEvidenceFound, result.Verdict);
        Assert.Equal(VerdictLevel.RemoteAccessActive, result.VerdictIfNothingMuted);
        Assert.True(result.MutingChangedVerdict);
        Assert.Contains("would read", result.Summary, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void An_unchanged_verdict_does_not_invent_a_counterfactual()
    {
        var low = Finding(severity: Severity.Low);
        var alsoLow = Finding(identity: @"C:\Other\thing.dll", severity: Severity.Low);

        var result = Score(new AllowlistFilter(
            new StubHasher(new() { [low.IdentityKey!] = "AA11" }))
            .Apply([low, alsoLow], [Entry(low)]));

        Assert.Equal(VerdictLevel.ReviewRecommended, result.Verdict);
        Assert.False(result.MutingChangedVerdict);
        Assert.DoesNotContain("would read", result.Summary, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void With_nothing_muted_the_verdict_is_untouched()
    {
        var finding = Finding(severity: Severity.High);
        var result = Score(new AllowlistFilter(new StubHasher([])).Apply([finding], []));

        Assert.Equal(VerdictLevel.RemoteAccessActive, result.Verdict);
        Assert.False(result.MutingChangedVerdict);
        Assert.DoesNotContain("muted", result.Headline, StringComparison.OrdinalIgnoreCase);
    }

    // ---- the store ---------------------------------------------------------------

    [Fact]
    public void Sqlite_store_round_trips_entries_across_a_reopen()
    {
        var path = Path.Combine(Path.GetTempPath(), $"ratscan-test-{Guid.NewGuid():n}.db");

        try
        {
            var entry = AllowlistEntry.For(Finding(), "known-good, it is Bonjour");

            using (var store = new SqliteAllowlistStore(path))
            {
                store.Add(entry);
            }

            using (var reopened = new SqliteAllowlistStore(path))
            {
                var loaded = Assert.Single(reopened.All());

                Assert.Equal(entry.Id, loaded.Id);
                Assert.Equal(entry.RuleId, loaded.RuleId);
                Assert.Equal(entry.IdentityKey, loaded.IdentityKey);
                Assert.Equal(entry.Reason, loaded.Reason);
                Assert.Equal(entry.PinnedSha256, loaded.PinnedSha256);

                // Round-tripped through text, so the kind has to survive too — a
                // timestamp that comes back as Unspecified renders in the wrong zone.
                Assert.Equal(DateTimeKind.Utc, loaded.CreatedUtc.Kind);
                Assert.Equal(entry.CreatedUtc, loaded.CreatedUtc, TimeSpan.FromSeconds(1));

                Assert.True(reopened.Remove(loaded.Id));
                Assert.Empty(reopened.All());
                Assert.False(reopened.Remove(loaded.Id));
            }
        }
        finally
        {
            File.Delete(path);
        }
    }

    /// <summary>
    /// The whole path against this machine: scan for real, mute something real, and
    /// check it actually stops being reported.
    /// <para>
    /// Synthetic findings cannot establish this. Every part that can realistically be
    /// wrong here — whether detectors populate an identity key at all, whether the path
    /// they put there is a file that can be hashed, whether re-scoring holds together —
    /// only shows up against real output. Uses its own database so the user's allowlist
    /// is never touched.
    /// </para>
    /// </summary>
    [Fact]
    public void Muting_a_real_finding_on_this_machine_stops_it_being_reported()
    {
        var path = Path.Combine(Path.GetTempPath(), $"ratscan-live-{Guid.NewGuid():n}.db");

        try
        {
            using var store = new SqliteAllowlistStore(path);
            var orchestrator = new ScanOrchestrator(allowlist: store);

            var first = orchestrator.Run(ScanOptions.Full);
            // Prefer a finding backed by a real file, so the run exercises pinning
            // rather than the weaker unpinned path a Windows feature would take.
            var target =
                first.Findings.FirstOrDefault(
                    f => f.CanBeMuted && f.IdentityKey is not null && File.Exists(f.IdentityKey))
                ?? first.Findings.FirstOrDefault(f => f.CanBeMuted);

            if (target is null)
            {
                // xunit 2.5 has no runtime skip, so say plainly in the output that this
                // run established nothing rather than letting a green tick imply it did.
                output.WriteLine(
                    "NOT VERIFIED: this machine produced no mutable finding, so the live path "
                    + "was not exercised. This run proves nothing about muting.");

                return;
            }

            output.WriteLine($"Muting: {target.Title}");
            output.WriteLine($"Identity: {target.IdentityKey}");

            var entry = AllowlistEntry.For(target, "live test — this is mine");
            output.WriteLine($"Pinned: {entry.PinnedSha256 ?? "no (target is not a readable file)"}");

            store.Add(entry);

            var after = orchestrator.ReapplyAllowlist(first);

            Assert.DoesNotContain(after.Findings, f => f.RuleId == target.RuleId
                                                       && f.IdentityKey == target.IdentityKey);

            Assert.Contains(after.Suppressed, s => s.Entry.Id == entry.Id);
            Assert.Equal(first.Findings.Count - 1, after.Findings.Count);
            Assert.Contains("muted", after.Headline, StringComparison.OrdinalIgnoreCase);

            output.WriteLine("");
            output.WriteLine(after.Headline);

            // And unmuting brings it back — a mute the user cannot reverse is a worse
            // problem than the noise it was silencing.
            Assert.True(store.Remove(entry.Id));

            var restored = orchestrator.ReapplyAllowlist(after);

            Assert.Equal(first.Findings.Count, restored.Findings.Count);
            Assert.Empty(restored.Suppressed);
            Assert.Equal(first.Verdict, restored.Verdict);
        }
        finally
        {
            File.Delete(path);
        }
    }

    /// <summary>
    /// Re-muting the same thing is a fresh approval of whatever it is now. Two entries
    /// disagreeing about which bytes were trusted is a state with no correct reading.
    /// </summary>
    [Fact]
    public void Re_muting_the_same_target_replaces_the_earlier_pin()
    {
        var path = Path.Combine(Path.GetTempPath(), $"ratscan-test-{Guid.NewGuid():n}.db");

        try
        {
            using var store = new SqliteAllowlistStore(path);
            var finding = Finding();

            store.Add(Entry(finding, pin: "AA11") with { Reason = "first" });
            store.Add(Entry(finding, pin: "BB22") with { Reason = "second, after an update" });

            var only = Assert.Single(store.All());
            Assert.Equal("BB22", only.PinnedSha256);
            Assert.Equal("second, after an update", only.Reason);
        }
        finally
        {
            File.Delete(path);
        }
    }
}
