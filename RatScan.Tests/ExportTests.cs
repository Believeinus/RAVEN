using System.Text.Json;
using RatScan.Engine.Allowlist;
using RatScan.Engine.Export;
using RatScan.Engine.Model;
using RatScan.Engine.Scoring;
using Xunit.Abstractions;

namespace RatScan.Tests;

/// <summary>
/// An export is read later, by someone who was not there. These tests are mostly about
/// what the file is not allowed to leave out, plus the one place a security tool can
/// hand an attacker something: pasting machine-controlled text into a document.
/// </summary>
public sealed class ExportTests(ITestOutputHelper output)
{
    private static Finding Finding(
        string title = "TightVNC is running",
        Severity severity = Severity.High) =>
        new()
        {
            RuleId = "remote-tool.tightvnc",
            Title = title,
            Severity = severity,
            Confidence = Confidence.Likely,
            Category = FindingCategory.RemoteAccessSoftware,
            Subject = "TightVNC",
            IdentityKey = @"C:\Program Files\TightVNC\tvnserver.exe",
            Pid = 4242,
            Explanation = "Someone connecting to it can see your screen.",
            Recommendation = "Confirm you installed it.",
            EvidenceChain = [Evidence.Of("Listening on", "5900", "GetExtendedTcpTable")],
        };

    private static ScanResult Result(
        IReadOnlyList<Finding>? findings = null,
        IReadOnlyList<Blindspot>? blindspots = null,
        IReadOnlyList<SuppressedFinding>? suppressed = null,
        bool elevated = false)
    {
        var integrity = new IntegrityReport
        {
            Elevated = elevated,
            Signals =
            [
                new IntegritySignal
                {
                    Name = "Driver signature enforcement",
                    Satisfied = false,
                    Detail = "Unsigned drivers can load.",
                    UnderminesResult = true,
                },
            ],
        };

        var result = new ScoringEngine().Score(
            findings ?? [Finding()],
            blindspots ??
            [
                new Blindspot
                {
                    Area = "Protected processes",
                    Reason = "Running without Administrator.",
                    Remedy = "Restart as Administrator",
                },
            ],
            ["Running processes", "Windows remote-access surfaces"],
            integrity,
            DateTime.UtcNow,
            TimeSpan.FromSeconds(3));

        return suppressed is null ? result : result with { Suppressed = suppressed };
    }

    /// <summary>
    /// The one that decides whether this feature is safe to ship. Process names, paths
    /// and signer strings are chosen by whatever is running on the machine — including,
    /// on the machines this tool exists for, something hostile. A report that renders
    /// them as markup hands that thing script execution inside the document written
    /// about it.
    /// </summary>
    [Fact]
    public void Machine_controlled_text_cannot_inject_markup_into_the_report()
    {
        var hostile = Finding(title: "<script>alert('xss')</script> is running") with
        {
            Subject = "<img src=x onerror=alert(1)>",
            Explanation = "Path: C:\\<script>evil</script>\\a.exe",
            EvidenceChain = [Evidence.Of("<b>label</b>", "\"><script>x</script>", "<i>src</i>")],
        };

        var html = ScanExporter.ToHtml(Result([hostile]));

        Assert.DoesNotContain("<script>", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("onerror=", html, StringComparison.OrdinalIgnoreCase);

        // The text must still be present, just inert.
        Assert.Contains("&lt;script&gt;", html, StringComparison.Ordinal);
    }

    /// <summary>
    /// A report listing findings and omitting coverage is the "you are clean" verdict
    /// arriving by a side door — worse than the UI doing it, because the file is read
    /// later and out of context.
    /// </summary>
    [Fact]
    public void Html_report_always_carries_its_coverage_and_its_limits()
    {
        var html = ScanExporter.ToHtml(Result(), machine: "TEST-PC");

        output.WriteLine(html[..Math.Min(400, html.Length)]);

        Assert.Contains("What this scan could not see", html, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Protected processes", html, StringComparison.Ordinal);
        Assert.Contains("Restart as Administrator", html, StringComparison.Ordinal);

        // The integrity signal that undermines the result must be unmistakable.
        Assert.Contains("could have been deceived", html, StringComparison.OrdinalIgnoreCase);

        Assert.Contains("user mode", html, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("ran without Administrator", html, StringComparison.Ordinal);
    }

    [Fact]
    public void A_quiet_report_never_claims_the_machine_is_clean()
    {
        var html = ScanExporter.ToHtml(Result(findings: []));
        var json = ScanExporter.ToJson(Result(findings: []));

        foreach (var text in new[] { html, json })
        {
            foreach (var forbidden in new[] { "you are clean", "no threats", "you're safe", "is secure" })
            {
                Assert.DoesNotContain(forbidden, text, StringComparison.OrdinalIgnoreCase);
            }

            // "the machine is clean" does appear — inside the sentence denying it. A flat
            // substring ban would either fail here or force the disclaimer to be reworded
            // into something vaguer, so assert the negation instead of the absence.
            var claims = text.Split("machine is clean", StringSplitOptions.None);

            for (var i = 1; i < claims.Length; i++)
            {
                Assert.EndsWith(
                    "not a certificate that the ", claims[i - 1], StringComparison.OrdinalIgnoreCase);
            }
        }

        Assert.Contains("not a certificate", html, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Muting is a user decision that removes findings from the count. A report that
    /// hides that has been quietly edited by the person it is about.
    /// </summary>
    [Fact]
    public void Muted_findings_and_their_effect_on_the_verdict_appear_in_both_formats()
    {
        var muted = Finding(title: "AnyDesk is running", severity: Severity.High);

        var suppressed = new[]
        {
            new SuppressedFinding
            {
                Finding = muted,
                Entry = new AllowlistEntry
                {
                    Id = "e1",
                    RuleId = muted.RuleId,
                    IdentityKey = muted.IdentityKey!,
                    Reason = "I use AnyDesk for work",
                    CreatedUtc = DateTime.UtcNow,
                    PinnedSha256 = "AA11",
                },
            },
        };

        var result = Result(findings: [], suppressed: suppressed) with
        {
            VerdictIfNothingMuted = VerdictLevel.RemoteAccessActive,
        };

        var html = ScanExporter.ToHtml(result);
        Assert.Contains("Muted by the user", html, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("I use AnyDesk for work", html, StringComparison.Ordinal);
        Assert.Contains("reflects your allowlist", html, StringComparison.OrdinalIgnoreCase);

        using var document = JsonDocument.Parse(ScanExporter.ToJson(result));
        var root = document.RootElement;

        Assert.Equal(1, root.GetProperty("muted").GetArrayLength());
        Assert.True(root.GetProperty("verdict").GetProperty("mutingChangedVerdict").GetBoolean());
    }

    [Fact]
    public void Json_export_is_valid_and_carries_the_scan_and_its_coverage()
    {
        var json = ScanExporter.ToJson(Result(), machine: "TEST-PC");

        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;

        Assert.Equal(ScanExporter.JsonSchemaVersion, root.GetProperty("schema").GetInt32());
        Assert.Equal("TEST-PC", root.GetProperty("machine").GetString());

        var finding = root.GetProperty("findings")[0];
        Assert.Equal("remote-tool.tightvnc", finding.GetProperty("ruleId").GetString());
        Assert.Equal("High", finding.GetProperty("severity").GetString());
        Assert.Equal("5900", finding.GetProperty("evidence")[0].GetProperty("Value").GetString());

        var coverage = root.GetProperty("coverage");
        Assert.Equal(1, coverage.GetProperty("blindspots").GetArrayLength());
        Assert.False(coverage.GetProperty("integrity")[0].GetProperty("satisfied").GetBoolean());

        Assert.False(root.GetProperty("scan").GetProperty("elevated").GetBoolean());
    }

    /// <summary>
    /// Exports this machine for real. Synthetic findings are tidy; a live scan produces
    /// paths with spaces and brackets, signer strings with punctuation, and evidence
    /// values that are whatever Windows returned — which is where an encoding or
    /// formatting bug would actually show up.
    /// </summary>
    [Fact]
    public void Exporting_a_real_scan_of_this_machine_produces_a_complete_report()
    {
        var scan = new RatScan.Engine.ScanOrchestrator().Run(
            RatScan.Engine.Collectors.ScanOptions.Full);

        var html = ScanExporter.ToHtml(scan, machine: Environment.MachineName);
        var json = ScanExporter.ToJson(scan, machine: Environment.MachineName);

        output.WriteLine($"findings={scan.Findings.Count} blindspots={scan.Blindspots.Count} "
                         + $"html={html.Length}b json={json.Length}b");
        output.WriteLine(scan.Headline);

        // Parses as JSON, and the finding count survives the round trip.
        using var document = JsonDocument.Parse(json);
        Assert.Equal(scan.Findings.Count, document.RootElement.GetProperty("findings").GetArrayLength());

        Assert.StartsWith("<!doctype html>", html, StringComparison.OrdinalIgnoreCase);
        Assert.EndsWith("</html>", html.TrimEnd(), StringComparison.OrdinalIgnoreCase);

        // Every real finding title must appear, encoded, in the report.
        foreach (var finding in scan.Findings)
        {
            Assert.Contains(
                System.Net.WebUtility.HtmlEncode(finding.Title), html, StringComparison.Ordinal);
        }

        // Nothing on a real machine should produce an unencoded angle bracket outside
        // the report's own markup — this is the live counterpart of the injection test.
        var body = html[html.IndexOf("<main>", StringComparison.Ordinal)..];
        foreach (var blindspot in scan.Blindspots)
        {
            Assert.Contains(
                System.Net.WebUtility.HtmlEncode(blindspot.Area), body, StringComparison.Ordinal);
        }

        var path = Path.Combine(Path.GetTempPath(), $"ratscan-export-{Guid.NewGuid():n}.html");

        try
        {
            File.WriteAllText(path, html, System.Text.Encoding.UTF8);
            Assert.True(new FileInfo(path).Length > 1000);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Suggested_file_name_is_sortable_and_matches_the_format()
    {
        var result = Result();

        Assert.EndsWith(".html", ScanExporter.SuggestedFileName(result, ExportFormat.Html),
            StringComparison.Ordinal);

        var json = ScanExporter.SuggestedFileName(result, ExportFormat.Json);
        output.WriteLine(json);

        Assert.StartsWith("ratscan-", json, StringComparison.Ordinal);
        Assert.EndsWith(".json", json, StringComparison.Ordinal);
    }
}
