using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using RatScan.Engine.History;
using RatScan.Engine.Model;

namespace RatScan.Engine.Export;

public enum ExportFormat
{
    /// <summary>A self-contained report to read, keep or hand to someone else.</summary>
    Html,

    /// <summary>The same scan as data, for diffing or feeding into something else.</summary>
    Json,
}

/// <summary>
/// Turns a scan into a document that outlives it.
/// <para>
/// An export is the most dangerous artefact this tool produces, and the reason is
/// timing: it is read later, by someone who was not there, quite possibly to decide
/// whether a machine is safe. A report that lists findings and drops the coverage is
/// the "you are clean" verdict arriving by a side door. So every export carries the
/// blind spots, the integrity signals, what the user muted, and the user-mode
/// limitation — not as an appendix, but in the same document, unavoidably.
/// </para>
/// <para>
/// It also contains host telemetry: process paths, ports, usernames, file hashes. The
/// caller announces that before writing; this class only states it in the file.
/// </para>
/// </summary>
public static class ScanExporter
{
    /// <summary>Bumped when the JSON shape changes in a way a consumer would notice.</summary>
    public const int JsonSchemaVersion = 1;

    public static string Export(
        ScanResult result, ExportFormat format, ScanDiff? diff = null, string? machine = null) =>
        format == ExportFormat.Json
            ? ToJson(result, diff, machine)
            : ToHtml(result, diff, machine);

    public static string SuggestedFileName(ScanResult result, ExportFormat format)
    {
        ArgumentNullException.ThrowIfNull(result);

        var stamp = result.StartedUtc.ToLocalTime().ToString("yyyy-MM-dd-HHmm", CultureInfo.InvariantCulture);
        return $"ratscan-{stamp}.{(format == ExportFormat.Json ? "json" : "html")}";
    }

    // ---- JSON -------------------------------------------------------------------

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public static string ToJson(ScanResult result, ScanDiff? diff = null, string? machine = null)
    {
        ArgumentNullException.ThrowIfNull(result);

        // Serialised through a declared shape rather than straight off the domain model,
        // so refactoring an internal record cannot silently change a file format someone
        // else's tooling depends on.
        var document = new
        {
            schema = JsonSchemaVersion,
            tool = "RAVEN",
            machine,
            scan = new
            {
                startedUtc = result.StartedUtc,
                durationSeconds = Math.Round(result.Duration.TotalSeconds, 2),
                elevated = result.Integrity.Elevated,
                surfacesExamined = result.SurfacesExamined,
            },
            verdict = new
            {
                level = result.Verdict.ToString(),
                headline = result.Headline,
                summary = result.Summary,
                ifNothingMuted = result.VerdictIfNothingMuted.ToString(),
                mutingChangedVerdict = result.MutingChangedVerdict,
            },
            findings = result.Findings.Select(f => new
            {
                ruleId = f.RuleId,
                title = f.Title,
                severity = f.Severity.ToString(),
                confidence = f.Confidence.ToString(),
                category = f.Category.ToString(),
                subject = f.Subject,
                identityKey = f.IdentityKey,
                pid = f.Pid,
                mitre = f.MitreTechnique,
                explanation = f.Explanation,
                recommendation = f.Recommendation,
                evidence = f.EvidenceChain.Select(e => new { e.Label, e.Value, e.Source }),
            }),
            muted = result.Suppressed.Select(s => new
            {
                ruleId = s.Finding.RuleId,
                title = s.Finding.Title,
                severity = s.Finding.Severity.ToString(),
                reason = s.Entry.Reason,
                mutedUtc = s.Entry.CreatedUtc,
                pinnedToFileContents = s.Entry.IsPinnedToFileContents,
            }),

            // Deliberately not last and not optional. A consumer that reads `findings`
            // without reading this is reading half the result.
            coverage = new
            {
                blindspots = result.Blindspots.Select(b => new { b.Area, b.Reason, b.Remedy }),
                integrity = result.Integrity.Signals.Select(s => new
                {
                    s.Name,
                    satisfied = s.Satisfied,
                    s.Detail,
                    underminesResult = s.UnderminesResult,
                }),
            },
            sinceLastScan = diff is null ? null : new
            {
                previousScanUtc = diff.Previous.StartedUtc,
                previousVerdict = diff.PreviousVerdict.ToString(),
                appeared = diff.Appeared.Select(f => new { f.RuleId, f.Title, severity = f.Severity.ToString() }),
                gone = diff.Gone.Select(f => new { f.RuleId, f.Title, severity = f.Severity.ToString() }),
                comparabilityCaveat = diff.ComparabilityCaveat,
            },
            limitation = UserModeLimitation,
        };

        return JsonSerializer.Serialize(document, JsonOptions);
    }

    // ---- HTML -------------------------------------------------------------------

    private const string UserModeLimitation =
        "RAVEN runs in user mode. Code running in the Windows kernel, in a hypervisor "
        + "beneath Windows, or in hardware attached to this machine can return clean answers "
        + "to every check in this report. This document states what was examined. It is not "
        + "a certificate that the machine is clean, and no user-mode tool can issue one.";

    public static string ToHtml(ScanResult result, ScanDiff? diff = null, string? machine = null)
    {
        ArgumentNullException.ThrowIfNull(result);

        var html = new StringBuilder();

        html.Append(
            """
            <!doctype html>
            <html lang="en"><head><meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>RAVEN report</title>
            <style>
              :root { color-scheme: light; }
              body { font: 15px/1.55 "Segoe UI", system-ui, sans-serif; color: #1b1f26;
                     background: #f6f7f9; margin: 0; padding: 32px; }
              main { max-width: 960px; margin: 0 auto; }
              h1 { font-size: 22px; margin: 0 0 4px; }
              h2 { font-size: 13px; letter-spacing: .06em; text-transform: uppercase;
                   color: #5b6472; margin: 32px 0 12px; }
              .card { background: #fff; border: 1px solid #dfe3e9; border-radius: 8px;
                      padding: 20px; margin-bottom: 16px; }
              .verdict { border-left: 6px solid #8b93a1; }
              .verdict.critical { border-left-color: #d13c3c; }
              .verdict.high { border-left-color: #d1791f; }
              .verdict.medium { border-left-color: #c9a413; }
              .verdict.quiet { border-left-color: #3f9e63; }
              .muted-text { color: #5b6472; }
              .badge { display: inline-block; font-size: 11px; font-weight: 700; padding: 2px 7px;
                       border-radius: 4px; color: #fff; }
              .s-critical { background: #d13c3c; } .s-high { background: #d1791f; }
              .s-medium { background: #b8940f; } .s-low { background: #4b7bb5; }
              .s-info { background: #6b7280; }
              table { border-collapse: collapse; width: 100%; font-size: 13px; }
              td { padding: 4px 10px 4px 0; vertical-align: top; }
              td.k { color: #5b6472; white-space: nowrap; width: 1%; }
              code { font-family: Consolas, monospace; font-size: 12.5px; word-break: break-all; }
              .finding + .finding { border-top: 1px solid #e6e9ee; margin-top: 18px; padding-top: 18px; }
              .warn { background: #fdf6e3; border: 1px solid #e8d9a0; border-radius: 6px;
                      padding: 14px; margin-bottom: 16px; }
              footer { color: #5b6472; font-size: 12.5px; margin-top: 36px;
                       border-top: 1px solid #dfe3e9; padding-top: 16px; }
              @media print { body { background: #fff; padding: 0; } .card { break-inside: avoid; } }
            </style></head><body><main>
            """);

        var local = result.StartedUtc.ToLocalTime();

        html.Append("<h1>RAVEN report</h1><p class=\"muted-text\">"
            + "<span class=\"muted-text\">Remote Access &amp; Visibility Examination Node</span><br />");
        html.Append(Text($"{local:dddd d MMMM yyyy, HH:mm}"));

        if (!string.IsNullOrWhiteSpace(machine))
        {
            html.Append(" &middot; ").Append(Text(machine));
        }

        html.Append(" &middot; ")
            .Append(result.Integrity.Elevated ? "ran as Administrator" : "ran without Administrator")
            .Append(" &middot; ")
            .Append(Text($"{result.Duration.TotalSeconds:F1}s"))
            .Append("</p>");

        html.Append("<div class=\"card verdict ").Append(VerdictClass(result.Verdict)).Append("\">")
            .Append("<h1 style=\"font-size:19px\">").Append(Text(result.Headline)).Append("</h1>")
            .Append("<p class=\"muted-text\">").Append(Text(result.Summary)).Append("</p>");

        if (result.MutingChangedVerdict)
        {
            html.Append("<div class=\"warn\"><b>This verdict reflects your allowlist.</b> ")
                .Append("With nothing muted it would read: <b>")
                .Append(Text(result.VerdictIfNothingMuted.ToString()))
                .Append("</b>.</div>");
        }

        html.Append("</div>");

        AppendChanges(html, diff);
        AppendFindings(html, result);
        AppendMuted(html, result);
        AppendCoverage(html, result);

        html.Append("<footer><b>What this report is not.</b> ")
            .Append(Text(UserModeLimitation))
            .Append("<br><br>This file contains details about this machine — program paths, "
                    + "network ports and file hashes. Treat it as you would any other record "
                    + "of what runs on your computer.</footer>");

        html.Append("</main></body></html>");

        return html.ToString();
    }

    private static void AppendChanges(StringBuilder html, ScanDiff? diff)
    {
        if (diff is null)
        {
            return;
        }

        html.Append("<h2>Since the previous scan</h2><div class=\"card\">")
            .Append("<p class=\"muted-text\">Compared against ")
            .Append(Text($"{diff.Previous.StartedUtc.ToLocalTime():d MMM yyyy, HH:mm}"))
            .Append(".</p>");

        if (diff.NothingChanged)
        {
            html.Append("<p>Nothing changed. That is not the same as nothing being there — "
                        + "the findings below are still present.</p>");
        }
        else
        {
            html.Append("<ul>");

            foreach (var f in diff.Appeared)
            {
                html.Append("<li><b>New</b> (").Append(Text(f.Severity.ToString())).Append("): ")
                    .Append(Text(f.Title)).Append("</li>");
            }

            foreach (var (was, now) in diff.Changed)
            {
                html.Append("<li>").Append(Text(was.Severity.ToString())).Append(" &rarr; ")
                    .Append(Text(now.Severity.ToString())).Append(": ")
                    .Append(Text(now.Title)).Append("</li>");
            }

            foreach (var f in diff.Gone)
            {
                html.Append("<li>No longer reported: ").Append(Text(f.Title)).Append("</li>");
            }

            html.Append("</ul>");
        }

        if (diff.ComparabilityCaveat is not null)
        {
            html.Append("<div class=\"warn\">").Append(Text(diff.ComparabilityCaveat)).Append("</div>");
        }

        html.Append("</div>");
    }

    private static void AppendFindings(StringBuilder html, ScanResult result)
    {
        html.Append("<h2>Findings — ").Append(result.Findings.Count).Append("</h2><div class=\"card\">");

        if (result.Findings.Count == 0)
        {
            html.Append("<p>Nothing was flagged in the areas this scan examined. "
                        + "See the coverage section for what it could not see.</p>");
        }

        foreach (var finding in result.Findings)
        {
            html.Append("<div class=\"finding\"><span class=\"badge s-")
                .Append(finding.Severity.ToString().ToLowerInvariant()).Append("\">")
                .Append(Text(finding.Severity.ToString().ToUpperInvariant()))
                .Append("</span> <span class=\"muted-text\" style=\"font-size:12px\">")
                .Append(Text(Confidence(finding.Confidence)))
                .Append("</span><h3 style=\"font-size:15px;margin:8px 0 6px\">")
                .Append(Text(finding.Title)).Append("</h3>")
                .Append("<p class=\"muted-text\">").Append(Text(finding.Explanation)).Append("</p>");

            if (!string.IsNullOrWhiteSpace(finding.Recommendation))
            {
                html.Append("<p><b>What to do:</b> ").Append(Text(finding.Recommendation)).Append("</p>");
            }

            if (finding.EvidenceChain.Count > 0)
            {
                html.Append("<table>");

                foreach (var e in finding.EvidenceChain)
                {
                    html.Append("<tr><td class=\"k\">").Append(Text(e.Label)).Append("</td><td><code>")
                        .Append(Text(e.Value)).Append("</code>");

                    if (e.Source is not null)
                    {
                        html.Append(" <span class=\"muted-text\">[").Append(Text(e.Source)).Append("]</span>");
                    }

                    html.Append("</td></tr>");
                }

                html.Append("</table>");
            }

            html.Append("</div>");
        }

        html.Append("</div>");
    }

    private static void AppendMuted(StringBuilder html, ScanResult result)
    {
        if (result.Suppressed.Count == 0)
        {
            return;
        }

        html.Append("<h2>Muted by the user — ").Append(result.Suppressed.Count)
            .Append("</h2><div class=\"card\"><p class=\"muted-text\">These were detected and "
                    + "withheld from the count and the verdict above.</p><table>");

        foreach (var s in result.Suppressed)
        {
            html.Append("<tr><td class=\"k\">").Append(Text(s.Finding.Severity.ToString()))
                .Append("</td><td>").Append(Text(s.Finding.Title))
                .Append("<br><span class=\"muted-text\">&ldquo;").Append(Text(s.Entry.Reason))
                .Append("&rdquo; — muted ")
                .Append(Text($"{s.Entry.CreatedUtc.ToLocalTime():d MMM yyyy}"))
                .Append(s.Entry.IsPinnedToFileContents
                    ? ", pinned to the file's contents"
                    : ", not pinned to any file")
                .Append("</span></td></tr>");
        }

        html.Append("</table></div>");
    }

    private static void AppendCoverage(StringBuilder html, ScanResult result)
    {
        html.Append("<h2>What this scan could not see — ").Append(result.Blindspots.Count)
            .Append("</h2><div class=\"card\">");

        if (result.Blindspots.Count == 0)
        {
            html.Append("<p>No blind spots were recorded.</p>");
        }
        else
        {
            html.Append("<table>");

            foreach (var b in result.Blindspots)
            {
                html.Append("<tr><td class=\"k\">").Append(Text(b.Area)).Append("</td><td>")
                    .Append(Text(b.Reason));

                if (b.Remedy is not null)
                {
                    html.Append("<br><span class=\"muted-text\">&rarr; ")
                        .Append(Text(b.Remedy)).Append("</span>");
                }

                html.Append("</td></tr>");
            }

            html.Append("</table>");
        }

        html.Append("</div><h2>Scan integrity</h2><div class=\"card\"><table>");

        foreach (var signal in result.Integrity.Signals)
        {
            var state = signal.Satisfied switch
            {
                true => "ok",
                false when signal.UnderminesResult => "FAILED — this scan could have been deceived",
                false => "not satisfied",
                null => "could not be determined",
            };

            html.Append("<tr><td class=\"k\">").Append(Text(signal.Name)).Append("</td><td><b>")
                .Append(Text(state)).Append("</b><br><span class=\"muted-text\">")
                .Append(Text(signal.Detail)).Append("</span></td></tr>");
        }

        html.Append("</table></div>");
    }

    private static string Confidence(Confidence confidence) => confidence switch
    {
        Model.Confidence.Confirmed => "confirmed",
        Model.Confidence.Likely => "likely",
        _ => "possible — may have a benign explanation",
    };

    private static string VerdictClass(VerdictLevel verdict) => verdict switch
    {
        VerdictLevel.CompromiseIndicated => "critical",
        VerdictLevel.RemoteAccessActive => "high",
        VerdictLevel.ReviewRecommended => "medium",
        _ => "quiet",
    };

    /// <summary>
    /// Encodes text for HTML.
    /// <para>
    /// Not a formality. Almost every string in a report is chosen by whatever is running
    /// on the scanned machine — process names, file paths, signer strings, service
    /// descriptions. A tool that pastes attacker-controlled text into a document the
    /// user opens in a browser has handed that attacker script execution in the report
    /// about them. Every interpolation into the HTML goes through here.
    /// </para>
    /// </summary>
    private static string Text(string? value) => WebUtility.HtmlEncode(value ?? string.Empty);
}
