using RatScan.Engine.Model;
using RatScan.Rules;

namespace RatScan.Engine.Detection;

/// <summary>
/// Identifies catalogued remote-access products from the process and connection facts.
/// <para>
/// Matching is deliberately layered. A process name on its own is weak evidence —
/// anything can be renamed <c>anydesk.exe</c>, and anything named <c>anydesk.exe</c>
/// can be something else — so the detector records which independent signals agreed
/// (name, signer, listening port) and sets confidence from that, rather than treating
/// a name hit as identification.
/// </para>
/// </summary>
public sealed class RemoteAccessToolDetector : IDetector
{
    private readonly IReadOnlyList<KnownTool> _catalogue;

    public RemoteAccessToolDetector(IReadOnlyList<KnownTool>? catalogue = null) =>
        _catalogue = catalogue ?? KnownToolCatalogue.Tools;

    public string Name => "Known remote-access software";

    public IEnumerable<Finding> Detect(
        DetectionContext context, CancellationToken cancellationToken = default)
    {
        var findings = new List<Finding>();

        foreach (var process in context.Processes.Processes)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (process.Name is null)
            {
                continue;
            }

            foreach (var tool in _catalogue)
            {
                var match = Match(process, tool);
                if (match is not null)
                {
                    findings.Add(match);
                }
            }
        }

        // One product, one finding. A tool with four helper processes produced four
        // near-identical entries, which pushes real signal off the top of the list and
        // makes the machine look busier than it is. The strongest match wins, since
        // that is the one carrying the most corroborating evidence.
        return findings
            .GroupBy(f => f.RuleId)
            .Select(g => g
                .OrderByDescending(f => f.Severity)
                .ThenByDescending(f => f.Confidence)
                .ThenByDescending(f => f.EvidenceChain.Count)
                .First())
            .ToList();
    }

    private static Finding? Match(ProcessFact process, KnownTool tool)
    {
        var nameHit = tool.Processes.Any(p =>
            string.Equals(p, process.Name, StringComparison.OrdinalIgnoreCase));

        if (!nameHit)
        {
            return null;
        }

        var evidence = new List<Evidence>
        {
            Evidence.Of("Process", process.Name!, "process enumeration"),
            Evidence.Of("PID", process.Pid.ToString()),
        };

        var signals = 1;

        var signer = process.Signature?.SignerName;
        var signerHit = signer is not null
                        && tool.Signers.Any(s => signer.Contains(s, StringComparison.OrdinalIgnoreCase));

        if (signerHit)
        {
            signals++;
            evidence.Add(Evidence.Of("Signed by", signer!, "Authenticode"));
        }
        else if (signer is not null)
        {
            evidence.Add(Evidence.Of("Signed by", signer, "Authenticode"));
        }

        var listeningPorts = process.Connections
            .Where(c => c.IsListener)
            .Select(c => c.LocalPort)
            .Distinct()
            .ToList();

        var portHits = tool.Ports.Intersect(listeningPorts).ToList();
        if (portHits.Count > 0)
        {
            signals++;
            evidence.Add(Evidence.Of("Listening on expected port(s)",
                string.Join(", ", portHits), "GetExtendedTcpTable"));
        }

        if (listeningPorts.Count > 0)
        {
            evidence.Add(Evidence.Of("All listening ports", string.Join(", ", listeningPorts)));
        }

        if (process.ImagePath is not null)
        {
            evidence.Add(Evidence.Of("Path", process.ImagePath));
        }

        // Impersonation is claimed ONLY when the binary fails signature verification
        // outright.
        //
        // It is tempting to also treat "valid signature, but the signer is not in our
        // list" as impersonation. That is unsound, and it fired on the very first live
        // run: the catalogue said TightVNC signs as "GlavSoft LLC", the installed copy
        // is signed "OOO GlavSoft", and a correctly-signed legitimate product was
        // accused of being an impostor at Critical severity. The catalogue is our data,
        // not ground truth — it goes stale, vendors rename, certificates get reissued.
        // An unrecognised signer lowers confidence and is surfaced as a caveat; it
        // never escalates severity.
        var status = process.Signature?.Status;
        var impersonating = status is not null
                            and not RatScan.Native.Signing.SignatureStatus.Valid
                            and not RatScan.Native.Signing.SignatureStatus.Unknown;

        var signerUnrecognised = tool.Signers.Count > 0 && signer is not null && !signerHit;

        if (impersonating)
        {
            evidence.Add(Evidence.Of("Signature status", status.ToString()!, "WinVerifyTrust"));
        }
        else if (signerUnrecognised)
        {
            evidence.Add(Evidence.Of("Expected signer", string.Join(" or ", tool.Signers),
                "RatScan catalogue"));
        }

        return new Finding
        {
            RuleId = impersonating ? "remote-tool.unsigned-impostor" : $"remote-tool.{tool.Id}",
            Title = impersonating
                ? $"'{process.Name}' uses the {tool.Name} executable name but fails signature verification"
                : $"{tool.Name} is running",
            Severity = SeverityFor(tool, impersonating, portHits.Count > 0),
            Confidence = ConfidenceFor(signals, impersonating, signerUnrecognised),
            Category = FindingCategory.RemoteAccessSoftware,
            Subject = tool.Name,
            Pid = process.Pid,
            MitreTechnique = "T1219",
            Explanation = Explain(tool, process, impersonating, signerUnrecognised, portHits, status),
            Recommendation = impersonating
                ? "Treat this binary as untrusted. A file using a known product's name that does not "
                  + "carry a valid signature is either tampered with or deliberately disguised. Do not "
                  + "run it again until you know where it came from."
                : $"If you installed {tool.Name} yourself and still use it, this is expected — you can "
                  + "allowlist it. If you did not install it, or no longer use it, remove it: while it "
                  + "runs, anyone with its credentials can connect.",
            EvidenceChain = evidence,
        };
    }

    private static Severity SeverityFor(KnownTool tool, bool impersonating, bool listening)
    {
        if (impersonating)
        {
            return Severity.Critical;
        }

        return (tool.ParsedCategory, tool.ParsedAbuse, listening) switch
        {
            (ToolCategory.RatFamily, _, _) => Severity.Critical,
            (ToolCategory.Tunneler, _, _) => Severity.High,
            (_, AbuseLevel.High, true) => Severity.High,
            (_, AbuseLevel.High, false) => Severity.Medium,
            (_, _, true) => Severity.Medium,
            _ => Severity.Low,
        };
    }

    private static Confidence ConfidenceFor(int signals, bool impersonating, bool signerUnrecognised)
    {
        if (impersonating)
        {
            return Confidence.Likely;
        }

        // An unrecognised signer means the identification itself is less certain — it
        // may be this product under a new certificate, or a different product sharing
        // an executable name. Either way, do not claim certainty.
        if (signerUnrecognised)
        {
            return Confidence.Possible;
        }

        return signals >= 3 ? Confidence.Confirmed
            : signals == 2 ? Confidence.Likely
            : Confidence.Possible;
    }

    private static string Explain(
        KnownTool tool,
        ProcessFact process,
        bool impersonating,
        bool signerUnrecognised,
        IReadOnlyList<int> portHits,
        RatScan.Native.Signing.SignatureStatus? status)
    {
        if (impersonating)
        {
            return $"A process named '{process.Name}' is running, which is the executable name used by "
                   + $"{tool.Name}. Its signature status is '{status}', so it is not a validly signed "
                   + "copy of that product. Legitimate builds are signed by their vendor, making this "
                   + "either a modified binary or something using a trusted name as cover.";
        }

        var capability = DescribeCapabilities(tool);
        var listening = portHits.Count > 0
            ? $" It is listening on {string.Join(", ", portHits)}, which means it is accepting incoming "
              + "connections right now."
            : string.Empty;

        var abuse = tool.ParsedAbuse == AbuseLevel.High
            ? $" {tool.Name} is also one of the products most often used against people in "
              + "remote-access scams and intrusions, so it is worth being certain you installed it."
            : string.Empty;

        // Stated as a caveat on our own data rather than as an accusation.
        var signerNote = signerUnrecognised
            ? $" Note: this copy is signed by '{process.Signature?.SignerName}', which is not the "
              + "publisher RatScan has on file for it. That may simply mean the catalogue is out of "
              + "date, or that a different product shares this executable name — it is not by itself "
              + "evidence of anything wrong."
            : string.Empty;

        return $"{tool.Name}{(tool.Vendor is not null ? $" by {tool.Vendor}" : "")} is running on this "
               + $"machine. {capability}{listening}{abuse}"
               + (tool.Notes is not null ? $" {tool.Notes.Trim()}" : string.Empty)
               + signerNote;
    }

    /// <summary>
    /// Turns capability tags into what someone can actually do to the user. The point
    /// of the finding is that a non-specialist can decide what to do about it.
    /// </summary>
    private static string DescribeCapabilities(KnownTool tool)
    {
        var parts = new List<string>();

        if (tool.Capabilities.Contains("screen-view"))
        {
            parts.Add("see your screen");
        }

        if (tool.Capabilities.Contains("input-control"))
        {
            parts.Add("control your keyboard and mouse");
        }

        if (tool.Capabilities.Contains("file-transfer"))
        {
            parts.Add("transfer files to and from this machine");
        }

        if (tool.Capabilities.Contains("command-execution"))
        {
            parts.Add("run commands as an administrator");
        }

        if (tool.Capabilities.Contains("keylogging"))
        {
            parts.Add("record what you type");
        }

        if (tool.Capabilities.Contains("inbound-tunnel"))
        {
            parts.Add("expose this machine's ports to the internet, bypassing your router and firewall");
        }

        if (tool.Capabilities.Contains("network-access"))
        {
            parts.Add("join this machine to a private network with other devices");
        }

        if (tool.Capabilities.Contains("clipboard-sharing"))
        {
            parts.Add("read and write your clipboard");
        }

        if (parts.Count == 0)
        {
            return "It provides remote access to this machine.";
        }

        var joined = parts.Count == 1
            ? parts[0]
            : string.Join(", ", parts[..^1]) + " and " + parts[^1];

        var unattended = tool.Capabilities.Contains("unattended")
            ? " It can be configured for unattended access, meaning a connection does not need anyone "
              + "sitting at this machine to approve it."
            : string.Empty;

        return $"Someone connecting to it can {joined}.{unattended}";
    }
}
