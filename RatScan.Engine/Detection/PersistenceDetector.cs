
using RatScan.Engine.Model;
using RatScan.Native.Signing;
using RatScan.Rules;

namespace RatScan.Engine.Detection;

/// <summary>
/// Judges the auto-start entries the persistence collector gathered.
/// <para>
/// Persistence is what turns an incident into a residency. Ending a process is a
/// temporary fix if something puts it back at the next logon, so an auto-start entry
/// belonging to remote-access software is a materially different statement from the same
/// software merely running — and the recommendation has to say so, or the user "fixes"
/// the machine and finds it undone by morning.
/// </para>
/// <para>
/// Every rule here was written against a measured baseline of this machine: 165 entries,
/// of which zero were fileless, zero occupied the injection surfaces, and Winlogon held
/// the Windows defaults. Rules that fire on a healthy desktop are worse than no rules —
/// they teach the user that this section is noise, and the one entry that mattered
/// scrolls past with the rest.
/// </para>
/// </summary>
public sealed class PersistenceDetector : IDetector
{
    private readonly IReadOnlyList<KnownTool> _catalogue;

    public PersistenceDetector(IReadOnlyList<KnownTool>? catalogue = null) =>
        _catalogue = catalogue ?? KnownToolCatalogue.Tools;

    public string Name => "Auto-start persistence";

    /// <summary>
    /// Surfaces that exist to load code into other programs, and which are empty on a
    /// stock Windows install. Anything at all here is worth saying out loud.
    /// </summary>
    private static readonly PersistenceSurface[] InjectionSurfaces =
    [
        PersistenceSurface.AppInitDll,
        PersistenceSurface.AppCertDll,
        PersistenceSurface.ImageFileExecutionOptions,
    ];

    public IEnumerable<Finding> Detect(
        DetectionContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (context.Persistence is null)
        {
            return [];
        }

        var findings = new List<Finding>();

        foreach (var entry in context.Persistence.Entries)
        {
            cancellationToken.ThrowIfCancellationRequested();

            findings.AddRange(CataloguedTool(entry));

            var hijack = WinlogonHijack(entry) ?? Injection(entry) ?? Fileless(entry);
            if (hijack is not null)
            {
                findings.Add(hijack);
            }
        }

        // One product, one finding, as with the running-process detector: a tool with a
        // Run key, a service and a scheduled task is one thing to deal with, not three.
        return findings
            .GroupBy(f => f.RuleId + "|" + (f.IdentityKey ?? f.Subject ?? string.Empty),
                StringComparer.OrdinalIgnoreCase)
            .Select(g => g
                .OrderByDescending(f => f.Severity)
                .ThenByDescending(f => f.Confidence)
                .ThenByDescending(f => f.EvidenceChain.Count)
                .First())
            .ToList();
    }

    /// <summary>
    /// A catalogued remote-access product configured to start by itself.
    /// <para>
    /// Matched on the executable's file name, or on the service name for a service
    /// entry. Confidence stays at <see cref="Confidence.Likely"/> on a name alone —
    /// anything can be called <c>winvnc.exe</c> — and only reaches
    /// <see cref="Confidence.Confirmed"/> when the signature agrees with the catalogue.
    /// </para>
    /// </summary>
    private IEnumerable<Finding> CataloguedTool(PersistenceEntry entry)
    {
        var fileName = entry.ImagePath is null
            ? null
            : Path.GetFileName(entry.ImagePath);

        if (fileName is null && entry.Surface is not PersistenceSurface.Service)
        {
            yield break;
        }

        foreach (var tool in _catalogue)
        {
            var nameHit = fileName is not null && tool.Processes.Any(p =>
                string.Equals(p, fileName, StringComparison.OrdinalIgnoreCase));

            var serviceHit = entry.Surface is PersistenceSurface.Service
                && tool.Services.Any(s =>
                    string.Equals(s, entry.Name, StringComparison.OrdinalIgnoreCase));

            if (!nameHit && !serviceHit)
            {
                continue;
            }

            var evidence = new List<Evidence>
            {
                Evidence.Of("Auto-start", Describe(entry.Surface), entry.Location),
                Evidence.Of("Entry", entry.Name, entry.Location),
            };

            if (entry.Command is not null)
            {
                evidence.Add(Evidence.Of("Command", entry.Command, entry.Location));
            }

            var signerAgrees = entry.Signature?.SignerName is { } signer
                && tool.Signers.Any(s => signer.Contains(s, StringComparison.OrdinalIgnoreCase));

            // Stated on every finding, agreement or not. A user deciding whether an
            // auto-start entry is theirs needs to know who signed it far more than they
            // need to know that RAVEN recognised the name.
            evidence.Add(DescribeSignature(entry));

            if (signerAgrees)
            {
                // Sourced to the catalogue by name, because that is what it is. The
                // catalogue raises confidence in an identification; it never convicts,
                // and a signer it does not recognise is not evidence of anything.
                evidence.Add(Evidence.Of(
                    "Signer matches catalogue",
                    entry.Signature!.SignerName!,
                    $"RAVEN catalogue entry for {tool.Name}"));
            }

            yield return new Finding
            {
                RuleId = $"persistence.tool.{tool.Id}",
                Title = $"{tool.Name} is configured to start automatically",
                Category = FindingCategory.Persistence,

                // A machine-scope entry starts for everyone, including before anyone
                // logs in; that is a stronger position than a per-user entry.
                Severity = entry.Scope is PersistenceScope.Machine ? Severity.High : Severity.Medium,
                Confidence = signerAgrees ? Confidence.Confirmed : Confidence.Likely,
                Subject = tool.Name,
                IdentityKey = entry.ImagePath ?? $"persistence:{entry.Location}\\{entry.Name}",
                EvidenceChain = evidence,

                Explanation =
                    $"{tool.Name} is not just present — it is set to start on its own, via "
                    + $"{Describe(entry.Surface)}. {Capability(tool)} Because this runs "
                    + "automatically, ending the program does not stop it coming back at the next "
                    + (entry.Scope is PersistenceScope.Machine ? "boot." : "logon."),

                Recommendation =
                    "If this is yours, nothing needs doing. If it is not, remove the auto-start "
                    + $"entry as well as the program — the entry lives at {entry.Location} under "
                    + $"the name \"{entry.Name}\". Removing the entry does not stop a copy that is "
                    + "already running.",
            };
        }
    }

    /// <summary>
    /// Winlogon's shell or user-init pointing somewhere other than Windows' own.
    /// <para>
    /// These two values decide what runs when a user logs in, before anything else. On
    /// every healthy machine they are <c>explorer.exe</c> and <c>userinit.exe</c>;
    /// appending a second command is a classic and durable hijack, and it is one of the
    /// few checks here where a deviation has essentially no benign explanation.
    /// </para>
    /// </summary>
    private static Finding? WinlogonHijack(PersistenceEntry entry)
    {
        if (entry.Surface is not (PersistenceSurface.WinlogonShell or PersistenceSurface.WinlogonUserinit))
        {
            return null;
        }

        var expected = entry.Surface is PersistenceSurface.WinlogonShell
            ? "explorer.exe"
            : "userinit.exe";

        // Both values are comma-separated lists, and the default carries a trailing
        // comma. Empty segments are normal; extra populated ones are the finding.
        var parts = (entry.Command ?? string.Empty)
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .ToList();

        var unexpected = parts
            .Where(p => !string.Equals(Path.GetFileName(p.Trim('"')), expected, StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (unexpected.Count == 0 && parts.Count > 0)
        {
            return null;
        }

        return new Finding
        {
            RuleId = $"persistence.winlogon.{(entry.Surface is PersistenceSurface.WinlogonShell ? "shell" : "userinit")}",
            Title = $"Winlogon {entry.Name} runs something other than Windows' own {expected}",
            Category = FindingCategory.Persistence,
            Severity = Severity.Critical,
            Confidence = Confidence.Confirmed,
            Subject = entry.Name,
            IdentityKey = $"persistence:{entry.Location}\\{entry.Name}",

            EvidenceChain =
            [
                Evidence.Of("Configured", entry.Command ?? "(empty)", entry.Location),
                Evidence.Of("Windows default", expected, "expected value"),
                .. unexpected.Select(u => Evidence.Of("Unexpected", u, entry.Location)),
            ],

            Explanation =
                $"This value decides what Windows runs the moment someone logs in. It should be "
                + $"{expected} and nothing else; here it is \"{entry.Command}\". Anything listed "
                + "here starts with the user's session automatically, every time, before the "
                + "desktop appears.",

            Recommendation =
                $"Restore this value to \"{expected}\" at {entry.Location}, then find out what the "
                + "extra entry points at before deleting it — it is the best evidence of what put "
                + "it there.",
        };
    }

    /// <summary>
    /// Anything occupying the surfaces whose only purpose is loading a DLL into other
    /// processes. Empty on a stock install, so presence alone is the signal.
    /// </summary>
    private static Finding? Injection(PersistenceEntry entry)
    {
        if (!InjectionSurfaces.Contains(entry.Surface))
        {
            return null;
        }

        // An IFEO key exists for plenty of benign reasons; only a Debugger value turns
        // it into "run this instead of that program".
        if (entry.Surface is PersistenceSurface.ImageFileExecutionOptions
            && !entry.Name.Contains("Debugger", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        // The only reason this rule is not stated as proof is that a handful of older
        // security and accessibility products still use these surfaces legitimately —
        // and every one of those is signed. An unsigned library here has no such
        // explanation left, so the caveat that held the severity down no longer applies.
        // Unknown is not Unsigned: a library that could not be read keeps the caveat.
        var unsigned = entry.Signature?.Status is SignatureStatus.Unsigned;

        var what = entry.Surface switch
        {
            PersistenceSurface.AppInitDll =>
                "AppInit_DLLs loads a library into almost every program that draws a window.",
            PersistenceSurface.AppCertDll =>
                "AppCertDlls loads a library into every program that creates a process.",
            _ =>
                "An Image File Execution Options debugger replaces one program with another: "
                + "Windows launches the debugger instead of the program the user asked for.",
        };

        return new Finding
        {
            RuleId = $"persistence.injection.{entry.Surface}".ToLowerInvariant(),
            Title = $"{Describe(entry.Surface)} is in use",
            Category = FindingCategory.Persistence,
            Severity = unsigned ? Severity.Critical : Severity.High,
            Confidence = Confidence.Likely,
            Subject = entry.ImagePath ?? entry.Name,
            IdentityKey = entry.ImagePath ?? $"persistence:{entry.Location}\\{entry.Name}",

            EvidenceChain =
            [
                Evidence.Of("Surface", Describe(entry.Surface), entry.Location),
                Evidence.Of("Entry", entry.Name, entry.Location),
                Evidence.Of("Value", entry.Command ?? entry.ImagePath ?? "(none)", entry.Location),
                DescribeSignature(entry),
            ],

            Explanation =
                $"{what} This surface is empty on a stock Windows install, so something put this "
                + "here deliberately. "
                + (unsigned
                    ? "The library named here carries no Authenticode signature at all, so the "
                      + "usual benign explanation — an older security or accessibility product — "
                      + "does not fit: those are signed."
                    : "A few older security and accessibility products still use it legitimately, "
                      + "which is why this is not stated as proof."),

            Recommendation =
                $"Identify what \"{entry.ImagePath ?? entry.Name}\" is before removing it. If you "
                + "do not recognise it, treat every program on this machine as having had that "
                + "library loaded into it.",
        };
    }

    /// <summary>
    /// Persistence that runs code with no file on disk. Nothing legitimate needs to be
    /// invisible to a file scan.
    /// </summary>
    private static Finding? Fileless(PersistenceEntry entry)
    {
        if (!entry.IsFileless)
        {
            return null;
        }

        return new Finding
        {
            RuleId = "persistence.fileless",
            Title = $"Fileless auto-start entry: {entry.Name}",
            Category = FindingCategory.Persistence,
            Severity = Severity.High,
            Confidence = Confidence.Likely,
            Subject = entry.Name,
            IdentityKey = $"persistence:{entry.Location}\\{entry.Name}",

            EvidenceChain =
            [
                Evidence.Of("Surface", Describe(entry.Surface), entry.Location),
                Evidence.Of("Entry", entry.Name, entry.Location),
                Evidence.Of("Payload", entry.Command ?? "(stored in place)", entry.Location),
            ],

            Explanation =
                "This entry carries its code with it — a script body stored in the registry or in "
                + "WMI rather than a program on disk. It survives reboots, and a scan that only "
                + "looks at files will not find it. That is a deliberate property, and it is one "
                + "very few legitimate installers want.",

            Recommendation =
                $"Read the stored command at {entry.Location} before removing it. If it is "
                + "obfuscated or fetches something from the network, treat this machine as "
                + "compromised rather than merely misconfigured.",
        };
    }

    /// <summary>
    /// States the signature position of an entry's image.
    /// <para>
    /// Keeps three things apart that a shorter rendering would collapse: verification was
    /// never run, verification ran and could not reach the file, and verification ran and
    /// the file carries nothing. Only the last is a fact about the file — the other two
    /// are facts about the scan, and a user who cannot tell them apart cannot tell a
    /// limitation from a result.
    /// </para>
    /// </summary>
    private static Evidence DescribeSignature(PersistenceEntry entry)
    {
        var signature = entry.Signature;

        if (signature is null)
        {
            return Evidence.Of("Signature", "not verified for this entry", "Authenticode");
        }

        return signature.Status switch
        {
            SignatureStatus.Valid => Evidence.Of(
                "Signature",
                signature.SignerName is { } signer
                    ? $"valid, signed by {signer}"
                    : "valid, signer name unavailable",
                signature.IsCatalogSigned ? "Windows security catalog" : "embedded Authenticode"),

            SignatureStatus.Unsigned => Evidence.Of(
                "Signature", "none — the file carries no signature", "Authenticode"),

            SignatureStatus.Unknown => Evidence.Of(
                "Signature",
                $"could not be checked: {signature.Error ?? "the file could not be read"}",
                "Authenticode"),

            _ => Evidence.Of(
                "Signature",
                $"present but rejected ({signature.Status.ToString().ToLowerInvariant()})",
                "Authenticode"),
        };
    }

    private static string Capability(KnownTool tool) =>
        tool.Capabilities.Count == 0
            ? string.Empty
            : $"Someone using it can {string.Join(", ", tool.Capabilities).Replace("-", " ", StringComparison.Ordinal)}.";

    private static string Describe(PersistenceSurface surface) => surface switch
    {
        PersistenceSurface.RunKey => "a Run registry key",
        PersistenceSurface.RunOnceKey => "a RunOnce registry key",
        PersistenceSurface.StartupFolder => "the Startup folder",
        PersistenceSurface.ScheduledTask => "a scheduled task",
        PersistenceSurface.WmiEventSubscription => "a WMI event subscription",
        PersistenceSurface.WinlogonShell => "the Winlogon shell value",
        PersistenceSurface.WinlogonUserinit => "the Winlogon userinit value",
        PersistenceSurface.AppInitDll => "AppInit_DLLs injection",
        PersistenceSurface.AppCertDll => "AppCertDlls injection",
        PersistenceSurface.ImageFileExecutionOptions => "an Image File Execution Options debugger",
        PersistenceSurface.ComHijack => "a COM registration",
        PersistenceSurface.LsaPackage => "an LSA security package",
        PersistenceSurface.PrintMonitor => "a print monitor",
        PersistenceSurface.NetshHelper => "a netsh helper DLL",
        PersistenceSurface.Service => "a Windows service",
        PersistenceSurface.ActiveSetup => "an Active Setup component",
        PersistenceSurface.PowerShellProfile => "a PowerShell profile script",
        _ => surface.ToString(),
    };
}
