using RatScan.Engine.Collectors;
using RatScan.Engine.Detection;
using RatScan.Engine.Model;
using RatScan.Native.Signing;
using RatScan.Rules;
using Xunit.Abstractions;

namespace RatScan.Tests;

/// <summary>
/// The persistence detector's job is to stay silent on a healthy machine and speak up
/// on a compromised one, so most of what is worth asserting here is what it refuses to
/// report. Rules are exercised against synthetic entries; the live test at the end runs
/// the whole thing against this machine, because every false positive this project has
/// shipped passed its unit tests first.
/// </summary>
public sealed class PersistenceDetectorTests(ITestOutputHelper output)
{
    private static PersistenceEntry Entry(
        PersistenceSurface surface,
        string name,
        string? command = null,
        string? imagePath = null,
        PersistenceScope scope = PersistenceScope.Machine,
        bool fileless = false,
        SignatureStatus? signature = null,
        string? signer = null) =>
        new()
        {
            Surface = surface,
            Scope = scope,
            Name = name,
            Command = command,
            ImagePath = imagePath,
            Location = @"HKLM\SOFTWARE\Test",
            IsFileless = fileless,
            Signature = signature is null
                ? null
                : new SignatureInfo
                {
                    FilePath = imagePath ?? name,
                    Status = signature.Value,
                    SignerName = signer,
                },
            EvidenceChain = [Evidence.Of(name, command ?? string.Empty)],
        };

    private static List<Finding> Detect(params PersistenceEntry[] entries) =>
        new PersistenceDetector(Catalogue)
            .Detect(new DetectionContext
            {
                Processes = new ProcessCollectionResult(),
                Persistence = new PersistenceResult { Entries = entries },
            })
            .ToList();

    private static readonly IReadOnlyList<KnownTool> Catalogue =
    [
        new()
        {
            Id = "testvnc",
            Name = "TestVNC",
            Category = "remote-desktop",
            Abuse = "medium",
            Capabilities = ["screen-view", "input-control"],
            Processes = ["testvnc.exe"],
            Services = ["testvncservice"],
            Signers = ["Test Publisher"],
        },
    ];

    // ---- what it must not report ------------------------------------------------

    [Fact]
    public void Winlogon_at_the_windows_defaults_is_not_a_finding()
    {
        var findings = Detect(
            Entry(PersistenceSurface.WinlogonShell, "Shell", "explorer.exe"),
            Entry(PersistenceSurface.WinlogonUserinit, "Userinit", @"C:\windows\system32\userinit.exe,"));

        Assert.Empty(findings);
    }

    [Fact]
    public void An_ordinary_run_key_entry_is_not_a_finding()
    {
        var findings = Detect(Entry(
            PersistenceSurface.RunKey, "OneDrive",
            @"C:\Program Files\Microsoft OneDrive\OneDrive.exe /background",
            @"C:\Program Files\Microsoft OneDrive\OneDrive.exe"));

        Assert.Empty(findings);
    }

    [Fact]
    public void An_execution_options_key_without_a_debugger_value_is_not_a_finding()
    {
        // IFEO keys exist for plenty of benign reasons. Only a Debugger value makes
        // Windows launch something else in the program's place.
        var findings = Detect(Entry(
            PersistenceSurface.ImageFileExecutionOptions, "GlobalFlag", "0x100"));

        Assert.Empty(findings);
    }

    // ---- what it must report ----------------------------------------------------

    [Fact]
    public void A_catalogued_tool_set_to_auto_start_is_reported_as_persistence()
    {
        var findings = Detect(Entry(
            PersistenceSurface.RunKey, "TestVNC",
            @"C:\Program Files\TestVNC\testvnc.exe -service",
            @"C:\Program Files\TestVNC\testvnc.exe"));

        var finding = Assert.Single(findings);

        Assert.Equal(FindingCategory.Persistence, finding.Category);
        Assert.Equal(Severity.High, finding.Severity);
        Assert.Contains("TestVNC", finding.Title, StringComparison.Ordinal);

        // The point of the finding: removing the program is not enough on its own.
        Assert.Contains("coming back", finding.Explanation, StringComparison.Ordinal);
    }

    [Fact]
    public void A_service_entry_matches_on_the_service_name()
    {
        var findings = Detect(Entry(
            PersistenceSurface.Service, "testvncservice",
            @"C:\Program Files\TestVNC\hidden.exe"));

        Assert.Single(findings);
    }

    [Fact]
    public void A_per_user_entry_is_ranked_below_a_machine_wide_one()
    {
        var user = Detect(Entry(
            PersistenceSurface.RunKey, "TestVNC", null,
            @"C:\Users\x\testvnc.exe", PersistenceScope.User));

        Assert.Equal(Severity.Medium, Assert.Single(user).Severity);
    }

    [Fact]
    public void Winlogon_shell_with_an_extra_command_is_critical()
    {
        var findings = Detect(Entry(
            PersistenceSurface.WinlogonShell, "Shell", @"explorer.exe, C:\ProgramData\svchost.exe"));

        var finding = Assert.Single(findings);

        Assert.Equal(Severity.Critical, finding.Severity);
        Assert.Equal(Confidence.Confirmed, finding.Confidence);
        Assert.Contains("svchost.exe", string.Join(" ", finding.EvidenceChain.Select(e => e.Value)),
            StringComparison.Ordinal);
    }

    [Fact]
    public void An_execution_options_debugger_is_reported()
    {
        var findings = Detect(Entry(
            PersistenceSurface.ImageFileExecutionOptions, "Debugger",
            @"C:\ProgramData\thing.exe", @"C:\ProgramData\thing.exe"));

        Assert.Equal(Severity.High, Assert.Single(findings).Severity);
    }

    [Fact]
    public void Fileless_persistence_is_reported()
    {
        var findings = Detect(Entry(
            PersistenceSurface.WmiEventSubscription, "Updater",
            "powershell -enc SQBFAFgA", fileless: true));

        var finding = Assert.Single(findings);

        Assert.Equal("persistence.fileless", finding.RuleId);
        Assert.Contains("rather than a program on disk", finding.Explanation, StringComparison.Ordinal);
    }

    // ---- what the signature is allowed to change ---------------------------------

    [Fact]
    public void An_unsigned_binary_starting_automatically_is_not_a_finding_by_itself()
    {
        // Measured on this machine: 5 of 308 auto-start entries point at an unsigned
        // binary, and all five are the user's own software — a download manager, a
        // privacy utility, an Intel graphics service. A rule that fired on "unsigned and
        // automatic" would produce more findings than the entire detector currently
        // does, and every one of them would be wrong. Signature narrows a finding that
        // already has a reason to exist; it never manufactures one.
        var findings = Detect(
            Entry(PersistenceSurface.RunKey, "Updater", null, @"C:\Program Files\Thing\thing.exe",
                signature: SignatureStatus.Unsigned));

        Assert.Empty(findings);
    }

    [Fact]
    public void An_unsigned_library_on_an_injection_surface_is_critical()
    {
        // AppInit_DLLs is empty on a stock install, and the one benign explanation for
        // something being there — an older security or accessibility product — is always
        // signed. Unsigned removes the caveat that held this at High.
        var findings = Detect(Entry(
            PersistenceSurface.AppInitDll, "AppInit_DLLs",
            @"C:\ProgramData\hook.dll", @"C:\ProgramData\hook.dll",
            signature: SignatureStatus.Unsigned));

        var finding = Assert.Single(findings);

        Assert.Equal(Severity.Critical, finding.Severity);
        Assert.Contains("does not fit", finding.Explanation, StringComparison.Ordinal);
    }

    [Fact]
    public void A_library_whose_signature_could_not_be_read_keeps_the_benign_caveat()
    {
        // The invariant that costs this project the most when it is broken: Unknown is
        // not Unsigned. A locked or deleted file must not be escalated as though the
        // scan had established something about it.
        var findings = Detect(Entry(
            PersistenceSurface.AppInitDll, "AppInit_DLLs",
            @"C:\ProgramData\hook.dll", @"C:\ProgramData\hook.dll",
            signature: SignatureStatus.Unknown));

        var finding = Assert.Single(findings);

        Assert.Equal(Severity.High, finding.Severity);
        Assert.Contains("still use it legitimately", finding.Explanation, StringComparison.Ordinal);
    }

    [Fact]
    public void A_catalogued_tool_reaches_confirmed_only_when_the_signer_agrees()
    {
        var onName = Assert.Single(Detect(Entry(
            PersistenceSurface.RunKey, "TestVNC", null, @"C:\x\testvnc.exe",
            signature: SignatureStatus.Valid, signer: "Some Other Publisher")));

        var onSigner = Assert.Single(Detect(Entry(
            PersistenceSurface.RunKey, "TestVNC", null, @"C:\x\testvnc.exe",
            signature: SignatureStatus.Valid, signer: "Test Publisher, Inc.")));

        // A signer the catalogue does not recognise is not evidence against anything —
        // catalogues go stale and certificates get reissued. It withholds confidence
        // rather than adding suspicion, and severity is identical either way.
        Assert.Equal(Confidence.Likely, onName.Confidence);
        Assert.Equal(Confidence.Confirmed, onSigner.Confidence);
        Assert.Equal(onName.Severity, onSigner.Severity);
    }

    [Fact]
    public void Every_finding_states_where_it_stands_on_the_signature()
    {
        // Invariant 9 applied to signatures: "not checked", "could not be checked" and
        // "checked, and there is none" must never render identically, because only the
        // last says anything about the file.
        var notChecked = Assert.Single(Detect(Entry(
            PersistenceSurface.RunKey, "TestVNC", null, @"C:\x\testvnc.exe")));

        var unreadable = Assert.Single(Detect(Entry(
            PersistenceSurface.RunKey, "TestVNC", null, @"C:\x\testvnc.exe",
            signature: SignatureStatus.Unknown)));

        var none = Assert.Single(Detect(Entry(
            PersistenceSurface.RunKey, "TestVNC", null, @"C:\x\testvnc.exe",
            signature: SignatureStatus.Unsigned)));

        static string Signature(Finding f) =>
            f.EvidenceChain.Single(e => e.Label == "Signature").Value;

        Assert.Equal("not verified for this entry", Signature(notChecked));
        Assert.StartsWith("could not be checked", Signature(unreadable), StringComparison.Ordinal);
        Assert.StartsWith("none", Signature(none), StringComparison.Ordinal);
    }

    // ---- integration with the rest of the product --------------------------------

    [Fact]
    public void Every_persistence_finding_can_be_muted()
    {
        // Persistence findings are the ones a user is most likely to want silenced —
        // it is their own remote-desktop tool, set to start with Windows, on purpose.
        // Muting requires a stable identity, so the absence of one is a defect.
        var findings = Detect(
            Entry(PersistenceSurface.RunKey, "TestVNC", null, @"C:\x\testvnc.exe"),
            Entry(PersistenceSurface.WinlogonShell, "Shell", @"explorer.exe, C:\x\bad.exe"),
            Entry(PersistenceSurface.WmiEventSubscription, "U", "x", fileless: true));

        Assert.Equal(3, findings.Count);
        Assert.All(findings, f => Assert.True(f.CanBeMuted));
    }

    [Fact]
    public void One_product_across_several_surfaces_is_one_finding_per_location()
    {
        // The same binary in a Run key and the Startup folder is one thing to deal
        // with; the same product installed twice in different places is two.
        var findings = Detect(
            Entry(PersistenceSurface.RunKey, "TestVNC", null, @"C:\x\testvnc.exe"),
            Entry(PersistenceSurface.StartupFolder, "TestVNC", null, @"C:\x\testvnc.exe"),
            Entry(PersistenceSurface.RunKey, "TestVNC2", null, @"C:\other\testvnc.exe"));

        Assert.Equal(2, findings.Count);
    }

    // ---- against this machine -----------------------------------------------------

    [Fact]
    public void Stays_quiet_on_this_machine_except_for_what_is_really_there()
    {
        var entries = new PersistenceCollector().Collect();

        var findings = new PersistenceDetector()
            .Detect(new DetectionContext
            {
                Processes = new ProcessCollectionResult(),
                Persistence = entries,
            })
            .ToList();

        output.WriteLine($"{entries.Entries.Count} auto-start entries -> {findings.Count} findings");
        output.WriteLine("");

        foreach (var group in entries.Entries.GroupBy(e => e.Surface).OrderByDescending(g => g.Count()))
        {
            output.WriteLine($"  {group.Key,-28} {group.Count()}");
        }

        output.WriteLine("");

        // The signature distribution is printed, not asserted. It is the measurement any
        // signature-based rule has to be designed against: a threshold picked from first
        // principles rather than from what a healthy machine actually looks like is how
        // this project would ship a rule that fires on everyone.
        foreach (var group in entries.Entries
            .Where(e => e.ImagePath is not null)
            .GroupBy(e => e.Signature?.Status)
            .OrderByDescending(g => g.Count()))
        {
            output.WriteLine($"  signature {group.Key?.ToString() ?? "(not verified)",-18} {group.Count()}");

            foreach (var entry in group
                .Where(e => group.Key is not SignatureStatus.Valid)
                .DistinctBy(e => e.ImagePath, StringComparer.OrdinalIgnoreCase))
            {
                output.WriteLine($"      {entry.Surface}/{entry.Scope} {entry.Name} -> {entry.ImagePath}");
            }
        }

        output.WriteLine("");

        foreach (var finding in findings.OrderByDescending(f => f.Severity))
        {
            output.WriteLine($"  [{finding.Severity}/{finding.Confidence}] {finding.Title}");
            output.WriteLine($"      {finding.Subject}");
        }

        // Not an assertion about how many findings are correct - only that the detector
        // is not indiscriminate. A rule set that fires on a large share of a healthy
        // machine's auto-start entries is noise, whatever each individual finding says.
        Assert.True(
            findings.Count < entries.Entries.Count / 10,
            $"{findings.Count} findings from {entries.Entries.Count} entries is too noisy to trust.");

        // Anything reported has to be actionable: the user must be able to find it.
        Assert.All(findings, f => Assert.False(string.IsNullOrWhiteSpace(f.Recommendation)));
    }
}
