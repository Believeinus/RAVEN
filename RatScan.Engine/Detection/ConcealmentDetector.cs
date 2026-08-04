using System.Globalization;
using RatScan.Engine.Model;
using RatScan.Native.Processes;
using RatScan.Native.Signing;

namespace RatScan.Engine.Detection;

/// <summary>
/// Finds objects that are visible to one kernel interface and hidden from another.
/// <para>
/// This is the detector the whole architecture exists to enable, and it works
/// differently from every other rule here. It does not recognise malware. It does not
/// consult a catalogue. It notices that two independent parts of Windows disagree
/// about what is running, and a disagreement is not something benign software
/// produces. That makes it the only detector capable of catching a RAT nobody has
/// seen before.
/// </para>
/// <para>
/// The cost of being wrong is proportionally high — "something is hiding on your
/// machine" is the most alarming thing this tool can say — so every finding here
/// requires a confirmation pass to have already ruled out process churn, and every
/// source involved must have actually succeeded.
/// </para>
/// </summary>
public sealed class ConcealmentDetector : IDetector
{
    public string Name => "Cross-view concealment";

    public IEnumerable<Finding> Detect(
        DetectionContext context, CancellationToken cancellationToken = default)
    {
        var findings = new List<Finding>();

        if (!context.Processes.UsableForCrossView)
        {
            // Fewer than two independent views means nothing can be corroborated.
            // Silence here would imply "checked and clean", so say what happened.
            findings.Add(new Finding
            {
                RuleId = "concealment.unavailable",
                Title = "Concealment detection could not run",
                Severity = Severity.Info,
                Confidence = Confidence.Confirmed,
                Category = FindingCategory.ScanIntegrity,
                Explanation = "Fewer than two process enumeration sources succeeded, so their "
                              + "results could not be cross-checked. A process hidden from one "
                              + "interface would not have been noticed.",
                Recommendation = "Re-run the scan, elevated if possible.",
                EvidenceChain = context.Processes.Coverage
                    .Select(c => Evidence.Of(c.Source, c.Succeeded ? "ok" : c.Error ?? "failed"))
                    .ToList(),
            });

            return findings;
        }

        foreach (var process in context.Processes.Processes)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (process.ConfirmedHidden)
            {
                findings.Add(HiddenProcess(process));
                continue;
            }

            var selective = SelectivelyHidden(process);
            if (selective is not null)
            {
                findings.Add(selective);
            }
        }

        if (context.Drivers is { AddressesWithheld: false })
        {
            findings.AddRange(UnregisteredDrivers(context.Drivers));
        }

        return findings;
    }

    private static Finding HiddenProcess(ProcessFact process) => new()
    {
        RuleId = "concealment.hidden-process",
        Title = $"Process {process.Pid} is running but hidden from every listing interface",
        Severity = Severity.Critical,
        Confidence = Confidence.Confirmed,
        Category = FindingCategory.Concealment,
        Subject = process.Name ?? $"PID {process.Pid}",
        Pid = process.Pid,
        MitreTechnique = "T1014",
        Explanation =
            "This process answers a direct handle request and is confirmed to be running, yet it "
            + "appears in none of the APIs Windows uses to list processes. Task Manager, and every "
            + "tool built on the same interfaces, cannot see it. Ordinary software has no reason "
            + "to be invisible, and a process that started mid-scan was already ruled out by a "
            + "second confirmation pass. This is the signature of an active rootkit.",
        Recommendation =
            "Treat this machine as compromised until identified. Do not sign in to anything "
            + "sensitive from it. Capture the evidence below, then have the machine examined "
            + "offline — a rootkit at this level can defeat tools running on the live system, "
            + "including this one.",
        EvidenceChain =
        [
            Evidence.Of("PID", process.Pid.ToString(CultureInfo.InvariantCulture)),
            Evidence.Of("Confirmed alive", "yes", "OpenProcess + WaitForSingleObject"),
            Evidence.Of("Reported by", process.SeenBy.Count > 0
                ? string.Join(", ", process.SeenBy)
                : "no listing source"),
            Evidence.Of("Absent from", string.Join(", ", process.MissingFrom)),
            Evidence.Of("Second pass", "still alive, still unlisted"),
        ],
    };

    /// <summary>
    /// A process listed by some interfaces but not others. Distinct from fully hidden:
    /// it usually means a hook that filters one API and misses the rest, which is the
    /// common failure mode of off-the-shelf process hiders.
    /// </summary>
    private static Finding? SelectivelyHidden(ProcessFact process)
    {
        // A disagreement seen once is not evidence. The listing sources run one after
        // another, so a process that starts or exits between two of them appears in one
        // and not the next — indistinguishable, in a single pass, from a hooked API.
        // Only a discrepancy the confirmation pass reproduced gets this far.
        if (!process.ConfirmedSelectiveHiding)
        {
            return null;
        }

        // The PID probe is not a listing interface; absence from it says nothing.
        var missingListings = process.MissingFrom
            .Where(k => k != ProcessSourceKind.BruteForceOpen)
            .ToList();

        var seenListings = process.SeenBy
            .Where(k => k != ProcessSourceKind.BruteForceOpen)
            .ToList();

        if (missingListings.Count == 0 || seenListings.Count == 0)
        {
            return null;
        }

        return new Finding
        {
            RuleId = "concealment.selective-hiding",
            Title = $"Process {process.Pid} is visible to some kernel interfaces but not others",
            Severity = Severity.Critical,
            Confidence = Confidence.Likely,
            Category = FindingCategory.Concealment,
            Subject = process.Name ?? $"PID {process.Pid}",
            Pid = process.Pid,
            MitreTechnique = "T1014",
            Explanation =
                $"This process is reported by {string.Join(", ", seenListings)} but not by "
                + $"{string.Join(", ", missingListings)}. Windows should return a consistent answer "
                + "across all of them. Selective absence is what happens when something hooks one "
                + "enumeration path and misses the others. The ordinary explanation — a process "
                + "starting or exiting partway through the scan — was ruled out by a second pass "
                + "that found the same interface still missing it. Confidence is not absolute "
                + "because a process can in principle churn across both passes.",
            Recommendation =
                "Investigate this binary offline. A process that two Windows enumeration "
                + "interfaces disagree about, twice, is not behaving normally.",
            EvidenceChain =
            [
                Evidence.Of("PID", process.Pid.ToString(CultureInfo.InvariantCulture)),
                Evidence.Of("Name", process.Name ?? "unknown"),
                Evidence.Of("Visible to", string.Join(", ", seenListings)),
                Evidence.Of("Hidden from", string.Join(", ", missingListings)),
                Evidence.Of("Second pass", "same interface still missing it",
                    "re-enumeration"),
            ],
        };
    }

    /// <summary>
    /// A driver in kernel memory, with no service registration behind it, whose image does
    /// not verify.
    /// <para>
    /// The missing registration alone used to be the whole rule, on the premise that the
    /// supported load path always leaves a registry trace. The first elevated scan measured
    /// that premise and it is false: 50 of this machine's 270 loaded modules have no service
    /// key of their own — <c>ntoskrnl.exe</c>, <c>hal.dll</c>, <c>CI.dll</c>, <c>win32k.sys</c>,
    /// the whole HID and storage dependency chain — because dependency imports and
    /// boot-loaded modules are loaded by something other than the service control manager.
    /// A rule that reports fifty Highs on a healthy machine does not detect rootkits, it
    /// teaches the user to close the window.
    /// </para>
    /// <para>
    /// What manual mapping is actually for is loading code Windows would otherwise refuse,
    /// so the signature carries the signal and the registration only narrows where to look.
    /// Of those 50, 47 verified as Microsoft-signed and are not reported. The remaining 3
    /// are the crash-dump stack (<c>dump_stornvme.sys</c> and friends), in-memory copies
    /// whose files deliberately do not exist on disk: they come back <c>Unknown</c>, which
    /// means <em>could not be checked</em> and must never be judged as <em>unsigned</em>.
    /// They are disclosed as a blind spot by the collector instead of accused here.
    /// </para>
    /// </summary>
    private static IEnumerable<Finding> UnregisteredDrivers(DriverCensusResult drivers) =>
        drivers.Drivers
            .Where(d => d.LoadedWithoutRegistration && FailsVerification(d.Signature))
            .Select(driver => new Finding
            {
                RuleId = "concealment.unregistered-driver",
                Title = $"Kernel driver '{driver.Name}' is loaded with no service registration "
                        + "and does not verify",
                Severity = Severity.High,
                Confidence = Confidence.Likely,
                Category = FindingCategory.Concealment,
                Subject = driver.Name,
                MitreTechnique = "T1014",
                Explanation =
                    "This driver is resident in kernel memory, has no corresponding entry under the "
                    + "Services registry key, and its image fails signature verification. Kernel "
                    + "modules loaded by another driver rather than by the service control manager "
                    + "legitimately have no registration, so that alone means little — but they are "
                    + "signed. Code that is both loaded outside the supported path and unsigned is "
                    + "what mapping a driver into the kernel directly looks like, a technique used "
                    + "to avoid the signing requirement itself.",
                Recommendation =
                    "Identify the driver before acting. Kernel code runs below every user-mode "
                    + "protection on the machine, including this tool.",
                EvidenceChain =
                [
                    Evidence.Of("Driver", driver.Name),
                    Evidence.Of("Image path", driver.ImagePath ?? "unresolved"),
                    Evidence.Of("Loaded in kernel", "yes", "EnumDeviceDrivers"),
                    Evidence.Of("Service registration", "absent",
                        @"HKLM\SYSTEM\CurrentControlSet\Services"),
                    Evidence.Of("Signature", driver.Signature!.Status.ToString(), "Authenticode"),
                    Evidence.Of("Signer", driver.Signature.SignerName ?? "none"),
                ],
            });

    /// <summary>
    /// True only when the image was verified and the answer was bad.
    /// <para>
    /// Both exclusions are the same rule, and it is the one this project keeps relearning: a
    /// question that was never asked is not an answer. <c>null</c> means signature
    /// verification was switched off for the scan, and <see cref="SignatureStatus.Unknown"/>
    /// means the file could not be read. Treating either as "not signed" is a limitation
    /// reported as an observation, and here it would accuse the crash-dump stack of being
    /// a rootkit on every machine Windows ships.
    /// </para>
    /// </summary>
    private static bool FailsVerification(SignatureInfo? signature) =>
        signature is not null
        && signature.Status is not (SignatureStatus.Valid or SignatureStatus.Unknown);
}
