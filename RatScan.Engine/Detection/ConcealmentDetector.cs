using RatScan.Engine.Model;
using RatScan.Native.Processes;

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
            Evidence.Of("PID", process.Pid.ToString()),
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
                + "enumeration path and misses the others. A process that exited during the scan "
                + "can produce this pattern too, which is why the confidence is not absolute.",
            Recommendation =
                "Re-run the scan. If the same process reappears with the same inconsistency, treat "
                + "it as concealment and investigate the binary offline.",
            EvidenceChain =
            [
                Evidence.Of("PID", process.Pid.ToString()),
                Evidence.Of("Name", process.Name ?? "unknown"),
                Evidence.Of("Visible to", string.Join(", ", seenListings)),
                Evidence.Of("Hidden from", string.Join(", ", missingListings)),
            ],
        };
    }

    /// <summary>
    /// A driver in kernel memory with no service registration behind it. The supported
    /// way to load a driver leaves a registry trace; skipping it is characteristic of
    /// manual mapping.
    /// </summary>
    private static IEnumerable<Finding> UnregisteredDrivers(DriverCensusResult drivers) =>
        drivers.Drivers
            .Where(d => d.LoadedWithoutRegistration)
            .Select(driver => new Finding
            {
                RuleId = "concealment.unregistered-driver",
                Title = $"Kernel driver '{driver.Name}' is loaded with no service registration",
                Severity = Severity.High,
                Confidence = Confidence.Likely,
                Category = FindingCategory.Concealment,
                Subject = driver.Name,
                MitreTechnique = "T1014",
                Explanation =
                    "This driver is resident in kernel memory but has no corresponding entry under "
                    + "the Services registry key. Loading a driver through the supported path always "
                    + "creates one, so its absence suggests the driver was mapped into the kernel "
                    + "directly — a technique used to avoid both the signing requirement and the "
                    + "registry trace.",
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
                    Evidence.Of("Signature", driver.Signature?.Status.ToString() ?? "unknown"),
                ],
            });
}
