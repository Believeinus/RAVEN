using System.Globalization;
using RatScan.Engine.Model;
using RatScan.Native.Signing;

namespace RatScan.Engine.Detection;

/// <summary>
/// Answers, as far as anything can, "is something watching my screen or driving my
/// keyboard?"
/// <para>
/// There is no API that answers that question, and this detector does not pretend
/// otherwise. Screen capture uses the same graphics interfaces as every game, browser
/// and video call, so capability alone is meaningless — Chrome can capture the screen
/// and always could. What distinguishes surveillance is the <em>combination</em>:
/// capture capability held by a process that shows no window, holds a sustained
/// outbound connection, and is not signed by anyone recognisable. Each factor is
/// unremarkable; together they describe something with no honest purpose.
/// </para>
/// <para>
/// So this scores a correlation and says so plainly, rather than issuing a verdict it
/// cannot support.
/// </para>
/// </summary>
public sealed class SurveillanceDetector : IDetector
{
    /// <summary>
    /// Modules that indicate an ability to read the screen. Desktop Duplication and
    /// Windows.Graphics.Capture both run through DXGI; the Magnification API is the
    /// older route and is disproportionately common in commodity spyware.
    /// </summary>
    private static readonly string[] CaptureModules =
    [
        "dxgi.dll",
        "d3d11.dll",
        "magnification.dll",
        "windows.graphics.capture.dll",
        "graphicscapture.dll",
    ];

    /// <summary>
    /// Processes that hold capture-capable modules as a matter of course. Flagging
    /// these would bury every real finding under the browser tabs.
    /// </summary>
    private static readonly string[] ExpectedCaptureHolders =
    [
        "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "vivaldi.exe",
        "explorer.exe", "dwm.exe", "shellexperiencehost.exe", "searchhost.exe",
        "teams.exe", "ms-teams.exe", "zoom.exe", "slack.exe", "discord.exe", "obs64.exe",
        "steam.exe", "steamwebhelper.exe", "nvcontainer.exe", "radeonsoftware.exe",
        "devenv.exe", "code.exe", "widgets.exe", "startmenuexperiencehost.exe",
    ];

    /// <summary>
    /// A DLL present in at least this many <em>distinct programs</em> has the shape of
    /// a global input hook: SetWindowsHookEx forces the hook DLL into every GUI process
    /// on the desktop, so breadth across unrelated software is the signal.
    /// <para>
    /// The unit of breadth is the executable name, not the PID. Counting PIDs
    /// mismeasures this badly — twenty Chrome renderer processes all load chrome.dll,
    /// and every .NET program loads coreclr.dll. On first run against this machine that
    /// produced 38 findings, of which zero were input hooks.
    /// </para>
    /// </summary>
    private const int InjectionBreadthThreshold = 8;

    public string Name => "Screen and input surveillance";

    public IEnumerable<Finding> Detect(
        DetectionContext context, CancellationToken cancellationToken = default)
    {
        var findings = new List<Finding>();
        var processes = context.Processes.Processes;

        var readable = processes.Count(p => p.ModulesReadable);
        if (readable == 0)
        {
            // Without module visibility this detector is blind. Saying nothing would
            // imply it looked and found nothing.
            findings.Add(new Finding
            {
                RuleId = "surveillance.unavailable",
                Title = "Screen and input surveillance checks could not run",
                Severity = Severity.Info,
                Confidence = Confidence.Confirmed,
                Category = FindingCategory.ScanIntegrity,
                Explanation = "The DLLs loaded into running processes could not be read, so "
                              + "screen-capture capability and injected input hooks were not assessed.",
                Recommendation = "Run the scan as Administrator with module collection enabled.",
            });

            return findings;
        }

        foreach (var process in processes)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var finding = AssessCapture(process);
            if (finding is not null)
            {
                findings.Add(finding);
            }
        }

        findings.AddRange(AssessInjectedHooks(processes));
        findings.AddRange(AssessUiAccess(processes));

        return findings;
    }

    private static Finding? AssessCapture(ProcessFact process)
    {
        if (!process.ModulesReadable || process.Name is null)
        {
            return null;
        }

        if (ExpectedCaptureHolders.Contains(process.Name, StringComparer.OrdinalIgnoreCase))
        {
            return null;
        }

        var captureModules = process.Modules
            .Where(m => CaptureModules.Contains(m.Name, StringComparer.OrdinalIgnoreCase))
            .Select(m => m.Name)
            .ToList();

        if (captureModules.Count == 0)
        {
            return null;
        }

        // Capability alone is not a finding. Count the aggravating factors.
        var factors = new List<string>();
        var evidence = new List<Evidence>
        {
            Evidence.Of("Process", process.Name),
            Evidence.Of("PID", process.Pid.ToString(CultureInfo.InvariantCulture)),
            Evidence.Of("Screen-capture modules", string.Join(", ", captureModules), "module list"),
        };

        var hidden = process.Windows?.RunsHidden == true || process.Windows is null;
        if (hidden)
        {
            factors.Add("shows no visible window");
            evidence.Add(Evidence.Of("Visible windows",
                process.Windows?.VisibleWindows.ToString(CultureInfo.InvariantCulture) ?? "none",
                "EnumWindows"));
        }

        var outbound = process.Connections.Any(c => !c.IsListener && c.RemoteAddress is not null);
        if (outbound)
        {
            factors.Add("holds an outbound network connection");
            evidence.Add(Evidence.Of("Outbound connections",
                process.Connections.Count(c => !c.IsListener).ToString(CultureInfo.InvariantCulture),
                "GetExtendedTcpTable"));
        }

        var untrusted = process.Signature is null
                        || process.Signature.Status != SignatureStatus.Valid;
        if (untrusted)
        {
            factors.Add("is not validly signed");
            evidence.Add(Evidence.Of("Signature",
                process.Signature?.Status.ToString() ?? "not verified", "WinVerifyTrust"));
        }
        else
        {
            evidence.Add(Evidence.Of("Signed by", process.Signature!.SignerName ?? "unknown"));
        }

        // One factor is background noise on any real desktop; two or more is a shape
        // worth a person's attention.
        if (factors.Count < 2)
        {
            return null;
        }

        var severity = factors.Count >= 3 ? Severity.High : Severity.Medium;

        return new Finding
        {
            RuleId = "surveillance.screen-capture-correlation",
            Title = $"'{process.Name}' can capture the screen and {string.Join(", ", factors)}",
            Severity = severity,
            Confidence = factors.Count >= 3 ? Confidence.Likely : Confidence.Possible,
            Category = FindingCategory.ScreenOrInputSurveillance,
            Subject = process.Name,
            Pid = process.Pid,

            // The binary, not the PID. Muting this must mean "this program is mine",
            // which stays true across restarts and false if the file is replaced.
            IdentityKey = process.ImagePath,
            MitreTechnique = "T1113",
            Explanation =
                $"'{process.Name}' has loaded the Windows components used to read the contents of the "
                + $"screen, and it also {string.Join(", ", factors)}. Any one of those on its own is "
                + "ordinary — plenty of legitimate software captures the screen, and plenty runs "
                + "without a window. In combination they describe a process positioned to watch this "
                + "desktop and send what it sees elsewhere. This is a correlation, not proof: identify "
                + "the program before drawing a conclusion.",
            Recommendation =
                "Check what this program is and whether you installed it. If you do not recognise it, "
                + "look up its full path and publisher before ending it — some legitimate software "
                + "matches this pattern.",
            EvidenceChain = evidence,
        };
    }

    /// <summary>
    /// Finds a DLL loaded across an implausible number of unrelated processes, which
    /// is what a global keyboard or mouse hook looks like from outside.
    /// </summary>
    private static IEnumerable<Finding> AssessInjectedHooks(IReadOnlyList<ProcessFact> processes)
    {
        var readable = processes.Where(p => p.ModulesReadable).ToList();
        if (readable.Count < InjectionBreadthThreshold * 2)
        {
            yield break;
        }

        var windowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);

        var breadth = readable
            .SelectMany(p => p.Modules
                .Where(m => m.Path is not null)

                // A program's own executable and the libraries shipped beside it are
                // not injection — they are the program.
                .Where(m => !IsOwnComponent(p, m))
                .Select(m => (Module: m, Program: p.Name ?? $"pid{p.Pid}"))
                .DistinctBy(x => x.Module.Name, StringComparer.OrdinalIgnoreCase))
            .GroupBy(x => x.Module.Path!, StringComparer.OrdinalIgnoreCase)
            .Select(g => new
            {
                Path = g.Key,
                Name = g.First().Module.Name,
                Programs = g.Select(x => x.Program).Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
            })
            // Anything under the Windows directory is system infrastructure and is
            // expected to be everywhere; the interesting case is a DLL from elsewhere.
            .Where(x => x.Programs.Count >= InjectionBreadthThreshold
                        && !x.Path.StartsWith(windowsDir, StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(x => x.Programs.Count)
            .ToList();

        foreach (var entry in breadth)
        {
            yield return new Finding
            {
                RuleId = "surveillance.broad-dll-injection",
                Title = $"'{entry.Name}' is loaded into {entry.Programs.Count} unrelated programs",
                Severity = Severity.Medium,
                Confidence = Confidence.Possible,
                Category = FindingCategory.ScreenOrInputSurveillance,
                Subject = entry.Name,
                IdentityKey = entry.Path,
                MitreTechnique = "T1056.004",
                Explanation =
                    $"The library '{entry.Name}' is present in {entry.Programs.Count} unrelated programs "
                    + $"({string.Join(", ", entry.Programs.Take(5))}"
                    + $"{(entry.Programs.Count > 5 ? ", …" : "")}) and "
                    + "does not live in the Windows directory. That breadth is characteristic of a "
                    + "global input hook: installing one forces Windows to inject the hook library into "
                    + "every program with a window, which is how keyloggers capture typing everywhere "
                    + "at once. Some legitimate software — accessibility tools, input-method editors, "
                    + "graphics overlays and some antivirus products — does exactly the same thing.",
                Recommendation =
                    "Identify the software this library belongs to. If it is not something you "
                    + "installed deliberately, treat it as a keylogging candidate.",
                EvidenceChain =
                [
                    Evidence.Of("Library", entry.Name),
                    Evidence.Of("Path", entry.Path),
                    Evidence.Of("Loaded into", string.Join(", ", entry.Programs), "module lists"),
                ],
            };
        }
    }

    /// <summary>
    /// True when a module is the process's own executable, or a library shipped in the
    /// same install directory. Neither is injection.
    /// </summary>
    private static bool IsOwnComponent(ProcessFact process, RatScan.Native.Processes.LoadedModule module)
    {
        if (process.ImagePath is null || module.Path is null)
        {
            // Without the process path, fall back to matching the executable name so a
            // process's own image is still never counted as injected into itself.
            return string.Equals(module.Name, process.Name, StringComparison.OrdinalIgnoreCase);
        }

        if (string.Equals(module.Path, process.ImagePath, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var processDir = Path.GetDirectoryName(process.ImagePath);
        var moduleDir = Path.GetDirectoryName(module.Path);

        return processDir is not null
               && moduleDir is not null
               && string.Equals(processDir, moduleDir, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// UIAccess lets a process drive the user interface of higher-integrity windows —
    /// the capability needed to click through prompts the user never sees.
    /// </summary>
    private static IEnumerable<Finding> AssessUiAccess(IReadOnlyList<ProcessFact> processes) =>
        processes
            .Where(p => p.HasUiAccess == true)
            .Where(p => p.Signature?.Status != SignatureStatus.Valid)
            .Select(p => new Finding
            {
                RuleId = "surveillance.uiaccess-unsigned",
                Title = $"'{p.Name}' holds UIAccess without a valid signature",
                Severity = Severity.High,
                Confidence = Confidence.Likely,
                Category = FindingCategory.ScreenOrInputSurveillance,
                Subject = p.Name,
                Pid = p.Pid,
                IdentityKey = p.ImagePath,
                MitreTechnique = "T1056.001",
                Explanation =
                    "This process holds a UIAccess token, which allows it to send input to and read "
                    + "windows belonging to programs running at a higher privilege level than itself. "
                    + "Windows only grants this to signed software installed in a trusted location, so "
                    + "a process holding it without a valid signature is anomalous. The capability is "
                    + "what an attacker needs to drive this machine's interface without the user seeing "
                    + "prompts.",
                Recommendation = "Identify this program. Accessibility software legitimately needs "
                                 + "UIAccess; little else does.",
                EvidenceChain =
                [
                    Evidence.Of("Process", p.Name ?? $"PID {p.Pid}"),
                    Evidence.Of("UIAccess token", "held", "GetTokenInformation"),
                    Evidence.Of("Signature", p.Signature?.Status.ToString() ?? "not verified"),
                ],
            });
}
