using System.Collections.Concurrent;
using System.Globalization;
using System.Management;
using System.Reflection;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using RatScan.Engine.Model;
using RatScan.Native.Signing;

namespace RatScan.Engine.Collectors;

public interface IPersistenceCollector
{
    PersistenceResult Collect(bool verifySignatures = true, CancellationToken cancellationToken = default);
}

/// <summary>
/// Sweeps the auto-start extensibility points (ASEPs).
/// <para>
/// Breadth is the point. A RAT that only survives while its process runs is a
/// nuisance; one that reinstates itself every boot is an infestation, and the
/// reinstating mechanism is often the only durable artefact left to find.
/// </para>
/// </summary>
public sealed class PersistenceCollector : IPersistenceCollector
{
    private static readonly string[] RunKeyPaths =
    [
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    ];

    private const string WinlogonKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
    private const string WindowsKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows";
    private const string IfeoKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
    private const string LsaKey = @"SYSTEM\CurrentControlSet\Control\Lsa";
    private const string PrintMonitorsKey = @"SYSTEM\CurrentControlSet\Control\Print\Monitors";
    private const string NetshKey = @"SOFTWARE\Microsoft\Netsh";
    private const string ServicesKey = @"SYSTEM\CurrentControlSet\Services";
    private const string ActiveSetupKey = @"SOFTWARE\Microsoft\Active Setup\Installed Components";

    public PersistenceResult Collect(
        bool verifySignatures = true, CancellationToken cancellationToken = default)
    {
        var entries = new List<PersistenceEntry>();
        var blindspots = new List<Blindspot>();

        CollectRunKeys(entries, cancellationToken);
        CollectStartupFolders(entries);
        CollectWinlogon(entries);
        CollectAppInitAndAppCert(entries);
        CollectImageFileExecutionOptions(entries);
        CollectLsaPackages(entries);
        CollectPrintMonitors(entries);
        CollectNetshHelpers(entries);
        CollectComHijacks(entries, cancellationToken);
        CollectWmiSubscriptions(entries, blindspots, cancellationToken);
        CollectScheduledTasks(entries, blindspots, cancellationToken);
        CollectAutoStartServices(entries, cancellationToken);
        CollectActiveSetup(entries);
        CollectPowerShellProfiles(entries);

        if (verifySignatures)
        {
            VerifySignatures(entries, cancellationToken);
        }

        return new PersistenceResult { Entries = entries, Blindspots = blindspots };
    }

    /// <summary>
    /// Attaches Authenticode facts to every entry that names a file on disk.
    /// <para>
    /// Without this the collector reports <em>what</em> starts automatically but nothing
    /// about whether it is what it claims to be, and the detector's signer check has
    /// nothing to read. An auto-start entry pointing at an unsigned binary in a user-
    /// writable folder is a materially different statement from the same entry pointing
    /// at a catalog-signed component of Windows.
    /// </para>
    /// <para>
    /// Verified once per distinct path rather than once per entry: auto-start entries
    /// share images heavily — a machine hosting forty services out of one
    /// <c>svchost.exe</c> would otherwise pay for forty identical verifications.
    /// </para>
    /// <para>
    /// INVARIANT: a path that cannot be verified keeps
    /// <see cref="SignatureStatus.Unknown"/>, which is not
    /// <see cref="SignatureStatus.Unsigned"/>. A file that is locked, deleted, or on a
    /// disconnected drive must never reach a rule as "this is not signed" — that is the
    /// privilege-limitation-as-observation mistake, and here it would accuse the user's
    /// own software.
    /// </para>
    /// </summary>
    private static void VerifySignatures(
        List<PersistenceEntry> entries, CancellationToken cancellationToken)
    {
        var distinct = entries
            .Select(e => e.ImagePath)
            .Where(p => !string.IsNullOrWhiteSpace(p))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var signatures = new ConcurrentDictionary<string, SignatureInfo>(StringComparer.OrdinalIgnoreCase);

        Parallel.ForEach(
            distinct,
            new ParallelOptions { CancellationToken = cancellationToken },
            path => signatures[path!] = AuthenticodeVerifier.Verify(path!));

        for (var i = 0; i < entries.Count; i++)
        {
            if (entries[i].ImagePath is { } path && signatures.TryGetValue(path, out var signature))
            {
                entries[i] = entries[i] with { Signature = signature };
            }
        }
    }

    /// <summary>
    /// Services set to start without anyone asking.
    /// <para>
    /// The oldest persistence mechanism on Windows and still the most common one for
    /// remote-access software, because a service starts before any user logs in and
    /// survives them logging out. Read from the registry rather than the service
    /// control manager: the registry gives the image path directly, and it is the same
    /// place the SCM reads from, so an unelevated caller still sees the configuration
    /// even where it cannot query the running service.
    /// </para>
    /// </summary>
    private static void CollectAutoStartServices(
        List<PersistenceEntry> entries, CancellationToken cancellationToken)
    {
        using var services = RegistryKey
            .OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64)
            .OpenSubKey(ServicesKey);

        if (services is null)
        {
            return;
        }

        foreach (var name in services.GetSubKeyNames())
        {
            cancellationToken.ThrowIfCancellationRequested();

            using var service = services.OpenSubKey(name);
            if (service is null)
            {
                continue;
            }

            // 0 boot, 1 system, 2 automatic. 3 is manual and 4 disabled: neither starts
            // on its own, so neither is persistence.
            if (service.GetValue("Start") is not int start || start > 2)
            {
                continue;
            }

            // Kernel drivers (type 1/2) are the driver census's subject, not this one.
            // Counting them here would double-report every driver on the machine.
            if (service.GetValue("Type") is int type && type is 1 or 2)
            {
                continue;
            }

            var command = service.GetValue("ImagePath")?.ToString();

            entries.Add(new PersistenceEntry
            {
                Surface = PersistenceSurface.Service,
                Scope = PersistenceScope.Machine,
                Name = name,
                Command = command,
                ImagePath = ExtractExecutable(command),
                Location = $@"HKLM\{ServicesKey}\{name}",
                EvidenceChain =
                [
                    Evidence.Of(name, command ?? "(no image path)", $@"HKLM\{ServicesKey}\{name}"),
                    Evidence.Of("Start type", StartTypeName(start), "registry"),
                ],
            });
        }
    }

    private static string StartTypeName(int start) => start switch
    {
        0 => "boot",
        1 => "system",
        _ => "automatic",
    };

    /// <summary>
    /// Active Setup: commands Windows runs once per user, the first time each user logs
    /// in. Rarely examined, and it survives a profile being recreated.
    /// </summary>
    private static void CollectActiveSetup(List<PersistenceEntry> entries)
    {
        RegistryView[] views = [RegistryView.Registry64, RegistryView.Registry32];

        foreach (var view in views)
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
            using var components = baseKey.OpenSubKey(ActiveSetupKey);

            if (components is null)
            {
                continue;
            }

            foreach (var name in components.GetSubKeyNames())
            {
                using var component = components.OpenSubKey(name);

                // Only StubPath actually runs anything. A component without one is
                // bookkeeping, and recording it would bury the ones that execute.
                if (component?.GetValue("StubPath")?.ToString() is not { } stub
                    || string.IsNullOrWhiteSpace(stub))
                {
                    continue;
                }

                entries.Add(new PersistenceEntry
                {
                    Surface = PersistenceSurface.ActiveSetup,
                    Scope = PersistenceScope.Machine,
                    Name = component.GetValue(null)?.ToString() is { Length: > 0 } friendly
                        ? friendly
                        : name,
                    Command = stub,
                    ImagePath = ExtractExecutable(stub),
                    Location = $@"HKLM\{ActiveSetupKey}\{name} ({view})",
                    EvidenceChain = [Evidence.Of("StubPath", stub, $@"HKLM\{ActiveSetupKey}\{name}")],
                });
            }
        }
    }

    /// <summary>
    /// PowerShell profile scripts, which run on every shell start.
    /// <para>
    /// Only recorded when the file exists — a profile path is defined whether or not
    /// anything is there, and reporting the path alone would manufacture an entry out
    /// of a default.
    /// </para>
    /// </summary>
    private static void CollectPowerShellProfiles(List<PersistenceEntry> entries)
    {
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var documents = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);

        (string Path, PersistenceScope Scope)[] profiles =
        [
            (Path.Combine(windows, @"System32\WindowsPowerShell\v1.0\profile.ps1"), PersistenceScope.Machine),
            (Path.Combine(windows, @"System32\WindowsPowerShell\v1.0\Microsoft.PowerShell_profile.ps1"), PersistenceScope.Machine),
            (Path.Combine(documents, @"WindowsPowerShell\profile.ps1"), PersistenceScope.User),
            (Path.Combine(documents, @"WindowsPowerShell\Microsoft.PowerShell_profile.ps1"), PersistenceScope.User),
            (Path.Combine(documents, @"PowerShell\profile.ps1"), PersistenceScope.User),
            (Path.Combine(documents, @"PowerShell\Microsoft.PowerShell_profile.ps1"), PersistenceScope.User),
        ];

        foreach (var (path, scope) in profiles)
        {
            if (!File.Exists(path))
            {
                continue;
            }

            long length;
            try
            {
                length = new FileInfo(path).Length;
            }
            catch (IOException)
            {
                continue;
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            entries.Add(new PersistenceEntry
            {
                Surface = PersistenceSurface.PowerShellProfile,
                Scope = scope,
                Name = Path.GetFileName(path),
                Command = path,
                ImagePath = path,
                Location = path,
                EvidenceChain =
                [
                    Evidence.Of("Profile script", path, "filesystem"),
                    Evidence.Of("Size", $"{length} bytes", "filesystem"),
                ],
            });
        }
    }

    private static void CollectRunKeys(List<PersistenceEntry> entries, CancellationToken cancellationToken)
    {
        // Both registry views matter: a 32-bit installer writes under Wow6432Node, and
        // reading only the native view misses it entirely.
        (RegistryHive Hive, PersistenceScope Scope)[] hives =
        [
            (RegistryHive.LocalMachine, PersistenceScope.Machine),
            (RegistryHive.CurrentUser, PersistenceScope.User),
        ];

        RegistryView[] views = [RegistryView.Registry64, RegistryView.Registry32];

        foreach (var (hive, scope) in hives)
        {
            foreach (var view in views)
            {
                foreach (var path in RunKeyPaths)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    using var baseKey = RegistryKey.OpenBaseKey(hive, view);
                    using var key = baseKey.OpenSubKey(path);
                    if (key is null)
                    {
                        continue;
                    }

                    var surface = path.EndsWith("RunOnce", StringComparison.OrdinalIgnoreCase)
                        ? PersistenceSurface.RunOnceKey
                        : PersistenceSurface.RunKey;

                    foreach (var name in key.GetValueNames())
                    {
                        var command = key.GetValue(name)?.ToString();

                        entries.Add(new PersistenceEntry
                        {
                            Surface = surface,
                            Scope = scope,
                            Name = name,
                            Command = command,
                            ImagePath = ExtractExecutable(command),
                            Location = $@"{hive}\{path} ({view})",
                            EvidenceChain = [Evidence.Of(name, command ?? string.Empty, $@"{hive}\{path}")],
                        });
                    }
                }
            }
        }
    }

    private static void CollectStartupFolders(List<PersistenceEntry> entries)
    {
        (string Path, PersistenceScope Scope)[] folders =
        [
            (Environment.GetFolderPath(Environment.SpecialFolder.Startup), PersistenceScope.User),
            (Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup), PersistenceScope.Machine),
        ];

        foreach (var (folder, scope) in folders)
        {
            if (string.IsNullOrEmpty(folder) || !Directory.Exists(folder))
            {
                continue;
            }

            foreach (var file in Directory.EnumerateFiles(folder))
            {
                var target = ResolveShortcut(file);

                entries.Add(new PersistenceEntry
                {
                    Surface = PersistenceSurface.StartupFolder,
                    Scope = scope,
                    Name = Path.GetFileName(file),
                    Command = file,
                    ImagePath = target ?? file,
                    Location = folder,
                    EvidenceChain = target is null
                        ? [Evidence.Of("File", file, "Startup folder")]
                        :
                        [
                            Evidence.Of("File", file, "Startup folder"),
                            Evidence.Of("Shortcut target", target, "Startup folder"),
                        ],
                });
            }
        }
    }

    /// <summary>
    /// Winlogon's Shell and Userinit values name what runs at sign-in. Appending a
    /// second command after a comma is a classic, durable persistence trick — the
    /// desktop still loads normally, so nothing looks wrong.
    /// </summary>
    private static void CollectWinlogon(List<PersistenceEntry> entries)
    {
        using var key = Registry.LocalMachine.OpenSubKey(WinlogonKey);
        if (key is null)
        {
            return;
        }

        foreach (var (value, surface) in new[]
                 {
                     ("Shell", PersistenceSurface.WinlogonShell),
                     ("Userinit", PersistenceSurface.WinlogonUserinit),
                 })
        {
            var command = key.GetValue(value)?.ToString();
            if (string.IsNullOrWhiteSpace(command))
            {
                continue;
            }

            entries.Add(new PersistenceEntry
            {
                Surface = surface,
                Scope = PersistenceScope.Machine,
                Name = value,
                Command = command,
                ImagePath = ExtractExecutable(command),
                Location = $@"HKLM\{WinlogonKey}",
                EvidenceChain = [Evidence.Of(value, command, $@"HKLM\{WinlogonKey}")],
            });
        }
    }

    /// <summary>
    /// AppInit_DLLs is loaded into every process that links user32. AppCertDlls loads
    /// on every CreateProcess. Both are near-universal injection points and both are
    /// empty on a healthy modern system.
    /// </summary>
    private static void CollectAppInitAndAppCert(List<PersistenceEntry> entries)
    {
        using var windows = Registry.LocalMachine.OpenSubKey(WindowsKey);
        var appInit = windows?.GetValue("AppInit_DLLs")?.ToString();

        if (!string.IsNullOrWhiteSpace(appInit))
        {
            entries.Add(new PersistenceEntry
            {
                Surface = PersistenceSurface.AppInitDll,
                Scope = PersistenceScope.Machine,
                Name = "AppInit_DLLs",
                Command = appInit,
                ImagePath = ExtractExecutable(appInit),
                Location = $@"HKLM\{WindowsKey}",
                EvidenceChain =
                [
                    Evidence.Of("AppInit_DLLs", appInit, $@"HKLM\{WindowsKey}"),
                    Evidence.Of("LoadAppInit_DLLs", windows?.GetValue("LoadAppInit_DLLs")?.ToString() ?? "0",
                        $@"HKLM\{WindowsKey}"),
                ],
            });
        }

        using var appCert = Registry.LocalMachine.OpenSubKey(
            @"SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls");

        if (appCert is null)
        {
            return;
        }

        foreach (var name in appCert.GetValueNames())
        {
            var value = appCert.GetValue(name)?.ToString();

            entries.Add(new PersistenceEntry
            {
                Surface = PersistenceSurface.AppCertDll,
                Scope = PersistenceScope.Machine,
                Name = name,
                Command = value,
                ImagePath = value,
                Location = @"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls",
                EvidenceChain = [Evidence.Of(name, value ?? string.Empty, "AppCertDlls")],
            });
        }
    }

    /// <summary>
    /// An IFEO "Debugger" value hijacks a program: launching the named executable
    /// silently launches the debugger instead. Used both for persistence and to
    /// neuter security tools by pointing their entry at something inert.
    /// </summary>
    private static void CollectImageFileExecutionOptions(List<PersistenceEntry> entries)
    {
        using var ifeo = Registry.LocalMachine.OpenSubKey(IfeoKey);
        if (ifeo is null)
        {
            return;
        }

        foreach (var subName in ifeo.GetSubKeyNames())
        {
            using var sub = ifeo.OpenSubKey(subName);
            var debugger = sub?.GetValue("Debugger")?.ToString();

            if (string.IsNullOrWhiteSpace(debugger))
            {
                continue;
            }

            entries.Add(new PersistenceEntry
            {
                Surface = PersistenceSurface.ImageFileExecutionOptions,
                Scope = PersistenceScope.Machine,
                Name = subName,
                Command = debugger,
                ImagePath = ExtractExecutable(debugger),
                Location = $@"HKLM\{IfeoKey}\{subName}",
                EvidenceChain = [Evidence.Of("Debugger", debugger, $@"HKLM\{IfeoKey}\{subName}")],
            });
        }
    }

    private static void CollectLsaPackages(List<PersistenceEntry> entries)
    {
        using var lsa = Registry.LocalMachine.OpenSubKey(LsaKey);
        if (lsa is null)
        {
            return;
        }

        foreach (var value in new[] { "Security Packages", "Authentication Packages", "Notification Packages" })
        {
            if (lsa.GetValue(value) is not string[] packages)
            {
                continue;
            }

            foreach (var package in packages.Where(p => !string.IsNullOrWhiteSpace(p)))
            {
                entries.Add(new PersistenceEntry
                {
                    Surface = PersistenceSurface.LsaPackage,
                    Scope = PersistenceScope.Machine,
                    Name = package,
                    Command = package,
                    Location = $@"HKLM\{LsaKey}\{value}",
                    EvidenceChain = [Evidence.Of(value, package, $@"HKLM\{LsaKey}")],
                });
            }
        }
    }

    private static void CollectPrintMonitors(List<PersistenceEntry> entries)
    {
        using var monitors = Registry.LocalMachine.OpenSubKey(PrintMonitorsKey);
        if (monitors is null)
        {
            return;
        }

        foreach (var name in monitors.GetSubKeyNames())
        {
            using var monitor = monitors.OpenSubKey(name);
            var driver = monitor?.GetValue("Driver")?.ToString();

            if (string.IsNullOrWhiteSpace(driver))
            {
                continue;
            }

            entries.Add(new PersistenceEntry
            {
                Surface = PersistenceSurface.PrintMonitor,
                Scope = PersistenceScope.Machine,
                Name = name,
                Command = driver,
                ImagePath = ResolveImagePath(driver),
                Location = $@"HKLM\{PrintMonitorsKey}\{name}",
                EvidenceChain = [Evidence.Of("Driver", driver, $@"HKLM\{PrintMonitorsKey}\{name}")],
            });
        }
    }

    private static void CollectNetshHelpers(List<PersistenceEntry> entries)
    {
        using var netsh = Registry.LocalMachine.OpenSubKey(NetshKey);
        if (netsh is null)
        {
            return;
        }

        foreach (var name in netsh.GetValueNames())
        {
            var dll = netsh.GetValue(name)?.ToString();

            entries.Add(new PersistenceEntry
            {
                Surface = PersistenceSurface.NetshHelper,
                Scope = PersistenceScope.Machine,
                Name = name,
                Command = dll,
                ImagePath = ResolveImagePath(dll),
                Location = $@"HKLM\{NetshKey}",
                EvidenceChain = [Evidence.Of(name, dll ?? string.Empty, $@"HKLM\{NetshKey}")],
            });
        }
    }

    /// <summary>
    /// COM hijacking: a CLSID registered under HKCU shadows the same CLSID in HKLM,
    /// because HKCU is searched first. Whenever Windows instantiates that component,
    /// the attacker's DLL loads instead — no autostart entry, no new process.
    /// <para>
    /// Only user-hive CLSIDs that also exist machine-wide are collected, since those
    /// are the shadowing ones. A purely user-registered CLSID is ordinary.
    /// </para>
    /// </summary>
    private static void CollectComHijacks(List<PersistenceEntry> entries, CancellationToken cancellationToken)
    {
        using var userClasses = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Classes\CLSID");
        if (userClasses is null)
        {
            return;
        }

        using var machineClasses = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Classes\CLSID");

        foreach (var clsid in userClasses.GetSubKeyNames())
        {
            cancellationToken.ThrowIfCancellationRequested();

            using var userEntry = userClasses.OpenSubKey($@"{clsid}\InprocServer32");
            var userDll = userEntry?.GetValue(null)?.ToString();

            if (string.IsNullOrWhiteSpace(userDll))
            {
                continue;
            }

            using var machineEntry = machineClasses?.OpenSubKey($@"{clsid}\InprocServer32");
            var machineDll = machineEntry?.GetValue(null)?.ToString();

            if (machineDll is null)
            {
                continue;
            }

            entries.Add(new PersistenceEntry
            {
                Surface = PersistenceSurface.ComHijack,
                Scope = PersistenceScope.User,
                Name = clsid,
                Command = userDll,
                ImagePath = ExtractExecutable(userDll),
                Location = $@"HKCU\SOFTWARE\Classes\CLSID\{clsid}\InprocServer32",
                EvidenceChain =
                [
                    Evidence.Of("User (takes precedence)", userDll, $@"HKCU\...\CLSID\{clsid}"),
                    Evidence.Of("Machine (shadowed)", machineDll, $@"HKLM\...\CLSID\{clsid}"),
                ],
            });
        }
    }

    /// <summary>
    /// WMI permanent event subscriptions: a filter (when), a consumer (what), and a
    /// binding between them, all stored in the CIM repository.
    /// <para>
    /// The most under-checked persistence mechanism on Windows. Entirely fileless when
    /// the consumer is a script, survives reboots, runs as SYSTEM, and leaves nothing
    /// for a file scanner to find. Anything here on a home machine warrants a look;
    /// legitimate use outside enterprise management tooling is rare.
    /// </para>
    /// </summary>
    private static void CollectWmiSubscriptions(
        List<PersistenceEntry> entries, List<Blindspot> blindspots, CancellationToken cancellationToken)
    {
        try
        {
            var scope = new ManagementScope(@"\\.\root\subscription");
            scope.Connect();

            CollectWmiConsumers(scope, "CommandLineEventConsumer", "CommandLineTemplate", false, entries, cancellationToken);
            CollectWmiConsumers(scope, "ActiveScriptEventConsumer", "ScriptText", true, entries, cancellationToken);

            using var bindings = new ManagementObjectSearcher(
                scope, new ObjectQuery("SELECT * FROM __FilterToConsumerBinding"));

            foreach (var binding in bindings.Get().Cast<ManagementBaseObject>())
            {
                using (binding)
                {
                    entries.Add(new PersistenceEntry
                    {
                        Surface = PersistenceSurface.WmiEventSubscription,
                        Scope = PersistenceScope.Machine,
                        Name = "FilterToConsumerBinding",
                        Command = binding["Consumer"]?.ToString(),
                        Location = @"root\subscription:__FilterToConsumerBinding",

                        // A binding is a link, not a payload — it carries no code. Only
                        // the consumer can be fileless, and only when it is a script
                        // consumer. Flagging bindings as fileless would raise a
                        // permanent false positive on stock Windows, which ships an
                        // SCM event-log binding out of the box.
                        IsFileless = false,
                        EvidenceChain =
                        [
                            Evidence.Of("Filter", binding["Filter"]?.ToString() ?? "", "WMI"),
                            Evidence.Of("Consumer", binding["Consumer"]?.ToString() ?? "", "WMI"),
                        ],
                    });
                }
            }
        }
        catch (Exception ex)
        {
            blindspots.Add(new Blindspot
            {
                Area = "WMI permanent event subscriptions",
                Reason = $"root\\subscription unreadable: {ex.GetType().Name}. Fileless WMI persistence "
                         + "can be neither confirmed nor ruled out.",
                Remedy = "Run as Administrator",
            });
        }
    }

    private static void CollectWmiConsumers(
        ManagementScope scope,
        string className,
        string payloadProperty,
        bool fileless,
        List<PersistenceEntry> entries,
        CancellationToken cancellationToken)
    {
        using var searcher = new ManagementObjectSearcher(scope, new ObjectQuery($"SELECT * FROM {className}"));

        foreach (var consumer in searcher.Get().Cast<ManagementBaseObject>())
        {
            cancellationToken.ThrowIfCancellationRequested();

            using (consumer)
            {
                var payload = consumer[payloadProperty]?.ToString();

                entries.Add(new PersistenceEntry
                {
                    Surface = PersistenceSurface.WmiEventSubscription,
                    Scope = PersistenceScope.Machine,
                    Name = consumer["Name"]?.ToString() ?? className,
                    Command = payload,
                    ImagePath = fileless ? null : ExtractExecutable(payload),
                    Location = $@"root\subscription:{className}",
                    IsFileless = fileless,
                    EvidenceChain = [Evidence.Of(payloadProperty, payload ?? string.Empty, $"WMI {className}")],
                });
            }
        }
    }

    private static void CollectScheduledTasks(
        List<PersistenceEntry> entries, List<Blindspot> blindspots, CancellationToken cancellationToken)
    {
        try
        {
            using var service = new Microsoft.Win32.TaskScheduler.TaskService();

            foreach (var task in service.AllTasks)
            {
                cancellationToken.ThrowIfCancellationRequested();

                try
                {
                    if (!task.Enabled)
                    {
                        continue;
                    }

                    foreach (var action in task.Definition.Actions.OfType<Microsoft.Win32.TaskScheduler.ExecAction>())
                    {
                        entries.Add(new PersistenceEntry
                        {
                            Surface = PersistenceSurface.ScheduledTask,
                            Scope = PersistenceScope.Machine,
                            Name = task.Path,
                            Command = $"{action.Path} {action.Arguments}".Trim(),
                            ImagePath = ExtractExecutable(action.Path),
                            Location = "Task Scheduler",
                            EvidenceChain =
                            [
                                Evidence.Of("Action", $"{action.Path} {action.Arguments}".Trim(), "Task Scheduler"),
                                Evidence.Of("Author", task.Definition.RegistrationInfo.Author ?? "-", "Task Scheduler"),
                            ],
                        });
                    }
                }
                catch
                {
                    // Individual tasks can be unreadable without elevation. Skipping one
                    // task is correct; failing the whole sweep because of it is not.
                }
            }
        }
        catch (Exception ex)
        {
            blindspots.Add(new Blindspot
            {
                Area = "Scheduled tasks",
                Reason = $"Task Scheduler enumeration failed: {ex.GetType().Name}",
                Remedy = "Run as Administrator",
            });
        }
    }

    /// <summary>
    /// Pulls the executable out of a command line. Handles the quoted form and the
    /// bare form; anything more exotic is left to the detector, which has the rule
    /// context to interpret it.
    /// </summary>
    internal static string? ExtractExecutable(string? command)
    {
        if (string.IsNullOrWhiteSpace(command))
        {
            return null;
        }

        command = command.Trim();

        if (command.StartsWith('"'))
        {
            var end = command.IndexOf('"', 1);
            return end > 1 ? ResolveImagePath(command[1..end]) : null;
        }

        // Unquoted: take up to the first space that ends something .exe/.dll-shaped,
        // falling back to the first token.
        var exeIndex = command.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
        if (exeIndex > 0)
        {
            return ResolveImagePath(command[..(exeIndex + 4)]);
        }

        var space = command.IndexOf(' ');
        return ResolveImagePath(space > 0 ? command[..space] : command);
    }

    /// <summary>
    /// Directories Windows itself loads an unqualified auto-start image from. Ordered
    /// the way Windows searches, so a name that exists in more than one resolves to the
    /// same file the operating system would run.
    /// </summary>
    private static readonly string[] SearchDirectories =
    [
        Environment.GetFolderPath(Environment.SpecialFolder.System),
        Environment.GetFolderPath(Environment.SpecialFolder.SystemX86),
        Environment.GetFolderPath(Environment.SpecialFolder.Windows),
    ];

    /// <summary>
    /// Turns a configured image path into one a file API can actually open.
    /// <para>
    /// Auto-start entries store paths in whatever shape the thing that wrote them felt
    /// like: <c>%windir%\system32\defrag.exe</c> from Task Scheduler, a bare
    /// <c>tcpmon.dll</c> from a print monitor, <c>explorer.exe</c> from Winlogon. Handed
    /// to <see cref="File.Exists(string)"/> unchanged, every one of them reports missing
    /// — which is how 87 of this machine's 296 path-bearing entries were unverifiable
    /// while looking, from the outside, exactly like entries that had been checked.
    /// </para>
    /// <para>
    /// Only a probe that <em>finds</em> the file changes the answer. When nothing
    /// resolves, the configured value is returned as it stands rather than a guess: an
    /// entry pointing at something that is not there is a fact worth keeping, and it is
    /// not the same fact as an entry pointing at something unsigned.
    /// </para>
    /// </summary>
    /// <summary>
    /// Follows a Startup-folder shortcut to the program it actually launches.
    /// <para>
    /// A <c>.lnk</c> carries no Authenticode signature of its own, so verifying the
    /// shortcut instead of its target reports every Startup-folder item on every machine
    /// as unsigned. Two of the seven unsigned entries measured here were shortcuts, and
    /// one of them pointed at RustDesk — a catalogued remote-access tool the signer check
    /// could have confirmed outright if it had been looking at the right file.
    /// </para>
    /// <para>
    /// Resolved through the shell rather than by parsing the shortcut format directly:
    /// the format is versioned and only partly documented, and a parser that quietly gets
    /// it wrong aims the signature check at some other file, which is worse than not
    /// following the shortcut at all. Anything unexpected leaves the shortcut path in
    /// place and the signature <see cref="SignatureStatus.Unknown"/>.
    /// </para>
    /// </summary>
    private static string? ResolveShortcut(string linkPath)
    {
        if (!linkPath.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        object? shell = null;
        object? shortcut = null;

        try
        {
            var type = Type.GetTypeFromProgID("WScript.Shell");
            if (type is null)
            {
                return null;
            }

            shell = Activator.CreateInstance(type);
            if (shell is null)
            {
                return null;
            }

            shortcut = type.InvokeMember(
                "CreateShortcut", BindingFlags.InvokeMethod, null, shell, [linkPath],
                CultureInfo.InvariantCulture);

            if (shortcut is null)
            {
                return null;
            }

            var target = shortcut.GetType().InvokeMember(
                "TargetPath", BindingFlags.GetProperty, null, shortcut, null,
                CultureInfo.InvariantCulture) as string;

            return string.IsNullOrWhiteSpace(target) || !File.Exists(target) ? null : target;
        }
        catch (Exception ex) when (
            ex is COMException or TargetInvocationException or MissingMemberException
                or InvalidCastException or UnauthorizedAccessException)
        {
            // A shortcut that will not resolve is reported as the shortcut it is. Guessing
            // a target would put a signature verdict against a file nobody confirmed.
            return null;
        }
        finally
        {
            if (shortcut is not null)
            {
                Marshal.ReleaseComObject(shortcut);
            }

            if (shell is not null)
            {
                Marshal.ReleaseComObject(shell);
            }
        }
    }

    internal static string? ResolveImagePath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return null;
        }

        var candidate = path.Trim().Trim('"');

        if (candidate.Contains('%', StringComparison.Ordinal))
        {
            candidate = Environment.ExpandEnvironmentVariables(candidate);
        }

        if (Path.IsPathRooted(candidate))
        {
            return candidate;
        }

        foreach (var directory in SearchDirectories)
        {
            var probe = Path.Combine(directory, candidate);
            if (File.Exists(probe))
            {
                return probe;
            }
        }

        return candidate;
    }
}
