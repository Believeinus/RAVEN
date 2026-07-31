using Microsoft.Win32;
using RatScan.Engine.Model;
using RatScan.Native.Network;
using RatScan.Native.Services;

namespace RatScan.Engine.Collectors;

public interface IRemoteSurfaceCollector
{
    RemoteSurfaceResult Collect(CancellationToken cancellationToken = default);
}

/// <summary>
/// Audits Windows' built-in remote-access mechanisms.
/// <para>
/// Judgement-free like every collector: it reports observed configuration and the
/// registry values behind it. Whether "RDP enabled" is a finding is the detector's
/// call, since on a machine the user deliberately administers remotely it is not.
/// </para>
/// </summary>
public sealed class RemoteSurfaceCollector : IRemoteSurfaceCollector
{
    private const string TerminalServerKey = @"SYSTEM\CurrentControlSet\Control\Terminal Server";
    private const string RdpTcpKey = TerminalServerKey + @"\WinStations\RDP-Tcp";
    private const string TsPolicyKey = @"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services";
    private const string RemoteAssistanceKey = @"SYSTEM\CurrentControlSet\Control\Remote Assistance";
    private const string PortProxyKey = @"SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4\tcp";

    // Default ports for each surface, hoisted so the audit does not reallocate them
    // on every scan.
    private static readonly int[] WinRmPorts = [5985, 5986];
    private static readonly int[] SshPorts = [22];
    private static readonly int[] SmbPorts = [139, 445];

    public RemoteSurfaceResult Collect(CancellationToken cancellationToken = default)
    {
        var blindspots = new List<Blindspot>();

        var services = ServiceInventory.ReadAll(cancellationToken);
        if (!services.Succeeded)
        {
            blindspots.Add(new Blindspot
            {
                Area = "Service states for remote-access surfaces",
                Reason = services.Error ?? "service enumeration failed",
            });
        }

        var connections = ConnectionTables.ReadAll(cancellationToken);
        var listening = connections.Succeeded
            ? connections.Connections.Where(c => c.IsListener).Select(c => c.LocalPort).ToHashSet()
            : [];

        if (!connections.Succeeded)
        {
            blindspots.Add(new Blindspot
            {
                Area = "Listening ports",
                Reason = connections.Error ?? "connection table read failed",
            });
        }

        var surfaces = new List<RemoteSurface>
        {
            AuditRdp(services, listening),
            AuditRdpShadowing(),
            AuditWinRm(services, listening),
            AuditOpenSsh(services, listening),
            AuditRemoteRegistry(services),
            AuditRemoteAssistance(),
            AuditSmb(services, listening),
            AuditPortProxy(),
        };

        var (logons, logonBlindspot) = ReadRemoteLogonHistory();
        if (logonBlindspot is not null)
        {
            blindspots.Add(logonBlindspot);
        }

        return new RemoteSurfaceResult
        {
            Surfaces = surfaces,
            RecentRemoteLogons = logons,
            Blindspots = blindspots,
        };
    }

    private static RemoteSurface AuditRdp(ServiceInventoryResult services, HashSet<int> listening)
    {
        // fDenyTSConnections is inverted: 0 means connections are ALLOWED. Reading it
        // as a plain boolean gets the answer exactly backwards.
        var deny = ReadDword(TerminalServerKey, "fDenyTSConnections");
        var port = ReadDword(RdpTcpKey, "PortNumber") ?? 3389;
        var nla = ReadDword(RdpTcpKey, "UserAuthentication");
        var running = services.Services.Any(s =>
            s.Name.Equals("TermService", StringComparison.OrdinalIgnoreCase) && s.IsRunning);

        var evidence = new List<Evidence>
        {
            Evidence.Of("fDenyTSConnections", deny?.ToString() ?? "absent",
                $@"HKLM\{TerminalServerKey}"),
            Evidence.Of("Listening port", port.ToString(), $@"HKLM\{RdpTcpKey}"),
            Evidence.Of("Network Level Authentication", nla == 1 ? "required" : "not required",
                $@"HKLM\{RdpTcpKey}"),
            Evidence.Of("TermService running", running.ToString(), "SCM"),
        };

        var ports = listening.Contains((int)port) ? new List<int> { (int)port } : [];

        var state = deny switch
        {
            null => SurfaceState.Unknown,
            0 when ports.Count > 0 => nla == 1 ? SurfaceState.Restricted : SurfaceState.Enabled,
            0 => SurfaceState.Restricted,
            _ => SurfaceState.Disabled,
        };

        return new RemoteSurface
        {
            Id = "windows.rdp",
            Name = "Remote Desktop (RDP)",
            State = state,
            Capability = "Full remote desktop view and control, plus drive and clipboard redirection",
            Detail = deny == 0
                ? $"Connections permitted on port {port}; NLA {(nla == 1 ? "required" : "NOT required")}"
                : "Connections denied by policy",
            EvidenceChain = evidence,
            ListeningPorts = ports,
            DisableCommand =
                @"Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 1",
        };
    }

    /// <summary>
    /// RDP shadowing lets an administrator watch or take over an existing session —
    /// optionally, depending on this value, <em>without the user being asked</em>.
    /// It is the quietest remote-viewing mechanism Windows ships and almost nobody
    /// checks it.
    /// </summary>
    private static RemoteSurface AuditRdpShadowing()
    {
        var shadow = ReadDword(TsPolicyKey, "Shadow");

        // 0 disabled · 1 full control WITH consent · 2 full control WITHOUT consent
        // 3 view only WITH consent · 4 view only WITHOUT consent
        var (state, detail) = shadow switch
        {
            null => (SurfaceState.Disabled, "No shadow policy configured (Windows default: prompts for consent)"),
            0 => (SurfaceState.Disabled, "Shadowing explicitly disabled"),
            1 => (SurfaceState.Restricted, "Full control, user consent required"),
            2 => (SurfaceState.Enabled, "Full control WITHOUT user consent"),
            3 => (SurfaceState.Restricted, "View only, user consent required"),
            4 => (SurfaceState.Enabled, "View only WITHOUT user consent"),
            _ => (SurfaceState.Unknown, $"Unrecognised Shadow value {shadow}"),
        };

        return new RemoteSurface
        {
            Id = "windows.rdp.shadow",
            Name = "RDP session shadowing",
            State = state,
            Capability = "Watch or take over the signed-in user's session, silently when consent is not required",
            Detail = detail,
            EvidenceChain =
            [
                Evidence.Of("Shadow", shadow?.ToString() ?? "not set", $@"HKLM\{TsPolicyKey}"),
            ],
            DisableCommand =
                @"Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name Shadow -Value 0",
        };
    }

    private static RemoteSurface AuditWinRm(ServiceInventoryResult services, HashSet<int> listening)
    {
        var running = services.Services.Any(s =>
            s.Name.Equals("WinRM", StringComparison.OrdinalIgnoreCase) && s.IsRunning);

        var ports = WinRmPorts.Where(listening.Contains).ToList();

        return new RemoteSurface
        {
            Id = "windows.winrm",
            Name = "WinRM / PowerShell Remoting",
            State = ports.Count > 0 ? SurfaceState.Enabled
                : running ? SurfaceState.Restricted
                : SurfaceState.Disabled,
            Capability = "Remote command execution as an administrator — full control without any GUI",
            Detail = ports.Count > 0
                ? $"Listening on {string.Join(", ", ports)}"
                : running ? "Service running but no listener bound" : "Service not running",
            EvidenceChain =
            [
                Evidence.Of("WinRM service", running ? "running" : "stopped", "SCM"),
                Evidence.Of("Listeners", ports.Count > 0 ? string.Join(", ", ports) : "none", "GetExtendedTcpTable"),
            ],
            ListeningPorts = ports,
            DisableCommand = "Disable-PSRemoting -Force; Stop-Service WinRM; Set-Service WinRM -StartupType Disabled",
        };
    }

    private static RemoteSurface AuditOpenSsh(ServiceInventoryResult services, HashSet<int> listening)
    {
        var running = services.Services.Any(s =>
            s.Name.Equals("sshd", StringComparison.OrdinalIgnoreCase) && s.IsRunning);
        var ports = SshPorts.Where(listening.Contains).ToList();

        return new RemoteSurface
        {
            Id = "windows.sshd",
            Name = "OpenSSH Server",
            State = ports.Count > 0 ? SurfaceState.Enabled
                : running ? SurfaceState.Restricted
                : SurfaceState.Disabled,
            Capability = "Remote shell access, file transfer, and port forwarding into this machine",
            Detail = running ? "sshd service running" : "sshd not running",
            EvidenceChain =
            [
                Evidence.Of("sshd service", running ? "running" : "stopped/absent", "SCM"),
                Evidence.Of("Port 22", ports.Count > 0 ? "listening" : "not listening", "GetExtendedTcpTable"),
            ],
            ListeningPorts = ports,
            DisableCommand = "Stop-Service sshd; Set-Service sshd -StartupType Disabled",
        };
    }

    private static RemoteSurface AuditRemoteRegistry(ServiceInventoryResult services)
    {
        var running = services.Services.Any(s =>
            s.Name.Equals("RemoteRegistry", StringComparison.OrdinalIgnoreCase) && s.IsRunning);

        return new RemoteSurface
        {
            Id = "windows.remoteregistry",
            Name = "Remote Registry",
            State = running ? SurfaceState.Enabled : SurfaceState.Disabled,
            Capability = "Read and modify this machine's registry from across the network, "
                         + "including autostart keys",
            Detail = running ? "Service running" : "Service not running",
            EvidenceChain = [Evidence.Of("RemoteRegistry service", running ? "running" : "stopped", "SCM")],
            DisableCommand = "Stop-Service RemoteRegistry; Set-Service RemoteRegistry -StartupType Disabled",
        };
    }

    private static RemoteSurface AuditRemoteAssistance()
    {
        var allow = ReadDword(RemoteAssistanceKey, "fAllowToGetHelp");

        return new RemoteSurface
        {
            Id = "windows.remoteassistance",
            Name = "Remote Assistance",
            State = allow switch
            {
                null => SurfaceState.Unknown,
                0 => SurfaceState.Disabled,
                _ => SurfaceState.Enabled,
            },
            Capability = "Invite a remote helper to view and optionally control this desktop",
            Detail = allow == 1 ? "Assistance invitations permitted" : "Assistance invitations blocked",
            EvidenceChain =
            [
                Evidence.Of("fAllowToGetHelp", allow?.ToString() ?? "absent", $@"HKLM\{RemoteAssistanceKey}"),
            ],
            DisableCommand =
                @"Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -Name fAllowToGetHelp -Value 0",
        };
    }

    private static RemoteSurface AuditSmb(ServiceInventoryResult services, HashSet<int> listening)
    {
        var running = services.Services.Any(s =>
            s.Name.Equals("LanmanServer", StringComparison.OrdinalIgnoreCase) && s.IsRunning);
        var ports = SmbPorts.Where(listening.Contains).ToList();

        return new RemoteSurface
        {
            Id = "windows.smb",
            Name = "SMB file and printer sharing",
            State = ports.Count > 0 ? SurfaceState.Enabled
                : running ? SurfaceState.Restricted
                : SurfaceState.Disabled,
            Capability = "Read and write files on this machine over the network, including the "
                         + "C$ and ADMIN$ administrative shares",
            Detail = ports.Count > 0 ? $"Listening on {string.Join(", ", ports)}" : "No SMB listener",
            EvidenceChain =
            [
                Evidence.Of("LanmanServer", running ? "running" : "stopped", "SCM"),
                Evidence.Of("Listeners", ports.Count > 0 ? string.Join(", ", ports) : "none", "GetExtendedTcpTable"),
            ],
            ListeningPorts = ports,
        };
    }

    /// <summary>
    /// <c>netsh interface portproxy</c> entries silently forward an inbound port to
    /// somewhere else — often used to tunnel past a firewall rule. Rare enough on a
    /// desktop that any entry deserves a look.
    /// </summary>
    private static RemoteSurface AuditPortProxy()
    {
        var entries = new List<Evidence>();

        using var key = Registry.LocalMachine.OpenSubKey(PortProxyKey);
        if (key is not null)
        {
            foreach (var name in key.GetValueNames())
            {
                entries.Add(Evidence.Of(name, key.GetValue(name)?.ToString() ?? string.Empty,
                    $@"HKLM\{PortProxyKey}"));
            }
        }

        // Captured BEFORE the placeholder below is appended. Deriving state from
        // entries.Count afterwards flipped this surface to Enabled on a machine with no
        // forwarding rules at all — the evidence-completeness fix silently broke the
        // reading it was decorating.
        var ruleCount = entries.Count;

        // A clean result still records that the check ran. "We looked here and found
        // nothing" and "we never looked" must not render identically to the user.
        if (ruleCount == 0)
        {
            entries.Add(Evidence.Of(
                "Forwarding rules",
                key is null ? "portproxy key absent (feature never configured)" : "key present, no entries",
                $@"HKLM\{PortProxyKey}"));
        }

        return new RemoteSurface
        {
            Id = "windows.portproxy",
            Name = "Port forwarding (netsh portproxy)",
            State = ruleCount > 0 ? SurfaceState.Enabled : SurfaceState.Disabled,
            Capability = "Silently forwards an inbound port to another host or port, "
                         + "which can tunnel traffic past firewall rules",
            Detail = ruleCount > 0 ? $"{ruleCount} forwarding rule(s) configured" : "No forwarding rules",
            EvidenceChain = entries,
            DisableCommand = "netsh interface portproxy reset",
        };
    }

    /// <summary>
    /// Pulls interactive remote logons from the Security log — evidence that somebody
    /// actually connected, as opposed to merely being able to.
    /// </summary>
    private static (List<RemoteLogonEvent> Events, Blindspot? Blindspot) ReadRemoteLogonHistory()
    {
        var found = new List<RemoteLogonEvent>();

        try
        {
            // Logon type 10 is RemoteInteractive: RDP and equivalents.
            const string query =
                "*[System[(EventID=4624)] and EventData[Data[@Name='LogonType']='10']]";

            var reader = new System.Diagnostics.Eventing.Reader.EventLogQuery("Security",
                System.Diagnostics.Eventing.Reader.PathType.LogName, query)
            {
                ReverseDirection = true,
            };

            using var log = new System.Diagnostics.Eventing.Reader.EventLogReader(reader);

            for (var i = 0; i < 25; i++)
            {
                using var record = log.ReadEvent();
                if (record is null)
                {
                    break;
                }

                var values = record.Properties.Select(p => p.Value?.ToString()).ToList();

                found.Add(new RemoteLogonEvent
                {
                    TimeUtc = record.TimeCreated?.ToUniversalTime() ?? DateTime.MinValue,
                    Kind = "RemoteInteractive logon (RDP)",
                    Account = values.Count > 5 ? values[5] : null,
                    SourceAddress = values.Count > 18 ? values[18] : null,
                    Detail = "Security 4624, logon type 10",
                });
            }

            return (found, null);
        }
        catch (Exception ex)
        {
            // Reading the Security log requires elevation. Reported as a gap, never as
            // "nobody has ever connected".
            return (found, new Blindspot
            {
                Area = "Remote logon history (Security event log)",
                Reason = $"Security log unreadable: {ex.GetType().Name}. Past remote logons cannot be confirmed or ruled out.",
                Remedy = "Run as Administrator",
            });
        }
    }

    private static uint? ReadDword(string subKey, string valueName)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(subKey);
            var value = key?.GetValue(valueName);

            return value switch
            {
                int i => unchecked((uint)i),
                uint u => u,
                _ => null,
            };
        }
        catch
        {
            return null;
        }
    }
}
