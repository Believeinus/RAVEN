using System.Diagnostics;
using Microsoft.Win32;

namespace RatScan.Engine.Remediation;

public interface IRemediationExecutor
{
    /// <summary>
    /// Carries out an action. <paramref name="confirmed"/> must be true; it is a
    /// parameter rather than an assumption so that any call site which forgets to ask
    /// the user fails loudly instead of silently acting.
    /// </summary>
    RemediationOutcome Execute(RemediationAction action, bool confirmed);
}

/// <summary>
/// Performs confirmed remediation.
/// <para>
/// Two rules govern everything here. Nothing runs without explicit confirmation, and
/// what runs is exactly what the preview said would run — a confirmation dialog that
/// shows one command and executes another is worse than no dialog, because it trains
/// the user to trust it.
/// </para>
/// </summary>
public sealed class RemediationExecutor : IRemediationExecutor
{
    public RemediationOutcome Execute(RemediationAction action, bool confirmed)
    {
        if (!confirmed)
        {
            return RemediationOutcome.Failed(
                "Not confirmed. RatScan does not change anything on this machine without an "
                + "explicit go-ahead.");
        }

        try
        {
            return action.Kind switch
            {
                RemediationKind.KillProcess => KillProcess(action),
                RemediationKind.DisableService => DisableService(action),
                RemediationKind.RemoveAutostart => RemoveAutostart(action),
                RemediationKind.DisableWindowsSurface => RunPowerShell(action),
                RemediationKind.BlockInboundFirewall => RunPowerShell(action),
                _ => RemediationOutcome.Failed($"Unsupported action: {action.Kind}"),
            };
        }
        catch (UnauthorizedAccessException)
        {
            return RemediationOutcome.Failed(
                "Access denied. This action needs Administrator rights.",
                "Restart RatScan as Administrator and try again.");
        }
        catch (Exception ex)
        {
            return RemediationOutcome.Failed($"{ex.GetType().Name}: {ex.Message}");
        }
    }

    private static RemediationOutcome KillProcess(RemediationAction action)
    {
        if (action.Pid is not { } pid)
        {
            return RemediationOutcome.Failed("No process id was supplied.");
        }

        Process process;
        try
        {
            process = Process.GetProcessById((int)pid);
        }
        catch (ArgumentException)
        {
            // Gone between the scan and the click. Not a failure — the desired state
            // already holds.
            return RemediationOutcome.Ok($"Process {pid} is no longer running.");
        }

        using (process)
        {
            var name = process.ProcessName;
            process.Kill(entireProcessTree: true);

            if (!process.WaitForExit(10_000))
            {
                return RemediationOutcome.Failed(
                    $"'{name}' did not exit within 10 seconds.",
                    "A process that resists termination may be protected, or may be restarting "
                    + "itself. Look for a service or scheduled task bringing it back.");
            }

            return RemediationOutcome.Ok(
                $"Ended '{name}' (PID {pid}) and its child processes.",
                "If it reappears, something is restarting it — check the persistence findings.");
        }
    }

    private static RemediationOutcome DisableService(RemediationAction action)
    {
        if (string.IsNullOrWhiteSpace(action.ServiceName))
        {
            return RemediationOutcome.Failed("No service name was supplied.");
        }

        // Stop first, then disable. Disabling alone leaves it running until reboot,
        // which looks like the action failed.
        var stop = RunProcess("sc.exe", $"stop \"{action.ServiceName}\"");
        var disable = RunProcess("sc.exe", $"config \"{action.ServiceName}\" start= disabled");

        if (!disable.Succeeded)
        {
            return RemediationOutcome.Failed(
                $"Could not disable '{action.ServiceName}'.",
                disable.Detail);
        }

        return RemediationOutcome.Ok(
            $"Stopped '{action.ServiceName}' and set it to never start.",
            stop.Succeeded ? null : "The service was already stopped.");
    }

    private static RemediationOutcome RemoveAutostart(RemediationAction action)
    {
        if (string.IsNullOrWhiteSpace(action.RegistryPath) || string.IsNullOrWhiteSpace(action.RegistryValue))
        {
            return RemediationOutcome.Failed("No registry location was supplied.");
        }

        var (hive, subKey) = SplitHive(action.RegistryPath);
        if (hive is null)
        {
            return RemediationOutcome.Failed($"Unrecognised registry root in '{action.RegistryPath}'.");
        }

        using var key = hive.OpenSubKey(subKey, writable: true);
        if (key is null)
        {
            return RemediationOutcome.Ok("That registry key no longer exists.");
        }

        if (key.GetValue(action.RegistryValue) is null)
        {
            return RemediationOutcome.Ok($"'{action.RegistryValue}' was already gone.");
        }

        key.DeleteValue(action.RegistryValue);

        return RemediationOutcome.Ok(
            $"Removed the auto-start entry '{action.RegistryValue}'.",
            "This stops it launching at sign-in. It does not remove the program itself, and does "
            + "not stop it if it is running right now.");
    }

    /// <summary>
    /// Runs the previewed PowerShell verbatim. The command shown to the user and the
    /// command executed are the same string, deliberately — there is no second,
    /// hidden version.
    /// </summary>
    private static RemediationOutcome RunPowerShell(RemediationAction action)
    {
        var result = RunProcess(
            "powershell.exe",
            $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"{action.PreviewCommand.Replace("\"", "\\\"")}\"");

        return result.Succeeded
            ? RemediationOutcome.Ok($"{action.Title} — done.", action.Caveat)
            : RemediationOutcome.Failed($"{action.Title} — failed.", result.Detail);
    }

    private static (bool Succeeded, string? Detail) RunProcess(string fileName, string arguments)
    {
        var info = new ProcessStartInfo
        {
            FileName = fileName,
            Arguments = arguments,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };

        using var process = Process.Start(info);
        if (process is null)
        {
            return (false, $"Could not start {fileName}.");
        }

        var stdout = process.StandardOutput.ReadToEnd();
        var stderr = process.StandardError.ReadToEnd();
        process.WaitForExit(30_000);

        var detail = string.IsNullOrWhiteSpace(stderr) ? stdout : stderr;

        return (process.ExitCode == 0, string.IsNullOrWhiteSpace(detail) ? null : detail.Trim());
    }

    private static (RegistryKey? Hive, string SubKey) SplitHive(string path)
    {
        var separator = path.IndexOf('\\');
        if (separator < 0)
        {
            return (null, string.Empty);
        }

        var root = path[..separator];
        var rest = path[(separator + 1)..];

        return root.ToUpperInvariant() switch
        {
            "HKLM" or "HKEY_LOCAL_MACHINE" => (Registry.LocalMachine, rest),
            "HKCU" or "HKEY_CURRENT_USER" => (Registry.CurrentUser, rest),
            _ => (null, string.Empty),
        };
    }
}
