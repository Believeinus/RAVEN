using System.Security.Principal;
using Microsoft.Win32;
using RatScan.Engine.Model;
using RatScan.Native;

namespace RatScan.Engine.Scoring;

public interface IIntegrityAssessor
{
    IntegrityReport Assess();
}

/// <summary>
/// Establishes the conditions the scan ran under.
/// <para>
/// This exists because a verdict without its coverage is a guess wearing a uniform.
/// Every signal here is reported whether it passes or fails, and an indeterminate
/// signal stays indeterminate — guessing "probably fine" is the exact move this tool
/// refuses to make.
/// </para>
/// </summary>
public sealed class IntegrityAssessor : IIntegrityAssessor
{
    public IntegrityReport Assess()
    {
        var elevated = IsElevated();
        var signals = new List<IntegritySignal> { ElevationSignal(elevated) };

        var (enforced, testSigning, debugMode) = SystemIntegrityProbe.ReadCodeIntegrity();

        signals.Add(new IntegritySignal
        {
            Name = "Driver signature enforcement",
            Satisfied = enforced,
            UnderminesResult = true,
            Detail = enforced switch
            {
                true => "Windows is enforcing driver signing.",
                false => "Code integrity is NOT enforced. Unsigned kernel drivers can load, and a "
                         + "kernel driver can hide anything from this scan.",
                null => "Could not be determined.",
            },
        });

        signals.Add(new IntegritySignal
        {
            Name = "Test-signing mode",
            Satisfied = testSigning is null ? null : !testSigning,
            UnderminesResult = true,
            Detail = testSigning switch
            {
                false => "Off — only properly signed drivers load.",
                true => "ON. Windows is accepting test-signed drivers, so anyone can load kernel "
                        + "code without a real certificate.",
                null => "Could not be determined.",
            },
        });

        signals.Add(new IntegritySignal
        {
            Name = "Kernel debug mode",
            Satisfied = debugMode is null ? null : !debugMode,
            UnderminesResult = true,
            Detail = debugMode switch
            {
                false => "Off.",
                true => "ON. The kernel is running in debug mode.",
                null => "Could not be determined.",
            },
        });

        var debugger = SystemIntegrityProbe.IsKernelDebuggerPresent();
        signals.Add(new IntegritySignal
        {
            Name = "Kernel debugger",
            Satisfied = debugger is null ? null : !debugger,
            UnderminesResult = true,
            Detail = debugger switch
            {
                false => "No kernel debugger attached.",
                true => "A kernel debugger IS attached. It can read and alter anything on this "
                        + "machine, including the results of this scan.",
                null => "Could not be determined.",
            },
        });

        signals.Add(SecureBootSignal());
        signals.Add(HvciSignal());

        return new IntegrityReport { Elevated = elevated, Signals = signals };
    }

    private static IntegritySignal ElevationSignal(bool elevated) => new()
    {
        Name = "Administrator rights",
        Satisfied = elevated,

        // Missing elevation limits coverage but does not let anything deceive the
        // scan, so it reduces completeness rather than trustworthiness.
        UnderminesResult = false,
        Detail = elevated
            ? "Running elevated — full coverage available."
            : "Running WITHOUT Administrator. Process image paths, kernel driver identities, the "
              + "Security event log and SMB session data are unavailable, so much of this machine "
              + "could not be examined.",
    };

    private static IntegritySignal SecureBootSignal()
    {
        var value = ReadDword(@"SYSTEM\CurrentControlSet\Control\SecureBoot\State", "UEFISecureBootEnabled");

        return new IntegritySignal
        {
            Name = "Secure Boot",
            Satisfied = value is null ? null : value == 1,
            UnderminesResult = false,
            Detail = value switch
            {
                1 => "Enabled — the boot chain is verified.",
                0 => "Disabled. A bootkit could load before Windows and would be invisible to any "
                     + "tool running inside it.",
                _ => "Could not be determined (legacy BIOS, or the value is unreadable).",
            },
        };
    }

    private static IntegritySignal HvciSignal()
    {
        var value = ReadDword(
            @"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity",
            "Enabled");

        return new IntegritySignal
        {
            Name = "Memory integrity (HVCI)",
            Satisfied = value is null ? null : value == 1,
            UnderminesResult = false,
            Detail = value switch
            {
                1 => "Enabled — kernel code is verified by the hypervisor.",
                0 => "Not enabled. Turning it on makes malicious kernel drivers substantially harder "
                     + "to load.",
                _ => "Could not be determined.",
            },
        };
    }

    private static bool IsElevated()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    private static uint? ReadDword(string subKey, string valueName)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(subKey);
            return key?.GetValue(valueName) switch
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
