using RatScan.Native.Drivers;
using RatScan.Native.Processes;
using RatScan.Native.Services;
using RatScan.Native.Sessions;
using RatScan.Native.Smb;
using RatScan.Native.Windowing;
using Xunit.Abstractions;

namespace RatScan.Tests;

/// <summary>
/// Proves each collector returns real data from this machine. Compiling tells us
/// nothing about whether a pointer walk lands on the right fields.
/// </summary>
public sealed class InventoryTests(ITestOutputHelper output)
{
    [Fact]
    public void Services_enumerate_with_names_and_running_pids()
    {
        var result = ServiceInventory.ReadAll();
        Assert.True(result.Succeeded, result.Error);
        Assert.NotEmpty(result.Services);

        var running = result.Services.Where(s => s.IsRunning).ToList();
        var drivers = result.Services.Count(s => s.IsDriver);

        output.WriteLine($"services={result.Services.Count} running={running.Count} drivers={drivers}");

        // Garbled string pointers would show up as empty names.
        Assert.All(result.Services, s => Assert.False(string.IsNullOrWhiteSpace(s.Name)));

        // Every scheduler has these; their absence means the struct stride is wrong.
        Assert.Contains(result.Services, s => s.Name.Equals("Schedule", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(running, s => s.ProcessId > 0);
    }

    [Fact]
    public void Kernel_drivers_enumerate_with_paths()
    {
        var result = LoadedDriverInventory.ReadAll();
        Assert.True(result.Succeeded, result.Error);
        Assert.NotEmpty(result.Drivers);

        output.WriteLine($"loaded kernel modules: {result.Drivers.Count} addressesWithheld={result.AddressesWithheld}");
        foreach (var d in result.Drivers.Take(3))
        {
            output.WriteLine($"  base=0x{d.ImageBase:X} {d.BaseName}  <-  {d.NativePath}");
        }

        if (result.AddressesWithheld)
        {
            // Unelevated: Windows zeroes kernel image bases (KASLR protection), which
            // also blanks the name lookups keyed off them. The count is still real, and
            // the degradation must be declared rather than mistaken for a clean census.
            output.WriteLine("  running unelevated — kernel addresses withheld by the OS");
            Assert.All(result.Drivers, d => Assert.Equal(0ul, d.ImageBase));
            return;
        }

        // Elevated: the kernel itself is always loaded; its absence means a broken walk.
        Assert.Contains(result.Drivers, d =>
            d.BaseName is not null && d.BaseName.StartsWith("ntoskrnl", StringComparison.OrdinalIgnoreCase));

        Assert.All(result.Drivers, d => Assert.True(d.ImageBase > 0));
    }

    [Fact]
    public void Terminal_sessions_include_this_session()
    {
        var result = TerminalSessionInventory.ReadAll();
        Assert.True(result.Succeeded, result.Error);
        Assert.NotEmpty(result.Sessions);

        foreach (var s in result.Sessions)
        {
            output.WriteLine($"  session {s.SessionId,-3} station={s.WinStationName,-16} state={s.State} " +
                             $"user={s.UserName} client={s.ClientName} remote={s.IsRemote}");
        }

        Assert.Contains(result.Sessions, s => s.SessionId == 0);
    }

    [Fact]
    public void Window_inventory_maps_windows_to_processes()
    {
        var presence = WindowInventory.ReadAll();
        Assert.NotEmpty(presence);

        var withVisible = presence.Values.Count(p => p.VisibleWindows > 0);
        var hidden = presence.Values.Count(p => p.RunsHidden);

        output.WriteLine($"processes owning windows={presence.Count} with visible={withVisible} hidden-only={hidden}");

        Assert.True(withVisible > 0, "no process owns a visible window — enumeration is broken");
        Assert.All(presence.Values, p => Assert.True(p.VisibleWindows <= p.TotalWindows));
    }

    [Fact]
    public void Smb_inventory_lists_shares_and_declares_session_visibility()
    {
        var result = SmbInventory.ReadAll();
        Assert.True(result.Succeeded, result.Error);

        output.WriteLine($"shares={result.Shares.Count} sessions={result.Sessions.Count} " +
                         $"sessionsUnavailable={result.SessionsUnavailable}");

        foreach (var s in result.Shares)
        {
            output.WriteLine($"  {s.Name,-16} admin={s.IsAdministrative,-5} uses={s.CurrentUses} path={s.Path}");
        }

        // IPC$ exists on every Windows machine with the service running.
        Assert.Contains(result.Shares, s => s.Name.Equals("IPC$", StringComparison.OrdinalIgnoreCase));

        // Unelevated, session enumeration must report itself unavailable rather than
        // silently returning "nobody is connected".
        if (result.SessionsUnavailable)
        {
            Assert.Empty(result.Sessions);
        }
    }

    [Fact]
    public void Process_inspector_reads_this_process()
    {
        var self = ProcessInspector.Inspect((uint)Environment.ProcessId);

        output.WriteLine($"path={self.ImagePath}");
        output.WriteLine($"session={self.SessionId} elevated={self.IsElevated} " +
                         $"integrity={self.Integrity} uiAccess={self.HasUiAccess}");

        Assert.False(self.Inaccessible);
        Assert.NotNull(self.ImagePath);
        Assert.EndsWith(".exe", self.ImagePath!, StringComparison.OrdinalIgnoreCase);
        Assert.NotEqual(IntegrityLevel.Unknown, self.Integrity);
        Assert.False(self.HasUiAccess);
    }
}
