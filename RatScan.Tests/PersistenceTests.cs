using RatScan.Engine.Collectors;
using RatScan.Engine.Model;
using RatScan.Native.Signing;
using Xunit.Abstractions;

namespace RatScan.Tests;

public sealed class PersistenceTests(ITestOutputHelper output)
{
    [Fact]
    public void Sweeps_the_autostart_surfaces_on_this_machine()
    {
        var result = new PersistenceCollector().Collect();

        Assert.NotEmpty(result.Entries);

        foreach (var group in result.Entries.GroupBy(e => e.Surface).OrderByDescending(g => g.Count()))
        {
            output.WriteLine($"{group.Key,-28} {group.Count()}");
        }

        output.WriteLine("");
        output.WriteLine($"fileless entries: {result.Fileless.Count()}");
        foreach (var e in result.Fileless.Take(10))
        {
            output.WriteLine($"  {e.Surface} {e.Name} @ {e.Location}");
        }

        output.WriteLine("");
        foreach (var b in result.Blindspots)
        {
            output.WriteLine($"  blind spot: {b.Area} — {b.Reason}");
        }

        // Every Windows machine has Run-key entries and scheduled tasks; their total
        // absence would mean the sweep is not actually reading anything.
        Assert.Contains(result.Entries, e => e.Surface == PersistenceSurface.RunKey);
        Assert.All(result.Entries, e => Assert.False(string.IsNullOrWhiteSpace(e.Name)));
        Assert.All(result.Entries, e => Assert.False(string.IsNullOrWhiteSpace(e.Location)));
    }

    [Fact]
    public void Winlogon_shell_and_userinit_read_as_the_windows_defaults()
    {
        var result = new PersistenceCollector().Collect();

        var shell = result.Entries.FirstOrDefault(e => e.Surface == PersistenceSurface.WinlogonShell);
        var userinit = result.Entries.FirstOrDefault(e => e.Surface == PersistenceSurface.WinlogonUserinit);

        output.WriteLine($"Shell    = {shell?.Command}");
        output.WriteLine($"Userinit = {userinit?.Command}");

        Assert.NotNull(shell);
        Assert.NotNull(userinit);

        // Anything appended after a comma here is the classic hijack. On a healthy
        // machine these are exactly explorer.exe and userinit.exe.
        Assert.Contains("explorer.exe", shell!.Command!, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("userinit.exe", userinit!.Command!, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("\"C:\\Program Files\\App\\app.exe\" --flag", "C:\\Program Files\\App\\app.exe")]
    [InlineData("C:\\Windows\\System32\\cmd.exe /c whoami", "C:\\Windows\\System32\\cmd.exe")]
    [InlineData("C:\\tools\\thing.exe", "C:\\tools\\thing.exe")]
    [InlineData("rundll32.dll,Entry", "rundll32.dll,Entry")]
    [InlineData("", null)]
    [InlineData(null, null)]
    public void Extracts_the_executable_from_a_command_line(string? command, string? expected)
    {
        // Unquoted paths with spaces are exactly where naive parsers go wrong, and a
        // wrong path silently becomes an unverifiable signature.
        Assert.Equal(expected, PersistenceCollector.ExtractExecutable(command));
    }
}

public sealed class DriverCensusTests(ITestOutputHelper output)
{
    [Fact]
    public void Merges_loaded_modules_with_registry_registrations()
    {
        var result = new DriverCollector().Collect(verifySignatures: true);

        Assert.NotEmpty(result.Drivers);

        var loaded = result.Drivers.Count(d => d.IsLoaded);
        var registered = result.Drivers.Count(d => d.IsRegistered);
        var orphanLoaded = result.Drivers.Where(d => d.LoadedWithoutRegistration).ToList();
        var signed = result.Drivers.Count(d => d.Signature?.Status == SignatureStatus.Valid);
        var unsigned = result.Drivers.Where(d => d.Signature?.Status == SignatureStatus.Unsigned).ToList();

        output.WriteLine($"drivers={result.Drivers.Count} loaded={loaded} registered={registered}");
        output.WriteLine($"signed={signed} unsigned={unsigned.Count} addressesWithheld={result.AddressesWithheld}");

        output.WriteLine("");
        output.WriteLine($"loaded without a registry registration: {orphanLoaded.Count}");
        foreach (var d in orphanLoaded.Take(10))
        {
            output.WriteLine($"  {d.Name} <- {d.ImagePath}");
        }

        output.WriteLine("");
        output.WriteLine("non-Microsoft signers:");
        foreach (var d in result.Drivers
                     .Where(d => d.Signature?.SignerName is not null
                                 && !d.Signature.SignerName.Contains("Microsoft", StringComparison.OrdinalIgnoreCase))
                     .Take(15))
        {
            output.WriteLine($"  {d.Name,-32} {d.Signature!.SignerName}");
        }

        foreach (var b in result.Blindspots)
        {
            output.WriteLine($"  blind spot: {b.Area}");
        }

        Assert.True(registered > 0, "no driver service registrations found — registry walk is broken");

        // Unelevated, the loaded view must be dropped entirely rather than leaving a
        // handful of nameable stragglers that look like unregistered kernel modules.
        if (result.AddressesWithheld)
        {
            Assert.Empty(orphanLoaded);
            Assert.Equal(0, loaded);
        }
    }

    [Theory]
    [InlineData(@"\SystemRoot\System32\drivers\foo.sys", @"System32\drivers\foo.sys")]
    [InlineData(@"\??\C:\tools\bar.sys", @"C:\tools\bar.sys")]
    [InlineData(@"System32\drivers\baz.sys", @"System32\drivers\baz.sys")]
    [InlineData(null, null)]
    public void Resolves_native_driver_paths(string? native, string? expectedSuffix)
    {
        var resolved = DriverCollector.ResolveNativePath(native);

        if (expectedSuffix is null)
        {
            Assert.Null(resolved);
            return;
        }

        Assert.NotNull(resolved);
        Assert.EndsWith(expectedSuffix, resolved!, StringComparison.OrdinalIgnoreCase);

        // A native path handed straight to a file API fails, which would silently mark
        // every driver unsigned — so the result must be rooted and Win32-shaped.
        Assert.DoesNotContain(@"\??\", resolved!, StringComparison.Ordinal);
        Assert.DoesNotContain(@"\SystemRoot\", resolved!, StringComparison.OrdinalIgnoreCase);
    }
}
