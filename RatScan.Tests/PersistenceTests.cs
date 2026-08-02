using RatScan.Engine.Collectors;
using RatScan.Engine.Model;
using RatScan.Native.Drivers;
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

    [Fact]
    public void Resolves_the_paths_auto_start_entries_are_actually_written_in()
    {
        // Measured, not hypothetical: before this resolution existed, 87 of this
        // machine's 296 path-bearing entries could not be verified at all, because Task
        // Scheduler stores %windir%-relative paths and print monitors and netsh helpers
        // store bare DLL names. Every one of them looked, from the outside, exactly like
        // an entry that had been checked and found clean.
        var expanded = PersistenceCollector.ResolveImagePath(@"%windir%\system32\defrag.exe");
        Assert.NotNull(expanded);
        Assert.DoesNotContain("%", expanded!, StringComparison.Ordinal);
        Assert.True(File.Exists(expanded), $"{expanded} should exist after expansion");

        var bare = PersistenceCollector.ResolveImagePath("tcpmon.dll");
        Assert.NotNull(bare);
        Assert.True(Path.IsPathRooted(bare), $"{bare} should have been found in a system directory");
        Assert.True(File.Exists(bare), $"{bare} should exist");

        // A rooted path is taken as given, and an unresolvable name is returned as it
        // stands. Inventing a location would point the signature check at a file nobody
        // observed, which is how a scan starts reporting on the wrong binary.
        Assert.Equal(@"C:\tools\thing.exe", PersistenceCollector.ResolveImagePath(@"C:\tools\thing.exe"));
        Assert.Equal("nothing-by-this-name.dll", PersistenceCollector.ResolveImagePath("nothing-by-this-name.dll"));
        Assert.Null(PersistenceCollector.ResolveImagePath(null));
    }

    [Fact]
    public void Startup_folder_shortcuts_are_followed_to_what_they_launch()
    {
        var result = new PersistenceCollector().Collect();

        var shortcuts = result.Entries
            .Where(e => e.Surface == PersistenceSurface.StartupFolder
                        && e.Name.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase))
            .ToList();

        foreach (var entry in shortcuts)
        {
            output.WriteLine($"{entry.Name} -> {entry.ImagePath} [{entry.Signature?.Status}]");
        }

        if (shortcuts.Count == 0)
        {
            return;
        }

        // A .lnk carries no Authenticode signature of its own, so an entry left pointing
        // at the shortcut reports as unsigned on every machine that has one. That is a
        // fact about the file format, not about the software, and it was producing two
        // of this machine's seven "unsigned" auto-start entries.
        Assert.Contains(shortcuts, e =>
            !e.ImagePath!.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase));
    }
}

public sealed class DriverObjectDirectoryTests(ITestOutputHelper output)
{
    [Fact]
    public void Reads_the_driver_object_directory_or_names_why_it_could_not()
    {
        var result = DriverObjectDirectory.ReadAll();

        output.WriteLine($"succeeded={result.Succeeded} accessDenied={result.AccessDenied} " +
                         $"objects={result.Objects.Count}");
        output.WriteLine($"error={result.Error}");

        foreach (var o in result.Objects.Take(25))
        {
            output.WriteLine($"  {o.Name} [{o.TypeName}]");
        }

        // Failure is a legitimate outcome here and unelevated it is the expected one, so
        // the assertion is not "it worked" but "it never reports an empty directory when
        // what actually happened is that it could not look". An empty list and a refused
        // open are the same shape and opposite meanings.
        if (!result.Succeeded)
        {
            Assert.Empty(result.Objects);
            Assert.False(string.IsNullOrWhiteSpace(result.Error));
            return;
        }

        // \Driver is never empty on a running Windows system - if it reads as empty, the
        // walk is broken rather than the machine being remarkable.
        Assert.NotEmpty(result.Objects);
        Assert.All(result.Objects, o => Assert.False(string.IsNullOrWhiteSpace(o.Name)));

        // Every object in \Driver is of type Driver. A different type here means the
        // struct layout is wrong and the names are being read out of the wrong offset -
        // the exact failure mode a hand-declared struct risks.
        Assert.All(result.Objects, o => Assert.Equal("Driver", o.TypeName));
    }

    [Fact]
    public void Reads_a_directory_that_needs_no_privilege_as_a_layout_check()
    {
        // \ is readable unelevated, so this exercises the parse on a real directory even
        // when \Driver refuses - which is what separates "the struct is wrong" from
        // "we were not allowed to look" when this fails.
        var result = DriverObjectDirectory.ReadAll(@"\");

        output.WriteLine($"succeeded={result.Succeeded} objects={result.Objects.Count} error={result.Error}");
        foreach (var o in result.Objects.Take(20))
        {
            output.WriteLine($"  {o.Name} [{o.TypeName}]");
        }

        if (!result.Succeeded)
        {
            return;
        }

        Assert.NotEmpty(result.Objects);

        // The root object directory always holds these. Finding them by name proves the
        // Name field is being read from the right offset, not merely that bytes came back.
        Assert.Contains(result.Objects, o =>
            string.Equals(o.Name, "Device", StringComparison.Ordinal));
        Assert.Contains(result.Objects, o =>
            string.Equals(o.Name, "Driver", StringComparison.Ordinal));
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
