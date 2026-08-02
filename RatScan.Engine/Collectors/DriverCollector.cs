using Microsoft.Win32;
using RatScan.Engine.Model;
using RatScan.Native.Drivers;
using RatScan.Native.Signing;

namespace RatScan.Engine.Collectors;

public interface IDriverCollector
{
    DriverCensusResult Collect(bool verifySignatures = true, CancellationToken cancellationToken = default);
}

/// <summary>
/// Merges loaded kernel modules with their registry service registrations.
/// <para>
/// Drivers deserve their own census because a driver is the one thing on the machine
/// that can lie to every other check this tool performs. The merge also exposes the
/// two interesting mismatches: loaded without a registration (unusual — the normal
/// load path leaves a registry trace), and registered to auto-start but not present.
/// </para>
/// </summary>
public sealed class DriverCollector : IDriverCollector
{
    private const string ServicesKey = @"SYSTEM\CurrentControlSet\Services";

    // Service types that denote a kernel-mode driver.
    private const uint ServiceKernelDriver = 0x00000001;
    private const uint ServiceFileSystemDriver = 0x00000002;

    public DriverCensusResult Collect(bool verifySignatures = true, CancellationToken cancellationToken = default)
    {
        var blindspots = new List<Blindspot>();
        var byName = new Dictionary<string, DriverEntry>(StringComparer.OrdinalIgnoreCase);

        var loaded = LoadedDriverInventory.ReadAll(cancellationToken);

        if (!loaded.Succeeded)
        {
            blindspots.Add(new Blindspot
            {
                Area = "Loaded kernel modules",
                Reason = loaded.Error ?? "EnumDeviceDrivers failed",
            });
        }
        else if (loaded.AddressesWithheld)
        {
            blindspots.Add(new Blindspot
            {
                Area = "Loaded kernel module identities",
                Reason = $"Windows withheld kernel image bases from this process (KASLR protection below high "
                         + $"integrity), so the {loaded.Drivers.Count} loaded modules cannot be named or resolved "
                         + "to files. Only the count is trustworthy.",
                Remedy = "Run as Administrator",
            });
        }

        // When the OS withholds image bases, the name lookups keyed off them return
        // nothing for almost every module — leaving one or two stragglers that would
        // then appear "loaded but unregistered", a CRITICAL-looking finding produced
        // entirely by missing privilege. The loaded view is unusable in that state, so
        // it is dropped wholesale and the blind spot above carries the explanation.
        if (loaded.Succeeded && !loaded.AddressesWithheld)
        {
            foreach (var driver in loaded.Drivers)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var name = driver.BaseName;
                if (string.IsNullOrWhiteSpace(name))
                {
                    continue;
                }

                byName[name] = new DriverEntry
                {
                    Name = name,
                    ImagePath = ResolveNativePath(driver.NativePath),
                    IsLoaded = true,
                };
            }
        }

        CollectRegistered(byName, blindspots, cancellationToken);

        var objects = CollectDriverObjects(blindspots, cancellationToken);

        if (verifySignatures)
        {
            VerifySignatures(byName, cancellationToken);
        }

        return new DriverCensusResult
        {
            Drivers = byName.Values.OrderBy(d => d.Name, StringComparer.OrdinalIgnoreCase).ToList(),
            Blindspots = blindspots,
            AddressesWithheld = loaded.AddressesWithheld,
            DriverObjects = objects.Succeeded ? objects.Objects : [],
            DriverObjectsRead = objects.Succeeded,
        };
    }

    /// <summary>
    /// Reads <c>\Driver</c> as a third view of what is in the kernel.
    /// <para>
    /// Independent of both other sources in the way invariant 4 requires: unlinking a
    /// driver from <c>PsLoadedModuleList</c> hides it from the loaded-module view and
    /// deleting its service key hides it from the registry view, but a driver still needs
    /// an object in <c>\Driver</c> to be sent an IRP.
    /// </para>
    /// <para>
    /// Collected and disclosed, not yet judged. The obvious rule — a driver object with no
    /// module and no registration — needs a measured baseline before it can be trusted,
    /// because object names are not file names (<c>\Driver\nvlddmkm</c> against
    /// <c>nvlddmkm.sys</c>) and the rate at which legitimate drivers fail to match is
    /// exactly what has to be counted first. That measurement needs an elevated run, which
    /// has not happened yet, and guessing the threshold is how this detector would ship a
    /// flood of findings against a healthy machine.
    /// </para>
    /// </summary>
    private static DriverObjectResult CollectDriverObjects(
        List<Blindspot> blindspots, CancellationToken cancellationToken)
    {
        var objects = DriverObjectDirectory.ReadAll(cancellationToken: cancellationToken);

        if (objects.Succeeded)
        {
            return objects;
        }

        blindspots.Add(new Blindspot
        {
            Area = @"Driver object directory (\Driver)",
            Reason = $"{objects.Error}. The third, independent view of the kernel's drivers is "
                     + "unavailable, so a driver hidden from both the loaded-module list and the "
                     + "registry cannot be cross-checked against the object manager.",
            Remedy = objects.AccessDenied ? "Run as Administrator" : null,
        });

        return objects;
    }

    private static void CollectRegistered(
        Dictionary<string, DriverEntry> byName, List<Blindspot> blindspots, CancellationToken cancellationToken)
    {
        using var services = Registry.LocalMachine.OpenSubKey(ServicesKey);
        if (services is null)
        {
            blindspots.Add(new Blindspot
            {
                Area = "Driver service registrations",
                Reason = @"HKLM\SYSTEM\CurrentControlSet\Services could not be opened",
            });
            return;
        }

        foreach (var serviceName in services.GetSubKeyNames())
        {
            cancellationToken.ThrowIfCancellationRequested();

            using var key = services.OpenSubKey(serviceName);
            if (key?.GetValue("Type") is not int rawType)
            {
                continue;
            }

            var type = unchecked((uint)rawType);
            if ((type & (ServiceKernelDriver | ServiceFileSystemDriver)) == 0)
            {
                continue;
            }

            var imagePath = ResolveNativePath(key.GetValue("ImagePath")?.ToString());
            var startType = key.GetValue("Start") is int start ? unchecked((uint)start) : (uint?)null;

            // Loaded modules are keyed by file name (e.g. "foo.sys"); registrations by
            // service name (e.g. "foo"). Match on the file name so the two views join.
            var fileName = imagePath is not null ? Path.GetFileName(imagePath) : $"{serviceName}.sys";

            if (byName.TryGetValue(fileName, out var existing))
            {
                byName[fileName] = existing with
                {
                    IsRegistered = true,
                    StartType = startType,
                    ImagePath = existing.ImagePath ?? imagePath,
                };
            }
            else
            {
                byName[fileName] = new DriverEntry
                {
                    Name = fileName,
                    ImagePath = imagePath,
                    IsRegistered = true,
                    StartType = startType,
                };
            }
        }
    }

    private static void VerifySignatures(Dictionary<string, DriverEntry> byName, CancellationToken cancellationToken)
    {
        var withPaths = byName
            .Where(kv => !string.IsNullOrEmpty(kv.Value.ImagePath))
            .ToList();

        Parallel.ForEach(
            withPaths,
            new ParallelOptions { CancellationToken = cancellationToken },
            kv =>
            {
                var signature = AuthenticodeVerifier.Verify(kv.Value.ImagePath!);
                lock (byName)
                {
                    byName[kv.Key] = byName[kv.Key] with { Signature = signature };
                }
            });
    }

    /// <summary>
    /// Turns a driver's native path into a Win32 one.
    /// <para>
    /// Driver paths arrive in several shapes — <c>\SystemRoot\System32\drivers\x.sys</c>,
    /// <c>\??\C:\...</c>, or a bare relative path — and passing any of them straight to
    /// a file API fails, which would silently mark every driver unsigned.
    /// </para>
    /// </summary>
    internal static string? ResolveNativePath(string? nativePath)
    {
        if (string.IsNullOrWhiteSpace(nativePath))
        {
            return null;
        }

        var path = nativePath.Trim();
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);

        if (path.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
        {
            return Path.Combine(windows, path[12..]);
        }

        if (path.StartsWith(@"\??\", StringComparison.Ordinal))
        {
            return path[4..];
        }

        if (path.StartsWith(@"system32\", StringComparison.OrdinalIgnoreCase)
            || path.StartsWith(@"System32\", StringComparison.Ordinal))
        {
            return Path.Combine(windows, path);
        }

        return path;
    }
}
