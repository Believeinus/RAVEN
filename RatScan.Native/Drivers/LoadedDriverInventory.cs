using Windows.Win32;

namespace RatScan.Native.Drivers;

/// <summary>One kernel module currently loaded, as PSAPI reports it.</summary>
public sealed record LoadedDriver
{
    public required ulong ImageBase { get; init; }
    public string? BaseName { get; init; }

    /// <summary>
    /// Native path, e.g. <c>\SystemRoot\System32\drivers\foo.sys</c>. Translating this
    /// to a Win32 path is the engine's job, since it needs the device-map lookup.
    /// </summary>
    public string? NativePath { get; init; }
}

public sealed record LoadedDriverResult
{
    public required bool Succeeded { get; init; }
    public IReadOnlyList<LoadedDriver> Drivers { get; init; } = [];
    public string? Error { get; init; }

    /// <summary>
    /// True when the kernel withheld driver image base addresses.
    /// <para>
    /// Since Windows 8.1, <c>EnumDeviceDrivers</c> returns zeroed image bases to
    /// callers below high integrity — a KASLR protection against kernel address
    /// disclosure. The driver <em>count</em> survives, but the bases are zero and the
    /// name lookups keyed off them return nothing, so the census is reduced to a
    /// number. Elevation restores it.
    /// </para>
    /// <para>
    /// This is exactly the kind of degradation the Scan Integrity panel exists to
    /// name: without it, an unelevated scan would show an empty driver list and look
    /// indistinguishable from a machine with nothing to hide.
    /// </para>
    /// </summary>
    public bool AddressesWithheld { get; init; }
}

/// <summary>
/// Enumerates loaded kernel modules.
/// <para>
/// Kernel drivers matter disproportionately here: a driver is the one thing on the
/// machine that can lie to every other check this tool performs. Legitimate remote
/// tools also install them (mirror and indirect-display drivers, VPN adapters), so
/// the census feeds both the surveillance detector and the integrity panel.
/// </para>
/// </summary>
public static unsafe class LoadedDriverInventory
{
    public static LoadedDriverResult ReadAll(CancellationToken cancellationToken = default)
    {
        try
        {
            // EnumDeviceDrivers truncates silently rather than reporting overflow, so
            // grow until the kernel uses less than offered.
            var capacity = 1024;

            for (var attempt = 0; attempt < 8; attempt++)
            {
                var bytes = new byte[capacity * sizeof(ulong)];

                if (!PInvoke.EnumDeviceDrivers(bytes, out var written))
                {
                    return new LoadedDriverResult
                    {
                        Succeeded = false,
                        Error = $"EnumDeviceDrivers failed (win32 {System.Runtime.InteropServices.Marshal.GetLastWin32Error()})",
                    };
                }

                if (written == bytes.Length)
                {
                    capacity *= 2;
                    continue;
                }

                var count = (int)(written / sizeof(ulong));
                var found = new List<LoadedDriver>(count);

                fixed (byte* raw = bytes)
                {
                    var bases = (void**)raw;

                    for (var i = 0; i < count; i++)
                    {
                        cancellationToken.ThrowIfCancellationRequested();

                        var imageBase = bases[i];

                        found.Add(new LoadedDriver
                        {
                            ImageBase = (ulong)imageBase,
                            BaseName = ReadString(chars => PInvoke.GetDeviceDriverBaseName(imageBase, chars)),
                            NativePath = ReadString(chars => PInvoke.GetDeviceDriverFileName(imageBase, chars)),
                        });
                    }
                }

                // Every base zero on a non-empty list means the kernel withheld them
                // rather than that no drivers are loaded.
                var withheld = found.Count > 0 && found.All(d => d.ImageBase == 0);

                return new LoadedDriverResult
                {
                    Succeeded = true,
                    Drivers = found,
                    AddressesWithheld = withheld,
                };
            }

            return new LoadedDriverResult
            {
                Succeeded = false,
                Error = "driver list kept growing across 8 attempts",
            };
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            return new LoadedDriverResult { Succeeded = false, Error = ex.Message };
        }
    }

    private static string? ReadString(Func<char[], uint> read)
    {
        var buffer = new char[1024];
        var written = read(buffer);

        return written == 0 ? null : new string(buffer, 0, (int)written);
    }
}
