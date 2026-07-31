using System.Runtime.InteropServices;
using Windows.Win32;
using Windows.Win32.System.Diagnostics.ToolHelp;

namespace RatScan.Native.Processes;

/// <summary>A DLL loaded into a process.</summary>
public sealed record LoadedModule
{
    public required string Name { get; init; }
    public string? Path { get; init; }
}

public sealed record ModuleListResult
{
    public required uint Pid { get; init; }
    public required bool Succeeded { get; init; }
    public IReadOnlyList<LoadedModule> Modules { get; init; } = [];
    public string? Error { get; init; }
}

/// <summary>
/// Enumerates the DLLs loaded into a process.
/// <para>
/// Two detections depend on this. Screen-capture capability shows up as specific
/// graphics DLLs resident in a process that has no visual reason to hold them. And a
/// global input hook betrays itself structurally: <c>SetWindowsHookEx</c> forces the
/// hook DLL into every GUI process on the desktop, so one non-Microsoft DLL appearing
/// across dozens of unrelated processes is the footprint of a keylogger, regardless of
/// what the DLL is called.
/// </para>
/// </summary>
public static class ModuleInventory
{
    private const int ErrorPartialCopy = 299;

    public static ModuleListResult Read(uint pid, CancellationToken cancellationToken = default)
    {
        var modules = new List<LoadedModule>(64);

        try
        {
            // TH32CS_SNAPMODULE32 is included so a 64-bit scanner still sees the
            // modules of 32-bit processes; without it those come back empty and every
            // WOW64 process looks like it has loaded nothing at all.
            using var snapshot = PInvoke.CreateToolhelp32Snapshot_SafeHandle(
                CREATE_TOOLHELP_SNAPSHOT_FLAGS.TH32CS_SNAPMODULE
                | CREATE_TOOLHELP_SNAPSHOT_FLAGS.TH32CS_SNAPMODULE32,
                pid);

            if (snapshot.IsInvalid)
            {
                var error = Marshal.GetLastWin32Error();

                return new ModuleListResult
                {
                    Pid = pid,
                    Succeeded = false,

                    // ERROR_PARTIAL_COPY is the routine answer for a protected or
                    // higher-integrity process, not a malfunction.
                    Error = error == ErrorPartialCopy
                        ? "process is protected or at a higher integrity level"
                        : $"snapshot failed (win32 {error})",
                };
            }

            var entry = new MODULEENTRY32W { dwSize = (uint)Marshal.SizeOf<MODULEENTRY32W>() };

            if (!PInvoke.Module32FirstW(snapshot, ref entry))
            {
                return new ModuleListResult { Pid = pid, Succeeded = false, Error = "no modules readable" };
            }

            do
            {
                cancellationToken.ThrowIfCancellationRequested();

                modules.Add(new LoadedModule
                {
                    Name = entry.szModule.ToString(),
                    Path = entry.szExePath.ToString(),
                });
            }
            while (PInvoke.Module32NextW(snapshot, ref entry));
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            return new ModuleListResult { Pid = pid, Succeeded = false, Error = ex.Message };
        }

        return new ModuleListResult { Pid = pid, Succeeded = true, Modules = modules };
    }
}
