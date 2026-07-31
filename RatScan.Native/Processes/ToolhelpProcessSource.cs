using System.Runtime.InteropServices;
using Windows.Win32;
using Windows.Win32.System.Diagnostics.ToolHelp;

namespace RatScan.Native.Processes;

/// <summary>
/// View 1 — CreateToolhelp32Snapshot.
/// <para>
/// The oldest and most widely hooked process-listing interface, which is exactly
/// why it earns a place in the diff: userland rootkits and "process hider" tools
/// overwhelmingly target this one, so a process present in the native view but
/// missing here is a strong concealment signal.
/// </para>
/// </summary>
public sealed class ToolhelpProcessSource : IProcessSource
{
    public ProcessSourceKind Kind => ProcessSourceKind.Toolhelp;
    public string SourceName => "CreateToolhelp32Snapshot";

    public ProcessSourceResult Enumerate(CancellationToken cancellationToken = default)
    {
        var found = new List<RawProcess>(512);

        try
        {
            using var snapshot = PInvoke.CreateToolhelp32Snapshot_SafeHandle(
                CREATE_TOOLHELP_SNAPSHOT_FLAGS.TH32CS_SNAPPROCESS, 0);

            if (snapshot.IsInvalid)
            {
                return ProcessSourceResult.Fail(
                    Kind, SourceName, $"snapshot failed (win32 {Marshal.GetLastWin32Error()})");
            }

            var entry = new PROCESSENTRY32W { dwSize = (uint)Marshal.SizeOf<PROCESSENTRY32W>() };

            if (!PInvoke.Process32FirstW(snapshot, ref entry))
            {
                return ProcessSourceResult.Fail(
                    Kind, SourceName, $"Process32FirstW failed (win32 {Marshal.GetLastWin32Error()})");
            }

            do
            {
                cancellationToken.ThrowIfCancellationRequested();

                found.Add(new RawProcess
                {
                    Pid = entry.th32ProcessID,
                    ParentPid = entry.th32ParentProcessID,
                    Name = entry.szExeFile.ToString(),
                    ThreadCount = entry.cntThreads,
                });
            }
            while (PInvoke.Process32NextW(snapshot, ref entry));
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            return ProcessSourceResult.Fail(Kind, SourceName, ex.Message);
        }

        return ProcessSourceResult.Ok(Kind, SourceName, found);
    }
}
