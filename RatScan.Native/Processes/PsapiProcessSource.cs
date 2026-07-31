using System.Runtime.InteropServices;
using Windows.Win32;

namespace RatScan.Native.Processes;

/// <summary>
/// View 3 — EnumProcesses (PSAPI).
/// <para>
/// Returns PIDs and nothing else, which is the point: it is a third, structurally
/// different code path to the same truth, so it corroborates or contradicts the
/// other two without sharing their assumptions.
/// </para>
/// </summary>
public sealed class PsapiProcessSource : IProcessSource
{
    public ProcessSourceKind Kind => ProcessSourceKind.Psapi;
    public string SourceName => "EnumProcesses";

    public ProcessSourceResult Enumerate(CancellationToken cancellationToken = default)
    {
        // EnumProcesses silently truncates instead of reporting overflow, so the only
        // safe termination condition is "the kernel used less than we offered".
        var capacity = 1024;

        for (var attempt = 0; attempt < 8; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var bytes = new byte[capacity * sizeof(uint)];

            try
            {
                if (!PInvoke.EnumProcesses(bytes, out var written))
                {
                    return ProcessSourceResult.Fail(
                        Kind, SourceName, $"EnumProcesses failed (win32 {Marshal.GetLastWin32Error()})");
                }

                if (written == bytes.Length)
                {
                    capacity *= 2;
                    continue;
                }

                var count = (int)(written / sizeof(uint));
                var found = new List<RawProcess>(count);

                for (var i = 0; i < count; i++)
                {
                    found.Add(new RawProcess { Pid = BitConverter.ToUInt32(bytes, i * sizeof(uint)) });
                }

                return ProcessSourceResult.Ok(Kind, SourceName, found);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                return ProcessSourceResult.Fail(Kind, SourceName, ex.Message);
            }
        }

        return ProcessSourceResult.Fail(Kind, SourceName, "buffer never became large enough across 8 attempts");
    }
}
