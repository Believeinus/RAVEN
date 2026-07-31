using System.Runtime.InteropServices;
using Windows.Wdk;
using Windows.Wdk.System.SystemInformation;
using Windows.Win32.System.WindowsProgramming;

namespace RatScan.Native.Processes;

/// <summary>
/// View 2 — NtQuerySystemInformation(SystemProcessInformation).
/// <para>
/// The lowest-level process list reachable from user mode, and the richest: it is
/// the only source here that yields thread count, session and creation time in a
/// single pass without opening a handle to anything.
/// </para>
/// </summary>
public sealed unsafe class NtProcessSource : IProcessSource
{
    private const int StatusInfoLengthMismatch = unchecked((int)0xC0000004);

    /// <summary>
    /// Byte offset of <c>CreateTime</c> within SYSTEM_PROCESS_INFORMATION.
    /// <para>
    /// The Windows metadata collapses several documented-but-unstable fields into an
    /// opaque 48-byte <c>Reserved1</c> blob, so the creation time has to be read by
    /// offset. Derivation (x64):
    /// </para>
    /// <code>
    ///   0  NextEntryOffset               ULONG   (4)
    ///   4  NumberOfThreads               ULONG   (4)
    ///   8  WorkingSetPrivateSize         LARGE_INTEGER (8)   } Reserved1
    ///  16  HardFaultCount                ULONG   (4)         } spans
    ///  20  NumberOfThreadsHighWatermark  ULONG   (4)         } bytes
    ///  24  CycleTime                     ULONGLONG (8)       } 8..56
    ///  32  CreateTime                    LARGE_INTEGER (8)   &lt;-- here
    /// </code>
    /// </summary>
    private const int CreateTimeOffset = 32;

    public ProcessSourceKind Kind => ProcessSourceKind.NtQuerySystemInformation;
    public string SourceName => "NtQuerySystemInformation";

    public ProcessSourceResult Enumerate(CancellationToken cancellationToken = default)
    {
        // The list changes between the size query and the read, so grow and retry
        // rather than trusting a single returned length.
        uint capacity = 1 << 20;

        for (var attempt = 0; attempt < 8; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var buffer = Marshal.AllocHGlobal((int)capacity);
            try
            {
                uint needed = 0;
                var status = PInvoke.NtQuerySystemInformation(
                    SYSTEM_INFORMATION_CLASS.SystemProcessInformation,
                    (void*)buffer,
                    capacity,
                    ref needed);

                if (status.Value == StatusInfoLengthMismatch)
                {
                    capacity = Math.Max(needed + (64 * 1024), capacity * 2);
                    continue;
                }

                if (status.Value < 0)
                {
                    return ProcessSourceResult.Fail(
                        Kind, SourceName, $"NtQuerySystemInformation returned 0x{status.Value:X8}");
                }

                return ProcessSourceResult.Ok(Kind, SourceName, Walk((byte*)buffer, cancellationToken));
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                return ProcessSourceResult.Fail(Kind, SourceName, ex.Message);
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        return ProcessSourceResult.Fail(
            Kind, SourceName, "process list kept growing faster than the buffer across 8 attempts");
    }

    private static List<RawProcess> Walk(byte* start, CancellationToken cancellationToken)
    {
        var found = new List<RawProcess>(512);
        var cursor = start;

        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var info = (SYSTEM_PROCESS_INFORMATION*)cursor;

            var name = info->ImageName.Length > 0 && info->ImageName.Buffer.Value is not null
                ? new string(info->ImageName.Buffer.Value, 0, info->ImageName.Length / sizeof(char))
                : null;

            // Reserved2 holds InheritedFromUniqueProcessId — the parent PID.
            var parent = (uint)(nuint)info->Reserved2;

            var rawCreateTime = *(long*)(cursor + CreateTimeOffset);

            found.Add(new RawProcess
            {
                Pid = (uint)(nuint)info->UniqueProcessId.Value,
                ParentPid = parent,
                // PID 0 reports as "" rather than a real image name.
                Name = string.IsNullOrEmpty(name) ? null : name,
                SessionId = info->SessionId,
                ThreadCount = info->NumberOfThreads,
                CreatedUtc = rawCreateTime > 0 ? DateTime.FromFileTimeUtc(rawCreateTime) : null,
            });

            if (info->NextEntryOffset == 0)
            {
                break;
            }

            cursor += info->NextEntryOffset;
        }

        return found;
    }
}
