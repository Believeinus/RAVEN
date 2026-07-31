using Windows.Win32;
using Windows.Win32.System.Services;

namespace RatScan.Native.Services;

/// <summary>One service as the Service Control Manager reports it.</summary>
public sealed record ServiceRecord
{
    public required string Name { get; init; }
    public string? DisplayName { get; init; }
    public uint ServiceType { get; init; }
    public uint CurrentState { get; init; }

    /// <summary>PID of the hosting process, or 0 when the service is not running.</summary>
    public uint ProcessId { get; init; }

    public bool IsRunning => CurrentState == 4;   // SERVICE_RUNNING
    public bool IsDriver => (ServiceType & 0x0B) != 0;   // KERNEL_DRIVER | FILE_SYSTEM_DRIVER
}

public sealed record ServiceInventoryResult
{
    public required bool Succeeded { get; init; }
    public IReadOnlyList<ServiceRecord> Services { get; init; } = [];
    public string? Error { get; init; }
}

/// <summary>
/// Enumerates services through the Service Control Manager.
/// <para>
/// This is one half of the service cross-view: a key present under
/// <c>HKLM\SYSTEM\CurrentControlSet\Services</c> but absent here is a service hidden
/// from the SCM, which is a concealment technique rather than a configuration quirk.
/// The registry half lives in the engine, which owns registry access.
/// </para>
/// </summary>
public static unsafe class ServiceInventory
{
    private const uint ScManagerConnect = 0x0001;
    private const uint ScManagerEnumerateService = 0x0004;
    private const uint ErrorMoreData = 234;

    public static ServiceInventoryResult ReadAll(CancellationToken cancellationToken = default)
    {
        try
        {
            // Casts disambiguate the string and PCWSTR overloads, which a bare null
            // matches equally. Null machine/database means "this machine, SERVICES_ACTIVE".
            using var scm = PInvoke.OpenSCManager(
                (string?)null,
                (string?)null,
                ScManagerConnect | ScManagerEnumerateService);

            if (scm.IsInvalid)
            {
                return new ServiceInventoryResult
                {
                    Succeeded = false,
                    Error = $"OpenSCManager failed (win32 {System.Runtime.InteropServices.Marshal.GetLastWin32Error()})",
                };
            }

            // Size probe, then read. Both service and driver entries are requested so
            // the driver census has an SCM-side view to diff against.
            const ENUM_SERVICE_TYPE types =
                ENUM_SERVICE_TYPE.SERVICE_WIN32 | ENUM_SERVICE_TYPE.SERVICE_DRIVER;

            PInvoke.EnumServicesStatusEx(
                scm, SC_ENUM_TYPE.SC_ENUM_PROCESS_INFO, types, ENUM_SERVICE_STATE.SERVICE_STATE_ALL,
                Span<byte>.Empty, out var needed, out _, null);

            if (needed == 0)
            {
                return new ServiceInventoryResult { Succeeded = true };
            }

            var buffer = new byte[needed];

            if (!PInvoke.EnumServicesStatusEx(
                    scm, SC_ENUM_TYPE.SC_ENUM_PROCESS_INFO, types, ENUM_SERVICE_STATE.SERVICE_STATE_ALL,
                    buffer, out _, out var returned, null))
            {
                var error = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
                return new ServiceInventoryResult
                {
                    Succeeded = false,
                    Error = error == ErrorMoreData
                        ? "service list grew between the size probe and the read"
                        : $"EnumServicesStatusEx failed (win32 {error})",
                };
            }

            var found = new List<ServiceRecord>((int)returned);

            fixed (byte* raw = buffer)
            {
                var entries = (ENUM_SERVICE_STATUS_PROCESSW*)raw;

                for (uint i = 0; i < returned; i++)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    var entry = entries + i;
                    var status = entry->ServiceStatusProcess;

                    found.Add(new ServiceRecord
                    {
                        Name = entry->lpServiceName.ToString() ?? string.Empty,
                        DisplayName = entry->lpDisplayName.ToString(),
                        ServiceType = (uint)status.dwServiceType,
                        CurrentState = (uint)status.dwCurrentState,
                        ProcessId = status.dwProcessId,
                    });
                }
            }

            return new ServiceInventoryResult { Succeeded = true, Services = found };
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            return new ServiceInventoryResult { Succeeded = false, Error = ex.Message };
        }
    }
}
