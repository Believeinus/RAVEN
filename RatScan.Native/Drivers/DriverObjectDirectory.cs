using System.Runtime.InteropServices;
using Windows.Wdk.Foundation;
using Windows.Win32.Foundation;

// The NT object-directory calls live in CsWin32's Wdk surface while the handle types and
// CloseHandle live in the Win32 one, and both expose a class called PInvoke. Aliased
// rather than opened so every call below says which surface it came from.
using Nt = Windows.Wdk.PInvoke;
using Win32 = Windows.Win32.PInvoke;

namespace RatScan.Native.Drivers;

/// <summary>
/// One entry in an object-manager directory: the name the kernel knows an object by.
/// </summary>
public sealed record DriverObject
{
    /// <summary>Object name, e.g. <c>nvlddmkm</c> for <c>\Driver\nvlddmkm</c>.</summary>
    public required string Name { get; init; }

    /// <summary>Object type, normally <c>Driver</c>. Recorded rather than assumed.</summary>
    public required string TypeName { get; init; }
}

public sealed record DriverObjectResult
{
    public required bool Succeeded { get; init; }
    public IReadOnlyList<DriverObject> Objects { get; init; } = [];
    public string? Error { get; init; }

    /// <summary>
    /// True when <c>\Driver</c> could not be opened because the caller lacks the
    /// privilege, as opposed to any other failure.
    /// <para>
    /// Kept separate because it is the expected unelevated outcome and has a remedy the
    /// user can act on, where a genuine error does not.
    /// </para>
    /// </summary>
    public bool AccessDenied { get; init; }
}

/// <summary>
/// Enumerates the <c>\Driver</c> object-manager directory.
/// <para>
/// The third and most awkward view of the drivers on this machine, and the reason it is
/// worth the hand-written struct below: the other two views can both be defeated by the
/// same act. Unlinking a driver from <c>PsLoadedModuleList</c> hides it from
/// <c>EnumDeviceDrivers</c>, and deleting its service key hides it from the registry
/// walk — but a driver that wants to receive an IRP still needs a driver object, and that
/// object carries a name in <c>\Driver</c>. A discrepancy between the three is the
/// finding; two sources that can be silenced together are not a cross-view at all.
/// </para>
/// <para>
/// Unelevated this returns <see cref="DriverObjectResult.AccessDenied"/>, which the
/// engine must render as a named blind spot. An empty list here and a directory that
/// could not be opened are the same shape and opposite meanings, and collapsing them is
/// the mistake this project keeps a rule about.
/// </para>
/// </summary>
public static unsafe class DriverObjectDirectory
{
    /// <summary>
    /// The DDK's <c>OBJECT_DIRECTORY_INFORMATION</c>, hand-declared.
    /// <para>
    /// This is the one interop type in the project not generated from Windows metadata,
    /// because it is not published there. The layout is two <c>UNICODE_STRING</c>s and
    /// nothing else, which is small enough to write out with confidence — the reason
    /// CsWin32 is used everywhere else is that a wrong field offset fails silently and
    /// produces a confidently wrong answer, and that risk scales with struct size.
    /// </para>
    /// <para>
    /// The kernel returns an array of these at the head of the buffer, terminated by a
    /// zeroed entry, with the string data itself appended after the array — so the
    /// <c>Buffer</c> pointers point back into the same allocation and must be read
    /// before it is reused.
    /// </para>
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct ObjectDirectoryInformation
    {
        public UNICODE_STRING Name;
        public UNICODE_STRING TypeName;
    }

    /// <summary>DIRECTORY_QUERY — the only right needed to list a directory's contents.</summary>
    private const uint DirectoryQuery = 0x0001;

    private const int StatusSuccess = 0;
    private const int StatusMoreEntries = 0x00000105;
    private const int StatusNoMoreEntries = unchecked((int)0x8000001A);
    private const int StatusAccessDenied = unchecked((int)0xC0000022);
    private const int StatusBufferTooSmall = unchecked((int)0xC0000023);

    public static DriverObjectResult ReadAll(
        string directory = @"\Driver", CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(directory);

        HANDLE handle = default;

        try
        {
            var open = Open(directory, out handle);

            if (open != StatusSuccess)
            {
                return new DriverObjectResult
                {
                    Succeeded = false,
                    AccessDenied = open == StatusAccessDenied,
                    Error = open == StatusAccessDenied
                        ? $"{directory} could not be opened without Administrator rights"
                        : $"NtOpenDirectoryObject({directory}) returned 0x{open:X8}",
                };
            }

            return Enumerate(handle, directory, cancellationToken);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex) when (ex is EntryPointNotFoundException or DllNotFoundException)
        {
            return new DriverObjectResult { Succeeded = false, Error = ex.Message };
        }
        finally
        {
            if (!handle.IsNull)
            {
                Win32.CloseHandle(handle);
            }
        }
    }

    private static int Open(string directory, out HANDLE handle)
    {
        fixed (char* name = directory)
        {
            var unicode = new UNICODE_STRING
            {
                Buffer = new PWSTR(name),
                Length = (ushort)(directory.Length * sizeof(char)),
                MaximumLength = (ushort)(directory.Length * sizeof(char)),
            };

            var attributes = new OBJECT_ATTRIBUTES
            {
                Length = (uint)sizeof(OBJECT_ATTRIBUTES),
                ObjectName = &unicode,
            };

            return Nt.NtOpenDirectoryObject(out handle, DirectoryQuery, attributes).Value;
        }
    }

    private static DriverObjectResult Enumerate(
        HANDLE handle, string directory, CancellationToken cancellationToken)
    {
        var found = new List<DriverObject>();
        var buffer = new byte[64 * 1024];

        uint context = 0;
        var restart = true;

        for (var call = 0; call < 64; call++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            int status;

            fixed (byte* raw = buffer)
            {
                status = Nt.NtQueryDirectoryObject(
                    handle,
                    raw,
                    (uint)buffer.Length,
                    false,
                    restart,
                    ref context,
                    out _).Value;

                if (status is StatusSuccess or StatusMoreEntries)
                {
                    Read(raw, found);
                }
            }

            switch (status)
            {
                case StatusNoMoreEntries:
                case StatusSuccess:
                    return new DriverObjectResult { Succeeded = true, Objects = found };

                case StatusMoreEntries:
                    restart = false;
                    continue;

                // The kernel asks for more room only when a single entry will not fit,
                // which a 64 KB buffer makes unlikely — but growing is cheap and the
                // alternative is silently returning a partial directory.
                case StatusBufferTooSmall:
                    buffer = new byte[buffer.Length * 2];
                    restart = false;
                    continue;

                default:
                    return new DriverObjectResult
                    {
                        Succeeded = false,
                        AccessDenied = status == StatusAccessDenied,
                        Error = $"NtQueryDirectoryObject({directory}) returned 0x{status:X8}",
                    };
            }
        }

        return new DriverObjectResult
        {
            Succeeded = false,
            Error = $"{directory} kept returning more entries across 64 calls",
        };
    }

    /// <summary>
    /// Reads the returned array up to its zeroed terminator.
    /// <para>
    /// The terminating entry is all zeroes rather than being counted, so the count has to
    /// come from the data. Reading one entry past it would take a null
    /// <c>Buffer</c> pointer as a string.
    /// </para>
    /// </summary>
    private static void Read(byte* raw, List<DriverObject> found)
    {
        var entries = (ObjectDirectoryInformation*)raw;

        for (var i = 0; ; i++)
        {
            var entry = entries[i];

            if (entry.Name.Buffer.Value is null || entry.Name.Length == 0)
            {
                return;
            }

            found.Add(new DriverObject
            {
                Name = entry.Name.Buffer.AsSpan().ToString(),
                TypeName = entry.TypeName.Buffer.Value is null
                    ? string.Empty
                    : entry.TypeName.Buffer.AsSpan().ToString(),
            });
        }
    }
}
