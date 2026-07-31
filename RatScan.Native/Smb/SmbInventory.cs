using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.Storage.FileSystem;

namespace RatScan.Native.Smb;

/// <summary>A share exposed by this machine.</summary>
public sealed record SmbShare
{
    public required string Name { get; init; }
    public string? Path { get; init; }
    public string? Remark { get; init; }
    public uint Type { get; init; }
    public uint CurrentUses { get; init; }

    /// <summary>
    /// Administrative shares (C$, ADMIN$, IPC$) are flagged by a high bit in the type.
    /// They are present by default, so their existence is not itself a finding — but a
    /// live session against one is a different matter.
    /// </summary>
    public bool IsAdministrative => (Type & 0x80000000) != 0;

    /// <summary>A non-default share is something a person or an installer chose to create.</summary>
    public bool IsUserCreated => !IsAdministrative;
}

/// <summary>
/// A live inbound SMB session — somebody is connected to this machine right now.
/// </summary>
public sealed record SmbSession
{
    /// <summary>Computer name of the connecting client.</summary>
    public string? ClientName { get; init; }

    public string? UserName { get; init; }

    /// <summary>Seconds the session has been established.</summary>
    public uint SecondsConnected { get; init; }

    public uint SecondsIdle { get; init; }
}

public sealed record SmbInventoryResult
{
    public required bool Succeeded { get; init; }
    public IReadOnlyList<SmbShare> Shares { get; init; } = [];
    public IReadOnlyList<SmbSession> Sessions { get; init; } = [];

    /// <summary>
    /// True when session enumeration was denied. Session data requires elevation, and
    /// an empty list from a denied call must never be presented as "nobody is
    /// connected" — that is a blind spot, not a clean result.
    /// </summary>
    public bool SessionsUnavailable { get; init; }

    public string? Error { get; init; }
}

/// <summary>
/// Reads exposed shares and live inbound sessions. File-level access is a quieter
/// form of remote access than screen control, and it leaves the same kind of trace.
/// </summary>
public static unsafe class SmbInventory
{
    private const uint MaxPreferredLength = 0xFFFFFFFF;
    private const uint NerrSuccess = 0;
    private const uint ErrorAccessDenied = 5;

    public static SmbInventoryResult ReadAll(CancellationToken cancellationToken = default)
    {
        try
        {
            var shares = ReadShares(cancellationToken);
            var (sessions, denied) = ReadSessions(cancellationToken);

            return new SmbInventoryResult
            {
                Succeeded = true,
                Shares = shares,
                Sessions = sessions,
                SessionsUnavailable = denied,
            };
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            return new SmbInventoryResult { Succeeded = false, Error = ex.Message };
        }
    }

    private static List<SmbShare> ReadShares(CancellationToken cancellationToken)
    {
        var found = new List<SmbShare>();
        byte* buffer = null;

        try
        {
            var status = PInvoke.NetShareEnum(
                default, 502, out buffer, MaxPreferredLength, out var read, out _);

            if (status != NerrSuccess || buffer is null)
            {
                return found;
            }

            var entries = (SHARE_INFO_502*)buffer;

            for (uint i = 0; i < read; i++)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var entry = entries + i;

                found.Add(new SmbShare
                {
                    Name = entry->shi502_netname.ToString() ?? string.Empty,
                    Path = entry->shi502_path.ToString(),
                    Remark = entry->shi502_remark.ToString(),
                    Type = (uint)entry->shi502_type,
                    CurrentUses = entry->shi502_current_uses,
                });
            }
        }
        finally
        {
            if (buffer is not null)
            {
                // Free status is not actionable — the read already succeeded or not.
                _ = PInvoke.NetApiBufferFree(buffer);
            }
        }

        return found;
    }

    private static (List<SmbSession> Sessions, bool Denied) ReadSessions(CancellationToken cancellationToken)
    {
        var found = new List<SmbSession>();
        byte* buffer = null;

        try
        {
            var status = PInvoke.NetSessionEnum(
                default, default, default, 10, out buffer, MaxPreferredLength, out var read, out _);

            if (status == ErrorAccessDenied)
            {
                // Needs elevation. Reported as unavailable rather than empty.
                return (found, true);
            }

            if (status != NerrSuccess || buffer is null)
            {
                return (found, false);
            }

            var entries = (SESSION_INFO_10*)buffer;

            for (uint i = 0; i < read; i++)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var entry = entries + i;

                found.Add(new SmbSession
                {
                    ClientName = entry->sesi10_cname.ToString(),
                    UserName = entry->sesi10_username.ToString(),
                    SecondsConnected = entry->sesi10_time,
                    SecondsIdle = entry->sesi10_idle_time,
                });
            }
        }
        finally
        {
            if (buffer is not null)
            {
                // Free status is not actionable — the read already succeeded or not.
                _ = PInvoke.NetApiBufferFree(buffer);
            }
        }

        return (found, false);
    }
}
