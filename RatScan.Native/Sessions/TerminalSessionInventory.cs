using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.System.RemoteDesktop;

namespace RatScan.Native.Sessions;

/// <summary>
/// A logon session. <see cref="IsRemote"/> is the field that matters: it answers
/// "is somebody signed into this machine from somewhere else, right now".
/// </summary>
public sealed record TerminalSession
{
    public required uint SessionId { get; init; }
    public string? WinStationName { get; init; }
    public uint State { get; init; }
    public string? UserName { get; init; }
    public string? DomainName { get; init; }

    /// <summary>Client hostname for a remote session; null for a local one.</summary>
    public string? ClientName { get; init; }

    /// <summary>
    /// True when this session is driven from another machine. The console session
    /// reports an empty client name, so a populated one is the discriminator.
    /// </summary>
    public bool IsRemote => !string.IsNullOrEmpty(ClientName);

    public bool IsActive => State == 0;      // WTSActive
    public bool IsDisconnected => State == 4; // WTSDisconnected
}

public sealed record TerminalSessionResult
{
    public required bool Succeeded { get; init; }
    public IReadOnlyList<TerminalSession> Sessions { get; init; } = [];
    public string? Error { get; init; }
}

/// <summary>Enumerates Terminal Services sessions on this machine.</summary>
public static unsafe class TerminalSessionInventory
{
    public static TerminalSessionResult ReadAll(CancellationToken cancellationToken = default)
    {
        WTS_SESSION_INFOW* sessions = null;

        try
        {
            if (!PInvoke.WTSEnumerateSessions(HANDLE.Null, 0, 1, out sessions, out var count))
            {
                return new TerminalSessionResult
                {
                    Succeeded = false,
                    Error = $"WTSEnumerateSessions failed (win32 {System.Runtime.InteropServices.Marshal.GetLastWin32Error()})",
                };
            }

            var found = new List<TerminalSession>((int)count);

            for (uint i = 0; i < count; i++)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var entry = sessions + i;

                found.Add(new TerminalSession
                {
                    SessionId = entry->SessionId,
                    WinStationName = entry->pWinStationName.ToString(),
                    State = (uint)entry->State,
                    UserName = Query(entry->SessionId, WTS_INFO_CLASS.WTSUserName),
                    DomainName = Query(entry->SessionId, WTS_INFO_CLASS.WTSDomainName),
                    ClientName = Query(entry->SessionId, WTS_INFO_CLASS.WTSClientName),
                });
            }

            return new TerminalSessionResult { Succeeded = true, Sessions = found };
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            return new TerminalSessionResult { Succeeded = false, Error = ex.Message };
        }
        finally
        {
            if (sessions is not null)
            {
                PInvoke.WTSFreeMemory(sessions);
            }
        }
    }

    private static string? Query(uint sessionId, WTS_INFO_CLASS what)
    {
        if (!PInvoke.WTSQuerySessionInformation(HANDLE.Null, sessionId, what, out var buffer, out _))
        {
            return null;
        }

        try
        {
            var value = buffer.ToString();
            return string.IsNullOrEmpty(value) ? null : value;
        }
        finally
        {
            PInvoke.WTSFreeMemory(buffer.Value);
        }
    }
}
