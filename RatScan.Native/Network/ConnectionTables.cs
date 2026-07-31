using System.Buffers.Binary;
using System.Net;
using System.Runtime.InteropServices;
using Windows.Win32;
using Windows.Win32.NetworkManagement.IpHelper;

namespace RatScan.Native.Network;

public enum TransportProtocol
{
    Tcp,
    Udp,
}

/// <summary>
/// TCP states, as reported by the IP Helper tables.
/// <para>
/// <see cref="Listen"/> and <see cref="Established"/> carry most of the detection
/// weight: a listener is an inbound door, and a long-lived outbound connection from
/// an unsigned binary is what a beacon looks like.
/// </para>
/// </summary>
public enum TcpConnectionState
{
    Unknown = 0,
    Closed = 1,
    Listen = 2,
    SynSent = 3,
    SynReceived = 4,
    Established = 5,
    FinWait1 = 6,
    FinWait2 = 7,
    CloseWait = 8,
    Closing = 9,
    LastAck = 10,
    TimeWait = 11,
    DeleteTcb = 12,
}

/// <summary>One endpoint row, attributed to the process that owns it.</summary>
public sealed record Connection
{
    public required TransportProtocol Protocol { get; init; }
    public required uint OwningPid { get; init; }
    public required IPAddress LocalAddress { get; init; }
    public required int LocalPort { get; init; }
    public IPAddress? RemoteAddress { get; init; }
    public int? RemotePort { get; init; }
    public TcpConnectionState State { get; init; } = TcpConnectionState.Unknown;

    public bool IsListener =>
        Protocol == TransportProtocol.Tcp
            ? State == TcpConnectionState.Listen
            : RemoteAddress is null;
}

public sealed record ConnectionTableResult
{
    public required bool Succeeded { get; init; }
    public IReadOnlyList<Connection> Connections { get; init; } = [];
    public string? Error { get; init; }
}

/// <summary>
/// Reads the TCP and UDP tables with owning-PID attribution, over both address
/// families. This is view 1 of the cross-view network diff; ETW and WMI supply the
/// independent views it is checked against.
/// </summary>
public static unsafe class ConnectionTables
{
    private const uint AfInet = 2;
    private const uint AfInet6 = 23;
    private const uint NoError = 0;
    private const uint ErrorInsufficientBuffer = 122;

    /// <summary>Pointers cannot be generic type arguments, so this replaces Action&lt;byte*&gt;.</summary>
    private delegate void TableParser(byte* table);

    public static ConnectionTableResult ReadAll(CancellationToken cancellationToken = default)
    {
        var all = new List<Connection>(512);

        try
        {
            all.AddRange(ReadTcp(AfInet, cancellationToken));
            all.AddRange(ReadTcp(AfInet6, cancellationToken));
            all.AddRange(ReadUdp(AfInet, cancellationToken));
            all.AddRange(ReadUdp(AfInet6, cancellationToken));
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            return new ConnectionTableResult { Succeeded = false, Error = ex.Message };
        }

        return new ConnectionTableResult { Succeeded = true, Connections = all };
    }

    private static List<Connection> ReadTcp(uint family, CancellationToken cancellationToken)
    {
        var found = new List<Connection>();

        WithTcpTable(
            family,
            buffer =>
            {
                var count = *(uint*)buffer;
                var rows = buffer + sizeof(uint);

                for (uint i = 0; i < count; i++)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    if (family == AfInet)
                    {
                        var row = ((MIB_TCPROW_OWNER_PID*)rows) + i;
                        found.Add(new Connection
                        {
                            Protocol = TransportProtocol.Tcp,
                            OwningPid = row->dwOwningPid,
                            LocalAddress = new IPAddress(row->dwLocalAddr),
                            LocalPort = NetworkPort(row->dwLocalPort),
                            RemoteAddress = new IPAddress(row->dwRemoteAddr),
                            RemotePort = NetworkPort(row->dwRemotePort),
                            State = ToState((uint)row->dwState),
                        });
                    }
                    else
                    {
                        var row = ((MIB_TCP6ROW_OWNER_PID*)rows) + i;
                        found.Add(new Connection
                        {
                            Protocol = TransportProtocol.Tcp,
                            OwningPid = row->dwOwningPid,
                            LocalAddress = new IPAddress(new ReadOnlySpan<byte>(row->ucLocalAddr.AsSpan().ToArray())),
                            LocalPort = NetworkPort(row->dwLocalPort),
                            RemoteAddress = new IPAddress(new ReadOnlySpan<byte>(row->ucRemoteAddr.AsSpan().ToArray())),
                            RemotePort = NetworkPort(row->dwRemotePort),
                            State = ToState((uint)row->dwState),
                        });
                    }
                }
            });

        return found;
    }

    private static List<Connection> ReadUdp(uint family, CancellationToken cancellationToken)
    {
        var found = new List<Connection>();

        WithUdpTable(
            family,
            buffer =>
            {
                var count = *(uint*)buffer;
                var rows = buffer + sizeof(uint);

                for (uint i = 0; i < count; i++)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    if (family == AfInet)
                    {
                        var row = ((MIB_UDPROW_OWNER_PID*)rows) + i;
                        found.Add(new Connection
                        {
                            Protocol = TransportProtocol.Udp,
                            OwningPid = row->dwOwningPid,
                            LocalAddress = new IPAddress(row->dwLocalAddr),
                            LocalPort = NetworkPort(row->dwLocalPort),
                        });
                    }
                    else
                    {
                        var row = ((MIB_UDP6ROW_OWNER_PID*)rows) + i;
                        found.Add(new Connection
                        {
                            Protocol = TransportProtocol.Udp,
                            OwningPid = row->dwOwningPid,
                            LocalAddress = new IPAddress(new ReadOnlySpan<byte>(row->ucLocalAddr.AsSpan().ToArray())),
                            LocalPort = NetworkPort(row->dwLocalPort),
                        });
                    }
                }
            });

        return found;
    }

    /// <summary>
    /// Size-query, allocate, re-query, parse. The table can grow between the two
    /// calls, so ERROR_INSUFFICIENT_BUFFER on the second attempt is retried rather
    /// than treated as failure.
    /// </summary>
    private static void WithTcpTable(uint family, TableParser parse)
    {
        const TCP_TABLE_CLASS tableClass = TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL;

        for (var attempt = 0; attempt < 5; attempt++)
        {
            uint size = 0;
            var status = PInvoke.GetExtendedTcpTable(null, &size, false, family, tableClass, 0);
            Require(status, "TCP table size query");

            // A zero-length table is legitimate — nothing is listening or connected.
            size = Math.Max(size, sizeof(uint));
            var buffer = Marshal.AllocHGlobal((int)size);

            try
            {
                status = PInvoke.GetExtendedTcpTable((void*)buffer, &size, false, family, tableClass, 0);
                if (status == ErrorInsufficientBuffer)
                {
                    continue;
                }

                Require(status, "TCP table read");
                parse((byte*)buffer);
                return;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        throw new InvalidOperationException("TCP table kept growing across 5 attempts");
    }

    private static void WithUdpTable(uint family, TableParser parse)
    {
        const UDP_TABLE_CLASS tableClass = UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID;

        for (var attempt = 0; attempt < 5; attempt++)
        {
            uint size = 0;
            var status = PInvoke.GetExtendedUdpTable(null, &size, false, family, tableClass, 0);
            Require(status, "UDP table size query");

            size = Math.Max(size, sizeof(uint));
            var buffer = Marshal.AllocHGlobal((int)size);

            try
            {
                status = PInvoke.GetExtendedUdpTable((void*)buffer, &size, false, family, tableClass, 0);
                if (status == ErrorInsufficientBuffer)
                {
                    continue;
                }

                Require(status, "UDP table read");
                parse((byte*)buffer);
                return;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        throw new InvalidOperationException("UDP table kept growing across 5 attempts");
    }

    private static void Require(uint status, string what)
    {
        if (status is not NoError and not ErrorInsufficientBuffer)
        {
            throw new InvalidOperationException($"{what} failed (win32 {status})");
        }
    }

    /// <summary>
    /// Ports arrive in network byte order in the low 16 bits. Forgetting the swap
    /// yields plausible-looking but wrong port numbers — 80 reads as 20480 — which
    /// would silently break every port-based rule in the catalog.
    /// </summary>
    private static int NetworkPort(uint raw) =>
        BinaryPrimitives.ReverseEndianness((ushort)(raw & 0xFFFF));

    private static TcpConnectionState ToState(uint raw) =>
        raw is >= 1 and <= 12 ? (TcpConnectionState)raw : TcpConnectionState.Unknown;
}
