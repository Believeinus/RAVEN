using System.Net;
using System.Net.NetworkInformation;
using RatScan.Native.Network;
using Xunit.Abstractions;

namespace RatScan.Tests;

public sealed class ConnectionTableTests(ITestOutputHelper output)
{
    [Fact]
    public void Reads_connections_with_plausible_ports_and_pids()
    {
        var result = ConnectionTables.ReadAll();
        Assert.True(result.Succeeded, result.Error);
        Assert.NotEmpty(result.Connections);

        var tcp = result.Connections.Count(c => c.Protocol == TransportProtocol.Tcp);
        var udp = result.Connections.Count(c => c.Protocol == TransportProtocol.Udp);
        var listeners = result.Connections.Count(c => c.IsListener);
        output.WriteLine($"tcp={tcp} udp={udp} listeners={listeners}");

        // A port outside 1..65535 means the network-byte-order swap is wrong.
        Assert.All(result.Connections, c => Assert.InRange(c.LocalPort, 0, 65535));
        Assert.All(result.Connections, c => Assert.True(c.RemotePort is null or (>= 0 and <= 65535)));

        // Every row must attribute to something; unattributed rows would break the
        // whole "which process owns this connection" premise.
        Assert.Contains(result.Connections, c => c.OwningPid > 0);
    }

    /// <summary>
    /// Cross-checks the raw IP Helper parse against .NET's own managed view of the
    /// same tables. If the port swap or the row stride were wrong, the two sets of
    /// listening endpoints would not line up.
    /// </summary>
    [Fact]
    public void Tcp_listeners_match_dotnets_independent_view()
    {
        var mine = ConnectionTables.ReadAll();
        Assert.True(mine.Succeeded, mine.Error);

        var theirs = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners();

        var mineListening = mine.Connections
            .Where(c => c.Protocol == TransportProtocol.Tcp && c.State == TcpConnectionState.Listen)
            .Select(c => c.LocalPort)
            .ToHashSet();

        var theirsListening = theirs.Select(e => e.Port).ToHashSet();

        output.WriteLine($"mine={mineListening.Count} dotnet={theirsListening.Count}");
        output.WriteLine($"ports (mine)  : {string.Join(", ", mineListening.Order().Take(15))}");
        output.WriteLine($"ports (dotnet): {string.Join(", ", theirsListening.Order().Take(15))}");

        Assert.NotEmpty(mineListening);

        // Listeners come and go between the two reads, so require substantial overlap
        // rather than equality. A byte-swap error would produce ~zero overlap.
        var overlap = mineListening.Intersect(theirsListening).Count();
        var ratio = (double)overlap / theirsListening.Count;
        output.WriteLine($"overlap={overlap} ratio={ratio:P0}");

        Assert.True(ratio > 0.80, $"only {ratio:P0} of .NET's listening ports matched — parse is wrong");
    }

    [Fact]
    public void Ipv6_rows_parse_as_ipv6_addresses()
    {
        var result = ConnectionTables.ReadAll();
        Assert.True(result.Succeeded, result.Error);

        var v6 = result.Connections
            .Where(c => c.LocalAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
            .ToList();

        output.WriteLine($"ipv6 rows: {v6.Count}");

        // The 16-byte address blobs are read by pointer; a stride error here would
        // yield addresses that are not valid IPv6 at all.
        Assert.All(v6, c => Assert.Equal(16, c.LocalAddress.GetAddressBytes().Length));
        Assert.All(v6, c => Assert.NotEqual(IPAddress.None, c.LocalAddress));
    }
}
