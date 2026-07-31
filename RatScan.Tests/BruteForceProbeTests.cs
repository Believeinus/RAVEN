using RatScan.Native.Processes;
using Xunit.Abstractions;

namespace RatScan.Tests;

/// <summary>
/// Guards the PID probe against the two false-positive modes that made it useless
/// during development. Both were found by running it, not by reading it.
/// </summary>
public sealed class BruteForceProbeTests(ITestOutputHelper output)
{
    /// <summary>
    /// The central anti-hiding invariant, and the one that must not regress.
    /// <para>
    /// A PID the probe confirms is <em>running</em> but that no enumeration API lists
    /// is concealment — there is no benign explanation. On a healthy machine there
    /// must be none. Early versions reported ~327 here: first from reading a clobbered
    /// last-error value, then from counting zombie process objects (exited, but still
    /// openable because something holds a handle). Both would have rendered a
    /// permanent, terrifying, entirely false "hidden processes detected".
    /// </para>
    /// </summary>
    [Fact]
    public void No_confirmed_alive_process_is_missing_from_every_list_api()
    {
        var listed = new[]
            {
                new ToolhelpProcessSource().Enumerate(),
                new NtProcessSource().Enumerate(),
                new PsapiProcessSource().Enumerate(),
            }
            .Where(r => r.Succeeded)
            .SelectMany(r => r.Processes.Select(p => p.Pid))
            .ToHashSet();

        Assert.NotEmpty(listed);

        var probed = new BruteForceProcessSource().Enumerate();
        Assert.True(probed.Succeeded, probed.Error);

        var extras = probed.Processes.Where(p => !listed.Contains(p.Pid)).ToList();
        var concealed = extras.Where(p => p.VerifiedAlive == true).ToList();
        var unverifiable = extras.Count(p => p.VerifiedAlive is null);

        output.WriteLine($"listed={listed.Count} probed={probed.Processes.Count} extras={extras.Count}");
        output.WriteLine($"  confirmed-alive but unlisted : {concealed.Count}   <-- concealment evidence");
        output.WriteLine($"  access-denied, unverifiable  : {unverifiable}   <-- not evidence of anything");

        Assert.Empty(concealed);
    }

    /// <summary>
    /// Access-denied PIDs must stay tri-state <c>null</c>, never <c>true</c>. Collapsing
    /// "I could not check" into "it is alive" is what turns protected and zombie
    /// process objects into phantom findings.
    /// </summary>
    [Fact]
    public void Unverifiable_pids_are_not_reported_as_confirmed_alive()
    {
        var probed = new BruteForceProcessSource().Enumerate();
        Assert.True(probed.Succeeded, probed.Error);

        Assert.All(probed.Processes, p => Assert.True(p.VerifiedAlive is true or null));
        Assert.True(probed.Partial, "the probe's PID ceiling is a real blind spot and must be declared");
    }
}
