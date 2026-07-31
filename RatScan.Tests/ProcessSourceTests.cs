using System.Diagnostics;
using RatScan.Native.Processes;
using Xunit.Abstractions;

namespace RatScan.Tests;

/// <summary>
/// These run against the live machine on purpose. The cross-view engine's entire
/// value rests on the four sources being independently correct, and a mock cannot
/// tell us whether a struct offset is right — only the real kernel can.
/// </summary>
public sealed class ProcessSourceTests(ITestOutputHelper output)
{
    private static IProcessSource[] AllSources() =>
    [
        new ToolhelpProcessSource(),
        new NtProcessSource(),
        new PsapiProcessSource(),
        new BruteForceProcessSource(),
    ];

    [Fact]
    public void Every_source_succeeds_and_sees_this_test_process()
    {
        var self = (uint)Environment.ProcessId;

        foreach (var source in AllSources())
        {
            var result = source.Enumerate();

            Assert.True(result.Succeeded, $"{source.SourceName} failed: {result.Error}");
            Assert.NotEmpty(result.Processes);

            output.WriteLine($"{source.SourceName,-40} {result.Processes.Count,5} processes");

            Assert.Contains(result.Processes, p => p.Pid == self);
        }
    }

    [Fact]
    public void NtSource_populates_the_fields_only_it_can_see()
    {
        var result = new NtProcessSource().Enumerate();
        Assert.True(result.Succeeded, result.Error);

        var self = result.Processes.Single(p => p.Pid == (uint)Environment.ProcessId);

        // Name, parent, session, threads and creation time all come from the hand-
        // calculated struct walk. If any offset were wrong these would be garbage.
        Assert.Equal(Path.GetFileName(Environment.ProcessPath), self.Name);
        Assert.Equal((uint)Process.GetCurrentProcess().SessionId, self.SessionId);
        Assert.True(self.ThreadCount > 0);

        Assert.NotNull(self.CreatedUtc);
        var drift = (DateTime.UtcNow - self.CreatedUtc!.Value).Duration();
        Assert.True(drift < TimeSpan.FromHours(6), $"CreateTime offset looks wrong: {self.CreatedUtc} (drift {drift})");

        output.WriteLine($"self: pid={self.Pid} ppid={self.ParentPid} name={self.Name} " +
                         $"session={self.SessionId} threads={self.ThreadCount} created={self.CreatedUtc:O}");
    }

    /// <summary>
    /// The headline capability: agreement across independent kernel interfaces.
    /// On a healthy machine the only differences should be processes that genuinely
    /// started or exited between passes.
    /// </summary>
    [Fact]
    public void Cross_view_sources_agree_on_this_machine()
    {
        var results = AllSources().Select(s => s.Enumerate()).ToList();
        Assert.All(results, r => Assert.True(r.Succeeded, $"{r.SourceName}: {r.Error}"));

        var union = results.SelectMany(r => r.Processes.Select(p => p.Pid)).ToHashSet();

        foreach (var result in results)
        {
            var seen = result.Processes.Select(p => p.Pid).ToHashSet();
            var missing = union.Except(seen).Order().ToList();

            output.WriteLine($"{result.SourceName,-40} sees {seen.Count,4} / {union.Count} union" +
                             (missing.Count > 0 ? $" — absent: {string.Join(", ", missing.Take(20))}" : " — complete"));
        }

        // Deliberately not asserting exact equality: process churn between passes is
        // normal and would make this flaky. What must hold is that no single source
        // is missing a large slice of reality, which is what concealment looks like.
        foreach (var result in results)
        {
            var seen = result.Processes.Select(p => p.Pid).ToHashSet();
            var coverage = (double)seen.Count / union.Count;
            Assert.True(coverage > 0.80,
                $"{result.SourceName} saw only {coverage:P0} of the union — either broken or something is hiding");
        }
    }
}
