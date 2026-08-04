using RatScan.Etw;
using Xunit.Abstractions;

namespace RatScan.Tests;

public sealed class LiveAlertRuleTests(ITestOutputHelper output)
{
    private static LiveEvent Started(string processName, uint pid = 1234) => new()
    {
        TimeUtc = DateTime.UtcNow,
        Kind = LiveEventKind.ProcessStarted,
        Pid = pid,
        ProcessName = processName,
        Subject = $@"C:\Temp\{processName}",
    };

    [Fact]
    public void Alerts_when_a_catalogued_remote_tool_starts()
    {
        var alert = new LiveAlertRules().Evaluate(Started("anydesk.exe"));

        Assert.NotNull(alert);
        output.WriteLine($"{alert!.Title} (high priority: {alert.IsHighPriority})");
        output.WriteLine(alert.Explanation);

        Assert.Contains("AnyDesk", alert.Title);

        // AnyDesk is a high-abuse product; the alert must say what someone could
        // actually do, in the moment, not just name the process.
        Assert.True(alert.IsHighPriority);
        Assert.Contains("control the keyboard and mouse", alert.Explanation, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// An alert that fires repeatedly trains the user to dismiss it, which costs more
    /// than never alerting at all.
    /// </summary>
    [Fact]
    public void Alerts_once_per_tool_not_once_per_process_start()
    {
        var rules = new LiveAlertRules();

        Assert.NotNull(rules.Evaluate(Started("anydesk.exe", 1)));
        Assert.Null(rules.Evaluate(Started("anydesk.exe", 2)));
        Assert.Null(rules.Evaluate(Started("anydesk.exe", 3)));
    }

    [Fact]
    public void Ordinary_processes_do_not_alert()
    {
        var rules = new LiveAlertRules();

        Assert.Null(rules.Evaluate(Started("notepad.exe")));
        Assert.Null(rules.Evaluate(Started("chrome.exe")));
        Assert.Null(rules.Evaluate(Started("explorer.exe")));
    }

    [Fact]
    public void Non_start_events_are_recorded_but_never_alert()
    {
        var rules = new LiveAlertRules();

        foreach (var kind in new[]
                 {
                     LiveEventKind.ImageLoaded,
                     LiveEventKind.NetworkConnect,
                     LiveEventKind.NetworkAccept,
                     LiveEventKind.ProcessStopped,
                 })
        {
            var observed = Started("anydesk.exe") with { Kind = kind };
            Assert.Null(rules.Evaluate(observed));
        }
    }
}

public sealed class LiveWatcherTests(ITestOutputHelper output)
{
    /// <summary>
    /// A watcher that silently is not watching is the most dangerous state this
    /// component can be in, so failure to start must be explicit and explained.
    /// </summary>
    [Fact]
    public void Reports_why_it_could_not_start_rather_than_failing_quietly()
    {
        using var watcher = new LiveWatcher();
        var result = watcher.Start();

        output.WriteLine($"elevated={LiveWatcher.IsElevated()} started={result.Started}");
        output.WriteLine($"error={result.Error}");
        output.WriteLine($"remedy={result.Remedy}");

        if (LiveWatcher.IsElevated())
        {
            Assert.True(result.Started, result.Error);
            Assert.True(watcher.IsRunning);
            watcher.Stop();
            return;
        }

        // Unelevated is the expected case here and must be reported as a fixable
        // condition, not as a generic failure.
        Assert.False(result.Started);
        Assert.NotNull(result.Error);
        Assert.Contains("Administrator", result.Error!, StringComparison.OrdinalIgnoreCase);
        Assert.NotNull(result.Remedy);
        Assert.False(watcher.IsRunning);
    }

    [Fact]
    public void Stopping_a_watcher_that_never_started_is_safe()
    {
        using var watcher = new LiveWatcher();
        watcher.Stop();
        watcher.Stop();

        Assert.False(watcher.IsRunning);
        Assert.Empty(watcher.RecentEvents);
    }

    /// <summary>
    /// The regression this splits the buffers to prevent. Measured on an idle machine on
    /// 2026-08-04: ten minutes of watching produced 5,000 events, 4,885 of them image loads,
    /// against a single shared 5,000-event ring — so the ring was full and dropping, and what
    /// it dropped was the process starts and connections, at roughly 42 image loads to one.
    /// A watcher that forgets the beacon it saw is not watching.
    /// </summary>
    [Fact]
    public void A_flood_of_image_loads_cannot_push_out_process_and_network_events()
    {
        using var watcher = new LiveWatcher();

        watcher.Publish(Started("rat.exe", 4242));

        for (var i = 0; i < 20_000; i++)
        {
            watcher.Publish(new LiveEvent
            {
                TimeUtc = DateTime.UtcNow,
                Kind = LiveEventKind.ImageLoaded,
                Pid = 9000,
                Subject = $@"C:\WINDOWS\System32\noise{i}.dll",
            });
        }

        var kept = watcher.RecentEvents;
        var processStarts = kept.Where(e => e.Kind == LiveEventKind.ProcessStarted).ToList();

        output.WriteLine(
            $"kept={kept.Count} processStarts={processStarts.Count} "
            + $"imageLoads={kept.Count(e => e.Kind == LiveEventKind.ImageLoaded)} "
            + $"discardedSignal={watcher.DiscardedSignalEvents} "
            + $"discardedImages={watcher.DiscardedImageLoads}");

        // The one event worth having survives twenty thousand it is competing with.
        var survivor = Assert.Single(processStarts);
        Assert.Equal(4242u, survivor.Pid);
        Assert.Equal(0, watcher.DiscardedSignalEvents);

        // Image loads are still bounded, and what was dropped is counted rather than
        // disappearing quietly.
        Assert.Equal(LiveWatcher.ImageLoadBufferCapacity, kept.Count(e => e.Kind == LiveEventKind.ImageLoaded));
        Assert.Equal(20_000 - LiveWatcher.ImageLoadBufferCapacity, watcher.DiscardedImageLoads);
    }

    private static LiveEvent Started(string processName, uint pid) => new()
    {
        TimeUtc = DateTime.UtcNow,
        Kind = LiveEventKind.ProcessStarted,
        Pid = pid,
        ProcessName = processName,
        Subject = $@"C:\Temp\{processName}",
    };

    [Fact]
    public void Discarded_process_and_network_events_are_counted()
    {
        using var watcher = new LiveWatcher();

        var overflow = LiveWatcher.SignalBufferCapacity + 250;
        for (var i = 0; i < overflow; i++)
        {
            watcher.Publish(Started($"p{i}.exe", (uint)i));
        }

        output.WriteLine(
            $"published={overflow} kept={watcher.RecentEvents.Count} "
            + $"discarded={watcher.DiscardedSignalEvents}");

        Assert.Equal(LiveWatcher.SignalBufferCapacity, watcher.RecentEvents.Count);
        Assert.Equal(250, watcher.DiscardedSignalEvents);
    }
}
