using System.Collections.Concurrent;
using System.Security.Principal;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;

namespace RatScan.Etw;

public sealed record WatchStartResult
{
    public required bool Started { get; init; }
    public string? Error { get; init; }

    /// <summary>Set when the failure is fixable by the user, e.g. missing elevation.</summary>
    public string? Remedy { get; init; }
}

/// <summary>
/// Real-time observation of process, image-load and network activity via ETW.
/// <para>
/// This is the capability a scan cannot provide, and the reason the project is written
/// in C# rather than a scripting language: there is no maintained ETW binding outside
/// .NET. A scanner samples the machine at an instant; a watcher sees the thirty-second
/// beacon and the process that spawns, screenshots and exits between two scans.
/// </para>
/// <para>
/// Requires Administrator — ETW kernel sessions are privileged. Failure to start is
/// reported as a named condition, never swallowed, because a watcher that silently
/// is not watching is the most dangerous state this component can be in.
/// </para>
/// </summary>
public sealed class LiveWatcher : IDisposable
{
    private const string SessionName = "RatScanLiveWatch";

    /// <summary>Bounded so a busy machine cannot grow the history without limit.</summary>
    private const int RingCapacity = 5000;

    private readonly ILiveAlertRules _rules;
    private readonly ConcurrentQueue<LiveEvent> _ring = new();
    private readonly ConcurrentDictionary<uint, string> _processNames = new();

    private TraceEventSession? _session;
    private Thread? _pump;
    private volatile bool _running;

    public LiveWatcher(ILiveAlertRules? rules = null) => _rules = rules ?? new LiveAlertRules();

    /// <summary>Raised for every observed event. Called from the ETW pump thread.</summary>
    public event Action<LiveEvent>? Observed;

    /// <summary>Raised only for events the rules considered worth interrupting for.</summary>
    public event Action<LiveAlert>? Alerted;

    public bool IsRunning => _running;

    public IReadOnlyList<LiveEvent> RecentEvents => _ring.ToArray();

    public static bool IsElevated()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    public WatchStartResult Start()
    {
        if (_running)
        {
            return new WatchStartResult { Started = true };
        }

        if (!IsElevated())
        {
            return new WatchStartResult
            {
                Started = false,
                Error = "Live monitoring needs Administrator rights — ETW kernel sessions are privileged.",
                Remedy = "Restart RAVEN as Administrator.",
            };
        }

        try
        {
            // A stale session from a previous crash would block this one; ETW sessions
            // outlive the process that created them.
            TraceEventSession.GetActiveSessionNames();
            _session = new TraceEventSession(SessionName) { StopOnDispose = true };

            _session.EnableKernelProvider(
                KernelTraceEventParser.Keywords.Process
                | KernelTraceEventParser.Keywords.ImageLoad
                | KernelTraceEventParser.Keywords.NetworkTCPIP);

            Subscribe(_session.Source.Kernel);

            _running = true;
            _pump = new Thread(() =>
            {
                try
                {
                    _session.Source.Process();
                }
                catch (Exception)
                {
                    // Session torn down; Stop() owns the state transition.
                }
                finally
                {
                    _running = false;
                }
            })
            {
                IsBackground = true,
                Name = "RAVEN ETW pump",
            };

            _pump.Start();

            return new WatchStartResult { Started = true };
        }
        catch (Exception ex)
        {
            _running = false;
            _session?.Dispose();
            _session = null;

            return new WatchStartResult
            {
                Started = false,
                Error = $"Could not start the ETW session: {ex.Message}",
            };
        }
    }

    private void Subscribe(KernelTraceEventParser kernel)
    {
        kernel.ProcessStart += data =>
        {
            _processNames[(uint)data.ProcessID] = data.ImageFileName;

            Publish(new LiveEvent
            {
                TimeUtc = data.TimeStamp.ToUniversalTime(),
                Kind = LiveEventKind.ProcessStarted,
                Pid = (uint)data.ProcessID,
                ProcessName = data.ImageFileName,
                Subject = data.ImageFileName,
                Detail = data.CommandLine,
            });
        };

        kernel.ProcessStop += data =>
        {
            _processNames.TryRemove((uint)data.ProcessID, out _);

            Publish(new LiveEvent
            {
                TimeUtc = data.TimeStamp.ToUniversalTime(),
                Kind = LiveEventKind.ProcessStopped,
                Pid = (uint)data.ProcessID,
                ProcessName = data.ImageFileName,
            });
        };

        kernel.ImageLoad += data => Publish(new LiveEvent
        {
            TimeUtc = data.TimeStamp.ToUniversalTime(),
            Kind = LiveEventKind.ImageLoaded,
            Pid = (uint)data.ProcessID,
            ProcessName = NameOf((uint)data.ProcessID),
            Subject = data.FileName,
        });

        kernel.TcpIpConnect += data => Publish(new LiveEvent
        {
            TimeUtc = data.TimeStamp.ToUniversalTime(),
            Kind = LiveEventKind.NetworkConnect,
            Pid = (uint)data.ProcessID,
            ProcessName = NameOf((uint)data.ProcessID),
            Subject = $"{data.daddr}:{data.dport}",
        });

        kernel.TcpIpAccept += data => Publish(new LiveEvent
        {
            TimeUtc = data.TimeStamp.ToUniversalTime(),
            Kind = LiveEventKind.NetworkAccept,
            Pid = (uint)data.ProcessID,
            ProcessName = NameOf((uint)data.ProcessID),
            Subject = $"{data.saddr}:{data.sport}",
            Detail = "inbound connection accepted",
        });
    }

    private string? NameOf(uint pid) => _processNames.GetValueOrDefault(pid);

    private void Publish(LiveEvent observed)
    {
        _ring.Enqueue(observed);
        while (_ring.Count > RingCapacity && _ring.TryDequeue(out _))
        {
        }

        Observed?.Invoke(observed);

        // A throwing rule must not kill the pump — losing the watcher entirely is a
        // far worse outcome than missing one alert.
        try
        {
            var alert = _rules.Evaluate(observed);
            if (alert is not null)
            {
                Alerted?.Invoke(alert);
            }
        }
        catch
        {
            // Deliberately swallowed; see above.
        }
    }

    public void Stop()
    {
        _running = false;
        _session?.Dispose();
        _session = null;
        _pump = null;
    }

    public void Dispose() => Stop();
}
