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

    /// <summary>
    /// Process and network events — the ones a beacon shows up in.
    /// <para>
    /// These used to share a single 5,000-event ring with image loads, which is not a budget
    /// at all: measured on an idle machine on 2026-08-04, ten minutes produced 5,000 events
    /// of which 4,885 were image loads. The ring was full and discarding, at a ratio of about
    /// 42 image loads to every event worth reading, so the watcher forgot a process start
    /// from eleven minutes ago while faithfully remembering a DLL load from ten. A watcher
    /// that silently forgets what it saw is the failure this component exists to refuse.
    /// </para>
    /// <para>
    /// At the measured signal rate — 115 events in ten minutes — this holds around seven
    /// hours instead of ten minutes.
    /// </para>
    /// </summary>
    private const int SignalCapacity = 5000;

    /// <summary>
    /// Image loads, kept separately and deliberately short. They are context for a finding
    /// rather than the finding, and they arrive in the thousands.
    /// </summary>
    private const int ImageLoadCapacity = 1000;

    private readonly ILiveAlertRules _rules;
    private readonly ConcurrentQueue<LiveEvent> _signal = new();
    private readonly ConcurrentQueue<LiveEvent> _imageLoads = new();
    private readonly ConcurrentDictionary<uint, string> _processNames = new();

    private long _signalDiscarded;
    private long _imageLoadsDiscarded;

    private TraceEventSession? _session;
    private Thread? _pump;
    private volatile bool _running;

    public LiveWatcher(ILiveAlertRules? rules = null) => _rules = rules ?? new LiveAlertRules();

    /// <summary>Raised for every observed event. Called from the ETW pump thread.</summary>
    public event Action<LiveEvent>? Observed;

    /// <summary>Raised only for events the rules considered worth interrupting for.</summary>
    public event Action<LiveAlert>? Alerted;

    public bool IsRunning => _running;

    public IReadOnlyList<LiveEvent> RecentEvents =>
        _signal.Concat(_imageLoads).OrderBy(e => e.TimeUtc).ToArray();

    /// <summary>
    /// How much has been dropped off the back of each buffer. Exposed so the view can say so:
    /// the whole point of splitting the budgets was that discarding was happening silently.
    /// </summary>
    public long DiscardedSignalEvents => Interlocked.Read(ref _signalDiscarded);

    public long DiscardedImageLoads => Interlocked.Read(ref _imageLoadsDiscarded);

    public static int SignalBufferCapacity => SignalCapacity;

    public static int ImageLoadBufferCapacity => ImageLoadCapacity;

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

    /// <summary>
    /// Records one observation, bounds the buffers and lets the rules look at it.
    /// <para>
    /// Internal rather than private only so the retention behaviour can be tested: in
    /// production the ETW pump thread is the sole caller, and reaching it needs
    /// Administrator and a live kernel session.
    /// </para>
    /// </summary>
    internal void Publish(LiveEvent observed)
    {
        if (observed.Kind == LiveEventKind.ImageLoaded)
        {
            Retain(_imageLoads, ImageLoadCapacity, ref _imageLoadsDiscarded, observed);
        }
        else
        {
            Retain(_signal, SignalCapacity, ref _signalDiscarded, observed);
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

    /// <summary>
    /// Bounds one buffer and counts what falls off, rather than dropping it quietly.
    /// </summary>
    private static void Retain(
        ConcurrentQueue<LiveEvent> ring, int capacity, ref long discarded, LiveEvent observed)
    {
        ring.Enqueue(observed);

        while (ring.Count > capacity && ring.TryDequeue(out _))
        {
            Interlocked.Increment(ref discarded);
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
