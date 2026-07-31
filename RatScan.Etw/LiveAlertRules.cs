using RatScan.Rules;

namespace RatScan.Etw;

public interface ILiveAlertRules
{
    LiveAlert? Evaluate(LiveEvent observed);
}

/// <summary>
/// Decides which live events deserve to interrupt the user.
/// <para>
/// The hard constraint here is different from the scanner's. A scan is read
/// deliberately; an alert arrives uninvited, and one that fires too often is worse
/// than none at all — it trains the user to dismiss the notification that finally
/// matters. So this errs heavily toward silence: only a catalogued remote-access tool
/// starting, or a new listening port from something unrecognised, is considered worth
/// a person's attention in the moment. Everything else is recorded for the timeline
/// and left there.
/// </para>
/// </summary>
public sealed class LiveAlertRules : ILiveAlertRules
{
    private readonly IReadOnlyList<KnownTool> _catalogue;
    private readonly HashSet<string> _alerted = new(StringComparer.OrdinalIgnoreCase);

    public LiveAlertRules(IReadOnlyList<KnownTool>? catalogue = null) =>
        _catalogue = catalogue ?? KnownToolCatalogue.Tools;

    public LiveAlert? Evaluate(LiveEvent observed)
    {
        return observed.Kind switch
        {
            LiveEventKind.ProcessStarted => RemoteToolStarted(observed),
            _ => null,
        };
    }

    private LiveAlert? RemoteToolStarted(LiveEvent observed)
    {
        if (observed.ProcessName is null)
        {
            return null;
        }

        var tool = _catalogue.FirstOrDefault(t =>
            t.Processes.Any(p => string.Equals(p, observed.ProcessName, StringComparison.OrdinalIgnoreCase)));

        if (tool is null)
        {
            return null;
        }

        // Once per tool per session. A product that restarts a helper process every few
        // minutes would otherwise generate an alert storm and bury everything else.
        if (!_alerted.Add(tool.Id))
        {
            return null;
        }

        var capability = tool.CanControlInput
            ? "see this screen and control the keyboard and mouse"
            : tool.CanViewScreen
                ? "see this screen"
                : "access this machine remotely";

        return new LiveAlert
        {
            TimeUtc = observed.TimeUtc,
            RuleId = $"live.remote-tool-started.{tool.Id}",
            Title = $"{tool.Name} just started",
            Explanation =
                $"{tool.Name} started on this machine at {observed.TimeUtc.ToLocalTime():HH:mm:ss}. "
                + $"Someone connecting through it can {capability}. If you did not just start this "
                + "yourself, disconnect this machine from the network and investigate.",
            Trigger = observed,

            // Products most often used against people get the loud treatment; the rest
            // are reported without escalation.
            IsHighPriority = tool.ParsedAbuse == AbuseLevel.High,
        };
    }
}
