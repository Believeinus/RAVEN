using Windows.Win32;
using Windows.Win32.Foundation;

namespace RatScan.Native.Windowing;

/// <summary>Per-process summary of top-level window ownership.</summary>
public sealed record WindowPresence
{
    public required uint Pid { get; init; }
    public int TotalWindows { get; init; }
    public int VisibleWindows { get; init; }
    public IReadOnlyList<string> Titles { get; init; } = [];

    /// <summary>
    /// True when the process owns windows but shows none of them.
    /// <para>
    /// On its own this is unremarkable — plenty of well-behaved software keeps a
    /// hidden message-only window. It earns weight only in combination: a process
    /// that is invisible, capture-capable, and holding a sustained outbound
    /// connection is a very different proposition from one that merely hides.
    /// </para>
    /// </summary>
    public bool RunsHidden => TotalWindows > 0 && VisibleWindows == 0;
}

/// <summary>
/// Maps top-level windows to owning processes, feeding the surveillance detector's
/// visibility correlation.
/// </summary>
public static class WindowInventory
{
    public static IReadOnlyDictionary<uint, WindowPresence> ReadAll()
    {
        var total = new Dictionary<uint, int>();
        var visible = new Dictionary<uint, int>();
        var titles = new Dictionary<uint, List<string>>();

        PInvoke.EnumWindows(
            // Not named "_": that would shadow the discard and make the assignment
            // below write to the LPARAM parameter instead of discarding.
            (hwnd, lparam) =>
            {
                _ = PInvoke.GetWindowThreadProcessId(hwnd, out var pid);
                if (pid == 0)
                {
                    return true;
                }

                total[pid] = total.GetValueOrDefault(pid) + 1;

                if (PInvoke.IsWindowVisible(hwnd))
                {
                    visible[pid] = visible.GetValueOrDefault(pid) + 1;
                }

                var title = ReadTitle(hwnd);
                if (!string.IsNullOrWhiteSpace(title))
                {
                    if (!titles.TryGetValue(pid, out var list))
                    {
                        titles[pid] = list = [];
                    }

                    // Cap per process: a few titles identify the app, thousands only
                    // bloat the scan record.
                    if (list.Count < 8)
                    {
                        list.Add(title);
                    }
                }

                return true;
            },
            default);

        return total.Keys.ToDictionary(
            pid => pid,
            pid => new WindowPresence
            {
                Pid = pid,
                TotalWindows = total[pid],
                VisibleWindows = visible.GetValueOrDefault(pid),
                Titles = titles.GetValueOrDefault(pid) ?? [],
            });
    }

    private static string ReadTitle(HWND hwnd)
    {
        var length = PInvoke.GetWindowTextLength(hwnd);
        if (length <= 0)
        {
            return string.Empty;
        }

        Span<char> buffer = new char[length + 1];
        var written = PInvoke.GetWindowText(hwnd, buffer);

        return written > 0 ? new string(buffer[..written]) : string.Empty;
    }
}
