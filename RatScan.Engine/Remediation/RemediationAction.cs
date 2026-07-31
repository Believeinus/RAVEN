namespace RatScan.Engine.Remediation;

public enum RemediationKind
{
    /// <summary>End the running process. Reversible only in that it can be restarted.</summary>
    KillProcess,

    /// <summary>Stop a service and set it to not start again.</summary>
    DisableService,

    /// <summary>Delete an auto-start registry value.</summary>
    RemoveAutostart,

    /// <summary>Turn off a built-in Windows remote-access feature.</summary>
    DisableWindowsSurface,

    /// <summary>Block a program from accepting inbound connections.</summary>
    BlockInboundFirewall,
}

public enum RemediationRisk
{
    /// <summary>Undone by restarting the program or re-enabling the setting.</summary>
    Reversible,

    /// <summary>Ends something now; work in that program may be lost.</summary>
    Disruptive,

    /// <summary>Could affect how Windows or another program functions.</summary>
    Consequential,
}

/// <summary>
/// Something RatScan can do about a finding.
/// <para>
/// An action is a <em>proposal</em>. It carries the exact command that would run, what
/// it affects, and what it does not undo — and it does nothing until
/// <see cref="IRemediationExecutor"/> is called with explicit confirmation. Nothing in
/// this engine acts on its own, at any severity, ever. A false positive that kills a
/// driver unattended would do more damage than the malware most users will ever meet.
/// </para>
/// </summary>
public sealed record RemediationAction
{
    public required RemediationKind Kind { get; init; }
    public required string Title { get; init; }

    /// <summary>What this will do, in plain language, before it is done.</summary>
    public required string Description { get; init; }

    /// <summary>
    /// The exact command that will be executed, shown to the user verbatim. If this
    /// does not match what actually runs, the confirmation is theatre.
    /// </summary>
    public required string PreviewCommand { get; init; }

    public required RemediationRisk Risk { get; init; }

    /// <summary>What this does NOT fix — usually the thing that would bring it back.</summary>
    public string? Caveat { get; init; }

    public uint? Pid { get; init; }
    public string? ServiceName { get; init; }
    public string? RegistryPath { get; init; }
    public string? RegistryValue { get; init; }

    /// <summary>True when the action needs Administrator to succeed.</summary>
    public bool RequiresElevation { get; init; }
}

public sealed record RemediationOutcome
{
    public required bool Succeeded { get; init; }
    public required string Message { get; init; }
    public string? Detail { get; init; }

    public static RemediationOutcome Ok(string message, string? detail = null) =>
        new() { Succeeded = true, Message = message, Detail = detail };

    public static RemediationOutcome Failed(string message, string? detail = null) =>
        new() { Succeeded = false, Message = message, Detail = detail };
}
