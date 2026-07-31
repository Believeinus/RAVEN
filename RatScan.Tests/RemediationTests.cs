using System.Diagnostics;
using RatScan.Engine;
using RatScan.Engine.Collectors;
using RatScan.Engine.Remediation;
using Xunit.Abstractions;

namespace RatScan.Tests;

public sealed class RemediationTests(ITestOutputHelper output)
{
    /// <summary>
    /// The single most important guarantee in this component. If an unconfirmed action
    /// can execute, every other safeguard is decoration.
    /// </summary>
    [Fact]
    public void Nothing_executes_without_confirmation()
    {
        var destructive = new RemediationAction
        {
            Kind = RemediationKind.KillProcess,
            Title = "End the test host",
            Description = "would end this very test process",
            PreviewCommand = $"Stop-Process -Id {Environment.ProcessId} -Force",
            Risk = RemediationRisk.Disruptive,

            // Pointed at the test host on purpose: if the guard fails, this test run
            // dies, which is impossible to overlook.
            Pid = (uint)Environment.ProcessId,
        };

        var outcome = new RemediationExecutor().Execute(destructive, confirmed: false);

        Assert.False(outcome.Succeeded);
        Assert.Contains("not confirmed", outcome.Message, StringComparison.OrdinalIgnoreCase);

        using var self = Process.GetCurrentProcess();
        Assert.False(self.HasExited);
    }

    [Fact]
    public void Killing_an_absent_process_reports_success_not_failure()
    {
        // The desired state already holds; reporting failure would push the user to
        // act again on something that is already gone.
        var outcome = new RemediationExecutor().Execute(
            new RemediationAction
            {
                Kind = RemediationKind.KillProcess,
                Title = "End process",
                Description = "x",
                PreviewCommand = "x",
                Risk = RemediationRisk.Disruptive,
                Pid = 999_999,
            },
            confirmed: true);

        output.WriteLine(outcome.Message);
        Assert.True(outcome.Succeeded);
    }

    [Fact]
    public void Removing_an_absent_registry_value_is_not_an_error()
    {
        var outcome = new RemediationExecutor().Execute(
            new RemediationAction
            {
                Kind = RemediationKind.RemoveAutostart,
                Title = "Remove autostart",
                Description = "x",
                PreviewCommand = "x",
                Risk = RemediationRisk.Reversible,
                RegistryPath = @"HKCU\SOFTWARE\RatScanDefinitelyNotAReal\Key",
                RegistryValue = "Nothing",
            },
            confirmed: true);

        output.WriteLine(outcome.Message);
        Assert.True(outcome.Succeeded);
    }

    [Fact]
    public void Unknown_registry_root_is_rejected_rather_than_guessed()
    {
        var outcome = new RemediationExecutor().Execute(
            new RemediationAction
            {
                Kind = RemediationKind.RemoveAutostart,
                Title = "Remove autostart",
                Description = "x",
                PreviewCommand = "x",
                Risk = RemediationRisk.Reversible,
                RegistryPath = @"HKEY_CLASSES_ROOT\Something",
                RegistryValue = "Value",
            },
            confirmed: true);

        Assert.False(outcome.Succeeded);
    }

    /// <summary>
    /// Every proposed action must be presentable: a user cannot consent to a command
    /// they were not shown, and cannot weigh a risk that was not stated.
    /// </summary>
    [Fact]
    public void Every_action_offered_on_this_machine_is_fully_described()
    {
        var result = new ScanOrchestrator().Run(ScanOptions.Full);
        var actions = result.Findings.SelectMany(f => f.Actions).ToList();

        output.WriteLine($"findings={result.Findings.Count} actions offered={actions.Count}");
        foreach (var a in actions)
        {
            output.WriteLine("");
            output.WriteLine($"  {a.Title}  [{a.Risk}{(a.RequiresElevation ? ", needs admin" : "")}]");
            output.WriteLine($"    {a.Description}");
            output.WriteLine($"    runs: {a.PreviewCommand.Replace("\n", " ; ")}");
            if (a.Caveat is not null)
            {
                output.WriteLine($"    caveat: {a.Caveat}");
            }
        }

        Assert.All(actions, a =>
        {
            Assert.False(string.IsNullOrWhiteSpace(a.Title));
            Assert.False(string.IsNullOrWhiteSpace(a.Description));
            Assert.False(string.IsNullOrWhiteSpace(a.PreviewCommand));
        });

        // Killing a process and disabling a service are never "reversible" — labelling
        // them so would understate what the user is agreeing to.
        Assert.All(
            actions.Where(a => a.Kind is RemediationKind.KillProcess or RemediationKind.DisableService),
            a => Assert.NotEqual(RemediationRisk.Reversible, a.Risk));
    }

    /// <summary>
    /// Stopping a process is the action that actually cuts off a live intruder, so it
    /// must be offered wherever a remote-access tool is found.
    /// </summary>
    [Fact]
    public void Remote_access_findings_offer_a_way_to_stop_them()
    {
        var result = new ScanOrchestrator().Run(ScanOptions.Full);

        var toolFindings = result.Findings
            .Where(f => f.Category == RatScan.Engine.Model.FindingCategory.RemoteAccessSoftware)
            .ToList();

        if (toolFindings.Count == 0)
        {
            output.WriteLine("no remote-access tools detected on this machine");
            return;
        }

        Assert.All(toolFindings, f =>
            Assert.Contains(f.Actions, a => a.Kind == RemediationKind.KillProcess));
    }
}
