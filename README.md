<div align="center">

# RAVEN — Remote Access & Visibility Examination Node

**Find and shut down remote access and surveillance on Windows 11.**

[![Platform](https://img.shields.io/badge/platform-Windows%2011%20x64-0078D4)](https://github.com/Believeinus/RAVEN)
[![Language](https://img.shields.io/badge/C%23-.NET%208-512BD4)](https://github.com/Believeinus/RAVEN)
[![UI](https://img.shields.io/badge/UI-WPF-6A5ACD)](https://github.com/Believeinus/RAVEN)
[![Status](https://img.shields.io/badge/status-in%20development-orange)](https://github.com/Believeinus/RAVEN)

</div>

RAVEN is a Windows 11 desktop tool that looks for remote-access software, RATs, and
screen or input surveillance running on your machine — and then helps you stop it.
It runs entirely on the local machine. There is no server, no account, and nothing
leaves the computer.

> [!IMPORTANT]
> RAVEN is in active development and has not been released. The published executable
> is currently unsigned, so SmartScreen will warn on first run.

## 🧭 The constraint that shapes everything

The original goal was iron proof: *if this tool says nothing is spying on me, then
nothing is.* That bar is unreachable for any user-mode scanner. Kernel rootkits,
hypervisor implants, and hardware KVM-over-IP all defeat it, and no amount of
polish changes that.

So the project took a different commitment: **make it very hard for anything to
hide, and make the remaining blind spots visible and named.** Three things follow
from that, and they are the most important things to understand about RAVEN.

**It never renders a "you are clean" verdict.** This is enforced in the code, not
in the copy — the verdict type has no `Clean` value by construction, and a test
asserts that the output never claims safety. Every verdict is qualified by how much
of the machine it was actually able to see.

**Cross-view detection.** Processes and drivers are enumerated through several
independent kernel interfaces, and the results are diffed against each other. A
discrepancy between views *is* the finding: something visible to one interface and
hidden from another is exactly what a concealed component looks like.

**A Scan Integrity panel on every scan**, alongside an explicit "what this scan
could not see" list. When data is missing, coverage degrades and a named blind spot
is added. Missing data never manufactures a finding.

## 🔍 What it examines

| Surface | What RAVEN looks at |
| --- | --- |
| Processes | Every running process and its trust status, via Authenticode including catalog signatures |
| Network | TCP and UDP listeners and connections, with the owning process |
| Windows remote access | RDP, RDP shadowing, WinRM, OpenSSH, Remote Registry, Remote Assistance, SMB, `netsh portproxy` |
| Persistence | Auto-start across 17 surfaces (below) |
| Kernel | The loaded driver census |
| Surveillance | Screen-capture and input-hook indicators |

The 17 persistence surfaces are Run/RunOnce, startup folders, scheduled tasks,
services, Winlogon, AppInit_DLLs, AppCertDlls, IFEO debuggers, COM hijacks, LSA
packages, print monitors, netsh helpers, Active Setup, PowerShell profiles, and WMI
event subscriptions.

## ✨ What else it does

- **Identifies known tools** — a catalogue of known remote-access and RAT-family
  software. It is used as evidence for an identification, never as grounds to
  convict. A stale catalogue lowers confidence in an identification rather than
  raising a finding's severity.
- **Guided remediation** — nothing is stopped, disabled, or removed without an
  explicit confirmation that shows the exact command first.
- **Hash-pinned allowlist** — every allowlist entry is pinned to the SHA-256 of the
  file it excuses. Swap the file and the finding comes straight back.
- **Scan history and diff** — past scans are kept, and each scan can be diffed
  against the previous one.
- **Export** — HTML and JSON.
- **Real-time watch** — an ETW watch that catches software starting between scans.

## 🖥️ Requirements

Windows 11, x64.

Administrator rights are requested at launch. Without them, a substantial part of
the machine cannot be inspected — and RAVEN says so rather than pretending
otherwise. Declining is supported: the tool keeps running with reduced coverage,
and states clearly what that reduced coverage excludes.

## 🔒 Privacy

> [!NOTE]
> RAVEN is a local tool. It has no server component and no account system.

Everything it collects about the machine stays on the machine. Nothing is uploaded,
and there is no telemetry.

## 🚧 Status

In active development. Not yet released. The published executable is unsigned.

---

<div align="center">

Developed by **Hiteshwar Singh**

</div>
