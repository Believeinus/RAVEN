<div align="center">

# RAVEN

**Remote Access & Visibility Examination Node**

**Find out what's watching you.**

A Windows remote-access and RAT detection tool that tells you the truth about its own blind spots.

![status](https://img.shields.io/badge/status-in%20development-orange)
![license](https://img.shields.io/badge/license-MIT-green)
![platform](https://img.shields.io/badge/platform-Windows%2011%20x64-0078D4)
![dotnet](https://img.shields.io/badge/.NET-8.0-512BD4)
![ui](https://img.shields.io/badge/UI-WPF-blue)

</div>

---

> [!WARNING]
> **In active development — phases 0–10 of 11 complete.** The scanner runs, detects,
> explains and can shut down what it finds; scan history, the allowlist, the diff between
> scans and the live ETW watcher are all wired into the UI, and the watcher has been driven
> elevated and observed tracing. Still outstanding: **code signing** (the published binary is
> unsigned, so SmartScreen warns on first run), the ten end-to-end verification steps, and
> two cross-view rules that are collected but not yet judged. See `docs/` for the honest
> per-phase state.

## What it does

RAVEN finds — and can shut down — anything on a Windows 11 machine that gives a remote
party the ability to **see your screen, control your input, or reach your files**:
commercial remote-access products, abused RMM agents, built-in Windows remote surfaces
left enabled, and purpose-built RATs.

It runs a deep on-demand scan and a continuous ETW-backed watch, explains every
finding with its evidence chain, and offers remediation you have to confirm.

## The honest part

> [!IMPORTANT]
> **RAVEN will never tell you "you are clean."**

No user-mode program can prove a machine is unmonitored. Anything running in the
kernel (a malicious or vulnerable signed driver), below it (a thin hypervisor), or
beside it (IPMI/BMC, a hardware KVM-over-IP dongle, a capture device inline with your
monitor) can answer every API this tool calls with clean lies, or bypass the operating
system entirely. A scanner that renders a green checkmark is at its least trustworthy
exactly when it matters most.

So RAVEN is built to a different goal: **make it very hard for anything to hide, and
make the remaining blind spots visible and named.** Three things follow from that:

| Commitment | What it means |
|---|---|
| **Cross-view detection** | Processes are enumerated from **four independent kernel interfaces** and diffed; kernel drivers from **three** — the loaded-module list, the Services registry, and the `\Driver` object directory. Something that unhooks one API but not the others produces a discrepancy, and the discrepancy is itself the finding. This is how you catch active concealment rather than mere unfamiliarity. Two limits stated plainly: the `\Driver` view is collected and disclosed but **not yet judged**, and TCP connections still come from a single interface. |
| **Scan Integrity panel** | Every scan reports the conditions it ran under — Administrator rights, Secure Boot, memory integrity (HVCI), driver signature enforcement, test-signing mode, kernel debug mode, and kernel debugger presence — and the verdict is explicitly qualified by them. |
| **Coverage-qualified verdicts** | The headline is never "clean." It reads *"No evidence of remote access found — across N surfaces, with these M blind spots,"* and every blind spot is listed by name underneath, with the reason it could not be examined and the remedy where one exists. `VerdictLevel` has no `Clean` member by construction, and a test asserts the output never claims safety. |

## Detection coverage

- **Known remote-access software** — 56 catalogued products (AnyDesk, TeamViewer, RustDesk, ScreenConnect, NetSupport, Remote Utilities, the VNC family, RMM agents…), matched on process, service, driver, path, signer, and registry footprint. Portable/uninstalled instances are scored *higher* — that's the support-scam signature.
- **Windows' own remote surfaces** — RDP (including the `Shadow` policy, which permits silent session watching), WinRM, PS Remoting, OpenSSH, Remote Registry, Remote Assistance, Quick Assist, SMB sessions, `netsh portproxy`, inbound firewall rules.
- **Screen & input surveillance** — capture-capable module correlation, virtual/indirect display drivers, injected-hook footprints, UIAccess tokens, virtual HID drivers.
- **Persistence (ASEP)** — 14 surfaces: Run/RunOnce across both registry views, startup folders, scheduled tasks, **WMI permanent event subscriptions**, Winlogon Shell/Userinit, `AppInit_DLLs`, `AppCertDlls`, IFEO debuggers, COM hijacks, LSA packages, print monitors, netsh helpers.
- **Trust analysis** — Authenticode verification on every running image, including the catalog path (42 of 60 sampled System32 binaries are catalog-signed, so skipping it would misreport all 42 as unsigned).
- **Guided remediation** — end a process and its children, stop and disable a service, remove an auto-start entry, turn off a Windows remote feature. Every action shows the exact command first and runs only on explicit confirmation.
- **Live watch** — real-time ETW over kernel process, image-load and TCP events, in its own view, alerting once per catalogued tool rather than once per process start. Needs Administrator; without it the view says so and refuses rather than appearing to watch. Process and network events are retained separately from image loads, so a flood of DLL loads cannot push the beacon you care about out of the buffer.

## In the app

Four views on a Fluent shell, sharing one scan session:

- **Scan** — the verdict and its coverage line, every finding with its evidence chain, what
  the scan could not see, what changed since the last scan, and the allowlist in full.
- **Live watch** — the ETW feed described above, with its own start control.
- **History** — every recorded scan, newest first, each stating whether it ran elevated,
  because two scans taken at different coverage are not two readings of the same thing.
- **Settings** — what coverage you currently have and what it costs, the allowlist in
  summary, where the data lives, and what the tool does not claim.

Plus:

- **Diff between scans** — what appeared and what disappeared, with a caveat line when the
  two scans are not comparable. A finding that vanished because this scan saw *less* is not
  reported as good news.
- **Allowlist ("this is mine")** — muting requires a written reason and pins the SHA-256 of
  the file it excuses, so replacing that file brings the finding straight back. Muted items
  stay listed with your reason, and the scan says when muting changed its own verdict.
- **Export** — HTML to read or JSON to process, after a prompt that says what the file will
  contain about your machine.
- **Tray** — closing the window ends RAVEN unless a watch is running, in which case it hides
  to the tray and says so. Deliberately no start-with-Windows: giving RAVEN its own
  auto-start entry would make it an instance of the thing it reports.

## Requirements

- Windows 11 x64 (developed against Home Single Language, build 26200)
- .NET 8 desktop runtime (or use the self-contained build)
- **Administrator** for full coverage. It runs without it — and says exactly what it couldn't see.

## Build

```powershell
dotnet build RatScan.sln
dotnet test
dotnet publish RatScan.UI -c Release -r win-x64 --self-contained /p:PublishSingleFile=true
```

## Privacy

**Offline. Not "offline by default" — there is no network client in the product at all.**
No telemetry, no update check, no reputation lookup: nothing about your machine leaves it,
because nothing in the code can send it.

What does hold your data is local. `%LOCALAPPDATA%\RatScan\ratscan.db` stores scan history,
the allowlist and baselines — process paths, listening ports, usernames — and is gitignored.
Exported reports contain the same detail, which is why the export prompt says so before it
writes. Treat both as a description of your computer, because that is what they are.

## Planned

- **Code signing**, so the published binary stops tripping SmartScreen.
- **VirusTotal enrichment** — opt-in, off by default, using your own API key, with the UI
  announcing each hash at the moment it is about to leave the machine. It is not built yet,
  and the offline guarantee above holds until it is: the day that changes, this README and
  the app will both say so before anything is sent.
- **Two cross-view rules** that are collected but not yet judged — the `\Driver` object
  directory against the loaded-module list, and a second independent source for TCP
  connections via ETW.
- Signature rules for the driver census beyond the unregistered-driver case.

## Documentation

See [`docs/`](docs/) — changelog, build log, and the phase checkpoint.

## License

[MIT](LICENSE). Use it, fork it, ship it — with the warranty disclaimer meant literally:
this is a detection tool with named blind spots, and it can be wrong in both directions.

The published binary is **not code-signed**, so Windows SmartScreen warns on first run and
some anti-malware products may quarantine it. That is the expected reaction to an unsigned
executable that enumerates processes across four kernel interfaces, reads the driver list
and opens an ETW kernel session — the same behaviours the tool exists to look for. Build it
yourself if you would rather not trust a binary.
