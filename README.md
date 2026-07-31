<div align="center">

# RatScan

**Find out what's watching you.**

A Windows remote-access and RAT detection tool that tells you the truth about its own blind spots.

![status](https://img.shields.io/badge/status-in%20development-orange)
![platform](https://img.shields.io/badge/platform-Windows%2011%20x64-0078D4)
![dotnet](https://img.shields.io/badge/.NET-8.0-512BD4)
![ui](https://img.shields.io/badge/UI-WPF-blue)

</div>

---

> [!WARNING]
> **In active development — phase 0 of 11 complete.** The solution scaffolds and
> builds; the detection engine is not yet implemented. Nothing here detects anything
> yet. This notice comes down when the end-to-end verification in
> `docs/` actually passes.

## What it does

RatScan audits a Windows 11 machine for anything that gives a remote party the
ability to **see your screen, control your input, or reach your files** — commercial
remote-access products, abused RMM agents, built-in Windows remote surfaces left
enabled, and purpose-built RATs.

It runs a deep on-demand scan and a continuous ETW-backed watch, explains every
finding with its evidence chain, and offers remediation you have to confirm.

## The honest part

> [!IMPORTANT]
> **RatScan will never tell you "you are clean."**

No user-mode program can prove a machine is unmonitored. Anything running in the
kernel (a malicious or vulnerable signed driver), below it (a thin hypervisor), or
beside it (IPMI/BMC, a hardware KVM-over-IP dongle, a capture device inline with your
monitor) can answer every API this tool calls with clean lies, or bypass the operating
system entirely. A scanner that renders a green checkmark is at its least trustworthy
exactly when it matters most.

So RatScan is built to a different goal: **make it very hard for anything to hide, and
make the remaining blind spots visible and named.** Three things follow from that:

| Commitment | What it means |
|---|---|
| **Cross-view detection** | Processes, connections, services and drivers are each enumerated from 3–5 *independent* kernel interfaces and diffed. Something that unhooks one API but not the others produces a discrepancy — and the discrepancy is itself a critical finding. This is how you catch active concealment, as opposed to mere unfamiliarity. |
| **Scan Integrity panel** | Every scan reports the conditions it ran under: elevation, Secure Boot, HVCI/VBS, Defender + tamper-protection health, test-signing, kernel debugger, hypervisor presence. The verdict is explicitly qualified by these. |
| **Coverage-qualified verdicts** | The headline is never "clean." It reads *"No evidence of remote access found — across N surfaces, with these M blind spots,"* and the blind spots are enumerated and clickable. |

## Detection coverage

- **Known remote-access software** — ~60 products (AnyDesk, TeamViewer, RustDesk, ScreenConnect, NetSupport, Remote Utilities, the VNC family, RMM agents…), matched on process, service, driver, path, signer, and registry footprint. Portable/uninstalled instances are scored *higher* — that's the support-scam signature.
- **Windows' own remote surfaces** — RDP (including the `Shadow` policy, which permits silent session watching), WinRM, PS Remoting, OpenSSH, Remote Registry, Remote Assistance, Quick Assist, SMB sessions, `netsh portproxy`, inbound firewall rules.
- **Screen & input surveillance** — capture-capable module correlation, virtual/indirect display drivers, injected-hook footprints, UIAccess tokens, virtual HID drivers.
- **Persistence (ASEP)** — Run keys, scheduled tasks, services, **WMI permanent event subscriptions**, Winlogon, `AppInit_DLLs`, IFEO, COM hijacks, LSA packages, and more.
- **Trust analysis** — Authenticode verification on every running image (including the catalog path), path and masquerade anomalies.
- **Live watch** — real-time ETW over kernel process/image/network events and DNS.

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

Offline by default. No telemetry. VirusTotal enrichment is opt-in, uses your own API
key, and the UI states when a hash is about to leave the machine. The local scan
database holds host telemetry (process paths, connections, usernames) and is
gitignored — don't commit or share it casually.

## Documentation

See [`docs/`](docs/) — changelog, build log, and the phase checkpoint.
