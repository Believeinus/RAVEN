<div align="center">

<img src="assets/raven-banner.png" alt="RAVEN — Remote Access &amp; Visibility Examination Node" width="820">

<br>

[![Platform](https://img.shields.io/badge/platform-Windows%2011%20x64-0078D4?style=flat-square)](https://github.com/Believeinus/RAVEN)
[![Language](https://img.shields.io/badge/C%23-.NET%208-512BD4?style=flat-square)](https://github.com/Believeinus/RAVEN)
[![UI](https://img.shields.io/badge/UI-WPF%20%C2%B7%20Fluent-6A5ACD?style=flat-square)](https://github.com/Believeinus/RAVEN)
[![Runs](https://img.shields.io/badge/runs-fully%20offline-2E7D32?style=flat-square)](#-privacy)
[![Status](https://img.shields.io/badge/status-in%20development-E8873A?style=flat-square)](#-status)

</div>

---

RAVEN looks for remote-access software, RATs, and screen or input surveillance running on
your machine — and then helps you stop it. It runs entirely on the local machine. There is
no server, no account, and nothing leaves the computer.

> [!IMPORTANT]
> RAVEN is in active development. The published executable is not yet code-signed, so
> SmartScreen will warn on first run.

---

## 🧭 The constraint that shapes everything

The original goal was *"iron proof — if this tool says nothing is spying on me, nothing
is."*

**That bar is unreachable, and pretending otherwise is the most dangerous thing a tool like
this can do.** A kernel rootkit, a hypervisor beneath Windows, or a hardware KVM-over-IP all
defeat any user-mode scanner. So RAVEN took a different commitment instead:

> Make it very hard for anything to hide, and make the residual blind spots **visible and
> named**.

Three things follow from that, and they are not adjustable:

| | |
|---|---|
| **It never says you are clean** | The verdict type has no `Clean` value *by construction*, and a test asserts the output never claims safety. Every verdict is qualified by what the scan could actually see. |
| **A discrepancy is the finding** | Processes and drivers are enumerated through several independent kernel interfaces and the results are diffed. Something visible to one interface and hidden from another *is* the result. |
| **Missing data is never a finding** | A privilege limit degrades coverage and adds a named blind spot. It never manufactures a detection — nearly every false positive this project has produced came from breaking that rule. |

Every scan ends with a **Scan Integrity** panel and an explicit *"what this scan could not
see"* list. Those are not footnotes; they are the product.

---

## 🖥️ What it looks like

<div align="center">
<img src="assets/screenshot-scan.png" alt="RAVEN Scan view" width="880">
<br><em>The Scan view. Coverage is stated before any result is.</em>
<br><br>
<img src="assets/screenshot-live-watch.png" alt="RAVEN Live watch view" width="880">
<br><em>Live watch — a scan samples one moment; this sees what happens between them.</em>
</div>

---

## 🔍 What it examines

| Surface | What RAVEN reads |
|---|---|
| **Processes** | Every running process and its trust status — Authenticode including **catalog** signatures, since most of Windows is catalog-signed and an embedded-only check would call half the OS unsigned |
| **Network** | TCP/UDP listeners and connections, attributed to the owning process |
| **Windows' own remote access** | RDP, RDP shadowing, WinRM, OpenSSH, Remote Registry, Remote Assistance, SMB, and `netsh portproxy` forwarding |
| **Persistence** | 14 auto-start surfaces — Run/RunOnce, startup folders, scheduled tasks, services, Winlogon, AppInit_DLLs and AppCertDlls, IFEO debuggers, COM hijacks, LSA packages, print monitors, netsh helpers, Active Setup, PowerShell profiles, WMI event subscriptions. Every path is resolved before it is verified, so `%windir%\…`, a bare `explorer.exe` and a Startup shortcut are all checked against the real file rather than reported as missing |
| **Kernel drivers** | The loaded-module list, registry registrations, and the `\Driver` object directory — three views that can disagree |
| **Surveillance** | Screen-capture correlation and the structural footprint of a global input hook |

---

## ✨ What else it does

- **Identifies known tools** from a catalogue of remote-access and RAT-family software —
  used as evidence *for* an identification, never as grounds to convict. A stale catalogue
  lowers confidence rather than raising severity.
- **Stops things, with your hand on it.** No remediation runs without a confirmation showing
  the exact command and its impact.
- **An allowlist that cannot quietly lie.** Every entry is pinned to the SHA-256 of the file
  it excuses, so swapping that file brings the finding straight back. Muted items stay listed
  on the same screen as everything else.
- **Remembers, and compares.** Each scan is recorded and diffed against the previous one —
  and a finding that disappeared is never reported as good news if this scan simply saw less.
- **Exports** to HTML or JSON, stating what the file contains before writing it.
- **Watches between scans** with real-time ETW tracing, for software that starts, beacons and
  exits before any scan would notice. Process and network events are retained separately from
  image loads, because a busy machine produces DLL loads at roughly forty to one and they
  would otherwise push the beacon you care about out of the buffer.

---

## ⬇️ Install

RAVEN does not install anything. There is no installer, no service, and no registry
footprint — it is a folder you unzip and an executable you run, and deleting the folder
removes it.

1. Download `RAVEN-win-x64.zip` from [Releases](../../releases).
2. **Unzip the whole folder** and keep it together. `RAVEN.exe` needs the files beside it —
   in particular `amd64\KernelTraceControl.dll`, without which the live watch cannot start a
   kernel trace. Copying the `.exe` out on its own is the one way to break it.
3. Run `RAVEN.exe`.

> [!WARNING]
> **SmartScreen will warn on first run, and some anti-malware may object.** The executable is
> not code-signed yet. It also does exactly what heuristics are built to notice: enumerates
> every process through four kernel interfaces, reads the kernel driver list, and opens an ETW
> kernel session. If you would rather not trust a binary from the internet — reasonable, for a
> tool like this — build it yourself from source, below.

The only thing RAVEN writes outside its own folder is `%LOCALAPPDATA%\RatScan\ratscan.db`,
which holds your scan history, allowlist and baselines. Delete that folder to reset it
completely. (The directory keeps the project's old name on purpose: renaming it would strand
existing history behind a fresh-looking install.)

## ▶️ Running it

- **Accept the elevation prompt** for full coverage. Declining is supported and RAVEN keeps
  working — it just says, in a banner and on every scan, what it can no longer see.
- Press **Run full scan**. It takes a few seconds and ends with a verdict that states its own
  coverage.
- **Live watch** needs Administrator and refuses clearly without it, rather than appearing to
  watch while seeing nothing.
- Closing the window quits RAVEN — unless a watch is running, in which case it goes to the
  tray and tells you so once.
- `RAVEN.exe --no-elevate` skips the elevation request. That is a supported switch, not a
  workaround: it is how the reduced-coverage path is exercised, and how any automated run has
  to start, since UAC lives on the secure desktop.

### Build from source

```powershell
git clone https://github.com/Believeinus/RAVEN.git
cd RAVEN
dotnet build RatScan.sln
dotnet test
dotnet run --project RatScan.UI
```

Needs the [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0). To produce the same
self-contained build that ships in the release:

```powershell
dotnet publish RatScan.UI -c Release -r win-x64 --self-contained /p:PublishSingleFile=true -o release
```

The project files, namespaces and solution still say `RatScan`, the name this started under.
That is deliberate — renaming them is a one-way refactor with no benefit to anyone using it.

---

## 🛡️ Requirements

- Windows 11, x64
- **Administrator is requested at launch.** Without it, kernel driver identities, the
  `\Driver` object directory, the Security event log, SMB session data and the live watch are
  all out of reach.

> [!NOTE]
> Declining the prompt is fully supported. RAVEN keeps running with reduced coverage and says
> so, in a banner and on every scan. Elevation is *requested*, never demanded by the manifest
> — a tool that cannot demonstrate its own blind spots has no business claiming it has none.

---

## 🔒 Privacy

Everything stays on the machine. There is no server, no account, and no telemetry — and not
as a default you could flip: **there is no network client anywhere in the product.** Nothing
about your computer can leave it, because nothing in the code can send it.

Scan history, the allowlist and baselines live in a local SQLite database. That database
records what is running on your computer — program paths, connections and usernames — so it
is worth treating like any other record of your machine. Exported reports contain the same
kind of detail, and RAVEN tells you that *before* it writes one.

---

<details>
<summary><strong>Why does it refuse to tell me I'm clean?</strong></summary>

<br>

Because it cannot know. RAVEN runs in user mode. Code running in the Windows kernel, in a
hypervisor beneath Windows, or in hardware attached to the machine can return clean answers
to every check it performs.

A tool that says "you're clean" is making a claim about things it did not look at. RAVEN
reports what it examined and what it could not — which is less comforting and considerably
more useful.

</details>

<details>
<summary><strong>It flagged software I installed myself. Is that a bug?</strong></summary>

<br>

No. Remote-access software is not malware, and RAVEN does not pretend to know whose machine
it is on. TeamViewer, RustDesk, VNC and their relatives are flagged because they *can* be
used against you, not because they are.

The question RAVEN is built to answer is the one only you can: *did you set this up?* If yes,
mute it — the entry is pinned to that exact file, so a swapped binary comes straight back.

</details>

<details>
<summary><strong>Why does an unelevated scan find fewer things?</strong></summary>

<br>

Because it can see less, and that is reported rather than hidden. Windows withholds kernel
image bases below high integrity, refuses the `\Driver` object directory, and closes the
Security event log.

RAVEN never treats "I could not look" as "there was nothing there". Those gaps are listed
individually on every scan, and a comparison against an elevated scan carries a caveat saying
the two are not equivalent.

</details>

---

## 🚧 Status

In active development. It scans, watches, stops things, remembers and compares, and the
first pre-release build is published under [Releases](../../releases).

## 🗺️ Planned

- **Code signing**, so the download stops tripping SmartScreen.
- **VirusTotal enrichment** — opt-in, off by default, using your own API key, with the UI
  announcing each hash at the moment it is about to leave the machine. The offline guarantee
  above holds until then, and will change in the same release that adds it.
- Deeper cross-view detection: the `\Driver` object directory judged against the loaded-module
  list, and a second independent source for network connections via ETW.

## 📄 License

[MIT](LICENSE) — use it, fork it, ship it. The warranty disclaimer is meant literally: this
is a detection tool with named blind spots, and it can be wrong in both directions.

<div align="center">
<br>
<sub>Built by <a href="https://github.com/Believeinus">Believeinus</a></sub>
</div>
