# Changelog

All notable changes to RatScan are recorded here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased] — 2026-08-01

### Added

- Project scaffold: git repository, `.gitignore`, `docs/` with the context routines.
- .NET 8 solution — `RatScan.Native`, `.Engine`, `.Etw`, `.Rules`, `.UI`, `.Tests`.
- CsWin32 interop surface covering process, signature, network, service, driver,
  session, SMB and window APIs.
- Four independent process enumeration sources (Toolhelp32,
  `NtQuerySystemInformation`, PSAPI, brute-force `OpenProcess` probe) — the
  foundation of cross-view concealment detection.
- Live-machine test suite asserting the sources agree and that no confirmed-alive
  process is missing from every list API.
- Per-process detail: image path, token elevation, integrity level, UIAccess.
- TCP/UDP connection tables with owning-PID attribution over IPv4 and IPv6,
  cross-checked against `IPGlobalProperties` (29/29 listening ports matched).
- Service Control Manager enumeration, kernel driver census, Terminal Services
  sessions, SMB shares and inbound sessions, window-to-process mapping.
- Authenticode verification covering embedded **and** catalog signatures. Measured:
  42 of 60 sampled System32 binaries are catalog-signed — an embedded-only verifier
  would have called all 42 unsigned.
- `LoadedDriverResult.AddressesWithheld`, flagging that Windows zeroes kernel image
  bases below high integrity (KASLR protection) so an unelevated driver census is
  never mistaken for a clean one.
- Engine model: `Finding`, `Evidence`, `Blindspot`, `ProcessFact`, with `Severity` and
  `Confidence` deliberately independent.
- `ProcessCollector` merging all enumeration sources with per-process detail,
  connection attribution, window presence, signature status and SHA-256, plus
  per-source coverage. Full scan of 456 processes completes in ~1.6s.
- Quick / Full scan profiles; every profile emits its own blind spots, including one
  for the PID probe being disabled.
- `RemoteSurfaceCollector` auditing eight built-in Windows remote-access surfaces —
  RDP, RDP session shadowing, WinRM/PowerShell Remoting, OpenSSH, Remote Registry,
  Remote Assistance, SMB, and `netsh portproxy` forwarding — each with state,
  capability, evidence chain, correlated listening ports and a disable command.
- Remote logon history from Security event 4624 logon type 10, degrading to a named
  blind spot when the Security log is unreadable.
- `PersistenceCollector` sweeping fourteen auto-start surfaces: Run/RunOnce across
  both registry views, startup folders, scheduled tasks, Winlogon Shell/Userinit,
  AppInit_DLLs, AppCertDlls, IFEO debuggers, COM hijacks, LSA packages, print
  monitors, netsh helpers, and WMI permanent event subscriptions.
- `DriverCollector` merging loaded kernel modules with registry driver registrations,
  including native path resolution (`\SystemRoot\`, `\??\`, bare relative).
- `ConcealmentDetector` — cross-view detection of processes hidden from one kernel
  interface but not another, selective hiding, and kernel drivers loaded without a
  service registration. Reports a scan-integrity finding when too few sources
  succeed to cross-check at all.
- Confirmation pass in `ProcessCollector`: probe-only PIDs are re-checked against a
  fresh enumeration before being called hidden, so ordinary process churn cannot
  produce a concealment finding.
- 56-product remote-access catalogue as embedded YAML, covering remote-desktop, RMM,
  tunnellers, mesh VPNs, screen-streaming, remote-input and known RAT families.
- `RemoteAccessToolDetector` with layered matching — confidence scales with how many
  independent signals agree (name, signer, expected listening port) — and plain-language
  explanations written in terms of what someone can do to the user.
- `SystemIntegrityProbe` reading driver signature enforcement, test-signing mode,
  kernel debug mode and kernel-debugger presence; plus Secure Boot and HVCI.
- `IntegrityAssessor`, separating conditions that let a scan be *deceived* from those
  that merely reduce its completeness.
- `ScoringEngine` producing coverage-qualified verdicts. `VerdictLevel` has no `Clean`
  member by construction; the honesty clause appears on every verdict.
- `ScanOrchestrator` running a complete scan end to end. Collector and detector
  failures are non-fatal and become named blind spots.
- `ModuleInventory` enumerating loaded DLLs per process, including 32-bit modules.
- `SurveillanceDetector` — screen-capture correlation (capability plus at least two
  aggravating factors, never presented as proof), broad DLL injection as the
  structural footprint of a global input hook, and UIAccess held without a valid
  signature.
- WPF dashboard: verdict card, findings with expandable evidence chains, Scan
  Integrity panel, and the blind-spot list. Integrity signals render red when a
  failure means the scan could have been *deceived* and amber when it merely narrows
  coverage. A scan that throws states that nothing was established.
- Guided remediation — end a process and its children, stop and disable a service,
  remove an auto-start value, disable a Windows remote surface. Confirmation is a
  required executor parameter, and the previewed command is exactly what runs.
- `LiveWatcher` + `LiveAlertRules` (`RatScan.Etw`): real-time ETW over kernel
  process, image-load and TCP events, with a bounded ring buffer. Alerts fire once
  per tool per session and only for catalogued remote-access software starting.
  Failure to start reports the reason and the remedy rather than failing silently.
- Local state in SQLite at `%LOCALAPPDATA%\RatScan\ratscan.db` (schema v2), with one
  place owning the schema for both stores. Every `CommandText` is a compile-time
  constant and every observed value is bound as a parameter — nothing read off a
  scanned machine can reach the database as syntax.
- **Allowlist.** Entries are pinned to the SHA-256 of the file they excuse, so replacing
  the file brings the finding straight back; each records why it was created, and the
  whole list is shown back on every scan. `Finding.CanBeMuted` structurally refuses
  `Concealment` and `ScanIntegrity` findings — nothing benign produces a cross-view
  discrepancy, and muting a coverage finding would convert a known gap into silence.
  A pin that cannot be verified fails open: the finding is shown, annotated with why the
  mute did not apply.
- `ScanResult.VerdictIfNothingMuted` — the verdict the machine would have received with
  nothing muted, computed beside the real one so the two cannot drift. Muting is
  disclosed in the **headline**, and the counterfactual is spelled out in the summary
  whenever the user's own allowlist is the reason the verdict reads as calmly as it does.
- `ScanOrchestrator.ReapplyAllowlist` re-scores an existing scan, so muting takes effect
  immediately instead of after another full scan. Muting is applied after detection and
  before scoring: detectors never learn the allowlist exists, so a muted thing that
  changes is still noticed.
- **Scan history and diff.** Scans are recorded and compared against the previous one:
  what appeared, what went, what changed severity. Identity — not the title — decides
  whether two findings are the same one. A disappearance is never reported as an
  improvement when this scan saw less: lost elevation, more blind spots or more mutes
  each attach a named caveat.
- **Export** to HTML and JSON, with the UI stating what the file contains — program
  paths, ports, hashes, allowlist notes — before it is written rather than after. The
  report carries its own coverage and limits, and machine-controlled text is escaped.
- **Live Watch panel**, wiring `LiveWatcher` into the application for the first time:
  start/stop, a status line, alerts, and a feed of process starts and TCP
  connect/accept. The feed redraws on a one-second timer rather than per event, because
  image loads arrive in the thousands per second; it states how many events it is not
  showing. If the ETW session dies underneath it, the panel says the watch stopped and
  that nothing has been observed since.
- **"Restart as Administrator"** in the window header, shown only when unelevated.
  Offered rather than forced: the manifest stays `asInvoker` so the reduced-coverage
  path remains reachable and testable. Declining the UAC prompt is reported as a
  decision, not an error.
- **`PersistenceDetector`** — the auto-start entries were being collected and never
  judged, so a RAT with a Run-key entry produced no finding at all. Four rules, each
  designed against a measured baseline of a healthy machine: a catalogued remote-access
  product configured to start on its own; Winlogon's shell or userinit pointing anywhere
  other than Windows' own; anything occupying AppInit_DLLs, AppCertDlls or an IFEO
  debugger; and persistence that carries its code with no file on disk. On the
  development machine this produces 4 findings from 305 entries, all true.
- Three auto-start surfaces that had been declared without collectors for several
  phases now have them: **auto-start services** (kernel drivers excluded, since the
  driver census already reports those), **Active Setup** components that carry a
  `StubPath`, and **PowerShell profile scripts** that exist on disk. Swept entries on
  the development machine went 165 → 305.

### Removed

- `WPF-UI`, `CommunityToolkit.Mvvm`, `Hardcodet.NotifyIcon.Wpf` and
  `Microsoft.Extensions.Hosting`. Added in phase 0 for a Fluent/MVVM/tray/host build
  that was never written, and unreferenced by any code since. The solution builds clean
  without them.

### Known gaps

- **The ETW live watch has never run.** It is wired into the UI and its failure path is
  verified, but every test and every run so far has been unelevated, so session
  establishment and event flow are still exercised only through their failure branch.
- No tray icon and no background alerting: the Live Watch panel only reports while the
  window is open.
- The network cross-view still has one source. ETW was to supply the second.
- The JSON export path has not been driven through the UI; only HTML has. The format is
  chosen from the file extension, and `ExportTests` covers both.
- The published build is **not a true single file** — 6 native DLLs and an `amd64\`
  folder (TraceEvent's `KernelTraceControl.dll`) must ship beside the 173 MB exe. It is
  also unsigned, so SmartScreen will warn on first run.
- Persistence entries carry no signature information, so no rule can yet ask whether an
  auto-start binary is signed.

### Fixed

- **Finding titles rendered black on a black card and were effectively unreadable** —
  "RustDesk is running", the scan-integrity signal names and the blind-spot headings.
  The implicit `TextBlock` style lived in `MainWindow.Resources`, and a window-scoped
  implicit style does not reach TextBlocks created from a `DataTemplate`, so every
  templated item fell back to WPF's default black while the explicitly coloured
  paragraph directly beneath it looked correct. The palette and default text style moved
  to `App.xaml`, where application scope reaches template content.
- **`InvariantGlobalization` crashed the app on any non-invariant keyboard layout.** WPF
  builds a caret the moment a `TextBox` takes focus, which asks Windows for the current
  input language; on English (India) that is culture `0x4009`, which invariant mode
  refuses with `CultureNotFoundException`, taking the process down. Every text box in the
  app, for every affected user. Now an explicit `false` with the reason recorded beside
  it, so it is not re-added to save publish size.
- Selective hiding fired **Critical on `docker.exe`** during ordinary process churn. The
  listing sources run one after another, so a process that starts or exits between two of
  them is present in one and absent from the next — the exact shape of a hooked
  enumeration API. It is now confirmed by a second pass, as full hiding already was, with
  the re-listing kept **per source** rather than unioned: confirming selective hiding
  means asking which interface is still missing the process, not merely whether any
  interface saw it. Churn does not reproduce; a hooked enumeration path does. The
  finding's recommendation changed with it, from "re-run the scan" to "investigate this
  binary offline", because the tool has now done the re-run itself.
- PID probe reported ~327 phantom hidden processes on a clean machine. Two causes:
  reading a last-error value clobbered by CsWin32's `OpenProcess_SafeHandle` wrapper,
  and counting zombie process objects (exited, but still openable while a handle
  remains). Successful `OpenProcess` is not proof of life; a zero-timeout
  `WaitForSingleObject` is now the discriminator.
- PID probe then under-reported after that fix, because `WaitForSingleObject` needs
  `SYNCHRONIZE`, which `PROCESS_QUERY_LIMITED_INFORMATION` does not grant.
- WMI `__FilterToConsumerBinding` entries were all flagged fileless. A binding carries
  no code, and stock Windows ships an SCM event-log binding, so this raised a permanent
  "fileless persistence" false positive on clean machines.
- Driver census reported a phantom "loaded without registration" module when run
  unelevated, an artefact of withheld kernel image bases. The loaded view is now
  dropped entirely in that state rather than partially populated.
- Port forwarding reported as enabled on a machine with no forwarding rules. The fix
  guaranteeing every surface carries evidence appended a placeholder entry, and state
  was derived from the evidence count — so the completeness fix broke the reading it
  was decorating.
- Four near-identical findings for one product with multiple helper processes.
  Findings are now deduplicated per product, strongest match winning.
- Correctly-signed TightVNC was reported as an impostor at Critical severity because
  the catalogue held a stale publisher string. Impersonation is now claimed only when
  a binary fails signature verification outright; an unrecognised-but-valid signer
  lowers confidence and is disclosed as a limitation of RatScan's own data.

### Changed

- **RatScan now asks for Administrator when it launches**, rather than starting
  unelevated and offering to restart. It relaunches itself elevated at startup, so full
  coverage is the default. The manifest stays `asInvoker` deliberately: elevation is
  requested where it can be *declined*, and declining leaves RatScan running with
  reduced coverage rather than refusing to start. `--no-elevate` skips the request
  entirely, which is what keeps the reduced-coverage path exercisable by hand and by
  automation.
- **Scrolling follows the gesture.** WPF turns every wheel event into the same fixed
  jump, so a precision touchpad — which reports a stream of small deltas across one
  swipe — got a full jump per delta and the content outran the finger. All scroll
  regions now move in proportion to the wheel delta, tuned by a single constant
  (`App.PixelsPerNotch`).
- `RawProcess.VerifiedAlive` is tri-state (`true` / `null` / absent) so "could not
  verify" can never be mistaken for "is running" — the distinction between a real
  concealment signal and a phantom finding.
- App manifest is `asInvoker` rather than `requireAdministrator`, keeping the
  degraded-coverage path observable and testable.
- Dropped `<Platforms>x64</Platforms>` (kept `PlatformTarget`) to stop assemblies
  being emitted to two divergent output paths.
- Target framework raised to `net8.0-windows10.0.17763.0`. The catalog-verification
  APIs are Windows 8+, and plain `net8.0-windows` declares a Windows 7 floor, so the
  platform-compatibility analyzer rejected them.

### Deferred

- MFT-level file-hiding detection, memory scanning for injected code, a kernel-mode
  self-defense component, network-level capture from a second device, and non-Windows
  collectors. All named explicitly rather than silently omitted.
