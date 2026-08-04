# Changelog

All notable changes to RatScan are recorded here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased] — 2026-08-04

### Security

- **The published executable carried the developer's home directory, five times over.**
  Every assembly writes a CodeView (RSDS) debug record naming its `.pdb` by absolute path,
  so `RAVEN.exe` contained `C:\Users\<name>\…` — full path and personal name — baked into the
  binary. Excluding the `.pdb` files from the distribution zip did nothing about it, because
  the strings live in the executable itself. Release builds now emit no symbols at all and
  set `PathMap`, and the rebuilt binary contains zero occurrences of the build machine's
  paths, user name or host name. A tool that publishes what is on your computer had no
  business publishing what was on its author's.
- Assembly metadata is attributed to `Believeinus` rather than a personal name, and the
  `LICENSE` copyright line with it.
- Two changelog entries named the specific remote-access products installed on the
  development machine while describing bugs they had exposed. Replaced with the product
  *class*. This is the same rule that keeps the README screenshots at the empty state: a
  scanner's own repository should not be a scan result.

- **The unregistered-driver rule no longer reports fifty Windows drivers as rootkits.**
  `concealment.unregistered-driver` rested on a premise — that the supported way to load a
  driver always leaves a service key, so a loaded module without one was mapped in by hand.
  The first elevated scan measured it: 50 of this machine's 270 loaded modules have no
  service key of their own, including `ntoskrnl.exe`, `hal.dll`, `CI.dll`, `win32k.sys` and
  the whole HID and storage dependency chain. Dependency imports and boot-loaded code are
  loaded by something other than the service control manager. The rule now requires the
  missing registration **and** a failed signature verification, which is what manual mapping
  is actually for. Measured on this machine: 47 verified Microsoft-signed and are no longer
  reported, and the elevated verdict went from **56 high-severity findings to 6** — the same
  four real surfaces the unelevated scan finds, no longer buried under fifty false ones.
- **`Unknown` is excluded alongside `Valid`, and that is the same rule twice.** A signature
  that could not be checked is not a signature that failed. The three modules affected are
  Windows' crash-dump stack (`dump_stornvme.sys` and its siblings) — in-memory copies whose
  files deliberately do not exist on disk, confirmed by hand before the rule was written.
- **They are disclosed rather than dropped.** A driver mapped straight into memory would
  have exactly that shape, so `DriverCollector` now emits a blind spot naming the
  unverifiable modules. Elevated blind spots go 1 → 2, and the count of things this scan
  could not establish stays honest.
- **The guard test that should have caught this was blind.**
  `No_concealment_findings_on_this_machine` asserts the detector stays silent here, and it
  passed throughout — it built a `DetectionContext` with `Drivers` left null, so the rule
  never executed inside it. It now collects the census for real. A guard that cannot see the
  rule it guards does not fail; it certifies.

### Added

- **Confirmations are `ui:ContentDialog` instead of `MessageBox`.** The primary button
  carries the name of the action — *Write the report*, *Turn off Remote Assistance*, *Mute
  this finding* — never "OK", and it is red only where the risk is not reversible. Cancel is
  the default button, so Enter on an unread dialog does nothing. The dialog that names the
  exact command about to run no longer arrives looking like every "are you sure?" the user
  has clicked through. `MainWindow` hosts one `ContentDialogHost` for the whole shell.
- `MuteDialog` is a `ContentDialog` rather than its own `Window`, so a decision about the
  finding on screen no longer takes that context away.

### Verified

- **The ETW live watch has been driven elevated and it traces.** Process starts, image loads
  and TCP connections all arrive; 5,000 events in a ten-minute window. Every previous run
  had exercised only the unelevated refusal path, so this closes the last capability in the
  product that had never been observed working.
- The published build was regenerated after the driver fix and driven again: coverage-
  qualified verdict, 14 findings rendered (which is what proves the embedded YAML rule pack
  survived the single-file pack), 5 blind spots, history row written.

### Fixed

- **The published `release/` folder is repaired.** It had been a half-publish since
  2026-08-03: a stale executable predating the entire Fluent redesign, four native DLLs
  instead of six (`PenImc_cor3.dll` and `vcruntime140_cor3.dll` were gone), and no `amd64\`
  directory at all. `amd64\KernelTraceControl.dll` is what TraceEvent needs to open a kernel
  ETW session, so the shipped build would have failed to trace — and failed in a way that
  reads to a user as a product fault rather than a packaging one. A security tool silently
  under-reporting is the worst shape this bug could have taken.
- The repaired folder was **verified by running it**, not by listing it: a full scan on the
  published binary rendered a coverage-qualified verdict, produced 16 findings (which is
  what proves the embedded YAML rule pack survived the single-file pack), wrote a history
  row, and diffed correctly against the previous scan.

### Deployment

- **A locked executable is now repaired by renaming, not by killing.** The instance that
  broke the original publish was still running a day later and was *elevated*, so
  `Stop-Process` returned `Access is denied` from an ordinary shell. A running image cannot
  be deleted but can be renamed — the same technique updaters use to replace live binaries
  — which frees the publish path without touching the running process. The previous advice,
  "close every running RAVEN first", is sound prevention and no use at all as a cure.
- The published folder now also contains five `.pdb` files. Normal publish output; whether
  a security tool should ship its symbols is an open question, not a defect.

- `release\RAVEN.exe.locked-pid30420` is gone. The process holding it exited after three
  days, and `release/` was republished clean: 179.7 MB executable, six native DLLs,
  `amd64\KernelTraceControl.dll` and `amd64\msdia140.dll` both present.

- **The live watch no longer forgets what it saw.** Process/network events and image loads
  shared one 5,000-event ring, and the first elevated run measured what that means: ten
  minutes produced 5,000 events, 4,885 of them image loads, so the buffer was full and
  discarding — at roughly 42 image loads for every event worth reading. A watcher that
  silently drops the beacon it saw is the failure this component exists to refuse. The two
  now have separate budgets (5,000 signal events, 1,000 image loads), which at the measured
  rate holds about seven hours of process and network history instead of ten minutes, and
  anything discarded is counted and stated in the view rather than dropped quietly.

### Added

- **MIT licence.** The repo had no `LICENSE`, so nobody receiving a copy had any stated
  right to use it. The README now says so, and says plainly that the published binary is
  unsigned and will trip SmartScreen.
- **A distributable zip** — `dist/RAVEN-win-x64.zip`, 73.9 MB, the whole published folder
  minus the `.pdb` files, with `LICENSE` and `README.md` beside the executable. It is the
  folder that has to travel, not the exe: `amd64\KernelTraceControl.dll` must sit next to
  `RAVEN.exe` or ETW cannot open a kernel session, and that failure reads as a product
  defect. Verified by extracting the zip to a clean directory and running *that* copy.

---

## [Unreleased] — 2026-08-03

### Changed

- **The product is now RAVEN — Remote Access & Visibility Examination Node.** The title bar
  and taskbar show `RAVEN`; the full name appears in the window header, the executable's
  Windows metadata and the exported report. The executable is `RAVEN.exe`.
- **The data directory is deliberately still `%LOCALAPPDATA%\RatScan`.** It holds scan
  history, the allowlist and baselines; renaming it would leave all of that on disk while
  the app came up looking like a fresh install. Changing it needs a migration, not a new
  string. Namespaces and project names also keep the old name — a one-way refactor with no
  user-visible benefit.
- **The interface is rebuilt on WPF-UI 4.3.0 (Fluent).** `FluentWindow` with an integrated
  dark title bar, rounded corners, and the RAVEN mark behind the content at 5% opacity.
  The package was removed on 2026-08-01 for claiming an architecture that did not exist;
  the note it left said to re-add it when something actually used it, and now something
  does.
- **One dashboard became four views** on a navigation shell — Scan, Live watch, History,
  Settings. `MainWindow` dropped from 1,135 lines to 194 and now owns only the window,
  navigation, tray and the shared session. Live watch, previously squeezed into ~150 px of a
  shared column, now has the whole window, so its Start control is no longer below the fold.
  Scan stays first in the navigation — it is what the tool is opened to do.
- **Typography follows the Fluent ramp.** Prose at 14 px, dense data at 12 px, and nothing
  anywhere below 12 px — previously 20 of 44 sized text elements were beneath that floor and
  40 were beneath Fluent's body size. 21 of 23 hardcoded colours now come from theme brushes;
  the two that remain carry meaning and must not track a neutral one.
- The accent is pinned to RAVEN's blue rather than following the Windows accent colour,
  which rendered every primary button magenta on this machine. The accent is the only strong
  colour in the window that means nothing, and it sits beside amber and red that do.

### Added

- **Authenticode facts on persistence entries.** Auto-start paths are now resolved before
  verification — environment variables expanded, bare names probed against the system
  directories, and Startup-folder shortcuts followed to their target. Unverifiable entries on
  the development machine went from **87 of 296 down to 5**, and two catalogued tools reached
  `Confirmed` because the signer could finally be compared.
- Unsigned images escalate a finding **only on the injection surfaces** (AppInit_DLLs,
  AppCertDlls, IFEO debugger), where the measured baseline is zero. A general
  unsigned-auto-start rule was measured and deliberately not written: it fires five times on
  a healthy machine, every time on the user's own software.
- Every persistence finding now states its signature position, keeping "not verified",
  "could not be checked" and "there is none" distinguishable — only the last says anything
  about the file.
- **`\Driver` object-directory walk** (`NtOpenDirectoryObject` / `NtQueryDirectoryObject`), a
  third view of the kernel's drivers independent of both the loaded-module list and the
  registry. `OBJECT_DIRECTORY_INFORMATION` is hand-declared because it is absent from the
  Windows metadata; everything else is generated. Collected and disclosed as a named blind
  spot when it cannot be opened — **not yet judged**, because object names are not file names
  and the false-match rate needs an elevated baseline first.
- **Tray icon and background alerting.** Closing the window ends RAVEN unless a live watch is
  running, in which case it hides to the tray and says so once. The icon carries the logo plus
  a status dot, because an indicator that looks identical whether the watch is alive or dead
  is worse than none. Deliberately no start-with-Windows: giving RAVEN its own auto-start
  entry would make it an instance of the thing it reports.
- **History view** — recorded scans, newest first, each stating whether it ran elevated,
  because two scans with different coverage are not two readings of the same thing.
- **Settings view** — coverage and what it costs, the allowlist in summary, where the data
  lives, and what the tool does not claim.

### Fixed

- **Every card was pushed off-screen by the first scan after a coverage change.** The
  "since your last scan" list was an uncapped `ItemsControl` in an `Auto`-height row; a diff
  spanning an elevation change produces about a hundred rows and drove the findings card to
  y=2483 in a 1080 px window, with no scrollbar to reach it. The list is now capped and
  scrollable, and its total is stated in the header.
- Print monitors and netsh helpers stored bare DLL names that never reached path resolution.
- Startup-folder entries verified the `.lnk` instead of its target, so every Startup item on
  every machine reported as unsigned.
- `Card` and `SectionTitle` styles moved to application scope. At window scope the navigation
  pages could not see them at all — the same class of bug as the black-on-black text fixed on
  2026-08-02, for a second reason.

### Deployment

- **The project is public at `github.com/Believeinus/RAVEN`** — README and artwork only. No
  source code has been pushed and no remote is configured on the local repository.
- Branding generated from the master logo rather than shipping it: a 1280×640 social banner
  and a 480² mark. The README carries what the tool examines, how it decides, the privacy
  position and a short FAQ; the repository carries fourteen topics.
- Screenshots in the README are of the **empty state, deliberately**. A populated scan would
  publish which remote-access software is installed on the machine it ran on, the machine
  name and the user's home path — the same telemetry the tool warns about before writing an
  export.

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

### Fixed

- **Finding titles rendered black on a black card and were effectively unreadable** —
  the "<tool> is running" headlines, the scan-integrity signal names and the blind-spot
  headings.
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
- A correctly-signed VNC-family server was reported as an impostor at Critical severity
  because the catalogue held a stale publisher string. Impersonation is now claimed only when
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

### Out of scope for v1

- MFT-level file-hiding detection, memory scanning for injected code, a kernel-mode
  self-defense component, network-level capture from a second device, and non-Windows
  collectors.
