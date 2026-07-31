# Changelog

All notable changes to RatScan are recorded here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased] — 2026-07-31

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
- `PersistenceCollector` sweeping seventeen auto-start surfaces: Run/RunOnce across
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

### Fixed

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
