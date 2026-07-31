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

### Fixed

- PID probe reported ~327 phantom hidden processes on a clean machine. Two causes:
  reading a last-error value clobbered by CsWin32's `OpenProcess_SafeHandle` wrapper,
  and counting zombie process objects (exited, but still openable while a handle
  remains). Successful `OpenProcess` is not proof of life; a zero-timeout
  `WaitForSingleObject` is now the discriminator.
- PID probe then under-reported after that fix, because `WaitForSingleObject` needs
  `SYNCHRONIZE`, which `PROCESS_QUERY_LIMITED_INFORMATION` does not grant.

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
