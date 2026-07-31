# docs/

Index of project documentation for **RatScan**.

| File | Committed | Purpose |
|---|---|---|
| `README.md` | ✅ | This index + the context routines |
| `CHANGELOG.md` | ✅ | Terse, release-facing "what changed" |
| `BUILD-LOG.md` | ❌ local-only | The story: narrative timeline, walls hit and how they were solved, decisions, deferred ideas |
| `RATSCAN-PROGRESS.md` | ❌ local-only | Checkpoint for the in-flight v1 build (phases 0–11) |

Only `CLAUDE.md`, `AGENTS.md`, and `README.md` live at the repo root. Everything
else documentation-shaped belongs here.

---

## The context routines

### `update context`

Append, newest-first. **Never overwrite history.**

1. `BUILD-LOG.md` — new dated bullet at the **top** of the Progress log: what was
   done, walls hit + fixes, decisions, what was deferred. Refresh the *Current state
   (snapshot)* block if the stack or deployment state changed.
2. `CHANGELOG.md` — add to or extend the current dated `[Unreleased]` section
   (Added / Changed / Fixed / Security / Database / Deployment / Deferred).
3. `RATSCAN-PROGRESS.md` — update the status header and phase table.
4. Auto-memory — update `MEMORY.md` plus the relevant memory file(s).

### `absorb context`

The read-only mirror, run at session start. Changes nothing.

Read memory (`MEMORY.md` + active/recent memory files) → `BUILD-LOG.md` (snapshot +
newest few entries) → `CHANGELOG.md` (`[Unreleased]` + latest release) →
`RATSCAN-PROGRESS.md` → `git log --oneline -15` + `git status --short` to reconcile
the docs against the real repo tip and any uncommitted work.

Finish with: production/deploy status, stack, last ~3 sessions, and a numbered
**open items** list — then ask what to work on.
