# UPSTREAM.md — relationship to beelzebub-labs/beelzebub

This is a **research fork** of [beelzebub-labs/beelzebub](https://github.com/beelzebub-labs/beelzebub),
the low-code honeypot framework created by Mario Candela and now maintained under
the **Beelzebub Labs** org (the repo moved from `mariocandela/beelzebub`, which
still redirects). We are grateful for the upstream project — it's the foundation
everything here builds on — and we aim to be good citizens of it.

## Current state

- Forked around **`v3.6.5`**; `fork/main` is currently **~229 commits ahead** of
  upstream `main` and **~40 commits behind** it.
- Our additions are listed in the top of `README.md` / `CLAUDE.md` (agent
  detection, stateful MCP, cross-protocol bridge, fingerprint capture, fault
  injection, novelty scoring). They are designed to be **opt-in** and
  **backward-compatible** with upstream configs.

## Posture (as of 2026-07)

We have moved from "stabilize-now, decide-sync-later" to **actively tracking upstream**:

- We have **realigned to upstream's current structure** — module path
  `github.com/beelzebub-labs/beelzebub/v3` and packages under `internal/` — so
  rebases against upstream apply cleanly instead of needing a full path remap.
- The `origin` remote points at upstream and `fork` at our copy
  (`zgsec/beelzebub`), so a sync is always one fetch away. Upstream is now
  `beelzebub-labs/beelzebub`; if your `origin` still reads `mariocandela/...`
  (it redirects, but update it for clarity):
  `git remote set-url origin https://github.com/beelzebub-labs/beelzebub.git`
- We do **not** rewrite public history (no force-push). Hygiene happens forward.

## Why this matters now

We expect to **collaborate with Beelzebub directly**. That raises the bar on this
fork: it should read as a respectful, accurately-attributed extension of upstream,
not a private playground. Concretely:

- Keep commit messages and comments professional and free of internal infra
  identifiers (see the OPSEC hygiene pass, `chore(opsec)` commits).
- Frame our work as *additions to* a solid upstream, never as criticism of it.
- Keep our additions self-contained enough that the genuinely-general ones could
  be offered back as clean, standalone PRs.

## Upstream commits worth reconciling when we revisit sync

Most of upstream's lead is dependabot dependency bumps. The substantive ones:

| Upstream PR | What it is | Note for us |
|---|---|---|
| #320 | `feat(tcp)`: preserve raw client bytes in trace events | **Overlaps our `fix/tcp-preserve-raw-binary-bytes`** — reconcile (likely retire ours in favor of upstream's). |
| #300 | `feat`: `validate` flag to statically check config files | Useful; adopt rather than reinvent. |
| #306 | `fix`: prevent goroutine + ticker leak in `HistoryCleaner` | Check our `historystore/` for the same class of leak. |
| #323 | `feat`: `ServicePlugin` for background plugins at boot | May overlap our `plugins/` integration points. |
| #305 | `feat`: improve cloud plugin | Review for conflicts with our plugin changes. |

## Candidates to contribute upstream (potential, not committed)

To be proposed humbly and only where genuinely general-purpose — not the
research-specific or OPSEC-coupled pieces:

- Network-fingerprint capture in `tracer/` (JA4H wire-order, HASSH) — general
  honeypot value, independent of our research stack.
- The `TeeConn` raw-byte `net.Conn` wrapper pattern.

(Anything tied to our private sensor fleet, personas, or research pipeline stays
in the fork.)

## When we do sync

```sh
git fetch origin                 # upstream = beelzebub-labs/beelzebub
git log --oneline fork/main..origin/main   # review the delta first
# then a reviewed merge (NOT a blind one) onto a branch, resolve the overlaps above
```
