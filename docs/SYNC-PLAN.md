# SYNC-PLAN.md — upstream resync & fork-maintenance plan

Companion to [`UPSTREAM.md`](../UPSTREAM.md). `UPSTREAM.md` deferred the
"sync-or-not" decision to a focused session "so that decision starts from facts,
not archaeology." This document **is** those facts: a full file-by-file
divergence audit of the fork against upstream `main`, turned into an executable
stay / go / update plan.

**Posture:** we are a **tracking fork**, not a hard fork — the tree is
overwhelmingly a *superset* of upstream (and ahead of it in several subsystems),
config-compatible, and cleanly layered. The plan is therefore a **bounded,
one-shot resync onto upstream's current structure**, not perpetual drift.

> Scope note: this plan touches two code repos — this one and the Go log
> collector that consumes this honeypot's JSON output. The collector is affected
> only through the JSON event contract (see §6), not through Go imports.

---

## 1. Divergence at a glance

Measured against upstream `main` (upstream has restructured: packages under
`internal/`, a new cobra `cli/`, a `pkg/plugin` registry, thin root `main.go`).

| Bucket | Count | Meaning |
|---|---|---|
| Overlapping files | 27 | Exist both sides. 20 diverge heavily — almost all intentional fork value-add on a drifted base. |
| Upstream-only | 39 | We lack these: a config-validation framework, the `cli/` tree, `pkg/plugin`, new LLM/maze plugins. |
| Fork-only | 65 | Our research stack — agent detection, bridge, MCP world-model, fingerprinting, novelty, faults, etc. |

**Two findings that shrink the risk:**

- **Dependency/toolchain jump is a non-event.** Verified against both real
  module trees: every `mcp-go` call site is signature-identical 0.44→0.55, the
  `invopop/jsonschema` → `google/jsonschema-go` swap falls out of `go mod tidy`
  for free, and the only forced change is a one-line `go 1.25` directive bump.
  **(Landed — see Phase 1.)**
- **The structural move is mechanical.** 39 files / 124 import lines, one
  relative `go:embed` that rides along with its package, zero CI/Docker/Makefile
  edits, no external importers. A gated afternoon in isolation; the only real
  hazard is open branches/worktrees (§6).

---

## 2. STAY / GO / UPDATE

### 🟢 STAY — keep as-is, fork-retained (no upstream action)

- All fork-only packages: agent detection, cross-protocol bridge, novelty
  scoring, fault injection, artifact store, TTL cache, lifecycle cleaner, the
  MCP world-model (`state.go`), the SSH shell emulator, the MySQL handshake,
  response substitution, the OLLAMA strategy, persona loading.
- Protocol handlers (HTTP/SSH/TCP/TELNET) and MCP `mcp.go` — supersets of
  upstream; upstream added nothing here we lack.
- `tracer/tracer.go` + fingerprint files — additive superset, **no upstream
  schema conflict**. Guards the collector's JSON contract (§6).
- `historystore/history_store.go` — **already carries the cleaner
  goroutine/ticker leak fix independently** (marginally safer than upstream's).
  The corresponding upstream reconcile item is therefore closed.
- `plugins/llm-integration.go` (superset: output sanitization, call timeout,
  bounded LRU+TTL rate limiter), `response_sanitize`, tracer JA4H/HASSH/TeeConn.
  These are **fork-retained and not being offered upstream at this time.**
- TCP raw-byte preservation — ours is ahead of and compatible with upstream's.

### 🔴 GO — retire / do not adopt

- Old module path + flat layout → replaced by upstream's module path + `internal/`.
- `invopop/jsonschema`, the `go 1.24` directive → dropped by the dep bump.
- Upstream `pkg/plugin` registry, the `maze` plugin, the LLM adapter/bridge
  registry glue, and `cli/plugin.go` → **out of scope** (large rewire / low
  research value for this fork).
- The redundant local TCP raw-bytes branch (ours already supersedes it).
- Stale build artifacts must never be committed (ensure gitignored).

### 🟡 UPDATE — reconcile / adopt / fix

| Item | Type | Notes |
|---|---|---|
| `parser/configurations_parser.go` | Reconcile (hard) | Union struct + load loop. Fold in upstream's validation-mode split, trusted-proxies, per-file `Filename`, env-JSON source, core env-overrides + missing-file fallback. **Preserve** our env-var substitution + missing-var warnings (OPSEC-critical) and the large fork field surface. |
| `builder/builder.go` | Fix + Reconcile | Empty-`logsPath` boot crash **fixed (Phase 2)**. Still to do: consciously confirm the dropped background service-plugin lifecycle is intentional (bridge supersedes it) and not a silent capability loss. |
| `plugins/beelzebub-cloud.go` | Reconcile | Adopt upstream's cancelable `Stop()` + config-change hash (we are behind here) under our added telemetry fields. |
| Config-validation framework | Adopt | Adopt the engine (`parser/validator.go` + `validator_shared.go` + per-protocol validators) **as a `-validate` flag — no cobra**. Write a new OLLAMA validator (we have a protocol upstream lacks). Runs on demand, not at boot. |
| `go.mod` deps | Update | **Done (Phase 1).** |
| Module path + `internal/` move | Update (mechanical) | **Gated (Phase 3).** |
| `tracer.ProtocolFromString`, parser core env-overrides | Adopt | Trivial pull-ins on rebase. |
| Upstream tests | Adopt | SSH + director tests (import edits only); TCP raw-bytes test (needs 2 helpers); TELNET test (drop 2 tests for a handshake helper we replaced). Validator tests ride in with the framework. |
| Docs | Update | Refresh `UPSTREAM.md` (close the cleaner-leak item, mark contribute-back deferred, note the upstream restructure) and the README module-path narrative. |

---

## 3. Phased execution

**Phase 0 — Prep.** Commit/stash working-tree WIP; ensure the OLLAMA
`modelmeta/*.json` are tracked before any package move (the embed is relative);
quarantine in-progress test files that reference not-yet-written symbols.
Baseline must be green.

**Phase 1 — Dependency resync. ✅ DONE.** `mcp-go` 0.44.1→0.55.1, `go`→1.25.9,
`go mod tidy` (invopop dropped). Independent and verified; `go build ./...` and
the unit suite pass.

**Phase 2 — Empty-`logsPath` boot fix. ✅ DONE.** A core config without a logs
path aborted boot with `open : no such file or directory`; now falls back to
stdout. Directly de-risks fresh sensor stand-ups (§4). Test-first, regression
test added.

**Phase 3 — Structural flip. ⛔ GATED** on sign-off (§7) **and** a low
branch/worktree window (§6). Order, each behind a `build` + `vet` + `test` gate:
1. `go mod edit -module <upstream module path>`; rewrite import strings; gate.
2. `git mv` the 12 fork packages under `internal/`; rewrite moved-package import
   paths; gate (`gofmt -l` clean, full suite green).
3. Cosmetic doc/attribution follow-up as a separate commit.

**Phase 4 — Reconciles (the real work).** `configurations_parser.go`, then the
`builder.go` service-plugin confirmation, then `beelzebub-cloud.go` — each behind
the full suite, each preserving fork behavior.

**Phase 5 — Validator + tests.** Adopt the framework as `-validate`, add the
OLLAMA validator, pull the adoptable upstream tests.

**Phase 6 — Docs.** Refresh `UPSTREAM.md` / README.

---

## 4. Onboarding & code-clarity workstream (cross-repo)

Standing up the fork on a **new sensor** must be *simple and legible* — a
collaborator should be able to bring a region online without reverse-engineering
the tree. This spans both repos and is partly outside this repo's control.

**Principles**

- **Safe defaults.** A minimal/partial config must never crash on boot. The
  empty-`logsPath` fix (Phase 2) is the first instance; audit other required
  fields for the same class of "missing value → hard error" and prefer
  fall-backs with a clear log line over aborts.
- **One documented stand-up path.** There should be a single, followable
  onboarding checklist: which per-region config overlay to copy, which
  environment values must be present (canary tokens and credential-shaped
  values are env-injected at deploy — never committed), the bootstrap script to
  run, and how the collector is pointed at the new source. Today the per-region
  overlays exist but there is **no onboarding README** beside them — add one.
- **Reduce config duplication.** Per-region overlays should differ only by what
  is genuinely region-specific; shared persona/handler settings should live in
  one place so a new region is a small, obvious delta, not a 36 KB copy to
  hand-edit. Keep both SSH configs in sync (existing rule).
- **Legible field contract for the collector.** The collector consumes
  fork-only JSON fields (agent score, MCP tools used, correlation id, and the
  fingerprint fields). Keep that field set documented and stable so onboarding a
  sensor doesn't require reading Go to know what the collector will receive
  (§6). This is the honeypot-side half; the collector-side half lives in that
  repo.

**Action items**

- [ ] Add `configurations/prod-configs/README` (or equivalent): the new-sensor
      checklist, required env vars, and the render/bootstrap step.
- [ ] Audit config-required fields for boot-crash-on-missing; add safe
      fallbacks + warnings (Phase 2 pattern).
- [ ] Factor shared vs. region-specific config so a new overlay is a minimal delta.
- [ ] Cross-repo: confirm the collector's expected fork-field set is documented
      and matches `tracer.Event` (see §6 guardrail).

---

## 5. Dependency & toolchain notes

- `mcp-go` 0.44.1 → **0.55.1**: no API breakage; all strategy call sites
  signature-identical (verified against both module versions).
- `invopop/jsonschema` **removed** (was an indirect dep of old `mcp-go`); replaced
  by `google/jsonschema-go` + `santhosh-tekuri/jsonschema` transitively. No
  direct imports in the fork, so zero code impact.
- `go` directive → **1.25.9** (mcp-go 0.55 requires ≥1.25.5); toolchain pin
  removed. No 1.25-only language/stdlib features are used.
- cobra/pflag are only pulled in if the `cli/` tree is adopted — **not planned**
  (§7).
- Other bumps (amqp091, goph, x/term) are backward-compatible and touch no fork code.

---

## 6. Risks & guardrails

- **⚠ Open branches are the real hazard, not the code.** Active worktrees and any
  open PRs must each cross the *same* module-rename + directory-move, where git's
  rename detection is weakest. **Schedule Phase 3 when branch fan-out is lowest**;
  drain or re-anchor worktrees first.
- **Documented-stance reversal.** The README/`UPSTREAM.md` currently state the
  module path is *deliberately* kept as upstream's. Phase 3 reverses that — it
  needs a conscious decision, not a mechanical edit (§7).
- **Downstream JSON contract.** The collector reads `tracer.Event`, not our Go
  packages, so `internal/` is safe for it — **but** the `configurations_parser` /
  tracer reconcile must not drop any fork event field. **Guardrail:** diff the
  `tracer.Event` field set before/after Phase 4.
- **Deploy-window discipline.** Do not merge structural changes to the default
  branch during an active sensor stand-up. Phases 1–2 are committed to an
  isolated, unpushed branch precisely so they stay clear of live deploys.
- **OPSEC.** The rename blends the fork with upstream (net positive); the large
  mechanical diff carries no infra identifiers. Keep it that way — this doc and
  all resync commits stay free of internal hostnames, addresses, and paths.

---

## 7. Open decisions

1. **Structural flip — go / no-go?** Reverses the documented module-path stance.
   Everything mechanical in Phase 3 hinges on this.
2. **CLI —** adopt upstream's cobra `cli/` (clean, but a small persona graft into
   `run`), or keep the flag-based entrypoint and hand-roll a `-validate` flag?
   *Current lean: keep flag-based — smaller surface, preserves our entrypoint.*
3. **`builder.go` service-plugin lifecycle —** was dropping upstream's
   background service-plugin start/stop intentional (bridge replaces it), or an
   accidental capability loss to restore?

---

## Appendix — provenance

Classification derived from a full two-pass divergence audit (per-file
normalized diffs of every overlapping file, plus dependency/toolchain and
blast-radius deep-dives) against upstream `main`. Module-path differences were
normalized out so they did not mask real drift.
