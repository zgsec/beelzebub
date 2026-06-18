# bzb — honeynet persona deployment CLI

Operator surface for building, validating, deploying, and rotating honeynet
**persona bundles** — the per-deployment identity (services, lures, canaries,
narrative) a sensor wears.

A persona bundle is a directory under `personas/<slug>/`:

```
personas/<slug>/
  persona.yaml        # identity: org, hostnames, service set
  canaries.yaml       # canary-token slots (placeholders, minted at deploy)
  narrative.md        # human-facing backstory for coherence review
  nodes/<node>.yaml   # per-node overrides (one node = one sensor)
  lures/*.yaml        # per-service lure configs (ssh, http, mcp, ollama, ...)
  templates/          # rendered files (e.g. etc-hosts.tmpl)
  corpora/            # seed data files referenced by lures
```

`bzb` reads a bundle, renders the deployable artifact tree (Beelzebub service
YAMLs + a compose file) for a chosen node, optionally lints it, ships it to a
target host over rsync/ssh, and brings it up with `docker compose`. It also
handles canary/persona rotation, sensor liveness status, and teardown.

## Status

Working CLI (`version 0.1.0`). All command groups below are wired and
functional. Not yet covered: `persona init --from` (forking an existing
persona) is reserved for a later phase and currently refused.

## Commands

```
bzb persona init <slug>              scaffold personas/<slug>/ from the template
bzb persona render <slug> <node>     render → out/<slug>/<node>/ (runs lure_lint)
bzb persona validate <slug>          schema + cross-reference check (non-zero on error)

bzb deploy <slug> <node> --target H  render → rsync → ssh docker compose up → poll
bzb status [<slug>] --aggregator-url tabular sensor liveness (optionally + attestation)
bzb teardown <slug> <node> --target  docker compose down + mark sunset

bzb rotate canary <slug> <slot>      mint/replace a canary token, redeploy consumers
bzb rotate persona <slug> <node> --to  sunset old persona on a node, deploy a new one

bzb aggregator dump --db-dsn DSN      pg_dump shortcut for analysis handoff
```

Run `bzb <group> --help` for full options. Many flags also read environment
variables (`AGGREGATOR_URL`, `AGGREGATOR_TOKEN`, `DATABASE_URL`).

## Install

From the repo root:

    python3 -m venv bzb/.venv && source bzb/.venv/bin/activate
    pip install -e bzb            # add '[dev]' for the test extras (pytest, paramiko)
    bzb --help

Requires Python >= 3.12. Deploy/teardown shell out to `rsync`, `ssh`, and
`docker compose` on the operator host and target; `aggregator dump` shells out
to `pg_dump`.
