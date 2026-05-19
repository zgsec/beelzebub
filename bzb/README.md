# bzb — honeynet persona deployment CLI

Operator surface for deploying and rotating honeynet persona bundles.
Reads a persona bundle (directory of YAML), renders deployable artifacts,
ssh-pushes to a sensor host, and runs `docker compose up`.

See: `~/projects/beelzebub/docs/superpowers/specs/2026-05-05-honeynet-persona-system-design.md`
(currently lives at `~/projects/honeypot-research/docs/superpowers/specs/...`
during implementation; will move once handoff complete).

## Status

Phase A skeleton. Subcommands not yet wired — see plan tasks A6 onward.

## Install

    cd ~/projects/beelzebub
    python3 -m venv .venv && source .venv/bin/activate
    cd bzb && pip install -e .
    bzb --help
