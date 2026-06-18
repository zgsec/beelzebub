# bzb — honeynet persona deployment CLI

Operator surface for deploying and rotating honeynet persona bundles.
Reads a persona bundle (directory of YAML), renders deployable artifacts,
ssh-pushes to a sensor host, and runs `docker compose up`.

See the honeynet persona-system design doc under this repo's `docs/`.

## Status

Phase A skeleton. Subcommands not yet wired — see plan tasks A6 onward.

## Install

    cd ~/projects/beelzebub
    python3 -m venv .venv && source .venv/bin/activate
    cd bzb && pip install -e .
    bzb --help
