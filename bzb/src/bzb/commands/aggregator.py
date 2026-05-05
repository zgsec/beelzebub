"""bzb aggregator {deploy, dump} — cross-repo aggregator-side operations."""
import subprocess
import sys

import click


@click.command("deploy")
@click.argument("target", metavar="HOST")
@click.option("--with-public-api", is_flag=True,
              help="Also deploy api/public.py + nginx (operator's display layer)")
@click.option("--setup-script",
              default="~/projects/honeypot-research/ops/setup-aggregator.sh",
              help="Path to setup-aggregator.sh on target or local path to copy")
def deploy(target, with_public_api, setup_script):
    """Bring up FastAPI ingest + canary webhook + Postgres on aggregator host.

    For MVP this shells over ssh to run the setup-aggregator.sh script at the
    target. The script lives in the honeypot-research repo. Operator must
    pre-stage the script on the target or use --setup-script to point at a
    local copy.
    """
    flag = "--with-public-api" if with_public_api else ""
    cmd = ["ssh", target,
           f"bash {setup_script} {flag}".strip()]
    click.echo(f"ssh → bash {setup_script} {flag}".rstrip())
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        click.echo(f"setup failed: {r.stderr}", err=True)
        raise SystemExit(1)
    click.echo(f"OK: aggregator deployed on {target}")


@click.command("dump")
@click.option("--db-dsn", envvar="DATABASE_URL", required=True,
              help="Postgres DSN (or env DATABASE_URL)")
@click.option("--since", default="",
              help="Optional: trim sessions to last N units, e.g. 7d (informational; no-op in MVP)")
def dump(db_dsn, since):
    """pg_dump shortcut — outputs gzipped dump on stdout for analysis handoff."""
    if since:
        click.echo(f"# --since={since} is informational only in MVP "
                   f"(pg_dump dumps everything; trim post-hoc with psql)",
                   err=True)
    cmd = ["pg_dump", "--no-owner", "--no-privileges", db_dsn]
    r = subprocess.run(cmd, stdout=sys.stdout.buffer, stderr=subprocess.PIPE)
    if r.returncode != 0:
        click.echo(f"pg_dump failed: {r.stderr.decode(errors='replace')}", err=True)
        raise SystemExit(1)
