"""bzb aggregator dump — cross-repo aggregator-side operations."""
import subprocess
import sys

import click


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
