"""bzb persona render — emit deployable artifact tree.

Renders personas/<slug>/<node_id> into out/<slug>/<node_id>/. Hard-gates
on tools/lure_lint.py CRITICAL findings against the rendered output —
deception fingerprint regressions block deployment. Use --skip-lint for
emergencies (document why in a journal entry).
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import click

from bzb.models.bundle import load_bundle
from bzb.render.renderer import render_node


@click.command("render")
@click.argument("slug")
@click.argument("node_id")
@click.option("--persona-root", default="personas",
              help="Parent directory of personas/<slug>/")
@click.option("--out", default="out", help="Output root directory")
@click.option("--image-org", default="honeypot",
              help="GHCR org for beelzebub-fork + exporter images")
@click.option("--image-tag", default="v0.1.0", help="Image tag")
@click.option("--aggregator-url", envvar="AGGREGATOR_URL", default="",
              help="Aggregator URL (or env AGGREGATOR_URL)")
@click.option("--aggregator-token", envvar="AGGREGATOR_TOKEN", default="",
              help="Aggregator bearer token (or env AGGREGATOR_TOKEN)")
@click.option("--sensor-id", default="",
              help="SENSOR_ID for the rendered .env (default: node_id)")
@click.option("--skip-lint", is_flag=True, default=False,
              help="Bypass lure_lint deception-leak gate. Emergency use only — "
                   "document the bypass in a vault journal entry.")
def persona_render(slug: str, node_id: str, persona_root: str, out: str,
                   image_org: str, image_tag: str, aggregator_url: str,
                   aggregator_token: str, sensor_id: str, skip_lint: bool):
    """Render personas/<slug>/<node_id> into out/<slug>/<node_id>/."""
    bundle = load_bundle(Path(persona_root) / slug)
    out_path = render_node(
        bundle, node_id, Path(out),
        image_org=image_org, image_tag=image_tag,
        aggregator_url=aggregator_url, aggregator_token=aggregator_token,
        sensor_id=sensor_id,
    )
    sha = (out_path / "config_sha256").read_text().strip()
    click.echo(f"rendered {out_path}/  (config_sha256={sha[:12]}...)")

    if skip_lint:
        click.secho(
            "  WARNING: --skip-lint bypassed deception-leak checks. "
            "Document why in ~/vault/intel/journal/",
            fg="yellow",
        )
        return

    # Locate tools/lure_lint.py — typically alongside the bzb checkout.
    repo_root = _find_repo_root()
    linter = repo_root / "tools" / "lure_lint.py"
    if not linter.is_file():
        click.secho(
            f"  WARNING: lure_lint.py not found at {linter} — skipping gate. "
            "If this is a fresh checkout, ensure tools/lure_lint.py is present.",
            fg="yellow",
        )
        return

    click.echo(f"  lure_lint: scanning rendered tree {out_path}...")
    persona_dir = out_path / "persona"
    targets = [persona_dir / "lures"]
    targets = [t for t in targets if t.exists()]
    if not targets:
        click.secho(
            "  WARNING: no rendered lures dir found under "
            f"{persona_dir}; skipping lint.",
            fg="yellow",
        )
        return

    cmd = [sys.executable, str(linter), "--summary"] + [str(t) for t in targets]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    output = (proc.stdout or "") + (proc.stderr or "")
    click.echo(output, nl=False)

    if proc.returncode != 0:
        click.secho(
            f"\n  lure_lint failed (exit {proc.returncode}). Render output kept at "
            f"{out_path} for inspection but should NOT be deployed. "
            "Fix the violations or re-run with --skip-lint (and journal why).",
            fg="red",
        )
        sys.exit(proc.returncode)
    click.secho("  lure_lint: clean (no CRITICAL violations)", fg="green")


def _find_repo_root() -> Path:
    """Walk up from this file until we find a `tools/lure_lint.py`."""
    here = Path(__file__).resolve()
    for parent in [here, *here.parents]:
        candidate = parent / "tools" / "lure_lint.py"
        if candidate.is_file():
            return parent
    # Fallback: assume current working dir is repo root.
    return Path.cwd()
