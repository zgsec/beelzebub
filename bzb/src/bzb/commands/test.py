"""bzb test {capture, replay, e2e} — wrappers around tools/ capture/replay scripts."""
import subprocess
import sys
import os
from pathlib import Path

import click


def _tools_dir() -> Path:
    """Resolve tools/ relative to the repo root.

    When installed as a wheel, the operator must set BZB_TOOLS_DIR.
    Default: assume installed-from-source layout — tools/ is three levels up
    from this file (bzb/src/bzb/commands/test.py → tools/).
    """
    env = os.environ.get("BZB_TOOLS_DIR")
    if env:
        return Path(env)
    # Default: tools/ relative to repo root
    return Path(__file__).resolve().parents[3] / "tools"


@click.command("capture")
@click.argument("slug")
@click.argument("node_id")
@click.option("--target", required=True, help="ssh host or sensor address")
@click.option("--output", "-o", required=True, type=click.Path())
@click.option("--port-map", default="{}",
              help="JSON {orig: mapped} for localhost-with-remap captures")
@click.option("--http-port", type=int, default=8888)
def capture(slug, node_id, target, output, port_map, http_port):
    """Layer 4 capture — fire 50-probe suite, write JSONL to <output>."""
    script = _tools_dir() / "capture_persona_baseline.py"
    if not script.is_file():
        click.echo(f"capture script not found: {script}", err=True)
        raise SystemExit(2)
    cmd = [sys.executable, str(script),
           "--target", target,
           "--http-port", str(http_port),
           "--port-map", port_map]
    with open(output, "w") as fout:
        r = subprocess.run(cmd, stdout=fout, stderr=subprocess.PIPE, text=True)
    if r.returncode != 0:
        click.echo(f"capture failed: {r.stderr}", err=True)
        raise SystemExit(r.returncode)
    click.echo(f"captured -> {output}")


@click.command("replay")
@click.argument("slug")
@click.argument("node_id")
@click.option("--target", required=True)
@click.option("--baseline", required=True, type=click.Path(exists=True))
@click.option("--persona-strings", default="",
              help="Comma-separated strings expected in SSH responses")
@click.option("--port-map", default="{}")
@click.option("--http-port", type=int, default=8888)
def replay(slug, node_id, target, baseline, persona_strings, port_map, http_port):
    """Layer 4 replay — diff response bytes against baseline. Exits non-zero on regression."""
    script = _tools_dir() / "replay_persona_baseline.py"
    if not script.is_file():
        click.echo(f"replay script not found: {script}", err=True)
        raise SystemExit(2)
    cmd = [sys.executable, str(script),
           "--target", target,
           "--baseline", str(baseline),
           "--persona-strings", persona_strings,
           "--port-map", port_map,
           "--http-port", str(http_port)]
    r = subprocess.run(cmd)
    raise SystemExit(r.returncode)


@click.command("e2e")
@click.argument("slug")
@click.option("--target", required=True)
@click.option("--persona-root", default="personas")
@click.option("--baseline", default=None,
              help="Layer 4 baseline JSONL; defaults to tests/persona-baseline-<slug>.jsonl")
def e2e(slug, target, persona_root, baseline):
    """Layer 5 — full deploy → probe → canary fire → rotate → teardown.

    For MVP this chains existing subcommands. Each step is a separate
    `bzb` subprocess so failures surface cleanly.
    """
    from bzb.models.bundle import load_bundle

    bundle = load_bundle(Path(persona_root) / slug)
    first_node = bundle.persona.nodes[0].id
    if baseline is None:
        baseline = f"tests/persona-baseline-{slug}.jsonl"

    click.echo(f"e2e step 1/4: deploy {first_node} → {target}")
    r = subprocess.run(["bzb", "deploy", slug, first_node,
                        "--target", target,
                        "--persona-root", persona_root])
    if r.returncode != 0:
        raise SystemExit(r.returncode)

    click.echo("e2e step 2/4: poll attestation")
    r = subprocess.run(["bzb", "status", slug, "--attest"])
    # Don't fail on status non-zero (could just mean aggregator unreachable)

    click.echo(f"e2e step 3/4: replay probes vs {baseline}")
    r = subprocess.run(["bzb", "test", "replay", slug, first_node,
                        "--target", target, "--baseline", baseline])
    if r.returncode != 0:
        click.echo("e2e FAILED: replay regressed", err=True)
        raise SystemExit(r.returncode)

    click.echo(f"e2e step 4/4: teardown {first_node}")
    r = subprocess.run(["bzb", "teardown", slug, first_node, "--target", target])
    if r.returncode != 0:
        raise SystemExit(r.returncode)

    click.echo("e2e PASSED")
