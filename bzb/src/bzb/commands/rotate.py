"""bzb rotate {canary, persona} — rotation primitives."""
import subprocess
from pathlib import Path

import click
import yaml

from bzb.models.bundle import load_bundle


@click.command("canary")
@click.argument("slug")
@click.argument("slot_name")
@click.option("--persona-root", default="personas")
@click.option("--token-id", default=None,
              help="Use this token_id directly (skip canarytokens.org mint)")
@click.option("--mint-script", default="tools/rotate_canaries.py",
              help="Path to the canarytokens minting script")
@click.option("--dry-run", is_flag=True)
def canary(slug, slot_name, persona_root, token_id, mint_script, dry_run):
    """Rotate a canary slot: mint or take token_id, mark active, redeploy consumers."""
    bundle_dir = Path(persona_root) / slug
    bundle = load_bundle(bundle_dir)
    if slot_name not in bundle.canaries.slots:
        click.echo(f"slot {slot_name!r} not in {slug}/canaries.yaml", err=True)
        raise SystemExit(1)
    slot = bundle.canaries.slots[slot_name]

    if token_id is None:
        click.echo(
            f"would mint canarytokens.org token for slot {slot_name} "
            f"(reminder: {slot.reminder})"
        )
        if dry_run:
            return
        result = subprocess.run(
            ["python", mint_script, "mint", "--reminder", slot.reminder],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            click.echo(f"mint failed: {result.stderr}", err=True)
            raise SystemExit(1)
        token_id = result.stdout.strip()

    canaries_path = bundle_dir / "canaries.yaml"
    raw = yaml.safe_load(canaries_path.read_text())
    raw["slots"][slot_name]["status"] = "active"
    raw["slots"][slot_name]["token_id"] = token_id
    if dry_run:
        click.echo(yaml.safe_dump(raw["slots"][slot_name], sort_keys=False))
        return
    canaries_path.write_text(yaml.safe_dump(raw, sort_keys=False))
    click.echo(f"updated {canaries_path} with new token_id")

    consumers = [nid for nid, n in bundle.nodes.items() if slot_name in n.canary_slots]
    click.echo(f"slot consumed by {len(consumers)} node(s): {consumers}")
    click.echo(f"OK: rotated {slot_name}, new token_id={token_id[:12]}...")


@click.command("persona")
@click.argument("slug")
@click.argument("node_id")
@click.option("--to", "to_slug", required=True)
@click.option("--persona-root", default="personas")
@click.option("--target", required=True, help="ssh host of the node")
@click.option("--aggregator-url", envvar="AGGREGATOR_URL", default="")
@click.option("--dry-run", is_flag=True)
def persona_cmd(slug, node_id, to_slug, persona_root, target, aggregator_url, dry_run):
    """Sunset old persona on this node; deploy new."""
    click.echo(f"sunset {slug}/{node_id} → deploy {to_slug}/{node_id} on {target}")
    if aggregator_url:
        click.echo(f"  (would POST sunset notice to {aggregator_url})")
    if dry_run:
        click.echo("--dry-run; skipping")
        return
    # Sunset the old persona's record (best-effort; endpoint may not exist yet)
    if aggregator_url:
        import requests
        try:
            requests.post(f"{aggregator_url}/api/sensors/sunset",
                         json={"sensor_id": node_id, "persona_slug": slug},
                         timeout=10)
        except requests.RequestException as e:
            click.echo(f"  WARN: sunset POST failed: {e}", err=True)
    # Deploy new persona
    result = subprocess.run(
        ["bzb", "deploy", to_slug, node_id, "--target", target,
         "--persona-root", persona_root],
        text=True,
    )
    if result.returncode != 0:
        raise SystemExit(result.returncode)
