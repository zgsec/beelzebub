"""bzb deploy — render + rsync + ssh docker-compose up + poll attestation."""
import subprocess
import time
from pathlib import Path

import click

from bzb.models.bundle import load_bundle
from bzb.render.renderer import render_node


@click.command("deploy")
@click.argument("slug")
@click.argument("node_id")
@click.option("--target", required=True, help="ssh host or user@host")
@click.option("--persona-root", default="personas")
@click.option("--out", default="out")
@click.option("--remote-path", default="/opt/honeypot-sensor")
@click.option("--image-org", default="honeypot")
@click.option("--image-tag", default="v0.1.0")
@click.option("--aggregator-url", envvar="AGGREGATOR_URL", default="")
@click.option("--aggregator-token", envvar="AGGREGATOR_TOKEN", default="")
@click.option("--sensor-id", default="")
@click.option("--dry-run", is_flag=True, help="render only; no rsync/ssh")
@click.option("--poll-timeout", type=int, default=60,
              help="Seconds to wait for healthy attestation; 0 disables polling")
def deploy(slug, node_id, target, persona_root, out, remote_path,
           image_org, image_tag, aggregator_url, aggregator_token,
           sensor_id, dry_run, poll_timeout):
    """Render persona node → rsync to target → docker compose up → poll healthy."""
    bundle = load_bundle(Path(persona_root) / slug)
    out_path = render_node(
        bundle, node_id, Path(out),
        image_org=image_org, image_tag=image_tag,
        aggregator_url=aggregator_url, aggregator_token=aggregator_token,
        sensor_id=sensor_id or node_id,
    )
    sha = (out_path / "config_sha256").read_text().strip()
    click.echo(f"rendered {out_path}/  config_sha256={sha[:12]}...")

    if dry_run:
        click.echo("--dry-run; skipping rsync + compose up")
        return

    rsync_cmd = ["rsync", "-az", "--delete",
                 f"{out_path}/", f"{target}:{remote_path}/"]
    click.echo(f"rsync → {target}:{remote_path}/")
    r = subprocess.run(rsync_cmd, capture_output=True, text=True)
    if r.returncode != 0:
        click.echo(f"rsync failed: {r.stderr}", err=True)
        raise SystemExit(1)

    ssh_cmd = ["ssh", target,
               f"cd {remote_path} && docker compose up -d --remove-orphans"]
    click.echo("ssh → docker compose up")
    r = subprocess.run(ssh_cmd, capture_output=True, text=True)
    if r.returncode != 0:
        click.echo(f"compose up failed: {r.stderr}", err=True)
        raise SystemExit(1)

    if not aggregator_url or poll_timeout == 0:
        click.echo("OK (no aggregator URL set or poll disabled; skipping attestation poll)")
        return

    # Poll /api/sensors/info until liveness_status=healthy
    import requests
    target_id = sensor_id or node_id
    click.echo(f"polling attestation for {target_id}...")
    deadline = time.time() + poll_timeout
    while time.time() < deadline:
        try:
            resp = requests.get(f"{aggregator_url}/api/sensors/info", timeout=5)
            if resp.ok:
                sensors = resp.json().get("sensors", [])
                me = next((s for s in sensors if s.get("sensor_id") == target_id), None)
                if me and me.get("liveness_status") == "healthy":
                    click.echo(f"OK: {target_id} is healthy")
                    return
        except requests.RequestException:
            pass
        time.sleep(5)
    click.echo(f"WARN: attestation not confirmed in {poll_timeout}s", err=True)
    raise SystemExit(1)
