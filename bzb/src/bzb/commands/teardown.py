"""bzb teardown — stop a node and mark sunset."""
import subprocess

import click


@click.command("teardown")
@click.argument("slug")
@click.argument("node_id")
@click.option("--target", required=True, help="ssh host or user@host")
@click.option("--remote-path", default="/opt/honeypot-sensor")
@click.option("--purge", is_flag=True,
              help="Also remove docker volumes (DESTROYS local sensor state)")
@click.option("--aggregator-url", envvar="AGGREGATOR_URL", default="")
def teardown(slug, node_id, target, remote_path, purge, aggregator_url):
    """Stop a node and mark sunset on the aggregator (default: keep PG history)."""
    purge_flag = " -v" if purge else ""
    ssh_cmd = ["ssh", target,
               f"cd {remote_path} && docker compose down{purge_flag}"]
    click.echo(f"ssh → docker compose down{purge_flag}")
    r = subprocess.run(ssh_cmd, capture_output=True, text=True)
    if r.returncode != 0:
        click.echo(f"compose down failed: {r.stderr}", err=True)
        raise SystemExit(1)

    if aggregator_url:
        import requests
        try:
            requests.post(
                f"{aggregator_url}/api/sensors/sunset",
                json={"sensor_id": node_id, "persona_slug": slug, "purged": purge},
                timeout=10,
            )
        except requests.RequestException as e:
            click.echo(f"WARN: sunset POST failed: {e}", err=True)
    click.echo(f"OK: {slug}/{node_id} torn down" + (" (volumes purged)" if purge else ""))
