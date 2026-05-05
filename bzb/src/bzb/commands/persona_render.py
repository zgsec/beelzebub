"""bzb persona render — emit deployable artifact tree."""
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
def persona_render(slug: str, node_id: str, persona_root: str, out: str,
                   image_org: str, image_tag: str, aggregator_url: str,
                   aggregator_token: str, sensor_id: str):
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
