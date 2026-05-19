"""bzb status — tabular sensor liveness across one persona or all."""
import click
import requests


@click.command("status")
@click.argument("slug", required=False)
@click.option("--aggregator-url", envvar="AGGREGATOR_URL", required=True)
@click.option("--attest", is_flag=True, help="include latest attestation row")
def status(slug, aggregator_url, attest):
    """Tabular sensor liveness."""
    r = requests.get(f"{aggregator_url}/api/sensors/info", timeout=10)
    r.raise_for_status()
    sensors = r.json().get("sensors", [])
    if slug:
        sensors = [s for s in sensors if s.get("persona_slug") == slug]

    click.echo(f"{'sensor_id':<24} {'persona':<28} {'liveness':<22} {'last_seen':<25}")
    click.echo("-" * 100)
    for s in sensors:
        click.echo(
            f"{s.get('sensor_id', ''):<24} "
            f"{s.get('persona_slug', ''):<28} "
            f"{s.get('liveness_status', ''):<22} "
            f"{s.get('last_session_first_seen') or '<none>':<25}"
        )
    if attest:
        click.echo("\nLatest attestations:")
        for s in sensors:
            raw_digest = s.get("last_image_digest") or ""
            # Strip "sha256:" prefix before truncating so output matches hash chars
            digest = raw_digest.removeprefix("sha256:")[:12]
            click.echo(
                f"  {s.get('sensor_id', '')}: "
                f"status={s.get('last_attestation_status') or '<none>'} "
                f"sha={digest or '<none>'}"
            )
