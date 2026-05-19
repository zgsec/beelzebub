"""bzb persona validate — Layer 1+2 schema + coherence check."""
from pathlib import Path

import click

from bzb.models.bundle import load_bundle


@click.command("validate")
@click.argument("slug")
@click.option("--persona-root", default="personas")
def persona_validate(slug: str, persona_root: str):
    """Validate persona schema + cross-references. Exits non-zero on any error."""
    try:
        bundle = load_bundle(Path(persona_root) / slug)
    except Exception as e:
        click.echo(f"INVALID: {type(e).__name__}: {e}", err=True)
        raise SystemExit(1)
    click.echo(f"OK: {bundle.persona.slug} ({len(bundle.nodes)} nodes, "
               f"{len(bundle.canaries.slots)} canary slots)")
