"""bzb persona init — scaffold a new persona bundle."""
import shutil
from pathlib import Path

import click

# Templates live in the same package — resolves correctly under src-layout
# for both editable and wheel installs.
_SKELETON = Path(__file__).parent.parent / "templates" / "persona-skeleton"


@click.command("init")
@click.argument("slug")
@click.option(
    "--dest",
    default="personas",
    help="Parent directory; bundle will be created at <dest>/<slug>/",
)
@click.option(
    "--from",
    "from_existing",
    default=None,
    help="Fork from an existing persona slug (Phase 2 — not implemented in MVP).",
)
def persona_init(slug: str, dest: str, from_existing: str | None):
    """Scaffold personas/<slug>/ from the empty template."""
    if from_existing:
        click.echo("--from is reserved for Phase 2; not implemented in MVP.", err=True)
        raise SystemExit(2)

    out_root = Path(dest) / slug
    if out_root.exists():
        click.echo(f"refusing to overwrite: {out_root} already exists", err=True)
        raise SystemExit(1)

    shutil.copytree(_SKELETON, out_root)

    # Substitute REPLACE_ME (no space) and REPLACE ME (with space) with slug
    # in persona.yaml + canaries.yaml + narrative.md
    for relname in ("persona.yaml", "canaries.yaml", "narrative.md"):
        path = out_root / relname
        text = path.read_text()
        text = text.replace("REPLACE_ME", slug)
        text = text.replace("REPLACE ME", slug)
        path.write_text(text)

    click.echo(f"scaffolded {out_root}/  (edit persona.yaml + add nodes/)")
