"""Assemble a /configurations staging tree for beelzebub from a rendered persona.

Usage:
    python tools/stage_persona_configs.py \\
        --render-out /tmp/render-crestfield/crestfield-data-systems/placeholder \\
        --configs-src configurations \\
        --staged /tmp/staged-configs

Produces /tmp/staged-configs/ with:
  beelzebub.yaml            (from configs-src/)
  node.yaml                 (from render-out/persona/node.yaml)
  persona/
    persona.yaml            (from render-out/persona/persona.yaml)
    canaries.yaml           (from render-out/persona/canaries.yaml)
  services/
    # persona-bearing lures — every *.yaml under render-out/persona/lures/
    # is treated as a Jinja-rendered lure and copied here. Filenames are
    # discovered at stage time, so any persona's lure set works (Crestfield's
    # 4 lures, BlueSpark's 5, etc.).
    # non-persona service configs — copied unchanged from configs-src/services/,
    # SKIPPING any filename that already came from a rendered persona lure.

Beelzebub startup with the staged tree uses PERSONA_DIR to find persona.yaml:
    /main -confCore /configurations/beelzebub.yaml \\
          -confServices /configurations/services/
    PERSONA_DIR=/configurations/persona

persona.yaml is then read from /configurations/persona/persona.yaml.
node.yaml is read from /configurations/node.yaml (hardcoded in shellemulator).

NOTE: persona.yaml and canaries.yaml are in persona/ (not services/) so that
beelzebub's service config loader doesn't try to parse them as honeypot services.
"""
from __future__ import annotations

import argparse
import shutil
from pathlib import Path


def _discover_persona_lures(lures_dir: Path) -> list[Path]:
    """Return every *.yaml under render-out/persona/lures/ as a persona-bearing lure.

    PLACEHOLDER files (the bundle skeleton's marker file) are tolerated only
    when they don't have a .yaml extension; if a persona ever ships a yaml
    literally named PLACEHOLDER.yaml we still accept it (no path is hardcoded
    to a specific persona).
    """
    if not lures_dir.is_dir():
        return []
    return sorted(p for p in lures_dir.glob("*.yaml") if p.is_file())


def stage(render_out: Path, configs_src: Path, staged: Path) -> None:
    """Assemble the staged /configurations directory."""
    if staged.exists():
        shutil.rmtree(staged)
    staged.mkdir(parents=True)

    persona_src_dir = render_out / "persona"

    # beelzebub.yaml → /configurations/beelzebub.yaml
    shutil.copy2(configs_src / "beelzebub.yaml", staged / "beelzebub.yaml")

    # node.yaml → /configurations/node.yaml (shellemulator hardcodes this path)
    shutil.copy2(persona_src_dir / "node.yaml", staged / "node.yaml")

    # persona/ directory — PERSONA_DIR points here at runtime
    # Kept separate from services/ so persona.yaml is NOT parsed as a service config.
    persona_out = staged / "persona"
    persona_out.mkdir()
    shutil.copy2(persona_src_dir / "persona.yaml", persona_out / "persona.yaml")
    canaries_src = persona_src_dir / "canaries.yaml"
    if canaries_src.exists():
        shutil.copy2(canaries_src, persona_out / "canaries.yaml")

    # services/ directory — only valid beelzebub service configs go here
    services = staged / "services"
    services.mkdir()

    # Rendered persona-bearing lures → /configurations/services/.
    # Discover by globbing the rendered lures dir so any persona's lure set
    # works without code changes (Crestfield: 4, BlueSpark: 5, etc.).
    lures_dir = persona_src_dir / "lures"
    persona_lure_names: set[str] = set()
    for lure_path in _discover_persona_lures(lures_dir):
        shutil.copy2(lure_path, services / lure_path.name)
        persona_lure_names.add(lure_path.name)

    if not persona_lure_names:
        raise FileNotFoundError(
            f"No rendered lures found in {lures_dir}.\n"
            f"Run `bzb persona render` first, or check that the persona's "
            f"node.yaml lists at least one lure under `lures:`."
        )

    # Non-persona service configs → /configurations/services/.
    # Skip any filename already copied from the persona's rendered lures.
    src_services = configs_src / "services"
    for yaml_file in src_services.glob("*.yaml"):
        if yaml_file.name not in persona_lure_names:
            shutil.copy2(yaml_file, services / yaml_file.name)

    print(f"Staged configuration tree at: {staged}")
    print(f"  node.yaml:        {staged / 'node.yaml'}")
    print(f"  persona/:         {persona_out}")
    print(f"    persona.yaml")
    print(f"  services/:        {services}")
    for f in sorted(services.iterdir()):
        marker = "  (persona lure)" if f.name in persona_lure_names else ""
        print(f"    {f.name}{marker}")


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Stage a rendered persona bundle into a beelzebub /configurations tree."
    )
    ap.add_argument(
        "--render-out",
        required=True,
        help="Path to the rendered node dir (e.g. /tmp/render-crestfield/crestfield-data-systems/placeholder)",
    )
    ap.add_argument(
        "--configs-src",
        default="configurations",
        help="Path to the source configurations directory (default: ./configurations)",
    )
    ap.add_argument(
        "--staged",
        required=True,
        help="Output staging directory (will be created or overwritten)",
    )
    args = ap.parse_args()

    stage(
        render_out=Path(args.render_out).resolve(),
        configs_src=Path(args.configs_src).resolve(),
        staged=Path(args.staged).resolve(),
    )


if __name__ == "__main__":
    main()
