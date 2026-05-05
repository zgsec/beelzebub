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
    # persona-bearing lures — Jinja-rendered, Crestfield/Globex content substituted:
    mcp-8000.yaml           (from render-out/persona/lures/)
    http-8888.yaml          (from render-out/persona/lures/)
    ollama-11434.yaml       (from render-out/persona/lures/)
    openai-8001.yaml        (from render-out/persona/lures/)
    # non-persona service configs — unchanged from configs-src/services/:
    influxdb-8086.yaml
    openclaw-18789.yaml
    screenconnect-8042.yaml
    ssh-2222.yaml
    ssh-22.yaml
    tcp-mysql-3306.yaml
    tcp-redis-6379.yaml

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

# Lure files that are persona-bearing (Jinja-rendered per persona bundle).
# All others are taken unchanged from configurations/services/.
PERSONA_LURES = {
    "mcp-8000.yaml",
    "http-8888.yaml",
    "ollama-11434.yaml",
    "openai-8001.yaml",
}


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

    # Rendered persona-bearing lures → /configurations/services/
    lures_dir = persona_src_dir / "lures"
    for lure_name in PERSONA_LURES:
        src = lures_dir / lure_name
        if src.exists():
            shutil.copy2(src, services / lure_name)
        else:
            raise FileNotFoundError(
                f"Rendered lure not found: {src}\n"
                f"Run `bzb persona render` first."
            )

    # Non-persona service configs → /configurations/services/
    src_services = configs_src / "services"
    for yaml_file in src_services.glob("*.yaml"):
        if yaml_file.name not in PERSONA_LURES:
            shutil.copy2(yaml_file, services / yaml_file.name)

    print(f"Staged configuration tree at: {staged}")
    print(f"  node.yaml:        {staged / 'node.yaml'}")
    print(f"  persona/:         {persona_out}")
    print(f"    persona.yaml")
    print(f"  services/:        {services}")
    for f in sorted(services.iterdir()):
        print(f"    {f.name}")


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
