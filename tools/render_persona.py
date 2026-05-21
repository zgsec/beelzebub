#!/usr/bin/env python3
# =============================================================================
# render_persona.py — Jinja-flatten a persona's lure set for one node.
#
# Reads:
#   - personas/<slug>/persona.yaml            (persona context)
#   - personas/<slug>/nodes/<node>/node.yaml  (lure list + overrides)
#   - <each lure path from node.yaml>          (source yamls with {{ persona.* }})
#
# Writes:
#   - <out>/services/<basename of each lure>   (Jinja-resolved, ${CANARY_*} intact)
#   - <out>/persona.yaml                       (flat persona descriptor)
#
# Contract:
#   - Any unresolved {{ ... }} after rendering is a FATAL error (StrictUndefined).
#   - ${...} placeholders (canary env vars, ${time.*}, ${session.*}, ${request.*})
#     are preserved verbatim — they resolve at deploy time (envsubst) or runtime
#     (responsesubs / Go env-expand). Jinja doesn't touch the dollar syntax.
#   - Exit 0 on success; non-zero (with a printed reason) on any failure.
#
# Why this exists (2026-05-21):
#   The four prior render paths (bzb Phase A unwired, render-canaries.sh
#   ${VAR}-only, manual sensor edits, no-render-at-all) let the
#   crestfield-vs-cdf service_name drift ship to production undetected,
#   silently killing MCP canaries for ~2 days. This is the single
#   authoritative renderer the new bundle pipeline calls. See:
#     docs/superpowers/specs/2026-05-21-standardized-sensor-deploy-design.md
#
# Usage:
#   render_persona.py \
#     --persona-root personas/crestfield-data-systems \
#     --node sensor-ewr \
#     --base-services configurations/services \
#     --out /tmp/render-out
# =============================================================================

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import yaml
from jinja2 import (
    Environment,
    FileSystemLoader,
    StrictUndefined,
    UndefinedError,
    TemplateSyntaxError,
)

# Detects any unresolved {{ ... }} after rendering. The renderer should
# never leave Jinja syntax on the wire. ${...} dollar-syntax is allowed
# (resolved downstream by envsubst / responsesubs / Go env-expand).
UNRESOLVED_JINJA = re.compile(r"\{\{[^}]*\}\}|\{%[^%]*%\}")


def die(msg: str, code: int = 1) -> None:
    print(f"render_persona: {msg}", file=sys.stderr)
    sys.exit(code)


def load_yaml(path: Path) -> dict:
    if not path.exists():
        die(f"missing file: {path}")
    try:
        with path.open() as f:
            return yaml.safe_load(f) or {}
    except yaml.YAMLError as e:
        die(f"yaml parse error in {path}: {e}")


def deep_merge(base: dict, overlay: dict) -> dict:
    """Recursive dict merge; overlay wins on conflict. Lists are replaced, not concatenated."""
    out = dict(base)
    for k, v in overlay.items():
        if k in out and isinstance(out[k], dict) and isinstance(v, dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def render_one(env: Environment, src: Path, ctx: dict) -> str:
    try:
        # Load by absolute path via FileSystemLoader cwd-rooted env.
        template = env.get_template(str(src))
    except TemplateSyntaxError as e:
        die(f"jinja syntax error in {src}: {e.message} (line {e.lineno})")
    try:
        rendered = template.render(**ctx)
    except UndefinedError as e:
        die(f"undefined persona field while rendering {src}: {e.message}")
    leftover = UNRESOLVED_JINJA.search(rendered)
    if leftover:
        # First few chars of the offending fragment for actionable error.
        snippet = leftover.group(0)[:80]
        die(f"unresolved Jinja in rendered output of {src}: {snippet!r}")
    return rendered


def main() -> int:
    ap = argparse.ArgumentParser(description="Render a persona's lure set for one node.")
    ap.add_argument("--persona-root", required=True, type=Path,
                    help="Path to personas/<slug>/ (must contain persona.yaml and nodes/<node>/)")
    ap.add_argument("--node", required=True,
                    help="Node id (must match a directory under nodes/)")
    ap.add_argument("--base-services", required=True, type=Path,
                    help="Path to configurations/services/ — base lure set, used if node.yaml "
                         "references a base file by relative path starting with `../../configurations/`")
    ap.add_argument("--out", required=True, type=Path,
                    help="Output directory; <out>/services/ and <out>/persona.yaml are written")
    args = ap.parse_args()

    persona_root: Path = args.persona_root.resolve()
    node_dir = persona_root / "nodes" / args.node
    persona_file = persona_root / "persona.yaml"
    node_file = node_dir / "node.yaml"

    if not persona_root.is_dir():
        die(f"persona-root is not a directory: {persona_root}")
    if not node_dir.is_dir():
        die(f"node directory not found: {node_dir} (available: "
            f"{sorted(p.name for p in (persona_root / 'nodes').iterdir() if p.is_dir())})")

    persona = load_yaml(persona_file)
    node = load_yaml(node_file)

    # Apply per-node overrides to the persona before rendering. Lets a node
    # tweak persona fields (e.g. region-specific hostnames) without forking
    # the whole persona.yaml.
    overrides = node.get("overrides", {}) or {}
    if overrides:
        persona = deep_merge(persona, overrides)

    lures = node.get("lures") or []
    if not lures:
        die(f"node.yaml has no lures: {node_file}")

    out_services = args.out / "services"
    out_services.mkdir(parents=True, exist_ok=True)

    # FileSystemLoader rooted at filesystem root so we can pass absolute paths.
    env = Environment(
        loader=FileSystemLoader("/"),
        undefined=StrictUndefined,
        keep_trailing_newline=True,
    )

    rendered_count = 0
    for lure_relpath in lures:
        src = (persona_root / lure_relpath).resolve()
        if not src.exists():
            # Try the base-services dir as a fallback (for lures the node
            # inherits from the base config without persona overlay).
            alt = (args.base_services / Path(lure_relpath).name).resolve()
            if alt.exists():
                src = alt
            else:
                die(f"lure source not found: {src} (also tried {alt})")

        rendered = render_one(env, src, {"persona": persona})
        dst = out_services / src.name
        dst.write_text(rendered)
        rendered_count += 1

    # Flat persona.yaml for the runtime LoadPersona path.
    (args.out / "persona.yaml").write_text(yaml.safe_dump(persona, sort_keys=False))

    print(f"render_persona: ok — {rendered_count} lures rendered to {out_services}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
