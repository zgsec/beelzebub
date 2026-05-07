"""Tests for tools/stage_persona_configs.py — Crestfield + BlueSpark coverage.

These tests exercise the staging helper directly (no subprocess) so they're
quick to run. The staging helper does not Jinja-render — it only assembles a
tree from an already-rendered persona dir + the source configurations dir.
That means we can test the staging glob logic against any persona's lure set
without depending on Jinja being able to render every persona's lures.

Coverage:
1. Crestfield (4 lures) → staged tree contains the 4 persona lures + the rest
   of configurations/services/ unchanged.
2. BlueSpark (5 lures) → staged tree contains all 5 BlueSpark lures + a
   different set of non-persona service yamls (no overlap collision).
3. Empty `lures/` → stage() raises FileNotFoundError (clean failure when the
   persona has zero lures).
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools"))

from stage_persona_configs import stage  # noqa: E402

CRESTFIELD_LURES = {
    "mcp-8000.yaml",
    "http-8888.yaml",
    "ollama-11434.yaml",
    "openai-8001.yaml",
}
BLUESPARK_LURES = {
    "litellm-4000.yaml",
    "vllm-8000.yaml",
    "ollama-11434.yaml",
    "openwebui-8888.yaml",
    "docker-2375.yaml",
}


def _make_render_out(
    base: Path,
    lure_names: set[str],
    *,
    persona_name: str = "test-persona",
    write_jinja_marker: bool = False,
) -> Path:
    """Build a minimal render-out/<slug>/<node>/ tree with the given lure files."""
    render_out = base / persona_name / "node-1"
    persona_dir = render_out / "persona"
    lures_dir = persona_dir / "lures"
    lures_dir.mkdir(parents=True)

    # Required files in the persona dir
    (persona_dir / "persona.yaml").write_text(f"slug: {persona_name}\n")
    (persona_dir / "node.yaml").write_text("node_id: node-1\n")
    (persona_dir / "canaries.yaml").write_text("slots: {}\n")

    body = "name: test\napiVersion: \"v1\"\n"
    if write_jinja_marker:
        # Used by an explicit assertion that no `{{` substring remains.
        body = "name: rendered-ok\nfinal: aurora-7b\n"
    for name in lure_names:
        (lures_dir / name).write_text(body)

    return render_out


def test_stage_crestfield_lures(tmp_path: Path) -> None:
    """Crestfield: 4 persona lures get staged + all non-persona services kept."""
    render_out = _make_render_out(
        tmp_path / "render", CRESTFIELD_LURES, persona_name="crestfield-data-systems"
    )
    staged = tmp_path / "staged"
    stage(render_out=render_out, configs_src=REPO / "configurations", staged=staged)

    services = staged / "services"
    staged_names = {p.name for p in services.iterdir()}

    # All persona lures present
    assert CRESTFIELD_LURES.issubset(staged_names)

    # Non-persona services from configurations/services/ are also present
    src_services = {
        p.name for p in (REPO / "configurations" / "services").glob("*.yaml")
    }
    non_persona = src_services - CRESTFIELD_LURES
    assert non_persona.issubset(staged_names)

    # persona/persona.yaml + node.yaml present
    assert (staged / "persona" / "persona.yaml").is_file()
    assert (staged / "node.yaml").is_file()
    assert (staged / "beelzebub.yaml").is_file()


def test_stage_bluespark_lures(tmp_path: Path) -> None:
    """BlueSpark: all 5 lures staged + no `{{` markers in staged output."""
    render_out = _make_render_out(
        tmp_path / "render",
        BLUESPARK_LURES,
        persona_name="bluespark-labs",
        write_jinja_marker=True,
    )
    staged = tmp_path / "staged"
    stage(render_out=render_out, configs_src=REPO / "configurations", staged=staged)

    services = staged / "services"
    staged_names = {p.name for p in services.iterdir()}

    # All 5 BlueSpark lures present
    assert BLUESPARK_LURES.issubset(staged_names), (
        f"missing lures: {BLUESPARK_LURES - staged_names}"
    )

    # Non-persona services from configurations/services/ that DON'T collide
    # with BlueSpark filenames are also copied through.
    src_services = {
        p.name for p in (REPO / "configurations" / "services").glob("*.yaml")
    }
    non_colliding = src_services - BLUESPARK_LURES
    assert non_colliding.issubset(staged_names)

    # No filename collision regression: where a BlueSpark lure has the same
    # filename as a stock service config (e.g. ollama-11434.yaml), the
    # persona-rendered version should win — its body content stayed intact.
    for lure_name in BLUESPARK_LURES:
        body = (services / lure_name).read_text()
        assert "rendered-ok" in body, (
            f"{lure_name} was overwritten by stock services/ copy"
        )

    # No raw Jinja markers in the persona-rendered lures themselves
    # (regression for accidentally copying an unrendered file). Note:
    # configurations/services/mcp-8000.yaml carries Jinja-shaped runtime
    # substitutions (e.g. `{{ persona.* }}`) by design, so this check is
    # scoped to persona lures only.
    for lure_name in BLUESPARK_LURES:
        text = (services / lure_name).read_text()
        assert "{{" not in text, (
            f"unrendered Jinja in persona lure {lure_name}: {text[:80]!r}"
        )


def test_stage_fails_when_no_lures(tmp_path: Path) -> None:
    """Stage exits cleanly (FileNotFoundError) when the persona has zero lures."""
    render_out = _make_render_out(tmp_path / "render", set())
    staged = tmp_path / "staged"
    with pytest.raises(FileNotFoundError, match="No rendered lures found"):
        stage(
            render_out=render_out,
            configs_src=REPO / "configurations",
            staged=staged,
        )
