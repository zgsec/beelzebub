"""Asserts openai-8001.yaml renders cleanly against crestfield persona."""
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
RENDERED = REPO / "out/crestfield-data-systems/placeholder/persona/lures/openai-8001.yaml"

def _render():
    subprocess.run(
        ["bzb", "persona", "render", "crestfield-data-systems", "placeholder"],
        cwd=REPO, check=True, capture_output=True,
    )

def test_renders_no_raw_jinja():
    _render()
    text = RENDERED.read_text()
    assert "{{" not in text, "unrendered Jinja in rendered output"

def test_source_no_internal_corp():
    for f in ("configurations/services/openai-8001.yaml",
              "personas/crestfield-data-systems/lures/openai-8001.yaml"):
        src = (REPO / f).read_text()
        assert "internal.corp" not in src, f"literal 'internal.corp' in {f}"
        assert "devops-daily" not in src, f"literal 'devops-daily' in {f}"

def test_yaml_parses():
    """Catches the line-153 default('platform') YAML defect."""
    import yaml
    for f in ("configurations/services/openai-8001.yaml",
              "personas/crestfield-data-systems/lures/openai-8001.yaml"):
        try:
            yaml.safe_load((REPO / f).read_text())
        except yaml.YAMLError as e:
            raise AssertionError(f"{f} does not parse: {e}")

def test_rendered_contains_crestfield_domain():
    """Sanity: the rendered output should have crestfielddata.io (resolved from world)."""
    text = RENDERED.read_text()
    assert "crestfielddata.io" in text, "world.company.public_domain didn't render"
