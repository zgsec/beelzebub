"""Asserts mcp-8000.yaml renders cleanly against crestfield persona."""
import subprocess
from pathlib import Path

REPO = Path("/home/dev/projects/beelzebub")
RENDERED = REPO / "out/crestfield-data-systems/placeholder/persona/lures/mcp-8000.yaml"

def _render():
    subprocess.run(
        ["bzb", "persona", "render", "crestfield-data-systems", "placeholder"],
        cwd=REPO, check=True, capture_output=True,
    )

def test_renders_no_raw_jinja():
    _render()
    assert "{{" not in RENDERED.read_text(), "unrendered Jinja in mcp-8000"

def test_source_no_internal_corp():
    for f in ("configurations/services/mcp-8000.yaml",
              "personas/crestfield-data-systems/lures/mcp-8000.yaml"):
        src = (REPO / f).read_text()
        assert "internal.corp" not in src, f"literal 'internal.corp' in {f}"

def test_yaml_parses():
    import yaml
    for f in ("configurations/services/mcp-8000.yaml",
              "personas/crestfield-data-systems/lures/mcp-8000.yaml"):
        try:
            yaml.safe_load((REPO / f).read_text())
        except yaml.YAMLError as e:
            raise AssertionError(f"{f}: {e}")

def test_cdf_namespace_templated():
    """The cdf/* tool namespace should template via world.product.service_name."""
    for f in ("configurations/services/mcp-8000.yaml",
              "personas/crestfield-data-systems/lures/mcp-8000.yaml"):
        src = (REPO / f).read_text()
        # The literal "cdf/" prefix should not remain in raw YAML — should template.
        # Allow it only inside YAML comments (starts with #).
        lines = [l for l in src.splitlines()
                 if 'cdf/' in l and not l.lstrip().startswith('#')]
        assert not lines, f"hardcoded cdf/ namespace in {f}:\n" + "\n".join(lines[:5])
