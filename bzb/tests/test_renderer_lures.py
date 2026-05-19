from pathlib import Path

from bzb.models.bundle import load_bundle
from bzb.render.renderer import render_lures

FIXTURES = Path(__file__).parent / "fixtures"


def test_lure_substitution(tmp_path: Path):
    b = load_bundle(FIXTURES / "mini-persona")
    out = tmp_path / "lures-out"
    out.mkdir()
    render_lures(b, "web-01", out)
    rendered = (out / "lures/web-01/http-8888.yaml").read_text()
    # Mini fixture lure contains no {{ persona.X }} references currently;
    # this test catches regressions if we add them.
    assert "fixture-http" in rendered or "mini-fixture" in rendered


def test_lure_strict_undefined_fails(tmp_path: Path):
    """If a lure references an undefined variable, render fails."""
    b = load_bundle(FIXTURES / "mini-persona")
    lure = b.root / "lures/web-01/http-8888.yaml"
    original = lure.read_text()
    lure.write_text(original + "\n# tail: {{ persona.no_such_field }}\n")
    out = tmp_path / "lures-out"
    out.mkdir()
    try:
        import pytest
        from jinja2 import UndefinedError
        with pytest.raises(UndefinedError):
            render_lures(b, "web-01", out)
    finally:
        lure.write_text(original)
