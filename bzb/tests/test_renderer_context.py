from pathlib import Path

from bzb.models.bundle import load_bundle
from bzb.render.renderer import build_context

FIXTURES = Path(__file__).parent / "fixtures"


def test_context_includes_persona_node_peers():
    b = load_bundle(FIXTURES / "mini-persona")
    ctx = build_context(b, "web-01")
    assert ctx["persona"]["slug"] == "mini"
    assert ctx["node"]["node_id"] == "web-01"
    assert ctx["peers"] == []
    assert ctx["canary_values"] == {}  # no slots in mini fixture


def test_context_resolves_peers():
    # Mini bundle has no peers; we'll write a multi-node fixture in Task B5.
    b = load_bundle(FIXTURES / "mini-persona")
    ctx = build_context(b, "web-01")
    assert "peers" in ctx
    assert isinstance(ctx["peers"], list)
