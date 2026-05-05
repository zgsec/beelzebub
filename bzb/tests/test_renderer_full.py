"""Full render_node orchestrator tests."""
from pathlib import Path

from bzb.models.bundle import load_bundle
from bzb.render.renderer import render_node

FIXTURES = Path(__file__).parent / "fixtures"


def test_full_render_produces_expected_tree(tmp_path: Path):
    b = load_bundle(FIXTURES / "multi-persona")
    out = render_node(b, "jump-01", tmp_path)
    assert (out / "docker-compose.yml").is_file()
    assert (out / ".env").is_file()
    assert (out / "persona/persona.yaml").is_file()
    assert (out / "persona/node.yaml").is_file()
    assert (out / "persona/canaries.yaml").is_file()
    assert (out / "persona/lures/jump-01/ssh-22.yaml").is_file()
    assert (out / "persona/coherence/etc-hosts").is_file()
    assert (out / "config_sha256").is_file()


def test_render_is_deterministic(tmp_path: Path):
    """Two renders of the same bundle produce the same config_sha256."""
    b = load_bundle(FIXTURES / "multi-persona")
    out1 = render_node(b, "jump-01", tmp_path / "first")
    out2 = render_node(b, "jump-01", tmp_path / "second")
    sha1 = (out1 / "config_sha256").read_text().strip()
    sha2 = (out2 / "config_sha256").read_text().strip()
    assert sha1 == sha2
