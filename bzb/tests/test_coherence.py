from pathlib import Path

from bzb.models.bundle import load_bundle
from bzb.render.coherence import render_etc_hosts, render_bash_history

FIXTURES = Path(__file__).parent / "fixtures"


def test_etc_hosts_includes_self_and_peers():
    b = load_bundle(FIXTURES / "multi-persona")
    out = render_etc_hosts(b, "jump-01")
    assert "10.0.1.10   jump-01 jump-01.int.multi.test" in out
    assert "10.0.1.100   web-01 web-01.int.multi.test" in out
    assert "10.0.1.50   db-01 db-01.int.multi.test" in out


def test_etc_hosts_omits_non_peers():
    b = load_bundle(FIXTURES / "multi-persona")
    # db-01 has no peers
    out = render_etc_hosts(b, "db-01")
    assert "10.0.1.50   db-01" in out
    assert "web-01" not in out
    assert "jump-01" not in out


def test_bash_history_seeded_from_persona():
    b = load_bundle(FIXTURES / "multi-persona")
    history = render_bash_history(b, "jump-01")
    assert "ssh deploy@web-01.int.multi.test" in history
    assert "psql -h db-01.int.multi.test" in history


def test_bash_history_empty_for_node_with_no_seeds():
    b = load_bundle(FIXTURES / "multi-persona")
    history = render_bash_history(b, "db-01")
    assert history == ""
