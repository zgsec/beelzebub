from pathlib import Path

import pytest

from bzb.models.bundle import Bundle, load_bundle

FIXTURES = Path(__file__).parent / "fixtures"


def test_load_mini_bundle():
    b = load_bundle(FIXTURES / "mini-persona")
    assert b.persona.slug == "mini"
    assert "web-01" in b.nodes
    assert b.nodes["web-01"].node_id == "web-01"
    assert "WEB01_AWS_KEY_HTTP" in b.canaries.slots


def test_node_referenced_in_persona_must_have_file(tmp_path):
    src = FIXTURES / "mini-persona"
    dest = tmp_path / "broken"
    _copy_tree(src, dest)
    (dest / "nodes/web-01.yaml").unlink()
    with pytest.raises(FileNotFoundError, match="nodes/web-01.yaml"):
        load_bundle(dest)


def test_canary_slot_referenced_by_node_must_exist(tmp_path):
    src = FIXTURES / "mini-persona"
    dest = tmp_path / "broken"
    _copy_tree(src, dest)
    node_file = dest / "nodes/web-01.yaml"
    txt = node_file.read_text()
    node_file.write_text(txt.replace("canary_slots: []",
                                     "canary_slots:\n  - DOES_NOT_EXIST"))
    with pytest.raises(ValueError, match="DOES_NOT_EXIST"):
        load_bundle(dest)


def _copy_tree(src: Path, dest: Path) -> None:
    import shutil
    shutil.copytree(src, dest)
