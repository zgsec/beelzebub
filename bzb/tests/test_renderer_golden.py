"""Layer 3 — renderer golden tests. Byte-for-byte expected output."""
from pathlib import Path

import pytest

from bzb.models.bundle import load_bundle
from bzb.render.renderer import render_node

FIXTURES = Path(__file__).parent / "fixtures"
GOLDEN = Path(__file__).parent / "golden"


@pytest.mark.parametrize("node_id", ["jump-01"])
def test_golden_render(node_id: str, tmp_path: Path):
    b = load_bundle(FIXTURES / "multi-persona")
    rendered = render_node(
        b, node_id, tmp_path,
        image_org="honeypot", image_tag="v0.1.0",
        aggregator_url="http://aggregator.test:8080",
        aggregator_token="GOLDEN_TOKEN",
        sensor_id=f"{node_id}-golden",
    )
    expected = GOLDEN / "multi" / node_id

    rendered_files = sorted(p.relative_to(rendered).as_posix()
                            for p in rendered.rglob("*") if p.is_file())
    expected_files = sorted(p.relative_to(expected).as_posix()
                            for p in expected.rglob("*") if p.is_file())
    assert rendered_files == expected_files, "file set mismatch"

    diffs: list[str] = []
    for rel in rendered_files:
        if (rendered / rel).read_bytes() != (expected / rel).read_bytes():
            diffs.append(rel)
    assert not diffs, (
        f"rendered files differ from golden: {diffs}\n"
        f"To update goldens: rerun `bzb persona render` and commit "
        f"the new tree under tests/golden/."
    )
