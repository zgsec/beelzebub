"""Tests for bzb persona validate command."""
from pathlib import Path

from click.testing import CliRunner

from bzb.cli import cli

FIXTURES = Path(__file__).parent / "fixtures"


def test_validate_clean_bundle_exits_zero():
    runner = CliRunner()
    result = runner.invoke(cli, [
        "persona", "validate",
        "--persona-root", str(FIXTURES),
        "multi-persona",
    ])
    assert result.exit_code == 0, result.output
    assert "OK" in result.output or "valid" in result.output.lower()


def test_validate_missing_node_yaml_exits_nonzero(tmp_path: Path):
    import shutil
    src = FIXTURES / "multi-persona"
    dest = tmp_path / "broken"
    shutil.copytree(src, dest)
    (dest / "nodes" / "jump-01.yaml").unlink()
    runner = CliRunner()
    result = runner.invoke(cli, [
        "persona", "validate",
        "--persona-root", str(tmp_path),
        "broken",
    ])
    assert result.exit_code != 0
    assert "jump-01.yaml" in (result.output + (result.stderr or ""))
