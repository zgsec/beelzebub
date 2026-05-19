"""Tests for `bzb rotate canary`."""
import shutil
from pathlib import Path
from unittest.mock import patch, MagicMock

import yaml
from click.testing import CliRunner

from bzb.cli import cli

FIXTURES = Path(__file__).parent / "fixtures"


def _seed_persona(tmp_path: Path) -> Path:
    """Copy multi-persona fixture and add a canary slot for rotation tests."""
    src = FIXTURES / "multi-persona"
    dest = tmp_path / "personas" / "multi-persona"
    shutil.copytree(src, dest)
    canaries_path = dest / "canaries.yaml"
    raw = yaml.safe_load(canaries_path.read_text())
    raw["slots"]["TEST_AWS_KEY"] = {
        "type": "aws_key",
        "reminder": "test-rotation-cohort",
        "consumed_by": [{"lure": "lures/web-01/http-8888.yaml"}],
        "owner": "test",
        "rotation_cohort": "2026-Q2",
        "status": "planned",
    }
    canaries_path.write_text(yaml.safe_dump(raw, sort_keys=False))
    return tmp_path / "personas"


def test_rotate_canary_dry_run_prints_intent_no_mint(tmp_path: Path):
    runner = CliRunner()
    persona_root = _seed_persona(tmp_path)
    with patch("subprocess.run") as mock_run:
        result = runner.invoke(cli, [
            "rotate", "canary", "multi-persona", "TEST_AWS_KEY",
            "--persona-root", str(persona_root),
            "--dry-run",
        ])
    assert result.exit_code == 0, result.output
    assert mock_run.call_count == 0


def test_rotate_canary_with_token_id_skips_mint(tmp_path: Path):
    runner = CliRunner()
    persona_root = _seed_persona(tmp_path)
    completed = MagicMock(returncode=0, stdout="", stderr="")
    with patch("subprocess.run", return_value=completed) as mock_run:
        result = runner.invoke(cli, [
            "rotate", "canary", "multi-persona", "TEST_AWS_KEY",
            "--persona-root", str(persona_root),
            "--token-id", "AKIAEXISTINGTOKEN",
        ])
    assert result.exit_code == 0, result.output
    # Should NOT have called rotate_canaries.py mint
    cmds = [c.args[0] for c in mock_run.call_args_list]
    mint_calls = [c for c in cmds if any("rotate_canaries" in str(a) for a in c)]
    assert len(mint_calls) == 0, f"unexpected mint calls: {mint_calls}"
    # canaries.yaml should now contain the token
    raw = yaml.safe_load((persona_root / "multi-persona" / "canaries.yaml").read_text())
    assert raw["slots"]["TEST_AWS_KEY"]["token_id"] == "AKIAEXISTINGTOKEN"
    assert raw["slots"]["TEST_AWS_KEY"]["status"] == "active"


def test_rotate_canary_unknown_slot_exits_nonzero(tmp_path: Path):
    runner = CliRunner()
    persona_root = _seed_persona(tmp_path)
    result = runner.invoke(cli, [
        "rotate", "canary", "multi-persona", "DOES_NOT_EXIST",
        "--persona-root", str(persona_root),
        "--token-id", "AKIA",
    ])
    assert result.exit_code != 0
    assert "DOES_NOT_EXIST" in (result.output + (result.stderr or ""))
