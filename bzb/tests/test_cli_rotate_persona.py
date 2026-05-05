"""Tests for `bzb rotate persona`."""
from unittest.mock import patch, MagicMock

from click.testing import CliRunner

from bzb.cli import cli


def test_rotate_persona_dry_run():
    runner = CliRunner()
    with patch("subprocess.run") as mock_run:
        result = runner.invoke(cli, [
            "rotate", "persona", "old-slug", "node-01",
            "--to", "new-slug",
            "--target", "host",
            "--dry-run",
        ])
    assert result.exit_code == 0, result.output
    assert mock_run.call_count == 0  # dry-run skips


def test_rotate_persona_calls_deploy():
    runner = CliRunner()
    completed = MagicMock(returncode=0, stdout="", stderr="")
    with patch("subprocess.run", return_value=completed) as mock_run:
        result = runner.invoke(cli, [
            "rotate", "persona", "old-slug", "node-01",
            "--to", "new-slug",
            "--target", "host.example",
        ])
    assert result.exit_code == 0, result.output
    cmds = [call.args[0] for call in mock_run.call_args_list]
    # Should call bzb deploy
    deploy_calls = [c for c in cmds if any("deploy" in str(a) for a in c)]
    assert len(deploy_calls) >= 1, f"no deploy calls in {cmds}"


def test_rotate_persona_deploy_failure_exits_nonzero():
    runner = CliRunner()
    failed = MagicMock(returncode=1, stdout="", stderr="deploy failed")
    with patch("subprocess.run", return_value=failed):
        result = runner.invoke(cli, [
            "rotate", "persona", "old-slug", "node-01",
            "--to", "new-slug",
            "--target", "host",
        ])
    assert result.exit_code != 0
