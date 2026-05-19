"""Tests for `bzb teardown`."""
from unittest.mock import patch, MagicMock

from click.testing import CliRunner

from bzb.cli import cli


def test_teardown_runs_compose_down():
    runner = CliRunner()
    completed = MagicMock(returncode=0, stdout="", stderr="")
    with patch("subprocess.run", return_value=completed) as mock_run:
        result = runner.invoke(cli, [
            "teardown", "crestfield-data-systems", "fra-01",
            "--target", "host.example",
        ])
    assert result.exit_code == 0, result.output
    cmds = [call.args[0] for call in mock_run.call_args_list]
    # Must invoke ssh to run docker compose down
    ssh_calls = [c for c in cmds if c[0] == "ssh"]
    assert len(ssh_calls) >= 1
    assert any("compose down" in " ".join(c) for c in cmds)


def test_teardown_purge_uses_volumes_flag():
    runner = CliRunner()
    completed = MagicMock(returncode=0, stdout="", stderr="")
    with patch("subprocess.run", return_value=completed) as mock_run:
        result = runner.invoke(cli, [
            "teardown", "crestfield-data-systems", "fra-01",
            "--target", "host.example",
            "--purge",
        ])
    assert result.exit_code == 0, result.output
    cmds = [call.args[0] for call in mock_run.call_args_list]
    # --purge should add -v to docker compose down
    assert any("compose down -v" in " ".join(c) for c in cmds)


def test_teardown_ssh_failure_exits_nonzero():
    runner = CliRunner()
    failed = MagicMock(returncode=1, stdout="", stderr="ssh: connection refused")
    with patch("subprocess.run", return_value=failed):
        result = runner.invoke(cli, [
            "teardown", "x", "y", "--target", "host",
        ])
    assert result.exit_code != 0
