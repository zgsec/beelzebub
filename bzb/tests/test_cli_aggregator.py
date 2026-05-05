"""Tests for `bzb aggregator deploy/dump`."""
from unittest.mock import patch, MagicMock, call

from click.testing import CliRunner

from bzb.cli import cli


def test_aggregator_deploy_invokes_setup_script_via_ssh():
    runner = CliRunner()
    completed = MagicMock(returncode=0, stdout="", stderr="")
    with patch("subprocess.run", return_value=completed) as mock_run:
        result = runner.invoke(cli, [
            "aggregator", "deploy", "aggregator.example.com",
        ])
    assert result.exit_code == 0, result.output
    cmds = [call_obj.args[0] for call_obj in mock_run.call_args_list]
    # Should ssh to the host
    assert any(c[0] == "ssh" for c in cmds), f"No ssh command found in {cmds}"


def test_aggregator_deploy_with_public_api_passes_flag():
    runner = CliRunner()
    completed = MagicMock(returncode=0, stdout="", stderr="")
    with patch("subprocess.run", return_value=completed) as mock_run:
        result = runner.invoke(cli, [
            "aggregator", "deploy", "aggregator.example.com",
            "--with-public-api",
        ])
    assert result.exit_code == 0, result.output
    # The flag should appear in the ssh command
    cmds = [call_obj.args[0] for call_obj in mock_run.call_args_list]
    assert any("--with-public-api" in " ".join(c) for c in cmds)


def test_aggregator_dump_runs_pg_dump():
    runner = CliRunner()
    completed = MagicMock(returncode=0, stdout=b"PG_DUMP_OUTPUT", stderr=b"")
    with patch("subprocess.run", return_value=completed) as mock_run:
        result = runner.invoke(cli, [
            "aggregator", "dump",
            "--db-dsn", "postgresql://test@host/db",
        ])
    assert result.exit_code == 0, result.output
    cmds = [call_obj.args[0] for call_obj in mock_run.call_args_list]
    assert any("pg_dump" in c[0] for c in cmds)


def test_aggregator_dump_failure_exits_nonzero():
    runner = CliRunner()
    failed = MagicMock(returncode=1, stderr=b"connection refused")
    with patch("subprocess.run", return_value=failed):
        result = runner.invoke(cli, [
            "aggregator", "dump",
            "--db-dsn", "postgresql://bad@host/db",
        ])
    assert result.exit_code == 1
