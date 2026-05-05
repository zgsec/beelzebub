"""Tests for `bzb deploy` — verify dry-run renders only; full run shells out."""
from pathlib import Path
from unittest.mock import patch, MagicMock

from click.testing import CliRunner

from bzb.cli import cli

FIXTURES = Path(__file__).parent / "fixtures"


def test_deploy_dry_run_renders_only(tmp_path: Path):
    """--dry-run must not invoke rsync or ssh; just renders."""
    runner = CliRunner()
    with patch("subprocess.run") as mock_run:
        result = runner.invoke(cli, [
            "deploy", "multi-persona", "web-01",
            "--target", "host.example",
            "--persona-root", str(FIXTURES),
            "--out", str(tmp_path),
            "--dry-run",
        ])
    assert result.exit_code == 0, result.output
    assert mock_run.call_count == 0
    assert (tmp_path / "multi/web-01/docker-compose.yml").is_file()


def test_deploy_runs_rsync_and_compose_up(tmp_path: Path):
    """Full deploy invokes rsync + ssh; with no aggregator-url, skips poll."""
    runner = CliRunner()
    completed = MagicMock(returncode=0, stdout="", stderr="")
    with patch("subprocess.run", return_value=completed) as mock_run:
        result = runner.invoke(cli, [
            "deploy", "multi-persona", "web-01",
            "--target", "host.example",
            "--persona-root", str(FIXTURES),
            "--out", str(tmp_path),
        ])
    assert result.exit_code == 0, result.output
    cmds = [call.args[0] for call in mock_run.call_args_list]
    # First call is rsync; second is ssh+compose-up.
    assert any(cmd[0] == "rsync" for cmd in cmds), f"no rsync in {cmds}"
    assert any(cmd[0] == "ssh" for cmd in cmds), f"no ssh in {cmds}"


def test_deploy_rsync_failure_exits_nonzero(tmp_path: Path):
    """rsync non-zero exit → bzb deploy exits non-zero with stderr."""
    runner = CliRunner()
    failed = MagicMock(returncode=1, stdout="", stderr="rsync: connection refused\n")
    with patch("subprocess.run", return_value=failed):
        result = runner.invoke(cli, [
            "deploy", "multi-persona", "web-01",
            "--target", "host.example",
            "--persona-root", str(FIXTURES),
            "--out", str(tmp_path),
        ])
    assert result.exit_code != 0
    assert "rsync" in (result.output + (result.stderr or ""))
