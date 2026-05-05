"""Tests for `bzb test {capture, replay, e2e}` — thin wrappers."""
from unittest.mock import patch, MagicMock
from pathlib import Path

from click.testing import CliRunner

from bzb.cli import cli


def test_test_capture_invokes_capture_script(tmp_path):
    runner = CliRunner()
    completed = MagicMock(returncode=0, stdout="", stderr="")
    out = tmp_path / "baseline.jsonl"
    # Create a dummy script file
    tools = tmp_path / "tools"
    tools.mkdir()
    (tools / "capture_persona_baseline.py").touch()

    with patch("bzb.commands.test._tools_dir", return_value=tools):
        with patch("subprocess.run", return_value=completed) as mock_run:
            result = runner.invoke(cli, [
                "test", "capture", "crestfield-data-systems", "fra-01",
                "--target", "localhost",
                "--output", str(out),
            ])
    assert result.exit_code == 0, result.output
    cmds = [call_obj.args[0] for call_obj in mock_run.call_args_list]
    assert any("capture_persona_baseline.py" in str(c) for c in cmds)


def test_test_capture_missing_script_exits_nonzero(tmp_path):
    runner = CliRunner()
    # Patch _tools_dir to return a nonexistent path
    with patch("bzb.commands.test._tools_dir") as mock_tools:
        mock_tools.return_value = Path("/nonexistent/tools")
        result = runner.invoke(cli, [
            "test", "capture", "x", "y",
            "--target", "localhost",
            "--output", str(tmp_path / "out.jsonl"),
        ])
    assert result.exit_code == 2


def test_test_replay_invokes_replay_script_with_baseline(tmp_path):
    runner = CliRunner()
    completed = MagicMock(returncode=0, stdout="", stderr="")
    baseline = tmp_path / "baseline.jsonl"
    baseline.write_text("{}\n")
    # Create a dummy script file
    tools = tmp_path / "tools"
    tools.mkdir()
    (tools / "replay_persona_baseline.py").touch()

    with patch("bzb.commands.test._tools_dir", return_value=tools):
        with patch("subprocess.run", return_value=completed) as mock_run:
            result = runner.invoke(cli, [
                "test", "replay", "crestfield-data-systems", "fra-01",
                "--target", "localhost",
                "--baseline", str(baseline),
            ])
    assert result.exit_code == 0, result.output
    cmds = [call_obj.args[0] for call_obj in mock_run.call_args_list]
    assert any("replay_persona_baseline.py" in str(c) for c in cmds)
    # Baseline path should be passed to replay
    assert any(str(baseline) in " ".join(map(str, c)) for c in cmds)


def test_test_replay_propagates_failure_exit_code(tmp_path):
    runner = CliRunner()
    failed = MagicMock(returncode=2, stdout="", stderr="2 probes regressed")
    baseline = tmp_path / "b.jsonl"
    baseline.write_text("")
    with patch("subprocess.run", return_value=failed):
        result = runner.invoke(cli, [
            "test", "replay", "x", "y",
            "--target", "localhost",
            "--baseline", str(baseline),
        ])
    assert result.exit_code == 2


def test_test_e2e_chains_subcommands(tmp_path):
    runner = CliRunner()
    # Mock all the subprocess calls (deploy, status, replay, teardown)
    with patch("subprocess.run", return_value=MagicMock(returncode=0)):
        with patch("bzb.models.bundle.load_bundle") as mock_load:
            # Create minimal mock bundle structure
            mock_node = MagicMock()
            mock_node.id = "fra-01"
            mock_persona = MagicMock()
            mock_persona.nodes = [mock_node]
            mock_bundle = MagicMock()
            mock_bundle.persona = mock_persona
            mock_load.return_value = mock_bundle

            result = runner.invoke(cli, [
                "test", "e2e", "crestfield-data-systems",
                "--target", "localhost",
            ])
    assert result.exit_code == 0, result.output


def test_test_e2e_fails_if_replay_fails(tmp_path):
    runner = CliRunner()
    call_count = [0]

    def mock_run(*args, **kwargs):
        call_count[0] += 1
        # Fail on the third call (replay)
        if call_count[0] == 3:
            return MagicMock(returncode=1)
        return MagicMock(returncode=0)

    with patch("subprocess.run", side_effect=mock_run):
        with patch("bzb.models.bundle.load_bundle") as mock_load:
            mock_node = MagicMock()
            mock_node.id = "fra-01"
            mock_persona = MagicMock()
            mock_persona.nodes = [mock_node]
            mock_bundle = MagicMock()
            mock_bundle.persona = mock_persona
            mock_load.return_value = mock_bundle

            result = runner.invoke(cli, [
                "test", "e2e", "crestfield-data-systems",
                "--target", "localhost",
            ])
    # Should exit with 1 from the failing replay
    assert result.exit_code == 1
