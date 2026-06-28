"""Tests for `bzb status` — happy path + filter by slug + --attest."""
from unittest.mock import patch, MagicMock

from click.testing import CliRunner

from bzb.cli import cli


def _mock_resp(sensors):
    m = MagicMock()
    m.ok = True
    m.raise_for_status = lambda: None
    m.json = lambda: {"sensors": sensors}
    return m


SAMPLE_SENSORS = [
    {"sensor_id": "fra-01", "persona_slug": "example",
     "liveness_status": "healthy",
     "last_session_first_seen": "2026-05-05T22:00:00Z",
     "last_attestation_status": "match",
     "last_image_digest": "sha256:abc123def456"},
    {"sensor_id": "ewr-01", "persona_slug": "example",
     "liveness_status": "stale_data",
     "last_session_first_seen": "2026-05-04T10:00:00Z",
     "last_attestation_status": "match",
     "last_image_digest": "sha256:xyz789"},
    {"sensor_id": "sin-01", "persona_slug": "apex-research",
     "liveness_status": "healthy",
     "last_session_first_seen": "2026-05-05T22:01:00Z",
     "last_attestation_status": "match",
     "last_image_digest": "sha256:foobar"},
]


def test_status_lists_all_sensors():
    runner = CliRunner()
    with patch("requests.get", return_value=_mock_resp(SAMPLE_SENSORS)):
        result = runner.invoke(cli, ["status",
                                      "--aggregator-url", "http://aggregator.test"])
    assert result.exit_code == 0, result.output
    assert "fra-01" in result.output
    assert "ewr-01" in result.output
    assert "sin-01" in result.output


def test_status_filter_by_slug():
    runner = CliRunner()
    with patch("requests.get", return_value=_mock_resp(SAMPLE_SENSORS)):
        result = runner.invoke(cli, ["status", "apex-research",
                                      "--aggregator-url", "http://aggregator.test"])
    assert result.exit_code == 0
    assert "sin-01" in result.output
    assert "fra-01" not in result.output
    assert "ewr-01" not in result.output


def test_status_attest_flag_shows_attestation_detail():
    runner = CliRunner()
    with patch("requests.get", return_value=_mock_resp(SAMPLE_SENSORS)):
        result = runner.invoke(cli, ["status", "--attest",
                                      "--aggregator-url", "http://aggregator.test"])
    assert result.exit_code == 0
    assert "match" in result.output
    # Image digest first 12 chars should appear
    assert "abc123def456"[:12] in result.output
