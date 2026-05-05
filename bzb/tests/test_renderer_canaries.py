from pathlib import Path

from bzb.models.bundle import load_bundle
from bzb.render.renderer import render_env_file

FIXTURES = Path(__file__).parent / "fixtures"


def test_env_file_includes_canary_token_ids(tmp_path: Path):
    """Render .env from node + canaries — token_id values appear."""
    b = load_bundle(FIXTURES / "mini-persona")
    # Inject a token_id for the WEB01_AWS_KEY_HTTP slot
    b.canaries.slots["WEB01_AWS_KEY_HTTP"].token_id = "AKIAFAKETOKENXXXX"
    # Reference the slot from the node
    b.nodes["web-01"].canary_slots.append("WEB01_AWS_KEY_HTTP")

    text = render_env_file(b, "web-01", aggregator_url="http://aggregator.test:8080",
                           aggregator_token="bearertok", sensor_id="web-01-test")
    assert "WEB01_AWS_KEY_HTTP=AKIAFAKETOKENXXXX" in text
    assert "AGGREGATOR_URL=http://aggregator.test:8080" in text
    assert "SENSOR_ID=web-01-test" in text
