from pathlib import Path

from bzb.models.bundle import load_bundle
from bzb.render.renderer import render_compose

FIXTURES = Path(__file__).parent / "fixtures"


def test_compose_includes_beelzebub_exporter_p0f():
    b = load_bundle(FIXTURES / "multi-persona")
    out = render_compose(b, "web-01", image_org="testorg", image_tag="v0.1.0")
    assert "image: ghcr.io/testorg/beelzebub-fork:v0.1.0" in out
    assert "container_name: honeypot-exporter" in out
    assert "container_name: p0f" in out
    assert "cap_add:\n      - NET_RAW" in out


def test_compose_propagates_extra_env():
    b = load_bundle(FIXTURES / "multi-persona")
    b.nodes["web-01"].env_overrides = {"GREYNOISE_KEY": ""}
    out = render_compose(
        b,
        "web-01",
        image_org="t",
        image_tag="t",
        extra_exporter_env=["GREYNOISE_KEY"],
    )
    assert "- GREYNOISE_KEY=${GREYNOISE_KEY}" in out
