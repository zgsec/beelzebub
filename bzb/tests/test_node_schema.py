"""Layer 2 — nodes/<id>.yaml schema validation."""
from pathlib import Path

import pytest
import yaml

from bzb.models.node import Node

FIXTURES = Path(__file__).parent / "fixtures"


def test_node_loads():
    raw = yaml.safe_load((FIXTURES / "mini-persona/nodes/web-01.yaml").read_text())
    n = Node.model_validate(raw)
    assert n.node_id == "web-01"
    assert n.persona_local.internal_ip == "10.0.1.100"


def test_unknown_field_rejected():
    raw = yaml.safe_load((FIXTURES / "mini-persona/nodes/web-01.yaml").read_text())
    raw["surprise"] = True
    with pytest.raises(Exception, match="surprise"):
        Node.model_validate(raw)


def test_internal_ip_must_be_ipv4():
    raw = yaml.safe_load((FIXTURES / "mini-persona/nodes/web-01.yaml").read_text())
    raw["persona_local"]["internal_ip"] = "not-an-ip"
    with pytest.raises(Exception, match="internal_ip"):
        Node.model_validate(raw)


def test_node_with_no_lures_rejected():
    raw = yaml.safe_load((FIXTURES / "mini-persona/nodes/web-01.yaml").read_text())
    raw["lures"] = []
    with pytest.raises(Exception, match="at least one lure"):
        Node.model_validate(raw)
