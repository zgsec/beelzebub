"""Layer 1 — persona.yaml schema validation."""
from pathlib import Path

import pytest
import yaml

from bzb.models.persona import Persona

FIXTURES = Path(__file__).parent / "fixtures"


def test_minimal_persona_loads():
    raw = yaml.safe_load((FIXTURES / "mini-persona/persona.yaml").read_text())
    p = Persona.model_validate(raw)
    assert p.slug == "mini"
    assert p.identity.internal_domain == "int.mini.test"


def test_missing_required_field_rejected():
    with pytest.raises(Exception, match="display_name"):
        Persona.model_validate({"schema_version": 1, "slug": "x"})


def test_unknown_top_level_field_rejected():
    raw = yaml.safe_load((FIXTURES / "mini-persona/persona.yaml").read_text())
    raw["surprise_extra_field"] = "nope"
    with pytest.raises(Exception, match="surprise_extra_field"):
        Persona.model_validate(raw)


def test_node_id_collision_rejected():
    raw = yaml.safe_load((FIXTURES / "mini-persona/persona.yaml").read_text())
    raw["nodes"].append({"id": raw["nodes"][0]["id"], "role": "x", "peers": []})
    with pytest.raises(Exception, match="duplicate node id"):
        Persona.model_validate(raw)


def test_peer_must_be_known_node():
    raw = yaml.safe_load((FIXTURES / "mini-persona/persona.yaml").read_text())
    raw["nodes"][0]["peers"] = ["does-not-exist"]
    with pytest.raises(Exception, match="unknown peer"):
        Persona.model_validate(raw)
