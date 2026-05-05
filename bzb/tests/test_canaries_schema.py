from pathlib import Path

import pytest
import yaml

from bzb.models.canaries import Canaries

FIXTURES = Path(__file__).parent / "fixtures"


def test_canaries_loads():
    raw = yaml.safe_load((FIXTURES / "mini-persona/canaries.yaml").read_text())
    c = Canaries.model_validate(raw)
    assert c.persona == "mini"
    assert "WEB01_AWS_KEY_HTTP" in c.slots


def test_unknown_token_type_rejected():
    raw = yaml.safe_load((FIXTURES / "mini-persona/canaries.yaml").read_text())
    raw["slots"]["WEB01_AWS_KEY_HTTP"]["type"] = "garbage"
    with pytest.raises(Exception, match="type"):
        Canaries.model_validate(raw)


def test_slot_name_must_be_uppercase_snake():
    raw = yaml.safe_load((FIXTURES / "mini-persona/canaries.yaml").read_text())
    raw["slots"]["lowercase-slot"] = raw["slots"]["WEB01_AWS_KEY_HTTP"]
    with pytest.raises(Exception, match="slot name"):
        Canaries.model_validate(raw)
