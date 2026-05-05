"""canaries.yaml schema."""
from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

_SLOT_NAME = re.compile(r"^[A-Z][A-Z0-9_]+$")


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ConsumedBy(_Strict):
    lure: str
    rendering: str | None = None


class Slot(_Strict):
    type: Literal["aws_key", "decoy_password", "dns_token", "github_pat", "slack_token"]
    reminder: str
    consumed_by: list[ConsumedBy] = Field(min_length=1)
    owner: str
    rotation_cohort: str
    token_id: str | None = None
    minted_at: str | None = None
    status: Literal["planned", "active", "burned"] = "planned"


class Canaries(_Strict):
    schema_version: Literal[1]
    persona: str
    operator: str
    default_status: Literal["planned", "active"] = "planned"
    slots: dict[str, Slot]

    @model_validator(mode="after")
    def _check_slot_names(self) -> "Canaries":
        for name in self.slots:
            if not _SLOT_NAME.match(name):
                raise ValueError(f"slot name must be UPPERCASE_SNAKE_CASE: {name}")
        return self
