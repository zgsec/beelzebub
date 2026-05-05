"""nodes/<id>.yaml schema definitions."""
from __future__ import annotations

import ipaddress
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class PersonaLocal(_Strict):
    hostname: str
    fqdn: str
    os: str
    user: str
    internal_ip: str
    uptime_days: int = Field(ge=0)
    process_seed: str

    @field_validator("internal_ip")
    @classmethod
    def _ipv4(cls, v: str) -> str:
        try:
            ipaddress.IPv4Address(v)
        except ValueError as e:
            raise ValueError(f"internal_ip must be a valid IPv4: {v}") from e
        return v


class Node(_Strict):
    schema_version: Literal[1]
    node_id: str
    role: str
    persona_local: PersonaLocal
    lures: list[str]
    canary_slots: list[str] = Field(default_factory=list)
    env_overrides: dict[str, str] = Field(default_factory=dict)

    @field_validator("lures")
    @classmethod
    def _lures_not_empty(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("lures must have at least one lure")
        return v
