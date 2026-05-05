"""persona.yaml schema definitions."""
from __future__ import annotations

from datetime import date
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=False)


class Identity(_Strict):
    industry: str
    scale: Literal["small", "medium", "large"]
    internal_domain: str
    public_domain: str
    email_pattern: str
    founded: int | None = None
    hq: str | None = None


class NodeRef(_Strict):
    """Top-level entry in persona.yaml's nodes list — references a nodes/<id>.yaml file."""
    id: str
    role: str
    peers: list[str] = Field(default_factory=list)


class Coherence(_Strict):
    hosts_file_template: str
    ssh_history_seeds: dict[str, list[str]] = Field(default_factory=dict)
    vault_addr: str | None = None


class Persona(_Strict):
    schema_version: Literal[1]
    slug: str
    display_name: str
    version: int = Field(ge=1)
    created_at: date
    last_rotated_at: date
    identity: Identity
    nodes: list[NodeRef] = Field(min_length=1)
    coherence: Coherence
    llm_seed: str | None = None
    lure_content: dict[str, str] = Field(
        default_factory=dict,
        description="persona-specific key-value lure strings (DB creds, service accounts, hostnames, etc.)",
    )

    @model_validator(mode="after")
    def _check_node_graph(self) -> Persona:
        ids = [n.id for n in self.nodes]
        seen: set[str] = set()
        for nid in ids:
            if nid in seen:
                raise ValueError(f"duplicate node id: {nid}")
            seen.add(nid)
        for n in self.nodes:
            for peer in n.peers:
                if peer not in seen:
                    raise ValueError(f"node {n.id} references unknown peer: {peer}")
        return self
