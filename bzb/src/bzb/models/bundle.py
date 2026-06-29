"""Bundle loader — walks a persona directory + cross-references."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from bzb.models.canaries import Canaries
from bzb.models.node import Node
from bzb.models.persona import Persona


@dataclass(frozen=True)
class Bundle:
    root: Path
    persona: Persona
    nodes: dict[str, Node]
    canaries: Canaries


def load_bundle(root: Path) -> Bundle:
    """Load + cross-validate a persona bundle.

    Raises FileNotFoundError for missing files, ValueError for bad refs,
    pydantic.ValidationError for schema violations.
    """
    root = Path(root)
    persona_path = root / "persona.yaml"
    if not persona_path.is_file():
        raise FileNotFoundError(f"persona.yaml not found at {persona_path}")
    persona = Persona.model_validate(yaml.safe_load(persona_path.read_text()))

    canaries_path = root / "canaries.yaml"
    if not canaries_path.is_file():
        raise FileNotFoundError(f"canaries.yaml not found at {canaries_path}")
    canaries = Canaries.model_validate(yaml.safe_load(canaries_path.read_text()))
    if canaries.persona != persona.slug:
        raise ValueError(
            f"canaries.persona ({canaries.persona}) != persona.slug ({persona.slug})"
        )

    # Render node templates through Jinja (persona context) before parsing —
    # node files reference persona.coherence.world.* (e.g. world.instance.node.*)
    # so per-instance identity (mac/ip/pids/rss) diverges per persona instead of
    # shipping byte-identical. Lures already render this way; nodes must too.
    # See persona-rotation remediation tells #2 / #53. Local import avoids any
    # render<-models import-order coupling.
    from bzb.render.jinja_env import make_env

    _node_env = make_env()
    _node_ctx = {"persona": persona.model_dump(mode="json")}

    nodes: dict[str, Node] = {}
    for ref in persona.nodes:
        node_path = root / "nodes" / f"{ref.id}.yaml"
        if not node_path.is_file():
            raise FileNotFoundError(f"nodes/{ref.id}.yaml not found")
        _node_text = _node_env.from_string(node_path.read_text()).render(**_node_ctx)
        node = Node.model_validate(yaml.safe_load(_node_text))
        if node.node_id != ref.id:
            raise ValueError(
                f"nodes/{ref.id}.yaml has node_id={node.node_id}, expected {ref.id}"
            )
        nodes[ref.id] = node

    # Cross-ref: every canary_slot referenced by a node must exist
    for nid, node in nodes.items():
        for slot in node.canary_slots:
            if slot not in canaries.slots:
                raise ValueError(
                    f"node {nid} references canary slot {slot} not defined in canaries.yaml"
                )

    # Cross-ref: every lure path referenced by a node must exist
    for nid, node in nodes.items():
        for lure in node.lures:
            if not (root / lure).is_file():
                raise FileNotFoundError(f"node {nid} references missing lure: {lure}")

    # Cross-ref: every internal_ip is unique across nodes
    seen_ips: dict[str, str] = {}
    for nid, node in nodes.items():
        ip = node.persona_local.internal_ip
        if ip in seen_ips:
            raise ValueError(
                f"internal_ip {ip} used by both {seen_ips[ip]} and {nid}"
            )
        seen_ips[ip] = nid

    return Bundle(root=root, persona=persona, nodes=nodes, canaries=canaries)
