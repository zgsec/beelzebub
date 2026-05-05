"""Renderer — bundle + node id → deterministic output tree."""
from __future__ import annotations

from typing import Any

from bzb.models.bundle import Bundle


def build_context(bundle: Bundle, node_id: str) -> dict[str, Any]:
    """Build the Jinja context for rendering a single node."""
    if node_id not in bundle.nodes:
        raise KeyError(f"node {node_id} not in bundle {bundle.persona.slug}")
    node = bundle.nodes[node_id]

    # Resolve peers
    persona_node_ref = next(
        (n for n in bundle.persona.nodes if n.id == node_id), None
    )
    if persona_node_ref is None:
        raise KeyError(f"node {node_id} not declared in persona.yaml nodes list")
    peers = [
        bundle.nodes[peer_id]
        for peer_id in persona_node_ref.peers
        if peer_id in bundle.nodes
    ]

    # Canary values: pull token_id (if minted) from each slot the node consumes
    canary_values: dict[str, str] = {}
    for slot_name in node.canary_slots:
        slot = bundle.canaries.slots[slot_name]
        if slot.token_id is not None:
            canary_values[slot_name] = slot.token_id
        else:
            # MVP: leave unset; deploy gates on --mint-missing or fails
            canary_values[slot_name] = ""

    return {
        "persona": bundle.persona.model_dump(mode="json"),
        "node": node.model_dump(mode="json"),
        "peers": [p.model_dump(mode="json") for p in peers],
        "canary_values": canary_values,
    }
