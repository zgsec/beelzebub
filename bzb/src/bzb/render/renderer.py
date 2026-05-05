"""Renderer — bundle + node id → deterministic output tree."""
from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

import yaml as _yaml

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


def render_lures(bundle: Bundle, node_id: str, out_dir: Path) -> None:
    """Render every lure file referenced by the node into out_dir."""
    from bzb.render.jinja_env import make_env

    node = bundle.nodes[node_id]
    ctx = build_context(bundle, node_id)
    env = make_env()
    for lure_rel in node.lures:
        src = bundle.root / lure_rel
        dst = out_dir / lure_rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        if not src.is_file():
            raise FileNotFoundError(f"lure not found: {src}")
        text = src.read_text()
        rendered = env.from_string(text).render(**ctx)
        dst.write_text(rendered)


def render_env_file(
    bundle: Bundle,
    node_id: str,
    *,
    aggregator_url: str,
    aggregator_token: str,
    sensor_id: str,
) -> str:
    """Render the .env file for a node's docker-compose stack."""
    node = bundle.nodes[node_id]
    lines: list[str] = []

    # Aggregator + identity
    lines.append(f"AGGREGATOR_URL={aggregator_url}")
    lines.append(f"AGGREGATOR_TOKEN={aggregator_token}")
    lines.append(f"SENSOR_ID={sensor_id}")

    # Persona vars passed through to beelzebub at startup
    lines.append(f"PERSONA_SLUG={bundle.persona.slug}")
    lines.append(f"PERSONA_INTERNAL_DOMAIN={bundle.persona.identity.internal_domain}")
    lines.append(f"PERSONA_PUBLIC_DOMAIN={bundle.persona.identity.public_domain}")

    # Canary slots — only emit slots with an active token_id
    for slot_name in node.canary_slots:
        slot = bundle.canaries.slots[slot_name]
        if slot.token_id:
            lines.append(f"{slot_name}={slot.token_id}")

    # Node-level env_overrides
    for k, v in sorted(node.env_overrides.items()):
        lines.append(f"{k}={v}")

    lines.append("")  # trailing newline
    return "\n".join(lines)


def render_compose(
    bundle: Bundle,
    node_id: str,
    *,
    image_org: str,
    image_tag: str,
    p0f_tag: str = "latest",
    extra_exporter_env: list[str] | None = None,
) -> str:
    """Render the docker-compose.yml for a node from the framework template."""
    from bzb.render.jinja_env import make_env

    tmpl_path = (
        Path(__file__).parent.parent / "templates" / "sensor-compose.yml.j2"
    )
    env = make_env()
    return env.from_string(tmpl_path.read_text()).render(
        image_org=image_org,
        image_tag=image_tag,
        p0f_tag=p0f_tag,
        extra_exporter_env=extra_exporter_env or [],
    )


def render_node(
    bundle: Bundle,
    node_id: str,
    out_root: Path,
    *,
    image_org: str = "honeypot",
    image_tag: str = "v0.1.0",
    aggregator_url: str = "",
    aggregator_token: str = "",
    sensor_id: str = "",
) -> Path:
    """Render the full output tree for one node. Returns out_root/<slug>/<node_id>/."""
    from bzb.render.coherence import render_etc_hosts, render_bash_history
    from bzb.render.sha import sha256_of_tree

    out = out_root / bundle.persona.slug / node_id
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)

    # docker-compose.yml
    (out / "docker-compose.yml").write_text(
        render_compose(bundle, node_id, image_org=image_org, image_tag=image_tag,
                      extra_exporter_env=[k for k in bundle.nodes[node_id].env_overrides])
    )

    # .env
    (out / ".env").write_text(
        render_env_file(bundle, node_id,
                       aggregator_url=aggregator_url,
                       aggregator_token=aggregator_token,
                       sensor_id=sensor_id or node_id)
    )

    # persona/ dir mounted into beelzebub
    persona_dir = out / "persona"
    persona_dir.mkdir()

    # persona.yaml + node yaml + canaries — full bundle context for beelzebub
    (persona_dir / "persona.yaml").write_text(
        _yaml.safe_dump(bundle.persona.model_dump(mode="json"), sort_keys=True)
    )
    (persona_dir / "node.yaml").write_text(
        _yaml.safe_dump(bundle.nodes[node_id].model_dump(mode="json"), sort_keys=True)
    )
    (persona_dir / "canaries.yaml").write_text(
        _yaml.safe_dump(bundle.canaries.model_dump(mode="json"), sort_keys=True)
    )

    # Lures (substituted)
    render_lures(bundle, node_id, persona_dir)

    # Coherence artifacts
    coh = persona_dir / "coherence"
    coh.mkdir()
    (coh / "etc-hosts").write_text(render_etc_hosts(bundle, node_id))
    bash_history = render_bash_history(bundle, node_id)
    if bash_history:
        (coh / "bash-history").write_text(bash_history)

    # config_sha256
    sha = sha256_of_tree(out)
    (out / "config_sha256").write_text(sha + "\n")

    # README.md
    (out / "README.md").write_text(
        f"# {bundle.persona.display_name} — {node_id}\n\n"
        f"Generated by `bzb persona render`. config_sha256: `{sha}`\n"
    )

    return out
