"""Coherence renderers — /etc/hosts, bash_history seeds."""
from __future__ import annotations

from bzb.models.bundle import Bundle
from bzb.render.jinja_env import make_env
from bzb.render.renderer import build_context


def render_etc_hosts(bundle: Bundle, node_id: str) -> str:
    tmpl_path = bundle.root / bundle.persona.coherence.hosts_file_template
    if not tmpl_path.is_file():
        raise FileNotFoundError(f"hosts template not found: {tmpl_path}")
    ctx = build_context(bundle, node_id)
    env = make_env()
    return env.from_string(tmpl_path.read_text()).render(**ctx)


def render_bash_history(bundle: Bundle, node_id: str) -> str:
    seeds = bundle.persona.coherence.ssh_history_seeds.get(node_id, [])
    return "\n".join(seeds) + ("\n" if seeds else "")
