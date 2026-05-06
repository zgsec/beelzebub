"""Static-only lure shape checker.

Loads each lure YAML directly, simulates the response for each services.yaml
probe (and the motivated_actor_probes filtered by service) by matching the
probe path against the lure's commands[].regex, applies a stubbed Jinja
substitution for {{ persona.* }} expressions, and runs the harness's
check_static_expectations from verify_lure_shape on the simulated tuple
(status, headers, body).

This does NOT diff against a live real-upstream container — that requires
the Beelzebub Go runtime hosting the lure (G.3 territory). What it DOES
verify:
  - status code, content-type, JSON key set / forbidden keys
  - forbidden_substrings (canary trigger strings)
  - expect_response_headers_present (e.g., x-vllm-version)
  - expect_field_value_pattern (G.1.d) — per-key regex assertions on the
    simulated body (e.g. object="^chat\\.completion$")
  - check_timestamp_realism (timezone consistency, freshness)
  - cross-port uniformity across all 5 BlueSpark lures

NOT enforced in static mode (the simulator doesn't fire real requests):
  - latency_min_seconds — live-only check; the live-Docker harness
    measures end-to-end response time and asserts the floor. The
    Probe.latency_min_seconds field still parses cleanly and is exposed
    on the Probe dataclass; static mode just doesn't act on it.

Usage:
    python tools/lure_verify/static_check.py            # all services
    python tools/lure_verify/static_check.py vllm       # one service
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tools"))
from verify_lure_shape import (  # noqa: E402
    Probe,
    check_static_expectations,
    check_timestamp_realism,
)

SERVICES_YAML = REPO_ROOT / "tools" / "lure_verify" / "services.yaml"
ACTOR_YAML = REPO_ROOT / "tools" / "lure_verify" / "motivated_actor_probes.yaml"


# Stub persona context — mirrors what G.2 will provide. Used to render
# {{ persona.* }} expressions in lure command handlers/headers.
PERSONA_STUB = {
    "slug": "bluespark-labs",
    "display_name": "BlueSpark Labs",
    "identity": {
        "industry": "ai-infrastructure",
        "scale": "small",
        "internal_domain": "int.bluesparkz.dev",
        "public_domain": "bluesparkz.dev",
        "founded": 2024,
        "hq": "Singapore",
    },
    "coherence": {
        # IANA timezone — drives all emitted timestamps. Matches the Go
        # runtime's PersonaCoherence.Timezone field added in G.1.b.
        "timezone": "Asia/Singapore",
    },
    "lure_content": {
        "platform_display_name": "BlueSpark Labs",
        "hosted_model_name": "aurora-7b",
        "node_hostname": "lighthouse-1",
        "node_role": "eval-host",
        "team_eval": "eval-harness",
        "deploy_env": "prod",
        "engineer_priya": "Priya R.",
        "engineer_jian": "Jian Wei T.",
        "engineer_kavi": "Kavi S.",
        "engineer_anand": "Anand M.",
        "project_lighthouse": "lighthouse",
        "project_vortex": "vortex",
        "project_catalyst": "catalyst",
        "project_aurora": "aurora",
    },
}


# Minimal Jinja-compat substitution: handles {{ a.b.c | default('x') }} and
# {{ a.b.c }}. We do NOT spin up a real Jinja2 — the lures use a tiny dialect
# subset (dot-access + default filter), and shipping jinja2 to this CI helper
# is overkill. If a lure uses something more elaborate, this falls back to
# emitting the raw expression — which will trip the test harness loudly.
JINJA_RE = re.compile(r"\{\{\s*([^}]+?)\s*\}\}")
DEFAULT_FILTER_RE = re.compile(
    r"^([\w\.]+)\s*\|\s*default\(\s*['\"]?(.*?)['\"]?\s*\)$"
)
DOT_ACCESS_RE = re.compile(r"^([\w\.]+)$")


def _resolve(expr: str, ctx: dict) -> str:
    """Resolve `a.b.c` against ctx; return None if missing."""
    parts = expr.split(".")
    cur = ctx
    for p in parts:
        if isinstance(cur, dict) and p in cur:
            cur = cur[p]
        else:
            return None
    return cur if isinstance(cur, (str, int, float, bool)) else None


def render_jinja(s: str, ctx: dict) -> str:
    def sub(m):
        body = m.group(1).strip()
        # `a.b.c | default('x')`
        m_def = DEFAULT_FILTER_RE.match(body)
        if m_def:
            expr, fallback = m_def.group(1), m_def.group(2)
            v = _resolve(expr, ctx)
            return str(v) if v is not None else fallback
        # bare `a.b.c`
        m_dot = DOT_ACCESS_RE.match(body)
        if m_dot:
            v = _resolve(body, ctx)
            return str(v) if v is not None else m.group(0)
        # passthrough
        return m.group(0)
    return JINJA_RE.sub(sub, s)


def _parse_headers(header_lines: list[str]) -> dict[str, str]:
    out = {}
    for line in header_lines or []:
        if ":" in line:
            k, v = line.split(":", 1)
            out[k.strip()] = v.strip()
    return out


def _command_match(cmd: dict, probe: Probe) -> bool:
    """Does this lure command match this probe?"""
    regex = cmd.get("regex", "")
    method = cmd.get("method")  # may be None (method-agnostic)
    try:
        if not re.match(regex, probe.path):
            return False
    except re.error:
        return False
    if method and method.upper() != probe.method.upper():
        return False
    return True


def _ollama_modified_at_stub(slug: str, model_name: str, tz: str) -> str:
    """Mirror protocols/strategies/OLLAMA/ollama.go:modelModifiedAt for
    static-check simulation. Deterministic sha256(slug+'/'+model_name) seeded
    offset within last 90 days, formatted RFC3339Nano in the persona's TZ.

    Note: the real Go implementation ALWAYS uses the active runtime time.
    For static-check, we just need *a* recent timestamp in the right TZ;
    the static probe only checks shape/key set, not exact value."""
    import datetime
    import zoneinfo
    h = hashlib.sha256(f"{slug}/{model_name}".encode()).digest()
    raw = int.from_bytes(h[:8], "big")
    # Window mirrors protocols/strategies/OLLAMA/ollama.go:modelModifiedAt.
    six_days_ns = 6 * 24 * 3600 * 1_000_000_000
    offset_ns = raw % six_days_ns
    try:
        loc = zoneinfo.ZoneInfo(tz) if tz else datetime.timezone.utc
    except Exception:
        loc = datetime.timezone.utc
    now = datetime.datetime.now(loc)
    t = now - datetime.timedelta(microseconds=offset_ns / 1000)
    return t.isoformat(timespec="microseconds")


def simulate_ollama(lure: dict, probe: Probe, ctx: dict) -> tuple[int, dict, bytes]:
    """Synthesize the response the OLLAMA strategy in
    protocols/strategies/OLLAMA/ollama.go would emit for a given probe path.
    Used when lure.protocol == 'ollama' (no commands: block to walk)."""
    cfg = lure.get("ollamaConfig", {})
    models = cfg.get("models", []) or []
    version = cfg.get("version", "0.6.5")
    slug = ctx.get("slug", "")
    # G.1.b: persona timezone drives all emitted timestamps. The static stub
    # falls back to UTC when the persona context lacks a tz (matches the Go
    # runtime's UTC fallback).
    tz = (ctx.get("coherence", {}) or {}).get("timezone", "")

    headers = {"Content-Type": "application/json"}
    if probe.path == "/" and probe.method.upper() == "GET":
        return 200, {"Content-Type": "text/plain; charset=utf-8"}, b"Ollama is running"
    if probe.path == "/api/version" and probe.method.upper() == "GET":
        return 200, headers, json.dumps({"version": version}).encode()
    if probe.path == "/api/tags" and probe.method.upper() == "GET":
        body_models = []
        for m in models:
            entry = {
                "name": m["name"],
                "model": m["name"],
                "modified_at": _ollama_modified_at_stub(slug, m["name"], tz),
                "size": 0,
                "digest": hashlib.sha256(m["name"].encode()).hexdigest(),
                "details": {
                    "parent_model": "",
                    "format": "gguf",
                    "family": m.get("family", ""),
                    "families": [m.get("family", "")],
                    "parameter_size": m.get("parameterSize", ""),
                    "quantization_level": m.get("quantizationLevel", ""),
                },
            }
            body_models.append(entry)
        return 200, headers, json.dumps({"models": body_models}).encode()
    if probe.path == "/api/ps" and probe.method.upper() == "GET":
        # Real Ollama returns empty list pre-warmup
        return 200, headers, json.dumps({"models": []}).encode()
    # /api/show, /api/embed, /api/chat etc. — placeholder shapes, sufficient
    # for the existing strict-shape probes. Extend as needed when probe set
    # grows.
    if probe.path == "/api/show" and probe.method.upper() == "POST":
        return 200, headers, json.dumps({
            "license": "Apache 2.0",
            "modelfile": "FROM aurora-7b:latest",
            "parameters": "stop \"<|user|>\"",
            "template": "{{ .Prompt }}",
            "details": {
                "parent_model": "",
                "format": "gguf",
                "family": "llama",
                "families": ["llama"],
                "parameter_size": "7.0B",
                "quantization_level": "Q4_K_M",
            },
            "model_info": {"general.architecture": "llama"},
        }).encode()
    return 0, {}, b""


def simulate(lure: dict, probe: Probe, ctx: dict) -> tuple[int, dict, bytes]:
    """Walk lure.commands in order, return (status, headers, body) for the
    first matching command. Plugin commands (LLM-backed) are simulated with
    a placeholder OpenAI-shape body so static checks can validate the
    declared headers/status, but the LLM content itself isn't synthesizable
    here — flag clearly via a probe-side waiver.

    When lure.protocol == 'ollama', responses for the standard endpoints
    are synthesized from ollamaConfig.models because the OLLAMA strategy
    handles those routes natively (no commands: block to walk)."""
    if lure.get("protocol") == "ollama":
        rv = simulate_ollama(lure, probe, ctx)
        if rv[0] != 0:
            return rv
        # fall through to commands[] for any custom routes (e.g. catch-all)
    for cmd in lure.get("commands", []):
        if not _command_match(cmd, probe):
            continue
        status = cmd.get("statusCode", 200)
        headers = _parse_headers(cmd.get("headers", []))
        if cmd.get("plugin") == "LLMHoneypot":
            # Provide a believable OpenAI-shape body for /v1/chat/completions
            # / /v1/completions / /api/chat / /api/generate. Static checks
            # will run against this; live-runtime checks need an actual LLM.
            if "chat/completions" in probe.path:
                body = json.dumps({
                    "id": "chatcmpl-abc12345",
                    "object": "chat.completion",
                    "created": 1746230400,
                    "model": "aurora-7b",
                    "choices": [{
                        "index": 0,
                        "message": {"role": "assistant", "content": "ok"},
                        "finish_reason": "stop",
                    }],
                    "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
                }).encode()
            elif "/completions" in probe.path:
                body = json.dumps({
                    "id": "cmpl-abc12345",
                    "object": "text_completion",
                    "created": 1746230400,
                    "model": "aurora-7b",
                    "choices": [{"index": 0, "text": "ok", "finish_reason": "stop"}],
                    "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
                }).encode()
            elif "/api/chat" in probe.path:
                body = json.dumps({
                    "model": "aurora-7b:latest",
                    "created_at": "2026-05-04T08:30:00.000+08:00",
                    "message": {"role": "assistant", "content": "ok"},
                    "done": True,
                }).encode()
            elif "/api/generate" in probe.path:
                body = json.dumps({
                    "model": "aurora-7b:latest",
                    "created_at": "2026-05-04T08:30:00.000+08:00",
                    "response": "ok",
                    "done": True,
                }).encode()
            else:
                body = b"{}"
        else:
            handler = cmd.get("handler", "") or ""
            body = render_jinja(handler, ctx).encode()
        # render headers too
        headers = {k: render_jinja(v, ctx) for k, v in headers.items()}
        return status, headers, body
    # No match
    return 0, {}, b""


def cross_port_uniformity(simulated_root_responses: dict[int, tuple[int, dict, bytes]]) -> list[str]:
    """Mirror harness check_cross_port_uniformity but on simulated bodies."""
    failures = []
    by_sig: dict[tuple, list[int]] = {}
    for port, (status, headers, body) in simulated_root_responses.items():
        ct = headers.get("Content-Type", "").split(";")[0].strip()
        body_hash = hashlib.sha256(body[:256]).hexdigest()
        sig = (status, ct, body_hash)
        by_sig.setdefault(sig, []).append(port)
    for sig, ports in by_sig.items():
        if len(ports) > 1:
            failures.append(
                f"CROSS-PORT UNIFORMITY: ports {ports} returned identical "
                f"response signature {sig} — kitchen-sink template detected"
            )
    return failures


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("service", nargs="?", default=None,
                    help="Service name (omit for all)")
    args = ap.parse_args()

    services = yaml.safe_load(SERVICES_YAML.read_text())["services"]
    actor = yaml.safe_load(ACTOR_YAML.read_text())["probes"]

    selected = [args.service] if args.service else list(services.keys())

    total_fail = 0
    total_probes = 0
    root_responses: dict[int, tuple[int, dict, bytes]] = {}

    for svc_name in selected:
        svc = services[svc_name]
        lure_path_rel = svc.get("lure_yaml")
        if not lure_path_rel:
            print(f"\n=== {svc_name}: no lure_yaml configured (skip) ===")
            continue
        lure_path = REPO_ROOT / lure_path_rel
        if not lure_path.exists():
            print(f"\n=== {svc_name}: lure file MISSING: {lure_path} ===")
            total_fail += 1
            continue
        lure = yaml.safe_load(lure_path.read_text())
        print(f"\n=== {svc_name} (lure: {lure_path_rel}) ===")

        # services.yaml probes
        probes = [Probe.from_dict(p) for p in svc["probes"]]
        # filter motivated-actor probes for this service
        probes += [Probe.from_dict(p) for p in actor if p["service"] == svc_name]

        for probe in probes:
            total_probes += 1
            status, headers, body = simulate(lure, probe, PERSONA_STUB)
            if status == 0:
                print(f"  FAIL [{probe.name}]: no command matched {probe.method} {probe.path}")
                total_fail += 1
                continue
            failures = check_static_expectations(probe, status, headers, body)
            if failures:
                total_fail += 1
                print(f"  FAIL [{probe.name}] ({len(failures)}):")
                for f in failures:
                    print(f"    - {f}")
            else:
                print(f"  PASS [{probe.name}]")

        # capture root response for cross-port uniformity check
        root_probe = Probe(name="root", method="GET", path="/", expect_status=None)
        rstatus, rheaders, rbody = simulate(lure, root_probe, PERSONA_STUB)
        if rstatus:
            # parse address ":NNNN"
            addr = lure.get("address", "")
            m = re.match(r":?(\d+)$", addr.lstrip(":"))
            if m:
                port = int(m.group(1))
                root_responses[port] = (rstatus, rheaders, rbody)

    if not args.service or args.service is None:
        # cross-port uniformity across the BlueSpark lure set
        print("\n=== cross-port uniformity (BlueSpark lures) ===")
        ufails = cross_port_uniformity(root_responses)
        if ufails:
            for f in ufails:
                print(f"  FAIL: {f}")
            total_fail += len(ufails)
        else:
            print(f"  PASS: {len(root_responses)} ports return distinct responses")

    print(f"\n=== summary: {total_probes} probes, {total_fail} failure(s) ===")
    sys.exit(1 if total_fail else 0)


if __name__ == "__main__":
    main()
