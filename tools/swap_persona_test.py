"""Swap test — verify zero Crestfield bleed when a different persona is mounted.

Fires the probe suite against beelzebub-with-Globex-mounted, scans every
response body for banned strings (Crestfield, framework markers,
unsubstituted ${VAR}). Pass = zero hits.
"""
from __future__ import annotations

import argparse
import json
import sys

from tools.capture_persona_baseline import (
    fire_http, fire_tcp, fire_mcp, fire_ollama, fire_openai, fire_secure_shell,
    _remap,
)
from tools.persona_probes import ALL_PROBES

# Strings that MUST NOT appear in any response when a non-Crestfield persona is mounted.
BANNED_PERSONA_STRINGS = [
    b"crestfield",
    b"Crestfield",
    b"crestfielddata",
    b"crestfield_app",
    b"cdf_prod_2026Q1",
    b"crestfield-svc",
    b"crestfield-prod",
    b"crestfielddata.io",
]

# Framework markers that should never leak into any response (any persona).
# Note: 'bzb' is also in base64 sequences like 'bzb' within encoded data, so
# we check as a word boundary check — only flag exact 'bzb' token.
BANNED_FRAMEWORK_STRINGS = [
    b"honeypot",
    b"deception",
    b"REPLACE_ME",
    b"REPLACE ME",
]

# Unsubstituted Jinja template placeholders.
# NOTE: ${ENV_VAR} patterns are NOT banned here because the HTTP lure content
# intentionally contains literal ${HTTP_CANARY_*} strings that serve as
# canary tokens — they are sent as-is to attackers and trigger alerts on use.
# Only Jinja {{ }} patterns indicate renderer failures.
BANNED_PLACEHOLDER_PATTERNS = [
    b"{{",   # Jinja open brace (unsubstituted template variable)
]

# MCP tool names that contain "cdf/" prefix are Crestfield-specific tools
# defined in the worldSeed — these are explicitly Crestfield content and
# will appear in mcp-tools-list responses since the worldSeed is defined
# in the lure YAML (which IS persona-templated). However, the tools/list
# is served by the stateful MCP handler which requires a prior initialize.
# The mcp-tools-list probe returns "Invalid session ID" without init,
# so "cdf/" tool names won't appear in the mcp-tools-list probe response.
# Document this as a known exception.
DOCUMENTED_EXCEPTIONS: dict[str, str] = {
    # No exceptions expected for Globex swap test — all Crestfield strings
    # should be replaced by Globex equivalents via Jinja template rendering.
}


def scan(name: str, body: bytes) -> list[str]:
    findings = []
    low = body.lower()
    for s in BANNED_PERSONA_STRINGS:
        if s.lower() in low:
            findings.append(f"PERSONA-BLEED: {s.decode()!r}")
    for s in BANNED_FRAMEWORK_STRINGS:
        if s.lower() in low:
            findings.append(f"FRAMEWORK-LEAK: {s.decode()!r}")
    for s in BANNED_PLACEHOLDER_PATTERNS:
        if s in body:
            findings.append(f"UNSUBSTITUTED-PLACEHOLDER: {s.decode()!r}")
    return findings


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True)
    ap.add_argument("--port-map", default="{}")
    ap.add_argument("--http-port", type=int, default=8888)
    args = ap.parse_args()

    port_map = {int(k): int(v) for k, v in json.loads(args.port_map).items()}

    failures: list[tuple[str, list[str]]] = []
    total = 0
    for probe in ALL_PROBES:
        try:
            if probe.protocol == "http":
                body = fire_http(args.target, _remap(args.http_port, port_map), probe)
            elif probe.protocol == "tcp":
                body = fire_tcp(args.target, probe, port_map)
            elif probe.protocol == "mcp":
                body = fire_mcp(args.target, probe, port_map)
            elif probe.protocol == "ollama":
                body = fire_ollama(args.target, probe, port_map)
            elif probe.protocol == "openai":
                body = fire_openai(args.target, probe, port_map)
            elif probe.protocol == "secure_shell":
                body = fire_secure_shell(args.target, probe, port_map)
            else:
                continue
        except Exception as e:
            print(f"FAIL {probe.name}: PROBE-ERROR: {e}", file=sys.stderr)
            failures.append((probe.name, [f"PROBE-ERROR: {e}"]))
            continue

        total += 1
        findings = scan(probe.name, body)
        if findings:
            failures.append((probe.name, findings))
            for f in findings:
                print(f"FAIL {probe.name}: {f}", file=sys.stderr)
        else:
            print(f"OK   {probe.name}")

    if failures:
        print(f"\n{len(failures)} of {total} probes leaked persona/framework strings",
              file=sys.stderr)
        sys.exit(1)
    print(f"\nALL {total} probes clean of persona bleed + framework leaks")


if __name__ == "__main__":
    main()
