"""Replay the captured probes against the new beelzebub; diff bytes.

Tolerance:
- Timestamps + UUIDs regex-normalized before comparison.
- For LLM-driven SSH command probes (kind=interactive_cmd), use bounded
  byte-match: response length within 0.5x-2.0x of baseline, no self-reference
  leakage, persona-bearing strings present.
"""
from __future__ import annotations

import argparse
import base64
import json
import re
import sys

from tools.capture_persona_baseline import (
    fire_http, fire_tcp, fire_mcp, fire_ollama, fire_openai, fire_secure_shell,
    _remap,
)
from tools.persona_probes import ALL_PROBES

# Regex normalization — timestamps, UUIDs, sequence numbers vary per session
_NORMALIZERS = [
    (re.compile(rb"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z?"), b"<TS>"),
    (re.compile(rb"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"), b"<UUID>"),
    (re.compile(rb"\b\d{10,13}\b"), b"<EPOCH>"),
    # HTTP Date header varies per request
    (re.compile(rb"Date: [^\r\n]+\r\n"), b"Date: <DATE>\r\n"),
    # Content-Length may shift if any timestamp/uuid was in the body
    (re.compile(rb"Content-Length: \d+\r\n"), b"Content-Length: <LEN>\r\n"),
    # MCP session IDs in headers
    (re.compile(rb"Mcp-Session-Id: [^\r\n]+\r\n"), b"Mcp-Session-Id: <SID>\r\n"),
]

# MySQL handshake has a random thread-id + two random auth nonce chunks.
# Normalize by zeroing out the binary portion between the version string null
# and the auth-plugin name.  Called explicitly for tcp-mysql-banner probes.
_MYSQL_HANDSHAKE_RE = re.compile(
    rb"((?:[\x00-\xff]{4})\n8\.0\.[^\x00]+\x00)"  # pkt header + proto10 + version\0
    rb"[\x00-\xff]+"                                # thread-id + nonces + filler
    rb"((?:caching_sha2_password|mysql_native_password)\x00)"  # plugin name
)


def _normalize_mysql(data: bytes) -> bytes:
    return _MYSQL_HANDSHAKE_RE.sub(rb"\g<1><MYSQL-RANDOM>\g<2>", data)


def normalize(data: bytes) -> bytes:
    for pat, repl in _NORMALIZERS:
        data = pat.sub(repl, data)
    return data


def compare_exact(name: str, actual: bytes, expected: bytes) -> str | None:
    a, e = normalize(actual), normalize(expected)
    # MySQL banner has random nonces — apply extra normalization for tcp-mysql probes
    if name.startswith("tcp-mysql"):
        a, e = _normalize_mysql(a), _normalize_mysql(e)
    if a == e:
        return None
    # Produce a short diff hint
    if len(a) != len(e):
        hint = f"length {len(a)} vs {len(e)} after normalization"
    else:
        # Find first differing byte
        for i, (ab, eb) in enumerate(zip(a, e)):
            if ab != eb:
                hint = f"first diff at byte {i}: {a[max(0,i-20):i+20]!r} vs {e[max(0,i-20):i+20]!r}"
                break
        else:
            hint = "identical length but different content"
    return f"BYTE-MISMATCH ({hint})"


def compare_bounded(name: str, actual: bytes, expected: bytes,
                    persona_strings: list[bytes]) -> str | None:
    """Used for LLM-variable responses (SSH interactive_cmd, ollama chat).

    Special case: if both actual and expected are identical probe-framework
    sentinel values (auth-failed, paramiko-not-installed, etc.), the honeypot
    produced the same deterministic non-LLM output — treat as PASS without
    checking persona strings (there are none to check in an auth-rejection).
    """
    _SENTINELS = (
        b"<<auth-failed-as-expected>>",
        b"<<paramiko-not-installed>>",
        b"<<auth-succeeded-unexpected>>",
    )
    for sentinel in _SENTINELS:
        if actual == sentinel and expected == sentinel:
            return None  # deterministic sentinel — exact match, no persona check needed

    if not actual:
        return "EMPTY-RESPONSE"
    ratio = len(actual) / max(len(expected), 1)
    if ratio < 0.5 or ratio > 2.0:
        return f"LENGTH-OUT-OF-RANGE ({len(actual)} vs {len(expected)})"
    low = actual.lower()
    for banned in (b"i am an ai", b"language model", b"honeypot", b"as an ai"):
        if banned in low:
            return f"SELF-REFERENCE-LEAK: contains {banned!r}"
    missing = [s for s in persona_strings if s not in actual]
    if missing:
        return f"PERSONA-STRING-MISSING: {missing!r}"
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True)
    ap.add_argument("--baseline", required=True)
    ap.add_argument("--persona-strings", default="",
                    help="comma-separated strings expected in SSH responses")
    ap.add_argument("--port-map", default="{}",
                    help="JSON object {orig_port: mapped_port}")
    ap.add_argument("--http-port", type=int, default=8888)
    ap.add_argument("--verbose", action="store_true",
                    help="Print actual vs expected bytes for failures")
    args = ap.parse_args()

    port_map = {int(k): int(v) for k, v in json.loads(args.port_map).items()}

    baseline_by_name: dict[str, bytes] = {}
    baseline_protocols: dict[str, str] = {}
    with open(args.baseline) as f:
        for line in f:
            rec = json.loads(line)
            baseline_by_name[rec["name"]] = base64.b64decode(rec["response_b64"])
            baseline_protocols[rec["name"]] = rec["protocol"]

    persona_strings = [s.encode() for s in args.persona_strings.split(",") if s]

    failures: list[tuple[str, str]] = []
    ok_count = 0
    for probe in ALL_PROBES:
        if probe.name not in baseline_by_name:
            print(f"SKIP {probe.name} (not in baseline)")
            continue
        try:
            if probe.protocol == "http":
                actual = fire_http(args.target, _remap(args.http_port, port_map), probe)
            elif probe.protocol == "tcp":
                actual = fire_tcp(args.target, probe, port_map)
            elif probe.protocol == "mcp":
                actual = fire_mcp(args.target, probe, port_map)
            elif probe.protocol == "ollama":
                actual = fire_ollama(args.target, probe, port_map)
            elif probe.protocol == "openai":
                actual = fire_openai(args.target, probe, port_map)
            elif probe.protocol == "secure_shell":
                actual = fire_secure_shell(args.target, probe, port_map)
            else:
                continue
        except Exception as e:
            failures.append((probe.name, f"PROBE-ERROR: {e}"))
            print(f"FAIL {probe.name}: PROBE-ERROR: {e}", file=sys.stderr)
            continue

        expected = baseline_by_name[probe.name]
        # Bounded comparison for any LLM-generated response:
        #   - SSH interactive_cmd probes: bounded + persona-string check
        #   - ollama/openai chat/completions probes: bounded only (no persona strings;
        #     chat responses are generic LLM output, not persona-specific)
        if probe.protocol == "secure_shell" and probe.recipe.get("kind") == "interactive_cmd":
            err = compare_bounded(probe.name, actual, expected, persona_strings)
        elif probe.protocol in ("ollama", "openai") and "body" in probe.recipe:
            err = compare_bounded(probe.name, actual, expected, [])  # no persona strings
        else:
            err = compare_exact(probe.name, actual, expected)
        if err:
            failures.append((probe.name, err))
            print(f"FAIL {probe.name}: {err}", file=sys.stderr)
            if args.verbose:
                print(f"  ACTUAL   ({len(actual)}B): {normalize(actual)[:200]!r}", file=sys.stderr)
                print(f"  EXPECTED ({len(expected)}B): {normalize(expected)[:200]!r}", file=sys.stderr)
        else:
            print(f"OK   {probe.name}")
            ok_count += 1

    total = ok_count + len(failures)
    if failures:
        print(f"\n{len(failures)} of {total} probes regressed",
              file=sys.stderr)
        sys.exit(1)
    print(f"\nALL {total} probes match baseline (within tolerance)")


if __name__ == "__main__":
    main()
