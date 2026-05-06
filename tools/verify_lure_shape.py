"""Lure shape-verification harness.

Compares a beelzebub lure response to a real upstream service for
structural agreement (status, content-type, header set, JSON key set,
forbidden-key absence). Designed to catch the AS63949-style detection
signatures before lures ship.

Usage:
    python tools/verify_lure_shape.py <service-name> [--no-real-service]

If --no-real-service is passed, only schema-checks the lure response
against the static expectations in services.yaml (skips docker pull
and live diff). Useful for CI where we don't want to run docker.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import requests
import yaml


SERVICES_YAML = Path(__file__).parent / "lure_verify" / "services.yaml"


@dataclass
class Probe:
    name: str
    method: str
    path: str
    body: str = ""
    expect_status: int | None = None
    expect_status_in: list[int] | None = None
    expect_content_type_contains: str | None = None
    expect_keys: list[str] | None = None
    expect_keys_only: list[str] | None = None
    forbidden_keys: list[str] | None = None
    expect_body_contains: list[str] | None = None
    expect_response_headers_present: list[str] | None = None
    wildcard_paths: list[str] | None = None
    notes: str = ""
    forbidden_substrings: list[str] | None = None  # trigger-string check (G.1)
    # G.1.d: minimum acceptable end-to-end latency (seconds). When set, the
    # live-runner harness flags responses faster than this as suspicious
    # (real LLM endpoints take >=1s; static-template lures answer in
    # microseconds). The static_check.py simulator can't measure live
    # latency, so it skips this check (documented in code).
    latency_min_seconds: float | None = None
    # G.1.d: per-key regex assertions against the JSON response body.
    # Map of dotted-path → regex string. e.g. {"object": "^chat\\.completion$"}
    # confirms the OpenAI-compat literal that distinguishes a real chat
    # endpoint from a generic /v1/chat/completions stub. Dotted paths
    # support `choices.0.finish_reason` for nested arrays/objects.
    expect_field_value_pattern: dict[str, str] | None = None

    @classmethod
    def from_dict(cls, d: dict) -> "Probe":
        return cls(
            name=d["name"],
            method=d["method"],
            path=d["path"],
            body=d.get("body", ""),
            expect_status=d.get("expect_status"),
            expect_status_in=d.get("expect_status_in"),
            expect_content_type_contains=d.get("expect_content_type_contains"),
            expect_keys=d.get("expect_keys"),
            expect_keys_only=d.get("expect_keys_only"),
            forbidden_keys=d.get("forbidden_keys"),
            expect_body_contains=d.get("expect_body_contains"),
            expect_response_headers_present=d.get("expect_response_headers_present"),
            wildcard_paths=d.get("wildcard_paths"),
            notes=d.get("notes", ""),
            forbidden_substrings=d.get("forbidden_substrings"),
            latency_min_seconds=d.get("latency_min_seconds"),
            expect_field_value_pattern=d.get("expect_field_value_pattern"),
        )


def fire(target: str, port: int, probe: Probe) -> tuple[int, dict, bytes]:
    """Fire probe; return (status, headers, body). Back-compat wrapper that
    drops the latency. Live callers that need to enforce
    Probe.latency_min_seconds should use fire_with_latency() instead."""
    status, headers, body, _ = fire_with_latency(target, port, probe)
    return status, headers, body


def fire_with_latency(target: str, port: int, probe: Probe) -> tuple[int, dict, bytes, float]:
    """Fire probe; return (status, headers, body, latency_seconds).
    Latency is measured around the requests call with time.monotonic()."""
    url = f"http://{target}:{port}{probe.path}"
    started = time.monotonic()
    r = requests.request(probe.method, url, data=probe.body or None, timeout=15)
    elapsed = time.monotonic() - started
    return r.status_code, dict(r.headers), r.content, elapsed


ISO_TIMESTAMP_RE = re.compile(
    rb"\b(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2}))\b"
)


def check_timestamp_realism(body: bytes, max_age_days: int = 7) -> list[str]:
    """Verify timestamps in the response are fresh and timezone-consistent.

    Catches two May-2026 fleet-detection signals:
    - Frozen template values (timestamps >max_age_days old)
    - Timezone mixing within a single response (e.g. UTC + +08:00)
    - Future timestamps (clock skew or template artefact)

    NOTE: this check is intentionally broad — any ISO-8601 timestamp in the
    response body is evaluated. Services that legitimately embed historical
    timestamps (e.g. a "last_updated" field for a static resource) will trip
    this check. Known limitation: per-endpoint freshness comparison (verifying
    that two sequential probes produce different `created` values) is deferred
    to a follow-on harness mode.
    """
    failures = []
    matches = ISO_TIMESTAMP_RE.findall(body)
    if not matches:
        return failures  # no timestamps — nothing to check

    now = datetime.now(timezone.utc)
    parsed: list[datetime] = []
    timezones: set[str] = set()

    for m in matches:
        s = m.decode("ascii", errors="replace")
        try:
            if s.endswith("Z"):
                dt = datetime.fromisoformat(s[:-1]).replace(tzinfo=timezone.utc)
                timezones.add("UTC")
            else:
                dt = datetime.fromisoformat(s)
                # Extract the timezone offset string for consistency comparison
                # Offsets are either +HH:MM or -HH:MM (6 chars) at the end
                offset = s[-6:] if len(s) >= 6 and s[-6] in ("+", "-") else s[-5:]
                timezones.add(offset)
            parsed.append(dt)
        except ValueError:
            continue

    if len(timezones) > 1:
        failures.append(
            f"TIMESTAMP TIMEZONE MIXED: {sorted(timezones)} "
            f"(real services use one consistent tz per response)"
        )

    for dt in parsed:
        age = now - dt.astimezone(timezone.utc)
        if age > timedelta(days=max_age_days):
            failures.append(
                f"TIMESTAMP STALE: {dt.isoformat()} is {age.days} days old "
                f"(>{max_age_days}d threshold — frozen template value, not per-request)"
            )
        if age < timedelta(seconds=-60):
            failures.append(
                f"TIMESTAMP FUTURE: {dt.isoformat()} is in the future "
                f"(clock skew or template value)"
            )

    return failures


def check_cross_port_uniformity(target: str, ports: list[int]) -> list[str]:
    """Fire `GET /` at each port; flag if two ports return structurally identical responses.

    The May-2026 fleet methodology used cross-port uniformity as a strong fleet-detection
    heuristic — every probed port returning the same JSON template is the strongest single
    signal in the entire detection chain. Real hosts running real services produce
    different responses on different ports.
    """
    results: dict[int, tuple] = {}  # port -> (status, content-type, body-hash)
    for port in ports:
        try:
            r = requests.get(f"http://{target}:{port}/", timeout=5)
            ct = r.headers.get("Content-Type", "").split(";")[0].strip()
            body_hash = hashlib.sha256(r.content[:256]).hexdigest()
            results[port] = (r.status_code, ct, body_hash)
        except requests.RequestException:
            results[port] = (None, None, None)

    failures = []
    by_signature: dict[tuple, list[int]] = {}
    for port, sig in results.items():
        if sig == (None, None, None):
            continue  # port unreachable; skip uniformity check for it
        by_signature.setdefault(sig, []).append(port)

    for sig, sig_ports in by_signature.items():
        if len(sig_ports) > 1:
            failures.append(
                f"CROSS-PORT UNIFORMITY: ports {sig_ports} returned identical "
                f"response signature {sig} — kitchen-sink template detected"
            )
    return failures


def check_latency(probe: Probe, actual_seconds: float) -> list[str]:
    """G.1.d: assert end-to-end latency meets the probe's latency_min_seconds
    floor. Returns a non-empty failure list if the response was too fast —
    motivated researchers use sub-second response times as a signal that an
    LLM-shaped endpoint is template-backed, not actually inferring tokens.

    Only meaningful when actually firing a live request (the static-only
    simulator skips this; see static_check.py)."""
    if probe.latency_min_seconds is None:
        return []
    if actual_seconds < probe.latency_min_seconds:
        return [
            f"LATENCY TOO FAST: response in {actual_seconds:.3f}s "
            f"< minimum {probe.latency_min_seconds}s "
            f"(static-template lures answer faster than real LLMs do)"
        ]
    return []


def _resolve_field_path(obj: Any, path: str) -> Any:
    """Walk a dotted path against a parsed JSON value. Supports object key
    access and integer-indexed array access (e.g. `choices.0.finish_reason`).
    Returns a sentinel string when any segment is missing so the caller can
    distinguish "key absent" from "key present but value is None"."""
    cur = obj
    for seg in path.split("."):
        if isinstance(cur, dict) and seg in cur:
            cur = cur[seg]
        elif isinstance(cur, list) and seg.isdigit() and int(seg) < len(cur):
            cur = cur[int(seg)]
        else:
            return _MISSING
    return cur


_MISSING = object()


def check_field_value_pattern(probe: Probe, body: bytes) -> list[str]:
    """G.1.d: walk each declared dotted path against the JSON response body
    and assert the value matches the regex. Designed for the strict literals
    motivated researchers gate on (e.g. {"object": "^chat\\.completion$"} on
    /v1/chat/completions). Skips silently when the probe doesn't declare any
    field-value patterns."""
    if not probe.expect_field_value_pattern:
        return []
    failures: list[str] = []
    try:
        j = json.loads(body)
    except (ValueError, TypeError):
        # Treat unparseable JSON as a hard failure when the probe expects
        # field-value matches: the patterns can't be evaluated.
        return [
            f"FIELD VALUE PATTERN: JSON parse failed for body of length {len(body)}"
        ]
    for path, pattern in probe.expect_field_value_pattern.items():
        v = _resolve_field_path(j, path)
        if v is _MISSING:
            failures.append(
                f"FIELD VALUE PATTERN: path {path!r} not present in response"
            )
            continue
        # Coerce to str for regex match; bool→"True"/"False" is fine, list/dict
        # match-against-pattern is almost always a probe authoring error.
        s = str(v)
        try:
            if not re.search(pattern, s):
                failures.append(
                    f"FIELD VALUE PATTERN: path {path!r} value {s!r} "
                    f"does not match regex {pattern!r}"
                )
        except re.error as exc:
            failures.append(
                f"FIELD VALUE PATTERN: invalid regex for path {path!r}: {exc}"
            )
    return failures


def check_static_expectations(probe: Probe, status: int, headers: dict, body: bytes) -> list[str]:
    """Verify a single response against the static probe expectations.
    Returns list of failure messages (empty = pass)."""
    failures = []

    if probe.expect_status is not None and status != probe.expect_status:
        failures.append(f"status {status} != expected {probe.expect_status}")
    if probe.expect_status_in and status not in probe.expect_status_in:
        failures.append(f"status {status} not in {probe.expect_status_in}")

    headers_lower = {k.lower(): v for k, v in headers.items()}
    if probe.expect_content_type_contains:
        ct = headers_lower.get("content-type", "")
        if probe.expect_content_type_contains not in ct:
            failures.append(f"content-type {ct!r} missing {probe.expect_content_type_contains!r}")

    if probe.expect_response_headers_present:
        for h in probe.expect_response_headers_present:
            if h.lower() not in headers_lower:
                failures.append(f"missing response header {h}")

    if probe.expect_body_contains:
        text = body.decode("utf-8", errors="replace")
        for s in probe.expect_body_contains:
            if s not in text:
                failures.append(f"body missing required substring {s!r}")

    if probe.expect_keys or probe.expect_keys_only is not None or probe.forbidden_keys:
        try:
            j = json.loads(body)
        except (ValueError, TypeError):
            failures.append(f"JSON parse failed for body of length {len(body)}")
            return failures
        if not isinstance(j, dict):
            failures.append(f"top-level JSON is not a dict (got {type(j).__name__})")
            return failures
        keys = set(j.keys())
        if probe.expect_keys:
            missing = set(probe.expect_keys) - keys
            if missing:
                failures.append(f"JSON missing keys: {sorted(missing)}")
        if probe.expect_keys_only is not None:
            extra = keys - set(probe.expect_keys_only)
            if extra:
                failures.append(f"JSON has unexpected keys: {sorted(extra)} (allowed-only: {probe.expect_keys_only})")
        if probe.forbidden_keys:
            present = keys & set(probe.forbidden_keys)
            if present:
                failures.append(
                    f"JSON contains FORBIDDEN keys: {sorted(present)} "
                    f"(this is the AS63949 detection signature for this endpoint)"
                )

    # Trigger-string check: flag any May-2026 scanner marker in the response body
    if probe.forbidden_substrings:
        for needle in probe.forbidden_substrings:
            if needle.encode() in body:
                failures.append(
                    f"FORBIDDEN substring present in response: {needle!r} "
                    f"(motivated-actor scanner trigger string — would flag as honeypot)"
                )

    # G.1.d: per-field regex assertions against the JSON response body.
    # Distinct from expect_keys (presence) — this nails down the LITERAL
    # value of declared keys (e.g. "object" must equal "chat.completion").
    failures.extend(check_field_value_pattern(probe, body))

    # Timestamp freshness + timezone-consistency check (always runs)
    ts_failures = check_timestamp_realism(body)
    failures.extend(ts_failures)

    return failures


def diff_against_real(probe: Probe,
                      lure: tuple[int, dict, bytes],
                      real: tuple[int, dict, bytes]) -> list[str]:
    """Structural diff between lure response and real upstream response."""
    failures = []
    l_status, l_headers, l_body = lure
    r_status, r_headers, r_body = real

    if l_status != r_status:
        failures.append(f"status: lure={l_status} real={r_status}")

    l_ct = l_headers.get("Content-Type", l_headers.get("content-type", ""))
    r_ct = r_headers.get("Content-Type", r_headers.get("content-type", ""))
    if l_ct.split(";")[0].strip() != r_ct.split(";")[0].strip():
        failures.append(f"content-type mime: lure={l_ct!r} real={r_ct!r}")

    # Header set overlap (>=50%)
    l_hdrs = {k.lower() for k in l_headers}
    r_hdrs = {k.lower() for k in r_headers}
    overlap = len(l_hdrs & r_hdrs) / max(len(r_hdrs), 1)
    if overlap < 0.5:
        failures.append(f"header set overlap {overlap:.2f} < 0.5: lure-only={sorted(l_hdrs - r_hdrs)}, real-only={sorted(r_hdrs - l_hdrs)}")

    # JSON structural — when both look like JSON
    try:
        lj = json.loads(l_body)
        rj = json.loads(r_body)
    except (ValueError, TypeError):
        return failures  # one isn't JSON; skip JSON diff

    if isinstance(lj, dict) and isinstance(rj, dict):
        l_keys = set(lj.keys())
        r_keys = set(rj.keys())
        missing = r_keys - l_keys
        extra = l_keys - r_keys
        if missing:
            failures.append(f"JSON: lure missing real keys: {sorted(missing)}")
        if extra:
            failures.append(f"JSON: lure has keys real doesn't: {sorted(extra)} (potential tell)")
        # Type check on shared keys
        for k in l_keys & r_keys:
            if type(lj[k]).__name__ != type(rj[k]).__name__:
                failures.append(f"JSON: key {k!r} type mismatch: lure={type(lj[k]).__name__} real={type(rj[k]).__name__}")

    return failures


def start_real_service(svc_name: str, svc: dict) -> str:
    """Start the real upstream service in docker; return container name."""
    container = f"verify-real-{svc_name}"
    cmd = ["docker", "run", "-d", "--rm",
           "--name", container,
           "-p", f"{svc['real_port']+10000}:{svc['real_port']}"]
    if svc.get("real_privileged"):
        cmd.append("--privileged")
    for env in svc.get("real_env", []):
        cmd.extend(["-e", env])
    cmd.append(svc["real_image"])
    cmd.extend(svc.get("real_command", []))

    print(f"  starting real service: {' '.join(cmd)}", file=sys.stderr)
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"docker run failed: {r.stderr}")
    # Wait for service to be ready
    real_port = svc["real_port"] + 10000
    deadline = time.time() + 60
    while time.time() < deadline:
        try:
            with socket.create_connection(("localhost", real_port), timeout=2):
                time.sleep(2)  # extra warmup
                return container
        except (ConnectionRefusedError, socket.timeout, OSError):
            time.sleep(1)
    raise RuntimeError(f"real service {svc_name} didn't open port {real_port} in 60s")


def stop_real_service(container: str) -> None:
    subprocess.run(["docker", "stop", container], capture_output=True)


def _run_probe_and_report(probe: Probe, target: str, port: int) -> list[str]:
    """Fire a single probe, run static checks + the live-only latency
    check, and return failures."""
    try:
        status, headers, body, latency = fire_with_latency(target, port, probe)
    except requests.RequestException as e:
        return [f"lure unreachable: {e}"]
    failures = check_static_expectations(probe, status, headers, body)
    failures.extend(check_latency(probe, latency))
    return failures


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("service", help="Name of the service from services.yaml")
    ap.add_argument("--lure-target", default="localhost",
                    help="Host where the lure is running (default: localhost)")
    ap.add_argument("--lure-port", type=int, default=None,
                    help="Override lure port (default: from services.yaml real_port)")
    ap.add_argument("--no-real-service", action="store_true",
                    help="Skip docker pull + real-service comparison; only check static expectations")
    ap.add_argument("--uniformity-check", default=None,
                    help="Comma-separated port list. Fires GET / on each; fails if any two ports "
                         "respond identically. Skips per-service probe loop.")
    ap.add_argument("--motivated-actor-replay", action="store_true",
                    help="Run representative motivated-actor probe replay against the lure")
    args = ap.parse_args()

    # --uniformity-check is a no-service-required mode: skip per-service probe loop
    if args.uniformity_check:
        ports = [int(p) for p in args.uniformity_check.split(",")]
        print(f"\n=== cross-port uniformity check: {ports} ===")
        fails = check_cross_port_uniformity(args.lure_target, ports)
        if fails:
            for f in fails:
                print(f"  FAIL: {f}")
            sys.exit(1)
        print(f"  OK: all {len(ports)} ports return structurally distinct responses")
        sys.exit(0)

    services = yaml.safe_load(SERVICES_YAML.read_text())["services"]
    if args.service not in services:
        print(f"unknown service: {args.service}; known: {list(services)}", file=sys.stderr)
        sys.exit(2)
    svc = services[args.service]
    probes = [Probe.from_dict(p) for p in svc["probes"]]

    lure_port = args.lure_port or svc["real_port"]
    print(f"\n=== verifying lure for {args.service} (port {lure_port}) ===\n")

    failures_by_probe: dict[str, list[str]] = {}

    real_container = None
    real_port_remap = None
    try:
        if not args.no_real_service:
            real_container = start_real_service(args.service, svc)
            real_port_remap = svc["real_port"] + 10000

        for probe in probes:
            print(f"--- probe: {probe.name} ---")
            try:
                lure_status, lure_headers, lure_body, lure_latency = fire_with_latency(
                    args.lure_target, lure_port, probe)
            except requests.RequestException as e:
                failures_by_probe[probe.name] = [f"lure unreachable: {e}"]
                print(f"  FAIL: lure unreachable: {e}")
                continue
            lure_resp = (lure_status, lure_headers, lure_body)

            static_failures = check_static_expectations(probe, *lure_resp)
            failures = list(static_failures)
            # G.1.d: live-only latency floor.
            failures.extend(check_latency(probe, lure_latency))

            if real_container:
                try:
                    real_resp = fire(args.lure_target, real_port_remap, probe)
                    structural_failures = diff_against_real(probe, lure_resp, real_resp)
                    failures.extend(structural_failures)
                except requests.RequestException as e:
                    print(f"  WARN: real service unreachable: {e}")

            if failures:
                failures_by_probe[probe.name] = failures
                print(f"  FAIL ({len(failures)} issues):")
                for f in failures:
                    print(f"    - {f}")
            else:
                print(f"  PASS")
    finally:
        if real_container:
            stop_real_service(real_container)

    # --motivated-actor-replay: fire representative probe fixture filtered by service
    if args.motivated_actor_replay:
        fixture_path = Path(__file__).parent / "lure_verify" / "motivated_actor_probes.yaml"
        fixture_data = yaml.safe_load(fixture_path.read_text())["probes"]
        actor_probes = [
            Probe.from_dict(p) for p in fixture_data
            if p["service"] == args.service
        ]
        print(f"\n=== motivated-actor replay ({len(actor_probes)} probes) ===")
        for probe in actor_probes:
            print(f"--- replay: {probe.name} ---")
            probe_fails = _run_probe_and_report(probe, args.lure_target, lure_port)
            if probe_fails:
                failures_by_probe[f"replay:{probe.name}"] = probe_fails
                print(f"  FAIL ({len(probe_fails)} issues):")
                for f in probe_fails:
                    print(f"    - {f}")
            else:
                print(f"  PASS")

    print(f"\n=== summary ===")
    if not failures_by_probe:
        print(f"ALL {len(probes)} probes passed shape verification")
        sys.exit(0)
    print(f"{len(failures_by_probe)} of {len(probes)} probes have shape failures:")
    for name, fails in failures_by_probe.items():
        print(f"  {name}: {len(fails)} issues")
    sys.exit(1)


if __name__ == "__main__":
    main()
