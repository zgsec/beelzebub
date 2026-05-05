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
import json
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
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
        )


def fire(target: str, port: int, probe: Probe) -> tuple[int, dict, bytes]:
    """Fire probe; return (status, headers, body)."""
    url = f"http://{target}:{port}{probe.path}"
    r = requests.request(probe.method, url, data=probe.body or None, timeout=15)
    return r.status_code, dict(r.headers), r.content


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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("service", help="Name of the service from services.yaml")
    ap.add_argument("--lure-target", default="localhost",
                    help="Host where the lure is running (default: localhost)")
    ap.add_argument("--lure-port", type=int, default=None,
                    help="Override lure port (default: from services.yaml real_port)")
    ap.add_argument("--no-real-service", action="store_true",
                    help="Skip docker pull + real-service comparison; only check static expectations")
    args = ap.parse_args()

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
                lure_resp = fire(args.lure_target, lure_port, probe)
            except requests.RequestException as e:
                failures_by_probe[probe.name] = [f"lure unreachable: {e}"]
                print(f"  FAIL: lure unreachable: {e}")
                continue

            static_failures = check_static_expectations(probe, *lure_resp)
            failures = list(static_failures)

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
