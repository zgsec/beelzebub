"""Fire all probes at a target sensor; record exact response bytes as JSONL.

Usage:
    python tools/capture_persona_baseline.py \
        --target sensor.example.com \
        > tests/persona-baseline-crestfield.jsonl

    # With port remapping (e.g. local docker-compose with offset ports):
    python tools/capture_persona_baseline.py \
        --target localhost \
        --http-port 18888 \
        --port-map '{"22": 12222, "2222": 12223, "3306": 13306, "6379": 16379, \
"8086": 18086, "8000": 18000, "8001": 18001, "11434": 11434}' \
        > tests/persona-baseline-crestfield.jsonl

Output: one JSON object per probe per line:
    {"name": "http-root", "protocol": "http", "request_repr": "...",
     "response_b64": "...", "response_len": 123, "captured_at": "..."}
"""
from __future__ import annotations

import argparse
import base64
import json
import socket
import time
from datetime import datetime, timezone

import requests

from tools.persona_probes import ALL_PROBES, Probe


def _remap(orig: int, port_map: dict[int, int]) -> int:
    """Return the remapped port, or the original if no mapping is defined."""
    return port_map.get(orig, orig)


def fire_http(target: str, port: int, p: Probe) -> bytes:
    url = f"http://{target}:{port}{p.recipe['path']}"
    method = p.recipe.get("method", "GET")
    body = p.recipe.get("body", "")
    r = requests.request(method, url, data=body, timeout=10, allow_redirects=False)
    return f"HTTP/{r.raw.version // 10}.{r.raw.version % 10} {r.status_code}\r\n".encode() + \
           "".join(f"{k}: {v}\r\n" for k, v in r.headers.items()).encode() + \
           b"\r\n" + r.content


def fire_tcp(target: str, p: Probe, port_map: dict[int, int] | None = None) -> bytes:
    port_map = port_map or {}
    port = _remap(p.recipe["port"], port_map)
    send = p.recipe.get("send", b"")
    read_bytes = p.recipe.get("read_bytes", 1024)
    with socket.create_connection((target, port), timeout=10) as s:
        if send:
            s.sendall(send)
        s.settimeout(2)
        data = b""
        try:
            while len(data) < read_bytes:
                chunk = s.recv(min(4096, read_bytes - len(data)))
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            pass
        return data


def fire_mcp(target: str, p: Probe, port_map: dict[int, int] | None = None) -> bytes:
    """MCP requests use the JSON-RPC over HTTP transport."""
    port_map = port_map or {}
    port = _remap(8000, port_map)
    payload = {"jsonrpc": "2.0", "id": 1, **{
        "method": p.recipe["method"],
        "params": p.recipe.get("params", {}),
    }}
    r = requests.post(f"http://{target}:{port}/mcp", json=payload, timeout=10)
    return r.content


def fire_ollama(target: str, p: Probe, port_map: dict[int, int] | None = None) -> bytes:
    port_map = port_map or {}
    port = _remap(11434, port_map)
    method = "POST" if "body" in p.recipe else "GET"
    body = p.recipe.get("body", "")
    r = requests.request(method, f"http://{target}:{port}{p.recipe['path']}",
                          data=body, timeout=10)
    return r.content


def fire_openai(target: str, p: Probe, port_map: dict[int, int] | None = None) -> bytes:
    port_map = port_map or {}
    port = _remap(8001, port_map)
    method = "POST" if "body" in p.recipe else "GET"
    body = p.recipe.get("body", "")
    r = requests.request(method, f"http://{target}:{port}{p.recipe['path']}",
                          data=body, timeout=10)
    return r.content


def fire_secure_shell(target: str, p: Probe, port_map: dict[int, int] | None = None) -> bytes:
    """Banner / auth-fail / single-command capture."""
    port_map = port_map or {}
    port = _remap(p.recipe["port"], port_map)
    kind = p.recipe["kind"]
    if kind == "banner_only":
        with socket.create_connection((target, port), timeout=10) as s:
            s.settimeout(3)
            return s.recv(256)
    if kind in ("auth_fail", "interactive_cmd"):
        try:
            import paramiko
        except ImportError:
            return b"<<paramiko-not-installed>>"
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(target, port=port,
                          username=p.recipe.get("user", ""),
                          password=p.recipe.get("password", ""),
                          timeout=10, banner_timeout=10, auth_timeout=10,
                          look_for_keys=False, allow_agent=False)
            if kind == "auth_fail":
                return b"<<auth-succeeded-unexpected>>"
            stdin, stdout, stderr = client.exec_command(p.recipe["command"], timeout=10)
            return stdout.read() + stderr.read()
        except paramiko.AuthenticationException:
            return b"<<auth-failed-as-expected>>"
        except Exception as e:
            return f"<<error: {type(e).__name__}: {e}>>".encode()
        finally:
            client.close()
    return b"<<unknown-kind>>"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True, help="Sensor host:port or host")
    ap.add_argument("--http-port", type=int, default=8888)
    ap.add_argument("--port-map", default="{}",
                    help="JSON object {orig_port: mapped_port} for localhost-with-remapped-ports captures")
    args = ap.parse_args()
    port_map: dict[int, int] = {int(k): int(v) for k, v in json.loads(args.port_map).items()}

    for probe in ALL_PROBES:
        try:
            if probe.protocol == "http":
                data = fire_http(args.target, _remap(args.http_port, port_map), probe)
            elif probe.protocol == "tcp":
                data = fire_tcp(args.target, probe, port_map)
            elif probe.protocol == "mcp":
                data = fire_mcp(args.target, probe, port_map=port_map)
            elif probe.protocol == "ollama":
                data = fire_ollama(args.target, probe, port_map=port_map)
            elif probe.protocol == "openai":
                data = fire_openai(args.target, probe, port_map=port_map)
            elif probe.protocol == "secure_shell":
                data = fire_secure_shell(args.target, probe, port_map)
            else:
                data = b"<<unknown-protocol>>"
        except Exception as e:
            data = f"<<probe-error: {type(e).__name__}: {e}>>".encode()

        rec = {
            "name": probe.name,
            "protocol": probe.protocol,
            "request_repr": repr(probe.recipe),
            "response_b64": base64.b64encode(data).decode(),
            "response_len": len(data),
            "captured_at": datetime.now(timezone.utc).isoformat(),
        }
        print(json.dumps(rec, sort_keys=True))
        time.sleep(0.5)  # rate-limit


if __name__ == "__main__":
    main()
