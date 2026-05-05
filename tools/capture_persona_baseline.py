"""Fire all probes at a target sensor; record exact response bytes as JSONL.

Usage:
    python tools/capture_persona_baseline.py \
        --target sensor.example.com \
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
import sys
import time
from datetime import datetime, timezone

import requests

from tools.persona_probes import ALL_PROBES, Probe


def fire_http(target: str, port: int, p: Probe) -> bytes:
    url = f"http://{target}:{port}{p.recipe['path']}"
    method = p.recipe.get("method", "GET")
    body = p.recipe.get("body", "")
    r = requests.request(method, url, data=body, timeout=10, allow_redirects=False)
    return f"HTTP/{r.raw.version // 10}.{r.raw.version % 10} {r.status_code}\r\n".encode() + \
           "".join(f"{k}: {v}\r\n" for k, v in r.headers.items()).encode() + \
           b"\r\n" + r.content


def fire_tcp(target: str, p: Probe) -> bytes:
    port = p.recipe["port"]
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


def fire_mcp(target: str, p: Probe) -> bytes:
    """MCP requests use the JSON-RPC over HTTP transport."""
    payload = {"jsonrpc": "2.0", "id": 1, **{
        "method": p.recipe["method"],
        "params": p.recipe.get("params", {}),
    }}
    r = requests.post(f"http://{target}:8000/mcp", json=payload, timeout=10)
    return r.content


def fire_ollama(target: str, p: Probe) -> bytes:
    method = "POST" if "body" in p.recipe else "GET"
    body = p.recipe.get("body", "")
    r = requests.request(method, f"http://{target}:11434{p.recipe['path']}",
                          data=body, timeout=10)
    return r.content


def fire_openai(target: str, p: Probe) -> bytes:
    method = "POST" if "body" in p.recipe else "GET"
    body = p.recipe.get("body", "")
    r = requests.request(method, f"http://{target}:8001{p.recipe['path']}",
                          data=body, timeout=10)
    return r.content


def fire_secure_shell(target: str, p: Probe) -> bytes:
    """Banner / auth-fail / single-command capture."""
    port = p.recipe["port"]
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
    args = ap.parse_args()

    for probe in ALL_PROBES:
        try:
            if probe.protocol == "http":
                data = fire_http(args.target, args.http_port, probe)
            elif probe.protocol == "tcp":
                data = fire_tcp(args.target, probe)
            elif probe.protocol == "mcp":
                data = fire_mcp(args.target, probe)
            elif probe.protocol == "ollama":
                data = fire_ollama(args.target, probe)
            elif probe.protocol == "openai":
                data = fire_openai(args.target, probe)
            elif probe.protocol == "secure_shell":
                data = fire_secure_shell(args.target, probe)
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
