"""50-probe regression suite for persona-content baseline + replay.

Each probe is a (protocol, recipe) pair. Recipes are structured so the
capture tool and the replay tool produce identical request bytes.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Probe:
    name: str
    protocol: str  # http | tcp | secure_shell | mcp | ollama | openai
    recipe: dict


# HTTP probes (target :8888)
HTTP_PROBES: list[Probe] = [
    Probe("http-root", "http", {"method": "GET", "path": "/"}),
    Probe("http-robots", "http", {"method": "GET", "path": "/robots.txt"}),
    Probe("http-api-users", "http", {"method": "GET", "path": "/api/v1/users"}),
    Probe("http-api-creds", "http", {"method": "GET", "path": "/api/v1/credentials"}),
    Probe("http-env", "http", {"method": "GET", "path": "/.env"}),
    Probe("http-git-config", "http", {"method": "GET", "path": "/.git/config"}),
    Probe("http-aws", "http", {"method": "GET", "path": "/.aws/credentials"}),
    Probe("http-admin", "http", {"method": "GET", "path": "/admin"}),
    Probe("http-login-post", "http", {"method": "POST", "path": "/login",
                                       "body": "user=admin&pass=admin"}),
    Probe("http-mcp-tools", "http", {"method": "POST", "path": "/mcp",
                                      "body": '{"jsonrpc":"2.0","method":"tools/list"}'}),
]

# TCP probes (banner-grab style, no protocol negotiation)
TCP_PROBES: list[Probe] = [
    Probe("tcp-mysql-banner", "tcp", {"port": 3306, "send": b"", "read_bytes": 256}),
    Probe("tcp-redis-info", "tcp", {"port": 6379, "send": b"INFO\r\n", "read_bytes": 1024}),
    Probe("tcp-influx-ping", "tcp", {"port": 8086,
                                      "send": b"GET /ping HTTP/1.1\r\nHost: x\r\n\r\n",
                                      "read_bytes": 512}),
]

# MCP-protocol probes (target :8000)
MCP_PROBES: list[Probe] = [
    Probe("mcp-initialize", "mcp", {
        "method": "initialize",
        "params": {"protocolVersion": "2024-11-05",
                   "capabilities": {},
                   "clientInfo": {"name": "regression-probe", "version": "1.0"}},
    }),
    Probe("mcp-tools-list", "mcp", {"method": "tools/list", "params": {}}),
    Probe("mcp-tools-call-list-files", "mcp", {
        "method": "tools/call",
        "params": {"name": "list_files", "arguments": {"path": "/etc"}},
    }),
    Probe("mcp-tools-call-read-env", "mcp", {
        "method": "tools/call",
        "params": {"name": "read_file", "arguments": {"path": "/opt/app/.env"}},
    }),
]

# Ollama / OpenAI-compatible (target :11434, :8001)
OLLAMA_PROBES: list[Probe] = [
    Probe("ollama-api-tags", "ollama", {"path": "/api/tags"}),
    Probe("ollama-api-version", "ollama", {"path": "/api/version"}),
    Probe("ollama-chat-simple", "ollama", {"path": "/api/chat",
                                            "body": '{"model":"llama3","messages":[{"role":"user","content":"hello"}]}'}),
]

OPENAI_PROBES: list[Probe] = [
    Probe("openai-models", "openai", {"path": "/v1/models"}),
    Probe("openai-completions", "openai", {"path": "/v1/chat/completions",
                                            "body": '{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}'}),
]

# SSH banner-only probes — interactive shell tested via bounded byte-match in replay
SECURE_SHELL_PROBES: list[Probe] = [
    Probe("ssh-banner-22", "secure_shell", {"port": 22, "kind": "banner_only"}),
    Probe("ssh-banner-2222", "secure_shell", {"port": 2222, "kind": "banner_only"}),
    Probe("ssh-auth-fail", "secure_shell", {"port": 22, "kind": "auth_fail",
                                    "user": "root", "password": "wrong"}),
    Probe("ssh-cmd-whoami", "secure_shell", {"port": 22, "kind": "interactive_cmd",
                                     "user": "root", "password": "test",
                                     "command": "whoami"}),
    Probe("ssh-cmd-uname", "secure_shell", {"port": 22, "kind": "interactive_cmd",
                                    "user": "root", "password": "test",
                                    "command": "uname -a"}),
    Probe("ssh-cmd-cat-hosts", "secure_shell", {"port": 22, "kind": "interactive_cmd",
                                        "user": "root", "password": "test",
                                        "command": "cat /etc/hosts"}),
]


ALL_PROBES: list[Probe] = (
    HTTP_PROBES + TCP_PROBES + MCP_PROBES + OLLAMA_PROBES
    + OPENAI_PROBES + SECURE_SHELL_PROBES
)
