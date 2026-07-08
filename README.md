# Beelzebub — AI Agent Research Fork

**Instrument a honeypot to detect, fingerprint, and study autonomous AI agents in the wild.**

[![CI](https://github.com/beelzebub-labs/beelzebub/actions/workflows/ci.yml/badge.svg)](https://github.com/beelzebub-labs/beelzebub/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/beelzebub-labs/beelzebub/v3)](https://goreportcard.com/report/github.com/beelzebub-labs/beelzebub/v3)
[![Go Reference](https://pkg.go.dev/badge/github.com/beelzebub-labs/beelzebub/v3.svg)](https://pkg.go.dev/github.com/beelzebub-labs/beelzebub/v3)
[![Mentioned in Awesome Go](https://awesome.re/mentioned-badge.svg)](https://github.com/avelino/awesome-go)
![Go](https://img.shields.io/badge/Go-1.25-00ADD8?logo=go&logoColor=white)
![License](https://img.shields.io/badge/License-GPL%20v3-blue.svg)

> A **research fork** of [**beelzebub-labs/beelzebub**](https://github.com/beelzebub-labs/beelzebub) — the low-code, LLM-powered honeypot framework created by **Mario Candela** (Beelzebub Labs). Upstream provides an excellent multi-protocol honeypot; this fork builds on that foundation to add the instrumentation needed to **observe AI agents** as they explore, pivot, and act inside deceptive services. See [`UPSTREAM.md`](UPSTREAM.md) for the current fork ↔ upstream relationship and our sync posture.

As AI agents increasingly perform reconnaissance, credential hunting, and lateral movement on their own, honeypots become a uniquely valuable place to study them — agents *behave*, and behavior is observable. This fork turns each honeypot session into a richly-instrumented behavioral record: who connected, how mechanically, what they touched, what they pivoted to, and how novel it was — all opt-in and backward-compatible with upstream configs.

> **Scope note:** honeypot telemetry shows *intent and behavior*, not compromise of any real system. Everything here is designed for passive observation and defensive research. See [Responsible Use](#responsible-use).

---

## Highlights

- 🧭 **Real-time agent classification** — every session scored `agent` / `bot` / `human` from behavioral signals (`agentdetect`).
- 🌐 **Cross-protocol correlation** — a credential discovered on one protocol is visible to the others, so lateral movement is observable end-to-end (`bridge`).
- 🧠 **Stateful MCP honeypot** — a per-IP, mutable world model (users, logs, resources) that responds coherently to an agent's tool calls.
- 🐚 **LLM-backed shell** — an SSH shell grounded by a structured host-persona prompt, with canary-token lures and timing jitter.
- 🔬 **Network fingerprinting** — JA4H (HTTP), HASSH (SSH), and JA4 (TLS) captured without disrupting the handshake.
- 🆕 **Novelty scoring** — each session ranked `novel` / `variant` / `known` against everything seen before.
- 💥 **Fault injection** — configurable errors, delays, and jitter to study how agents handle adversity.
- 📦 **Artifact capture** — uploaded bodies stored content-addressably by SHA-256, capture-only.
- ➕ **Fully additive** — 20+ opt-in `tracer.Event` fields, all `omitempty`; existing upstream consumers and configs are untouched.

---

## Table of Contents

- [Quick Start](#quick-start)
- [What This Fork Adds](#what-this-fork-adds)
- [Architecture](#architecture)
- [Agent Detection](#agent-detection)
- [Stateful MCP Honeypot](#stateful-mcp-honeypot)
- [Cross-Protocol Bridge](#cross-protocol-bridge)
- [Shell Emulator](#shell-emulator)
- [Network Fingerprinting](#network-fingerprinting)
- [Novelty Detection](#novelty-detection)
- [Fault Injection](#fault-injection)
- [Trace Event Schema](#trace-event-schema)
- [Protocols](#protocols)
- [Configuration](#configuration)
- [Observability](#observability)
- [Testing](#testing)
- [Project Structure](#project-structure)
- [Responsible Use](#responsible-use)
- [Contributing & Upstream](#contributing--upstream)
- [License](#license)

---

## Quick Start

Requires **Go 1.24+** (see `go.mod`).

```bash
# Build
go mod download
go build -ldflags="-s -w" .

# Run with the bundled core + service configs
./beelzebub -confCore ./configurations/beelzebub.yaml \
            -confServices ./configurations/services/ \
            -memLimitMiB 100
```

Or with containers:

```bash
docker compose build
docker compose up -d
```

Or on Kubernetes via the bundled Helm chart:

```bash
helm install beelzebub ./beelzebub-chart
```

Every fork feature is opt-in through YAML — start with the upstream protocol configs and enable agent detection, the world model, fingerprinting, or fault injection per service as needed (see [Protocols](#protocols) and [Configuration](#configuration)).

---

## What This Fork Adds

Upstream is a solid multi-protocol honeypot with LLM-powered responses. This fork adds the infrastructure to **detect, classify, fingerprint, and study AI agents** that interact with honeypot services.

### New packages

| Package | Key file(s) | What it does |
|---|---|---|
| `agentdetect` | `detector.go` | Real-time agent/bot/human classification — scores sessions 0–100 from 7 behavioral signals. |
| `bridge` | `bridge.go` | Cross-protocol credential & flag sharing, keyed per source IP, with bounded memory. |
| `faults` | `faults.go` | Per-service fault injection — error rates, delays, jitter, and a grace period — to study agent retry behavior. |
| `noveltydetect` | `scorer.go`, `store.go` | Global fingerprint store + per-session novelty scoring across commands, credentials, paths, tool sequences, and user agents. |
| `historystore` | `history_store.go` | Per-session message history with sequence tracking and retry detection via a 16-slot ring buffer. |
| `artifactstore` | `store.go` | Content-addressable capture of request bodies (uploads, payloads) keyed by SHA-256, each with a sibling `meta.json`. Capture-only — no execution or analysis. |
| `protocols/strategies/SSH/shellemulator` | `emulator.go`, `llm_shell.go` | LLM-backed interactive shell grounded by a structured host-persona prompt, with per-session overlays, canary-token seeding, and per-category response jitter. |
| `protocols/strategies/responsesubs` | `responsesubs.go` | Response template substitution — environment variables and time tokens (e.g. `${time.now.unix}`, `${time.ago.2d}`) rendered into handler/LLM output. |

### Enhanced upstream modules

| Module | What changed |
|---|---|
| `protocols/strategies/MCP/` | Reworked into a stateful honeypot — per-IP world model (users, logs, resources) that mutates across tool calls, world-seed YAML, optional LLM enrichment, and bridge integration. |
| `protocols/strategies/OLLAMA/` | Ollama + OpenAI-compatible API honeypot for LLMjacking research — model-catalog simulation, streaming chat/completions with model-aware token timing, and per-IP session state. |
| `protocols/strategies/TCP/` | Added an interactive command loop (regex matching + LLM fallback) alongside the original banner mode. |
| `tracer/` | 20+ new opt-in event fields; JA4H/JA4/HASSH fingerprinting, `TeeConn` wire capture, inter-event timing cache, and multipart body parsing. |

---

## Architecture

```
                    ┌───────────────────────────────────────────┐
                    │              Protocol Handlers             │
                    │   SSH   HTTP   MCP   TCP   TELNET   OLLAMA  │
                    └────┬──────┬──────┬──────┬───────┬──────┬───┘
                         │      │      │      │       │      │
        ┌────────────────┴──────┴──────┴──────┴───────┴──────┴──────────┐
        │                                                               │
        │   ┌───────────────────────────────────────────────────────┐ │
        │   │                 Cross-Protocol Bridge                   │ │
        │   │      per-IP credential discovery · session flags        │ │
        │   └───────────────────────────────────────────────────────┘ │
        │                                                               │
        │   ┌──────────┐   ┌──────────┐   ┌──────────────────────────┐ │
        │   │  Agent   │   │ Novelty  │   │      Fault Injector       │ │
        │   │ Detector │   │  Scorer  │   │   error · delay · jitter   │ │
        │   │ (0–100)  │   │ (0–100)  │   │   (+ grace period)         │ │
        │   └──────────┘   └──────────┘   └──────────────────────────┘ │
        │                                                               │
        │   ┌───────────────────────────────────────────────────────┐ │
        │   │                  Tracer (5 async workers)               │ │
        │   │   events · timing · JA4H · JA4 · HASSH · TeeConn        │ │
        │   └───────────────┬───────────────┬───────────────┬────────┘ │
        │                   ▼               ▼               ▼          │
        │               Prometheus       RabbitMQ         Stdout        │
        └───────────────────────────────────────────────────────────────┘
```

All protocol handlers share a singleton `Tracer` and optional `ProtocolBridge` and `FingerprintStore`. Each handler independently applies `agentdetect` and `faults` based on its own service config, so capabilities can be enabled service-by-service.

---

## Agent Detection

The `agentdetect` package classifies sessions in real time from behavioral signals:

| Signal | Points | What it detects |
|---|---:|---|
| MCP `initialize` handshake | **+40** | Strong agent indicator — humans don't send MCP protocol handshakes |
| Mechanical timing (mean < 2 s, stddev < 500 ms) | **+25** | Machine-speed, low-variance inter-event timing (needs ≥ 3 samples) |
| AI discovery probe (`/.well-known/mcp.json`, `/llms.txt`, …) | **+20** | Agent-specific endpoint reconnaissance |
| Tool-chain depth ≥ 3 | **+20** | Sequential tool calls indicating workflow execution |
| Cross-protocol pivot (< 60 s gap) | **+15** | Lateral movement across SSH/HTTP/MCP |
| Identical retries | **+15** | Agents re-issue the same command on failure |
| Command corrections | **−20** | Humans correct typos; agents typically don't |

Scores are clamped to 0–100 and bucketed:

**Categories** — `agent` (≥ 60), `bot` (30–59), `human` (< 30, with ≥ 3 timing samples), `unknown` (insufficient data).

Both full-session (`Classify`) and per-event (`IncrementalClassify`) scoring are supported; per-event scoring converges as more signals arrive during a session.

---

## Stateful MCP Honeypot

The MCP handler builds a **per-IP world model** from a YAML seed. Each connecting IP gets its own mutable copy — users, resources, logs, and an audit trail — so repeat queries are internally consistent and tool calls have visible effects:

```yaml
worldSeed:
  users:
    - id: "f47ac10b-58cc-4372-a567-0e02b2c3d479"
      email: "admin@example.com"
      role: "platform-admin"
      lastLogin: "${time.ago.3d}"      # baked to a concrete RFC3339 value at world creation
  resources:
    aws_access_key_id: "AKIAIOSFODNN7EXAMPLE"   # AWS's public example key
    db_primary: "postgresql://app_user:REDACTED@db.example:5432/appdb"
  logs:
    - ts: "${time.ago.2d}"
      level: "error"
      msg: "LDAP sync failed for ou=contractors"
```

Tool calls mutate this state: `iam.manage` can list, deactivate, or modify users; `logs.query` filters the log store; `configstore.kv` reads and writes resources. The agent sees a realistic platform that reacts to its actions.

**Key behaviors**

- **Fault injection with a grace period** — the first few calls (default 3) are exempt from *error* faults so a session establishes before failures begin; configured delays still apply.
- **LLM enrichment** of tool responses (optional, via OpenAI or Ollama).
- **Bridge integration** — credentials surfaced here are visible to the other protocol handlers.
- **Tool-chain tracking** with cross-call dependency detection (feeds `agentdetect` and the trace schema).
- **StreamableHTTP transport** at `/mcp`.

Time tokens in the seed (`${time.ago.<N><unit>}`, `${time.in.*}`, `${time.now}`) are resolved **once at world creation** via `responsesubs`, so timestamps neither leak the literal token on the wire nor drift between reads — two common honeypot tells.

---

## Cross-Protocol Bridge

The `bridge` package gives every protocol handler a shared, per-IP view of what a visitor has already discovered. When a credential surfaces on one protocol — say an AWS key returned by an MCP tool call — the SSH and HTTP handlers can see it too, so the honeypot reacts consistently to lateral movement and `agentdetect` can score cross-protocol pivots.

- `RecordDiscovery(ip, source, type, key, value)` / `HasDiscovered(ip, type)` / `GetDiscoveries(ip)` — credential sharing across `ssh`, `http`, and `mcp` (credential types such as `aws_key`, `db_password`, `api_token`).
- `SetFlag` / `HasFlag` / `GetFlags` — per-IP session flags, timestamped so the cross-protocol pivot gap can be computed.
- **Bounded memory** — per-IP credential history is capped (FIFO-evicted), and a background cleaner (run every 5 minutes from `builder`) drops IPs idle longer than 60 minutes.

---

## Shell Emulator

The SSH protocol handler delegates command responses to an **LLM-backed shell** (`protocols/strategies/SSH/shellemulator/`). Instead of hardcoding output, the emulator builds a structured **world-state prompt** that grounds the LLM in a consistent host persona, so responses stay coherent across a session.

- **World state** (`BuildPromptContext`): hostname, kernel, OS, IP, configured processes (for `ps`/`top`), listening ports (for `netstat`/`ss`), environment variables, seeded users, and lure files are serialized into the system prompt. The persona is configured in YAML and merged over a sensible default.
- **Session state**: each connection carries a per-session overlay (`FileOverlay`, `DirOverlay`, `Deleted`) so files written or removed during a session persist for that session, plus a command counter and working-directory tracking.
- **Canary tokens**: environment variables and lure file contents (`AWS_ACCESS_KEY_ID`, `DB_PASSWORD`, …) are seeded from configured token values at startup. When a token is exfiltrated and later used externally, the canary fires.
- **Jitter**: optional per-category response delays to blunt timing-based honeypot detection. Categories are `identity`, `memory`, `fs`, and `network`; each is a `[min, max]` millisecond range (omit to use defaults):

```yaml
jitter:
  identity: [1, 5]     # ms
  memory:   [2, 10]    # ms
  fs:       [3, 25]    # ms
  network:  [5, 30]    # ms
```

---

## Network Fingerprinting

Fingerprints are captured passively via `TeeConn`, which mirrors raw bytes during the handshake without altering traffic — so the protocol exchange is never disrupted.

### JA4H (HTTP)
Client fingerprint following the JA4 standard, from HTTP method, version, cookie/header counts, and SHA-256 hashes of header names (in wire order), header values, and cookie pairs. Emitted as `JA4H` plus `HeaderOrder` on every HTTP event.

### HASSH (SSH)
Client fingerprint from the `SSH_MSG_KEXINIT` packet — key exchange, encryption, MAC, and compression offers — returned as an MD5 hash. Emitted as `HASSH` at session start, with the raw algorithm lists preserved in `HASSHAlgorithms`.

### JA4 (TLS)
Client fingerprint from the TLS ClientHello, following the JA4 standard. Emitted as `JA4` when a TLS handshake is observed.

### TeeConn
A `net.Conn` wrapper that captures raw bytes during `Read()` without modifying traffic flow. Protocol-aware stop functions detect end-of-headers (HTTP `\r\n\r\n`) or KEXINIT completion, so fingerprinting happens without disrupting the protocol handshake.

---

## Novelty Detection

The `noveltydetect` package maintains a global `FingerprintStore` of observed commands, credentials, paths, tool sequences, and user agents (stored as truncated SHA-256 hashes), and scores each session 0–100:

| Signal | Weight | Description |
|---|---:|---|
| New commands | 40 | Commands never seen before |
| New credentials | 20 | Novel credential pairs |
| New paths | 20 | Previously unseen HTTP paths |
| Tool sequence | 15 | New MCP tool-call ordering |
| Duration anomaly | 10 | Unusual session duration |
| Cross-protocol | 10 | Novel cross-protocol patterns |
| User agent | 5 | New user-agent string |

**Categories** — `novel` (≥ 70), `variant` (30–69), `known` (< 30).

---

## Fault Injection

The `faults` package injects realistic, configurable failure into any service to study how agents handle adversity — do they retry, back off, or adapt?

- `errorRate` — probability that a call returns an error response (drawn from the configured `errorResponses`).
- `delayMs` + `delayJitterMs` — base latency plus random jitter.
- **Grace period** — the first *N* calls (default 3) are exempt from *error* faults so a session can establish before failures begin; delays still apply during grace.
- The applied fault is reported to the tracer as `error`, `delay`, or `error+delay` via the `FaultInjected` field.

---

## Trace Event Schema

The fork adds 20+ fields to the `tracer.Event` struct. All are `json:",omitempty"`, so existing consumers see no change unless a feature is enabled.

### Session correlation
| Field | Type | Description |
|---|---|---|
| `SessionKey` | string | Per-IP session identifier |
| `Sequence` | int | Monotonic event counter per session |
| `CorrelationID` | string | Deterministic hash of source IP for cross-protocol linking |

### MCP
| Field | Type | Description |
|---|---|---|
| `ToolName` | string | MCP tool invoked |
| `ToolArguments` | string | Tool arguments (JSON) |
| `ToolChainDepth` | int | Sequential tool-call count |
| `ToolDependency` | string | Previous tool this call depends on |

### Behavioral analysis
| Field | Type | Description |
|---|---|---|
| `InterEventMs` | int64 | Milliseconds since the previous event in the session |
| `IsRetry` | bool | Duplicate of a recent command |
| `RetryOf` | string | Event ID of the original attempt |
| `CrossProtocolRef` | string | Reference to a related event on another protocol |
| `FaultInjected` | string | `error`, `delay`, or `error+delay` |
| `AgentScore` | int | 0–100 agent likelihood |
| `AgentCategory` | string | `agent`, `bot`, `human`, `unknown` |
| `AgentSignals` | string | Contributing signals (comma-separated) |
| `NoveltyScore` | int | 0–100 session novelty |
| `NoveltyCategory` | string | `novel`, `variant`, `known` |
| `NoveltySignals` | string | Contributing signals (comma-separated) |

### Network fingerprints
| Field | Type | Description |
|---|---|---|
| `JA4H` | string | HTTP client fingerprint |
| `HeaderOrder` | string | Wire-order header names |
| `HASSH` | string | SSH client fingerprint |
| `HASSHAlgorithms` | string | Raw SSH KEX algorithm lists behind the HASSH hash |
| `JA4` | string | TLS ClientHello fingerprint |
| `ResponseBytes` | int64 | HTTP response body size |

### Artifact / body capture (opt-in per service)
| Field | Type | Description |
|---|---|---|
| `RequestBody` | string | Captured request body (truncated) |
| `ResponseBody` | string | Captured response body (truncated) |
| `RequestBodySha256` | string | SHA-256 of the full request body (forensic identity) |
| `ResponseBodySha256` | string | SHA-256 of the full response body |
| `RequestBodyParts` | array | Parsed multipart parts of a request body |

> **Illustrative event** — field names are real; values are made up to show shape:
>
> ```json
> {
>   "Protocol": "MCP",
>   "SessionKey": "203.0.113.10",
>   "Sequence": 4,
>   "CorrelationID": "a3f1…",
>   "ToolName": "iam.manage",
>   "ToolChainDepth": 3,
>   "InterEventMs": 180,
>   "AgentScore": 80,
>   "AgentCategory": "agent",
>   "AgentSignals": "mcp_handshake,mechanical_timing,tool_chain_depth(3)",
>   "NoveltyScore": 35,
>   "NoveltyCategory": "variant",
>   "JA4H": "ge11nn09…"
> }
> ```

---

## Protocols

Each service is one YAML file under `configurations/services/`. All examples below are illustrative; secrets shown are placeholders.

### MCP (Model Context Protocol)

Stateful honeypot with a per-IP world model, tool-call handling, fault injection, and optional LLM enrichment. StreamableHTTP at `/mcp`. See [Stateful MCP Honeypot](#stateful-mcp-honeypot).

```yaml
apiVersion: "v1"
protocol: "mcp"
address: ":8000"
description: "Example Platform v3.12.1"
worldSeed:
  users: [...]
  resources: { aws_access_key_id: "...", db_primary: "..." }
  logs: [...]
faultInjection:
  enabled: true
  errorRate: 0.10
  delayJitterMs: 300
tools:
  - name: "cdf/iam.manage"
    description: "IAM for the platform"
    params:
      - name: "action"
        description: "list_users, get_user, deactivate, reset_credentials, update_role"
      - name: "user_id"
        description: "Target user ID (required for get_user, deactivate, reset_credentials, update_role)"
```

### SSH

LLM-powered interactive shell, optionally backed by the shell emulator and canary tokens:

```yaml
apiVersion: "v1"
protocol: "ssh"
address: ":2222"
description: "SSH Honeypot"
commands:
  - regex: "^(.+)$"
    plugin: "LLMHoneypot"
serverVersion: "OpenSSH"
serverName: "ubuntu"
passwordRegex: "^(root|admin|123456)$"
deadlineTimeoutSeconds: 60
plugin:
  llmProvider: "openai"
  llmModel: "gpt-4o"
  openAISecretKey: "<your-key>"
shellEmulator:
  enabled: true
  jitter:
    identity: [1, 5]
    memory: [2, 10]
    fs: [3, 25]
    network: [5, 30]
```

### HTTP

Regex-based URL routing with configurable responses, headers, and status codes:

```yaml
apiVersion: "v1"
protocol: "http"
address: ":8888"
description: "Web Application"
commands:
  - regex: "^/$"
    handler: "<html><body>Welcome</body></html>"
    headers:
      - "Content-Type: text/html"
      - "Server: nginx/1.24.0"
    statusCode: 200
  - regex: "^.*$"
    handler: "Not Found"
    statusCode: 404
```

### Ollama / OpenAI API

Ollama- and OpenAI-compatible API honeypot for studying LLMjacking — model-catalog simulation, streaming chat/completions with model-aware token timing, and per-IP session state:

```yaml
apiVersion: "v1"
protocol: "ollama"
address: ":11434"
description: "Ollama LLM Backend"
plugin:
  llmProvider: "ollama"
  llmModel: "llama3:latest"
  host: "http://localhost:11434/api/chat"
```

### TCP

Banner-only or interactive mode with regex command matching and LLM fallback:

```yaml
apiVersion: "v1"
protocol: "tcp"
address: ":3306"
description: "MySQL 8.0.32"
banner: "8.0.32\n"
deadlineTimeoutSeconds: 30
commands:   # optional — enables interactive mode
  - regex: "^SELECT"
    handler: "ERROR 1045 (28000): Access denied"
```

### TELNET

Terminal emulation with IAC negotiation and static or LLM-powered responses:

```yaml
apiVersion: "v1"
protocol: "telnet"
address: ":23"
description: "Router"
commands:
  - regex: "^show version$"
    handler: "Cisco IOS Software, Version 15.1(4)M4"
  - regex: "^(.+)$"
    plugin: "LLMHoneypot"
serverName: "router"
passwordRegex: "^(admin|cisco)$"
```

---

## Configuration

Two-tier YAML configuration:

1. **Core** (`configurations/beelzebub.yaml`) — logging, tracing strategy, Prometheus endpoint.
2. **Services** (`configurations/services/*.yaml`) — one file per honeypot service.

```bash
./beelzebub -confCore ./configurations/beelzebub.yaml \
            -confServices ./configurations/services/ \
            -memLimitMiB 100
```

### Core configuration

```yaml
core:
  logging:
    debug: false
    debugReportCaller: false
    logDisableTimestamp: true
    logsPath: ./logs
  tracings:
    rabbit-mq:
      enabled: false
      uri: "amqp://guest:guest@localhost:5672/"
  prometheus:
    path: "/metrics"
    port: ":2112"
  beelzebub-cloud:
    enabled: false
    uri: ""
    auth-token: ""
```

---

## Observability

### Prometheus metrics

Exposed at the configured endpoint (default `:2112/metrics`):

- `beelzebub_events_total` — all events
- `beelzebub_ssh_events_total` — SSH events
- `beelzebub_http_events_total` — HTTP events
- `beelzebub_tcp_events_total` — TCP events
- `beelzebub_mcp_events_total` — MCP events
- `beelzebub_telnet_events_total` — TELNET events

### RabbitMQ

Events are published as JSON to a configured RabbitMQ exchange for downstream processing (SIEM, ELK, custom pipelines).

### Beelzebub Cloud

Optional cloud telemetry via the upstream Beelzebub Cloud service.

---

## Testing

```bash
# Unit tests
go test ./...
make test.unit                 # equivalent Make target
make test.unit.verbose         # with -v

# Integration tests (require RabbitMQ)
make test.dependencies.start
make test.integration
make test.dependencies.down
```

---

## Project Structure

```
beelzebub/
├── main.go                           # Entry point (flags, parser, builder, run)
├── agentdetect/                      # Agent classification engine
├── artifactstore/                    # Content-addressable request-body/artifact capture
├── bridge/                           # Cross-protocol credential & flag sharing
├── builder/                          # Builder pattern for service init
├── configurations/
│   ├── beelzebub.yaml                # Core config
│   ├── services/                     # Service configs
│   ├── prod-configs/                 # Deployment-specific config overlays
│   └── test-services/                # Test configs
├── faults/                           # Fault injection (errors, delays, jitter)
├── historystore/                     # Per-session history + retry detection
├── noveltydetect/                    # Fingerprint store + novelty scoring
├── parser/                           # YAML configuration parser
├── plugins/                          # LLM providers (OpenAI, Ollama) + cloud
├── protocols/
│   ├── protocol_manager.go           # Strategy-pattern dispatcher
│   └── strategies/
│       ├── HTTP/                     # HTTP honeypot
│       ├── MCP/                      # Stateful MCP honeypot
│       │   ├── mcp.go                # Protocol handler + agent detection
│       │   └── state.go              # Per-IP world model
│       ├── SSH/
│       │   ├── ssh.go                # SSH handler
│       │   └── shellemulator/        # LLM-backed shell + world-state prompt
│       ├── TCP/                      # Banner + interactive TCP
│       ├── TELNET/                   # TELNET with IAC negotiation
│       ├── OLLAMA/                   # Ollama/OpenAI API honeypot
│       └── responsesubs/             # Response template substitution
├── tracer/
│   ├── tracer.go                     # Event tracing (5 async workers)
│   ├── timing.go                     # Inter-event timing cache
│   ├── ja4h.go                       # JA4H HTTP fingerprinting
│   ├── ja4.go                        # JA4 TLS fingerprinting
│   ├── hassh.go                      # HASSH SSH fingerprinting
│   ├── multipart.go                  # Multipart request-body parsing
│   └── teeconn.go                    # Wire-capture net.Conn wrapper
├── Dockerfile                        # Multi-stage scratch image
├── docker-compose.yml
├── Makefile
└── beelzebub-chart/                  # Helm chart
```

---

## Responsible Use

This is **defensive security research**. Honeypot telemetry reflects *intent and observed behavior* against deliberately deceptive services — it is not evidence that any real system was compromised. The fork is built for **passive observation**: it captures and records, it does not execute captured payloads or attack back. When publishing or sharing data, prefer language like "attempted", "observed", and "consistent with", and redact anything that could identify third parties. Operate honeypots only on infrastructure you control and in line with the laws and policies that apply to you.

---

## Contributing & Upstream

This is a research fork that aims to be a good citizen of the upstream project.

- **Relationship & sync posture:** see [`UPSTREAM.md`](UPSTREAM.md).
- **Contribution guidelines & code of conduct:** inherited from upstream — see [`CONTRIBUTING.md`](CONTRIBUTING.md).

Where an addition here is genuinely general-purpose, we'd rather offer it back upstream as a clean, standalone PR than carry it indefinitely in the fork.

### Acknowledgements

Built on [**beelzebub-labs/beelzebub**](https://github.com/beelzebub-labs/beelzebub) (formerly `mariocandela/beelzebub`), created by **Mario Candela**. The upstream project provides the core honeypot framework this fork builds on: YAML-based configuration, LLM integration, multi-protocol support, Prometheus metrics, RabbitMQ tracing, and Docker/Kubernetes deployment. This fork's Go module path is `github.com/beelzebub-labs/beelzebub/v3` and its packages live under `internal/`, mirroring upstream's current layout so rebases against it stay clean.

## License

[GNU GPL v3](LICENSE) — inherited from upstream.
