# Beelzebub — AI Agent Research Fork

> **Research fork of [beelzebub-labs/beelzebub](https://github.com/beelzebub-labs/beelzebub)** — the low-code honeypot framework created by Mario Candela (Beelzebub Labs). This fork adds ~10 new Go packages that turn Beelzebub into a research platform for studying AI agent behavior in adversarial environments. See [`UPSTREAM.md`](UPSTREAM.md) for the current fork↔upstream relationship.

All additions are backward-compatible. Existing configurations work unchanged — every new feature is opt-in via YAML config.

## What This Fork Adds

The upstream project is a solid multi-protocol honeypot with LLM-powered responses. This fork adds the infrastructure needed to **detect, classify, fingerprint, and study AI agents** that interact with honeypot services.

### New Packages

| Package | Key File | What It Does |
|---|---|---|
| `agentdetect` | `detector.go` | Real-time agent/bot/human classification. Scores sessions 0-100 using 7 behavioral signals. |
| `bridge` | `bridge.go` | Cross-protocol credential tracking. When an agent finds AWS keys via MCP, the SSH handler knows. |
| `faults` | `faults.go` | Per-service fault injection (configurable error rates, delays, jitter) to study agent retry behavior. |
| `noveltydetect` | `scorer.go`, `store.go` | Fingerprint store + novelty scoring. Tracks commands, credentials, paths, tool sequences, user agents across all sessions. |
| `historystore` | `history_store.go` | Per-session message history with sequence tracking, retry detection via 16-slot ring buffer. |
| `shellemulator` | `emulator.go` | 55+ command shell emulator with per-session filesystem overlay, pipe chains, canary token lures. |

### Enhanced Modules

| Module | What Changed |
|---|---|
| `protocols/strategies/MCP/` | Complete rewrite. Per-IP stateful world model (users, logs, resources) that mutates across tool calls. WorldSeed YAML config, LLM enrichment, bridge integration. |
| `protocols/strategies/OLLAMA/` | Full Ollama + OpenAI-compatible API honeypot for LLMjacking research. Progressive injection, per-IP session state, model catalog simulation. |
| `protocols/strategies/TCP/` | Added interactive command loop with regex matching and LLM fallback (was banner-only). |
| `tracer/` | 20+ new event fields. Added JA4H HTTP fingerprinting, HASSH SSH fingerprinting, TeeConn wire capture, inter-event timing cache. |

---

## Architecture

```
                    ┌─────────────────────────────────────────┐
                    │             Protocol Handlers            │
                    │  SSH  HTTP  MCP  TCP  TELNET  OLLAMA    │
                    └────────┬───────┬──────┬────────┬────────┘
                             │       │      │        │
              ┌──────────────┼───────┼──────┼────────┼──────────┐
              │              ▼       ▼      ▼        ▼          │
              │  ┌─────────────────────────────────────────┐    │
              │  │          Cross-Protocol Bridge           │    │
              │  │  credential discovery · session flags    │    │
              │  └─────────────────────────────────────────┘    │
              │                                                  │
              │  ┌──────────┐ ┌──────────┐ ┌───────────────┐   │
              │  │  Agent   │ │ Novelty  │ │    Fault      │   │
              │  │ Detector │ │ Scorer   │ │  Injector     │   │
              │  │ (0-100)  │ │ (0-100)  │ │ (error/delay) │   │
              │  └──────────┘ └──────────┘ └───────────────┘   │
              │                                                  │
              │  ┌─────────────────────────────────────────┐    │
              │  │              Tracer (5 workers)          │    │
              │  │  events · timing · JA4H · HASSH · TeeConn│   │
              │  └───────────┬──────────┬──────────┬───────┘    │
              │              ▼          ▼          ▼            │
              │          Prometheus  RabbitMQ   Stdout          │
              └─────────────────────────────────────────────────┘
```

All protocol handlers share a singleton `Tracer`, optional `ProtocolBridge`, and optional `FingerprintStore`. Each handler independently uses `agentdetect` and `faults` based on its service config.

---

## Agent Detection

The `agentdetect` package classifies sessions in real-time using behavioral signals:

| Signal | Points | What It Detects |
|---|---|---|
| MCP handshake (`initialize`) | +40 | Strong agent indicator — humans don't send MCP protocol handshakes |
| Mechanical timing (mean < 2s, stddev < 500ms) | +25 | Machine-speed, low-variance inter-event timing |
| AI discovery probe (`/.well-known/mcp.json`, `/llms.txt`) | +20 | Agent-specific endpoint reconnaissance |
| Tool chain depth >= 3 | +20 | Sequential tool calls indicating workflow execution |
| Cross-protocol pivot (< 60s gap) | +15 | Lateral movement across SSH/HTTP/MCP |
| Identical retries | +15 | Agents retry the same command on failure |
| Command corrections | -20 | Humans correct typos — agents don't |

**Categories**: `agent` (>= 60), `bot` (30-59), `human` (< 30), `unknown` (insufficient data)

Both full-session (`Classify`) and per-event (`IncrementalClassify`) scoring are supported. Per-event scoring converges as more signals arrive during a session.

---

## Stateful MCP Honeypot

The MCP handler creates a **per-IP world model** from a YAML seed. Each connecting IP gets its own mutable copy with users, resources, logs, and an audit trail:

```yaml
worldSeed:
  users:
    - id: "f47ac10b-58cc-4372-a567-0e02b2c3d479"
      email: "admin@crestfielddata.io"
      role: "platform-admin"
      lastLogin: "2026-03-05T14:22:00Z"
  resources:
    aws_access_key_id: "AKIAIOSFODNN7EXAMPLE"
    db_primary: "postgresql://crestfield_app:s3cret@db.internal:5432/crestfield"
  logs:
    - ts: "2026-03-06T04:12:00Z"
      level: "error"
      msg: "LDAP sync failed for ou=contractors"
```

Tool calls mutate this state. `iam.manage` can list, deactivate, or modify users. `logs.query` filters the log store. `configstore.kv` reads and writes resources. The agent sees a realistic, internally consistent platform that responds to its actions.

**Key behaviors**:
- Fault injection with grace period (first 3 calls always succeed, then configured error rate applies)
- LLM enrichment of tool responses (optional, via OpenAI or Ollama)
- Bridge integration — credential discovery is shared across all protocol handlers
- Tool chain tracking with dependency detection across calls
- StreamableHTTP transport at `/mcp`

---

## Shell Emulator

The SSH protocol handler includes a high-fidelity shell emulator (`shellemulator/`) with 55+ commands:

**Identity/System**: `whoami`, `id`, `hostname`, `uname`, `uptime`, `w`, `who`, `last`, `date`
**Filesystem**: `pwd`, `cd`, `ls`, `cat`, `find`, `file`, `df`, `mount`, `du`, `stat`, `wc`, `head`, `tail`, `rm`, `mkdir`, `touch`, `cp`
**Network**: `ifconfig`, `ip`, `netstat`, `ss`, `ping`, `dig`, `nslookup`
**Process**: `ps`, `free`, `top`, `docker`, `systemctl`, `service`, `lsof`, `kill`
**Credential lures**: `env`, `printenv`, `history`, `set`
**Utility**: `echo`, `which`, `type`, `grep`, `export`, `alias`

**Session state**: Per-connection filesystem overlay (files written/deleted persist within session), working directory tracking, PID offsets.

**Command chaining**: Supports `cmd1 ; cmd2`, `cmd1 && cmd2`, `cmd1 | cmd2`, subshell expansion `$(cmd)`, and redirects `>` / `>>`.

**Canary tokens**: Environment variables (`AWS_ACCESS_KEY_ID`, `DB_PASSWORD`, etc.) are seeded from per-sensor env vars. Commands like `env`, `cat .bash_history`, and `cat /var/log/syslog` return these tokens. When an agent exfiltrates and uses them externally, the canary fires.

**Jitter**: Configurable per-category response delays to defeat timing-based honeypot detection:
```yaml
jitterRanges:
  identity: [1, 5]     # ms — whoami, id, hostname
  memory:   [2, 10]    # ms — free, ps, docker
  fs:       [3, 25]    # ms — ls, cat, find
  network:  [5, 30]    # ms — curl, dig, ping
```

---

## Network Fingerprinting

### JA4H (HTTP)

HTTP client fingerprinting based on the JA4 standard. Computed from HTTP method, version, cookie/header counts, and SHA-256 hashes of header names (wire order), header values, and cookie pairs. Emitted as `JA4H` and `HeaderOrder` on every HTTP event.

### HASSH (SSH)

SSH client fingerprinting from the `SSH_MSG_KEXINIT` packet. Extracts key exchange algorithms, encryption, MAC, and compression offers. Returns an MD5 hash for client identification. Emitted as `HASSH` on SSH session start.

### TeeConn

A `net.Conn` wrapper that captures raw bytes during `Read()` without modifying traffic flow. Protocol-aware stop functions detect end-of-headers (HTTP `\r\n\r\n`) or SSH KEXINIT completion. Used by JA4H and HASSH to fingerprint without disrupting the protocol handshake.

---

## Novelty Detection

The `noveltydetect` package maintains a global `FingerprintStore` of observed commands, credentials, paths, tool sequences, and user agents (stored as truncated SHA-256 hashes).

Each session is scored 0-100:

| Signal | Weight | Description |
|---|---|---|
| New commands | 40% | Commands never seen before |
| New credentials | 20% | Novel username:password pairs |
| New paths | 20% | Previously unseen HTTP paths |
| Tool sequence | 15% | New MCP tool call ordering |
| Duration anomaly | 10% | Unusual session duration |
| Cross-protocol | 10% | Novel cross-protocol patterns |
| User agent | 5% | New user agent string |

**Categories**: `novel` (>= 70), `variant` (30-69), `known` (< 30)

---

## Trace Event Fields

The fork adds 20+ fields to the `tracer.Event` struct. All are `json:",omitempty"` — zero impact on existing consumers.

### Session Correlation
| Field | Type | Description |
|---|---|---|
| `SessionKey` | string | Per-IP session identifier |
| `Sequence` | int | Monotonic event counter per session |
| `CorrelationID` | string | SHA-256 hash of IP for cross-protocol linking |

### MCP
| Field | Type | Description |
|---|---|---|
| `ToolName` | string | MCP tool invoked |
| `ToolArguments` | string | Tool arguments (JSON) |
| `ToolChainDepth` | int | Sequential tool call count |
| `ToolDependency` | string | Previous tool this call depends on |

### Behavioral Analysis
| Field | Type | Description |
|---|---|---|
| `InterEventMs` | int64 | Milliseconds since previous event in session |
| `IsRetry` | bool | Duplicate of a recent command |
| `RetryOf` | string | Event ID of the original attempt |
| `CrossProtocolRef` | string | Reference to related event on another protocol |
| `FaultInjected` | string | "error", "delay", or "error+delay" |
| `AgentScore` | int | 0-100 agent likelihood |
| `AgentCategory` | string | "agent", "bot", "human", "unknown" |
| `AgentSignals` | string | Contributing signals (comma-separated) |
| `NoveltyScore` | int | 0-100 session novelty |
| `NoveltyCategory` | string | "novel", "variant", "known" |
| `NoveltySignals` | string | Contributing signals (comma-separated) |

### Network Fingerprints
| Field | Type | Description |
|---|---|---|
| `JA4H` | string | HTTP client fingerprint |
| `HeaderOrder` | string | Wire-order header names |
| `HASSH` | string | SSH client fingerprint |
| `ResponseBytes` | int64 | HTTP response body size |

---

## Protocols

### MCP (Model Context Protocol)

Stateful honeypot with per-IP world model, tool call handling, fault injection, and LLM enrichment. StreamableHTTP at `/mcp`. See [Stateful MCP Honeypot](#stateful-mcp-honeypot) above.

```yaml
apiVersion: "v1"
protocol: "mcp"
address: ":8000"
description: "Crestfield Platform v3.12.1"
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
    description: "IAM for Crestfield platform"
    params:
      - name: "action"
        description: "list_users, get_user, deactivate, reset_credentials, update_role"
      - name: "user_id"
        description: "Target user ID (required for get_user, deactivate, reset_credentials, update_role)"
```

### SSH

LLM-powered interactive shell with optional shell emulator and canary tokens:

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
  openAISecretKey: "sk-proj-..."
shellEmulator:
  enabled: true
  jitterRanges:
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

Full Ollama API-compatible honeypot for studying LLMjacking. Simulates model catalog, chat completions, and embeddings with progressive prompt injection:

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

Terminal emulation with IAC negotiation, static or LLM-powered responses:

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

1. **Core** (`configurations/beelzebub.yaml`) — logging, tracing strategy, Prometheus endpoint
2. **Services** (`configurations/services/*.yaml`) — one file per honeypot service

```bash
./beelzebub --confCore ./configurations/beelzebub.yaml \
            --confServices ./configurations/services/ \
            --memLimitMiB 100
```

### Core Configuration

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

### Prometheus Metrics

Exposed at the configured endpoint (default `:2112/metrics`):

- `beelzebub_events_total` — all events
- `beelzebub_ssh_events_total` — SSH events
- `beelzebub_http_events_total` — HTTP events
- `beelzebub_tcp_events_total` — TCP events
- `beelzebub_mcp_events_total` — MCP events
- `beelzebub_telnet_events_total` — TELNET events

### RabbitMQ

Events published as JSON to a configured RabbitMQ exchange for downstream processing (SIEM, ELK, custom pipelines).

### Beelzebub Cloud

Optional cloud telemetry via the upstream Beelzebub Cloud service.

---

## Quick Start

### Go

```bash
go mod download
go build -ldflags="-s -w" .
./beelzebub
```

### Docker Compose

```bash
docker compose build
docker compose up -d
```

### Kubernetes (Helm)

```bash
helm install beelzebub ./beelzebub-chart
```

---

## Testing

```bash
# Unit tests
go test ./...

# With verbose output
go test -v ./...

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
├── bridge/                           # Cross-protocol credential tracking
├── builder/                          # Builder pattern for service init
├── configurations/
│   ├── beelzebub.yaml                # Core config
│   ├── services/                     # Production service configs
│   ├── prod-configs/                 # Per-sensor overrides
│   └── test-services/                # Test configs
├── faults/                           # Fault injection (errors, delays, jitter)
├── historystore/                     # Per-session history + retry detection
├── noveltydetect/                    # Fingerprint store + novelty scoring
├── parser/                           # YAML configuration parser
├── plugins/                          # LLM providers (OpenAI, Ollama)
├── protocols/
│   ├── protocol_manager.go           # Strategy pattern dispatcher
│   └── strategies/
│       ├── HTTP/                     # HTTP honeypot
│       ├── MCP/                      # Stateful MCP honeypot
│       │   ├── mcp.go                # Protocol handler + agent detection
│       │   └── state.go              # Per-IP world model
│       ├── SSH/
│       │   ├── ssh.go                # SSH handler
│       │   └── shellemulator/        # 55+ command shell emulator
│       ├── TCP/                      # Banner + interactive TCP
│       ├── TELNET/                   # TELNET with IAC negotiation
│       └── OLLAMA/                   # Ollama/OpenAI API honeypot
├── tracer/
│   ├── tracer.go                     # Event tracing (5 async workers)
│   ├── timing.go                     # Inter-event timing cache
│   ├── ja4h.go                       # JA4H HTTP fingerprinting
│   ├── hassh.go                      # HASSH SSH fingerprinting
│   └── teeconn.go                    # Wire-capture net.Conn wrapper
├── Dockerfile                        # Multi-stage scratch image
├── docker-compose.yml
├── Makefile
└── beelzebub-chart/                  # Helm chart
```

---

## Upstream

This fork is based on [beelzebub-labs/beelzebub](https://github.com/beelzebub-labs/beelzebub) (formerly `mariocandela/beelzebub`). The upstream project provides the core honeypot framework: YAML-based configuration, LLM integration, multi-protocol support, Prometheus metrics, RabbitMQ tracing, and Docker/Kubernetes deployment. Upstream badges and community links:

[![CI](https://github.com/mariocandela/beelzebub/actions/workflows/ci.yml/badge.svg)](https://github.com/mariocandela/beelzebub/actions/workflows/ci.yml) [![Go Report Card](https://goreportcard.com/badge/github.com/mariocandela/beelzebub/v3)](https://goreportcard.com/report/github.com/mariocandela/beelzebub/v3) [![Go Reference](https://pkg.go.dev/badge/github.com/mariocandela/beelzebub/v3.svg)](https://pkg.go.dev/github.com/mariocandela/beelzebub/v3) [![Mentioned in Awesome Go](https://awesome.re/mentioned-badge.svg)](https://github.com/avelino/awesome-go)

## License

[GNU GPL v3](LICENSE)
