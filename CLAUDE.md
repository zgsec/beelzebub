# CLAUDE.md — beelzebub (fork)

## What this is

Our fork of **mariocandela/beelzebub** — the Go low-code honeypot framework. This fork adds:

- **Stateful MCP** (`protocols/strategies/MCP/`): per-IP world model, tool-history tracking, tool-chain detection.
- **Agent detection** (`agentdetect/`): scores every session 0–100 on behavioral signals (MCP handshake shape, mechanical timing, cross-protocol pivots, AI-discovery probes). Wired into every protocol handler.
- **Cross-protocol bridge** (`bridge/`): message routing and state fusion across protocols so one actor shows up as one session.
- **Network fingerprint capture** (`tracer/`): JA4H (HTTP, wire-order), HASSH (SSH KEXINIT), SSH public-key log, TeeConn `net.Conn` wrapper for raw-byte access ahead of protocol parsers.
- **Fault injection** (`faults/`): grace-period-gated failure simulation.
- **Novelty scoring** (`noveltydetect/`): per-session novelty distinct from agent classification.

Deployed on a subset of fork sensors (see private operator inventory). Other sensors run stock upstream — do not confuse the two deployments. Current tag: `v3.6.7`.

## Layout

```
main.go                       # Entry — reads configs, builds the Director, runs event loop
Makefile                      # docker-compose wrappers + go test targets
Dockerfile / docker-compose.yml

agentdetect/                  # Agent classification (Verdict, Signal, scoring)
bridge/                       # Cross-protocol message bridge
builder/                      # Assembles services, connections, handlers
configurations/
  beelzebub.yaml              # Core: logging, Prometheus (:2112), tracing
  services/                   # Per-protocol YAMLs:
                              #   ssh-22.yaml, ssh-2222.yaml,
                              #   http-8888.yaml,
                              #   mcp-8000.yaml (stateful MCP, fork-only),
                              #   openai-8001.yaml (fork moves OpenAI off :8000),
                              #   ollama-11434.yaml,
                              #   tcp-mysql-3306.yaml, tcp-redis-6379.yaml,
                              #   influxdb-8086.yaml, openclaw-18789.yaml
  prod-configs/               # Sensor-specific prod overlays
  test-core.yaml / test-services/
faults/                       # Injected-failure simulation
historystore/                 # Thread-safe per-IP event ledger (atomic NextSequence, JSONL)
integration_test/             # docker-compose test harness
noveltydetect/                # Session novelty scoring
parser/                       # YAML config loader
plugins/                      # LLM integrations (OpenAI, Ollama, MCP tool virtualization)
protocols/
  protocol_manager.go         # Registry
  strategies/                 # HTTP / SSH / TCP / TELNET / MCP / OLLAMA handlers
tracer/                       # JA4H, HASSH, TeeConn, ConnContext propagation
test-tools/                   # CLI utilities
beelzebub-chart/              # Helm chart
logs/                         # Runtime test logs (gitignored / not authoritative)
```

Note: root also holds committed binary artifacts (`beelzebub`, `beelzebub-fork`, `beelzebub-fra`, `beelzebub-test`, `collector`) — these are build outputs, not source. Prefer `make` / `go build` over assuming they're fresh.

## Build / run / test

```bash
# Go build (static-ish)
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o beelzebub .

# Local stack (docker-compose)
make beelzebub.start
make beelzebub.stop

# Run the binary directly
./beelzebub \
  -confCore ./configurations/beelzebub.yaml \
  -confServices ./configurations/services/ \
  -memLimitMiB 100

# Tests
make test.unit                 # go test ./...
make test.unit.verbose         # with -v
make test.dependencies.start   # docker-compose -f integration_test/docker-compose.yml up -d
```

Prometheus metrics exposed on `:2112` when enabled in `beelzebub.yaml`.

## Fork vs upstream

Upstream: `github.com/mariocandela/beelzebub`. We rebase when it makes sense, but fork-specific packages (`agentdetect`, `bridge`, `historystore`, `noveltydetect`, `tracer`, MCP state in `protocols/strategies/MCP/`) and fork-specific service YAMLs (`mcp-8000`, `openai-8001`, `redis-6379`, `tcp-mysql-3306`) do not land upstream. Keep fork and stock service trees distinct — a bad YAML in `services/` only lands on fork sensors.

## Rules

1. **Never commit live canary tokens, API keys, or webhook URLs** in YAML service configs. The prod service trees contain placeholder tokens that are swapped in during deploy. Gitleaks pre-commit enforces.
2. **Never leak the word `beelzebub` (or `honeypot`, or sensor hostnames) in a protocol response, banner, or error message.** The persona is the product.
3. **Don't import patterns from `~/projects/mimic/`.** Mimic is a clean-sheet project and explicitly forbids reverse copying from this repo; keep the boundary clean in both directions.
4. **Don't block protocol handlers on LLM calls** without a short timeout. An attacker can exhaust LLM budget by opening many concurrent sessions.
5. **Changes to fingerprint capture (`tracer/`)** must preserve JA4H wire order (FoxIO spec) and HASSH KEXINIT order (Salesforce spec). Fingerprints shipped downstream are cross-comparable with Shodan / public corpora — breaking the spec silently breaks that.
6. **Both SSH configs (`ssh-22.yaml`, `ssh-2222.yaml`) must stay in sync.** Same persona, same LLM handler settings.
7. **Conventional commits. No force-push. No `.git/hooks` edits.**

## See also

- The parent `~/CLAUDE.md` for cross-repo rules (OPSEC, vault, sensor topology).
- `~/projects/honeypot.observer/CLAUDE.md` — the Go collector that consumes this honeypot's JSON log, including the fork-only fields (`AgentScore`, `MCPToolsUsed`, `CorrelationID`, etc.) produced here.
