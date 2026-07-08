# Sensor onboarding — standing up the fork on a new sensor

The goal of this guide is that bringing a region online is a small, obvious
delta — not a config to reverse-engineer. It covers the **config side** (service
overlays + environment); the **deploy side** is `ops/sensor-bootstrap-v8.sh`.

Per-sensor service overlays live in `configurations/prod-configs/`, which is
**gitignored** (kept out of this repo on purpose) — so those files are local to
the operator's checkout. This guide is tracked so it travels with a clone.

---

## How configs layer

A sensor runs the base config for a service from
[`../configurations/services/`](../configurations/services/) unless a per-sensor
overlay for that service is present, in which case the overlay is deployed
instead. Keep the two trees distinct — an overlay only reaches the sensor it is
named for.

**Overlay naming:**

```
<service>-<port>-<region>.yaml
```

e.g. `mcp-8000-<region>.yaml`, `ollama-11434-<region>.yaml`. Region is a short
code. Services without a region suffix are shared across sensors.

---

## Stand up a new sensor — checklist

1. **Mint canary tokens** for this sensor (see the operator canary-minting doc
   referenced by `ops/sensor-bootstrap-v8.sh`). Tokens are per-sensor so triggers
   attribute to the right source.

2. **Provide the environment** — never committed. Credential-shaped values are
   injected at deploy time and substituted into `${UPPER_CASE_VAR}` placeholders
   in the YAML at load. The MCP service **refuses to serve config-driven responses
   if any required canary env var is missing** — it will not fall back to example
   keys, since a recognizable example key burns the deception. Required for MCP:

   | Env var | Holds |
   |---|---|
   | `MCP_CANARY_AWS_KEY` | AWS access-key-shaped canary |
   | `MCP_CANARY_AWS_SECRET` | AWS secret-shaped canary |
   | `MCP_CANARY_DB_PASS` | DB password-shaped canary |
   | `MCP_CANARY_DNS` | DNS canary hostname |
   | `MCP_CANARY_WEB_URL` | web-bug / URL canary |
   | `MCP_CANARY_DD_KEY` | Datadog-key-shaped canary |
   | `MCP_CANARY_VAULT_TOKEN` | Vault-token-shaped canary |

   Shared deploy secrets (aggregator token, IP salt, LLM key, etc.) go in the
   operator-provided `.env.bootstrap` next to the bootstrap script. **Never commit
   `.env*`, tokens, or webhook URLs** — the gitleaks pre-commit hook enforces this.

3. **Add the service overlays** this sensor needs, under
   `configurations/prod-configs/`. Copy the closest existing
   `<service>-<port>-<region>.yaml` and change **only** what is genuinely
   region-specific. Everything shared (persona, handler settings, tool
   definitions) should stay identical across regions so a new region is a minimal
   diff. If you find yourself hand-editing large blocks, that shared content
   belongs in the base `services/` config, not duplicated per region.

4. **Run the bootstrap** — `ops/sensor-bootstrap-v8.sh` (set `SENSOR_ID` first).
   It clones the fork + collector, builds both images, and starts them with the
   right env and mounts. See the script header for host prerequisites (Docker,
   GeoIP data, aggregator reachability).

---

## Rules & guardrails

- **Placeholders, not secrets.** Overlays contain `${MCP_CANARY_*}` placeholders,
  never real values. A literal placeholder reaching a client is a fingerprint —
  the loader warns on any `${VAR}` whose env var is unset, so watch the boot log.
- **Keep the two secure-shell service configs in sync** (`ssh-22` / `ssh-2222`):
  same persona, same LLM handler settings.
- **Persona is the product.** Never leak internal identifiers, project names, or
  sensor hostnames in any served banner, response, or error.
- **Safe defaults.** A partial config must not crash on boot. For example,
  `logsPath` is optional — omit it and the honeypot logs to stdout only rather
  than aborting. Prefer a fall-back with a clear log line over a hard error when
  adding config-required fields.

---

## What lives where

| | |
|---|---|
| Base service configs (all sensors), tracked | `configurations/services/` |
| Core config (logging, metrics, tracing), tracked | `configurations/beelzebub.yaml` |
| Per-sensor overlays, **local / gitignored** | `configurations/prod-configs/` |
| Bootstrap / deploy, tracked | `ops/sensor-bootstrap-v8.sh` |
| Collector (consumes the JSON event stream) | separate repo |
