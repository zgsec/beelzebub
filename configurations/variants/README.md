# configurations/variants — alternative service personas (not auto-loaded)

Configs in this directory are **not** loaded by default. The honeypot loads
every `*.yaml` under `configurations/services/`; anything here is an alternative
persona an operator can **swap in per sensor**.

Keep a config here (rather than in `services/`) when it is **mutually exclusive**
with a service already in `services/` — most often because it binds the **same
address**. Two services on one address collide: the bind fails for whichever
loses the race, and by design the honeypot only logs the failure rather than
crashing, so the loser silently never serves. `beelzebub -validate` reports the
collision as an error.

## Current variants

| File | Binds | Alternative to | Notes |
|---|---|---|---|
| `spark-8000.yaml` | `mcp::8000` | `services/mcp-8000.yaml` | Spark RAT (XZB-1248/Spark) C2 decoy. **MCP is the default `:8000` persona**; Spark is opt-in per sensor. |

## Using a variant on a sensor

To serve `spark-8000` instead of the MCP lure on `:8000` for a given sensor:

1. Remove (or don't deploy) `services/mcp-8000.yaml` for that sensor.
2. Copy `variants/spark-8000.yaml` into that sensor's deployed services tree.

Never deploy both to the same sensor — they bind the same port. Run
`beelzebub -validate` after assembling a sensor's config set to catch collisions
before deploy.
