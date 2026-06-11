# crestfield-data-systems — narrative

## What this file is

The persona's voice — the operator-facing back-story that informs every
lure's tone. Lure content references the structured `persona.coherence.world.*`
data via Jinja; this narrative is the unstructured prose that helps any
LLM-driven handler (Ollama on :11434, SSH-2222's shell emulator, the
MCP `cdf/*` tool LLM-enrichment plugin) stay in character.

Treat it as the "show bible" — Disney's term for the canonical reference
that every cast member reads before working a themed land.

## The company

**Crestfield Data Systems** — Series B mid-stage data-platform startup,
Boston HQ, ~80 employees, founded 2018 by an ex-Splunk + ex-Snowflake
team. Originally pitched as "Snowflake for time-series + ML inference."
Sold their first product (a time-series ingest cluster) to four design-
partner customers in 2020, raised seed 2021, A-round 2023, B-round
late 2025. Currently ~25 paying enterprise customers, ARR mid-eight-
figures.

The platform has two layers visible to attackers:
- **Public-facing API** at `crestfielddata.io` — customer-facing data
  ingest + query. Behind nginx + AWS ALB. Not the lure surface.
- **Internal platform** at `int.crestfielddata.io` — the operator-only
  DevOps coordination plane. This is what every Crestfield lure
  pretends to be. An engineer working on Crestfield's product platform
  is connecting to services inside this internal network.

## The recent product initiative (the reason MCP exists in this world)

Q1 2026, the platform team (led by jpark + aruiz) launched the
**Crestfield Platform MCP server** — an internal coordination
service that exposes three tools:

- `cdf/iam.manage` — query and modify user accounts, roles, policies
- `cdf/logs.query` — query structured logs from the centralized pipeline
- `cdf/configstore.kv` — read/write configuration KV for the service mesh

Engineers connect their Cursor + Cline + Aider IDE workflows to this
MCP server via the `.cursorrules` / `.cline/memory.json` / `.aider.conf.yml`
config files that live in the platform repo. The MCP server runs on
:8000 alongside a LiteLLM proxy (also v3.12.1-rc1) that fronts external
LLM providers — OpenAI gpt-4o, Anthropic claude-sonnet-4, and AWS
Bedrock for batch — plus the internal Ollama deployment on the
`crestfield-worker-7f8b9c` pod.

The MCP launch is recent enough to be visible in `git log`, in the
`/.cursorrules` workspace file, and in the engineering team's
`.bash_history` — every Crestfield engineer has been running
`curl http://localhost:8000/.well-known/mcp.json` to sanity-check
the rollout, and there are PagerDuty incidents tied to early MCP
flakiness.

## Active incidents (the running show clock)

- **INC-4401** (since 2026-03-04): LDAP sync failing for ou=engineering;
  routed to oncall-rotation, P2 unacked for 15m. Real impact: new hires
  can't get group memberships, manual workaround via `cdf/iam.manage`.
- **TLS renewal pending** for *.int.crestfielddata.io, expiry 2026-06-09.
  cert-manager warnings in every component log.
- **crestfield-worker-7f8b9c OOM-killed** at 2026-03-05T18:30Z when the
  ollama model loader hit its 2Gi memory limit. Pod restarted clean;
  retry storm absorbed.
- **db-primary failover drill** completed cleanly 2026-03-05T16:42Z,
  promoted db-replica-2 in 4.2s. Routine.

## The people (canonical roster)

- **James Park (`jpark`)** — Senior Platform Engineer, MCP server lead.
  Mac user. Cursor + Cline workflow. Owns most of the platform repo.
  Internal Slack handle `@jpark`. Email `jpark@crestfielddata.io`.
- **Alejandro Ruiz (`aruiz`)** — Staff Platform Engineer. Kubeconfig
  owner (`/home/aruiz/.kube/config`). Co-lead on platform infrastructure.
  Mac user, deep Python + Go.
- **Mei Chen (`mchen`)** — Data Engineer on the data-science adjacent
  team. Read-only access to the platform.
- **SRE On-Call (`oncall-rotation`)** — group rotation, currently
  paged for INC-4401.
- **CI Service Account (`svc-deployer`)** — GitHub Actions egress
  IP `10.0.12.88`. Rate-limited recently per platform logs.

When a lure surfaces "current user" or "request initiator," it's one
of these five. Do not invent new names. Disney rule.

## The stack (what an internal engineer would casually mention)

- **Edge**: nginx 1.25.4 reverse proxy at the network boundary. All
  internal-domain hostnames are 4096-bit cert *.int.crestfielddata.io
  (renewal pending — see incident above).
- **API**: FastAPI + uvicorn (Python 3.12), SQLAlchemy ORM.
- **Workers**: Go microservices, k8s deployment in `crestfield-prod`
  namespace, one of which is `crestfield-worker-7f8b9c`.
- **Frontend**: Next.js on Vercel.
- **Primary DB**: PostgreSQL 15 at `db-primary.int.crestfielddata.io`,
  replica at `db-replica-01`.
- **Legacy billing DB**: MySQL 5.7 at `db-billing-legacy` — being
  migrated to Postgres, slow project.
- **Cache**: Redis 7 with Sentinel quorum (`redis-01/02/03`),
  alias `redis-sentinel.int.crestfielddata.io`.
- **Secrets**: HashiCorp Vault at `vault.int.crestfielddata.io:8200`.
- **Auth**: LDAP at `ldap.int.crestfielddata.io:636` + Vault JWT.
- **LLM stack**:
  - Ollama 0.5.x on `crestfield-worker-7f8b9c:11434` (internal inference)
  - LiteLLM 1.83.6 on prod-web-01:8000 (the proxy to OpenAI/Anthropic/Bedrock)
  - vLLM 0.6.3 on `gpu-worker-01/02:8001` (batch jobs)
  - Open WebUI 0.5.3 on prod-web-01:8888 (team chat interface)

  - LangFlow 1.2.x on langflow.int.crestfielddata.io:7860 (workflow
    automation — vulnerable to CVE-2025-3248, on engineering's TODO
    to upgrade)
- **Observability**: DataDog (scope `crestfield-prod`), Sentry,
  Langfuse for LLM observability.
- **Alerting**: Slack `#crestfield-platform-alerts`, PagerDuty for SRE.
- **CI/CD**: GitHub Actions (org `crestfielddata`), Docker registry on
  `registry.int.crestfielddata.io:5000`.

## Engineer culture

- Heavy IDE-AI usage. Every engineer's workstation has Cursor + Cline
  configured to use the local MCP server. Some use Aider too.
- Mac-dominant; some Linux dev VMs (Ubuntu 22.04.4 LTS, kernel 5.15).
- The `.bash_history` of any engineer's workstation includes
  `kubectl get pods -n crestfield-prod`, `psql -h db-primary ...`,
  `curl http://localhost:11434/api/tags` (smoke-checking the local
  Ollama), `git -C /opt/app pull origin main`, and `curl
  http://localhost:8000/mcp` (sanity-checking the MCP server).
- Conventional commits style. PR review required for `main`.
- Slack channels named with `crestfield-` prefix.

## What this world is NOT (negative space — keeps the show coherent)

- Crestfield is NOT publicly traded — no investor-relations URLs,
  no SEC filings, no IR @ crestfielddata.io emails.
- Crestfield is NOT a security company — no security product references,
  no MITRE ATT&CK in the platform tooling, no DETECTION engineering.
- Crestfield is NOT in Denver (an Ollama-lure error said so once; that
  was a Disney bug — Crestfield is Boston).
- Crestfield does NOT use Slack-Connect to share channels with
  outsiders (so an attacker-supplied `slack.com` URL isn't credible
  in any handler).
- Crestfield is NOT using GitLab — entirely GitHub Actions for CI.
- Crestfield does NOT use AWS GovCloud — `us-east-1` is the region.
- The "office NAS" at `nas-backup-01` (QNAP TS-453D) is a SEPARATE asset from the platform. Office
  IT, not engineering. Attackers who pivot to it should find a
  realistic isolated NAS, not platform infrastructure.
- Crestfield does NOT use ScreenConnect (removed from estate 2026-05-18
  after 30-day audit showed 0 high-value intent — replaced with
  LangFlow on :7860 which is a real-world KEV target).

## Persona swap-ability (operational note)

When this persona burns (e.g., system-prompt leak like Nexus did on
2026-04-06), the swap workflow is:

1. `cp -r personas/crestfield-data-systems personas/<new-slug>`
2. Edit the new persona.yaml — change `coherence.world.company.*`,
   the people roster, host hostnames, and the watermark password
   prefix
3. `bzb persona render <new-slug> placeholder` on the controller
4. Update `tools/manifest/canary-manifest.sensor-{a,b}.yaml` to
   reassign canary slots (or mint fresh) for the new persona
5. `ansible-playbook deploy/playbooks/lures-deploy.yml -e persona_slug=<new-slug>`

Total time: ~90 minutes for a clean swap with new canaries, ~30 for
quick rotate-existing-canaries.

The lure files themselves must NEVER hardcode "Crestfield" or any
specific Crestfield identity. Every Crestfield-specific string flows
through `{{ persona.coherence.world.* }}`. That's the architectural
contract Phase 4 of the Disney rebuild enforces.

## Pointers

- Plan: `~/vault/architecture/2026-05-18-crestfield-disney-cohesion-plan.md`
- Project memory: `memory/project_crestfield_disney_rebuild_2026_05_18.md`
- Persona structure: `persona.yaml` (this directory)
- Lure files: `lures/` subdirectory (plus `configurations/services/`
  for infra lures not yet migrated — SSH, MySQL, Redis, InfluxDB)
