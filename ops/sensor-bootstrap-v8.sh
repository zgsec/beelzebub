#!/bin/bash
# sensor-bootstrap-v8.sh — one-shot v8 sensor installer
#
# Usage:
#   sudo ./sensor-bootstrap-v8.sh
#
# Requires:
#   - Docker + git on the host
#   - A pre-filled `.env.bootstrap` next to this script (operator provides
#     this — contains shared secrets: AGGREGATOR_TOKEN, IP_SALT,
#     OPEN_AI_SECRET_KEY, etc.) You only need to set SENSOR_ID before running.
#
# Handles:
#   - Clone beelzebub-fork (v8/tracer-fixes) + honeypot.observer (v8/exporter-fixes)
#   - Build both images
#   - Create docker network + volumes
#   - Start beelzebub + exporter with the right env/mounts
#   - Stop stock m4r10/beelzebub:v3.3.6 if present
#
# Does NOT handle:
#   - Canary minting (see DOCS/CANARY_MINTING_FOR_OPERATORS.md)
#   - Network reachability to the aggregator (set AGGREGATOR_URL +
#     AGGREGATOR_PUBLIC_URL env vars; e.g., over Tailscale or a private VPC)
#   - GeoIP databases (must be placed at /opt/honeypot-sensor/geoip/ beforehand)

set -euo pipefail

# ─────────────────────────────────────────────────────────────────────────────
# Paths + constants
# ─────────────────────────────────────────────────────────────────────────────
SENSOR_ROOT="${SENSOR_ROOT:-/opt/honeypot-sensor}"
BEELZEBUB_REPO="https://github.com/zgsec/beelzebub.git"
BEELZEBUB_BRANCH="v8/tracer-fixes"
OBSERVER_REPO="https://github.com/zgsec/honeypot.observer.git"
OBSERVER_BRANCH="v8/exporter-fixes"
NETWORK="honeypot-sensor_honeypot-internal"
LOGS_VOLUME="honeypot-sensor_beelzebub-logs"
DATA_VOLUME="honeypot-sensor_exporter-data"

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────
say()  { printf "\033[1;34m==>\033[0m %s\n" "$*"; }
ok()   { printf "\033[1;32m ✓\033[0m %s\n" "$*"; }
warn() { printf "\033[1;33m !!\033[0m %s\n" "$*" >&2; }
die()  { printf "\033[1;31mXX\033[0m %s\n" "$*" >&2; exit 1; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"
}

# ─────────────────────────────────────────────────────────────────────────────
# 0. Preflight
# ─────────────────────────────────────────────────────────────────────────────
say "Preflight checks"
require_cmd docker
require_cmd git
require_cmd openssl
docker compose version >/dev/null 2>&1 || warn "docker compose v2 plugin not found (not required, but usually available)"
ok "docker + git + openssl present"

free_gb=$(df -BG /var/lib/docker 2>/dev/null | awk 'NR==2 {gsub("G",""); print $4}')
[[ -n "$free_gb" && "$free_gb" -lt 3 ]] && die "Less than 3 GB free on /var/lib/docker (have ${free_gb}G)"
ok "disk space OK"

: "${AGGREGATOR_URL:?AGGREGATOR_URL must be set (e.g., http://aggregator.example.com:8080)}"
if ! curl -sf --max-time 5 "${AGGREGATOR_URL}/health" >/dev/null 2>&1; then
  warn "Cannot reach aggregator at ${AGGREGATOR_URL} — ensure routing is up before launching."
fi

# ─────────────────────────────────────────────────────────────────────────────
# 1. Sensor root dir
# ─────────────────────────────────────────────────────────────────────────────
say "Setting up $SENSOR_ROOT"
mkdir -p "$SENSOR_ROOT"
cd "$SENSOR_ROOT"

# ─────────────────────────────────────────────────────────────────────────────
# 2. .env — merge existing + bootstrap, preserving operator's existing values
# ─────────────────────────────────────────────────────────────────────────────
say "Preparing .env"

BOOTSTRAP_ENV="${BOOTSTRAP_ENV:-${BASH_SOURCE%/*}/.env.bootstrap}"
TARGET_ENV="$SENSOR_ROOT/.env"

# Read a var from a file: `get_env_var KEY FILE` → prints value or empty
get_env_var() {
  local key="$1" file="$2"
  [[ -f "$file" ]] || return
  # Last-occurrence wins, same as docker's --env-file parsing
  grep -E "^${key}=" "$file" | tail -1 | cut -d= -f2-
}

# Write/replace a var in TARGET_ENV atomically. Appends if missing.
set_env_var() {
  local key="$1" val="$2" file="$TARGET_ENV"
  if grep -qE "^${key}=" "$file" 2>/dev/null; then
    # Replace (use | delimiter to survive / in URLs)
    sed -i "s|^${key}=.*|${key}=${val}|" "$file"
  else
    echo "${key}=${val}" >> "$file"
  fi
}

# If TARGET_ENV doesn't exist, start from BOOTSTRAP_ENV if available, else empty.
if [[ ! -f "$TARGET_ENV" ]]; then
  if [[ -f "$BOOTSTRAP_ENV" ]]; then
    cp "$BOOTSTRAP_ENV" "$TARGET_ENV"
    ok "Seeded $TARGET_ENV from $BOOTSTRAP_ENV"
  else
    touch "$TARGET_ENV"
    warn "No existing .env and no .env.bootstrap — starting empty. Must fill values manually."
  fi
fi
chmod 600 "$TARGET_ENV"

# Legacy name mappings — map old var names → v8 names if v8 name is missing.
# Specifically catches the IP_SALT → COLLECTOR_IP_SALT drift observed during the v7→v8 rollout.
declare -A LEGACY_MAP=(
  [IP_SALT]="COLLECTOR_IP_SALT"
)
for new_key in "${!LEGACY_MAP[@]}"; do
  old_key="${LEGACY_MAP[$new_key]}"
  new_val="$(get_env_var "$new_key" "$TARGET_ENV")"
  if [[ -z "$new_val" || "$new_val" == "change-me" ]]; then
    old_val="$(get_env_var "$old_key" "$TARGET_ENV")"
    if [[ -n "$old_val" ]]; then
      set_env_var "$new_key" "$old_val"
      ok "Mapped legacy $old_key → $new_key in .env"
    fi
  fi
done

# Merge: for each var in BOOTSTRAP_ENV, if TARGET_ENV doesn't already have a
# non-placeholder value, copy it over. Existing operator values are preserved.
if [[ -f "$BOOTSTRAP_ENV" ]]; then
  while IFS= read -r line; do
    # Skip comments and blank lines
    [[ "$line" =~ ^[[:space:]]*# ]] && continue
    [[ "$line" =~ ^[[:space:]]*$ ]] && continue
    [[ "$line" =~ ^([A-Z_][A-Z0-9_]*)= ]] || continue
    key="${BASH_REMATCH[1]}"
    bval="$(get_env_var "$key" "$BOOTSTRAP_ENV")"
    tval="$(get_env_var "$key" "$TARGET_ENV")"
    # Skip SENSOR_ID — must be set by operator, never auto-overwritten
    [[ "$key" == "SENSOR_ID" ]] && continue
    # Copy bootstrap value over only if target is empty or a placeholder
    if [[ -z "$tval" || "$tval" == "change-me" || "$tval" == REPLACE* ]] && [[ -n "$bval" ]]; then
      set_env_var "$key" "$bval"
    fi
  done < "$BOOTSTRAP_ENV"
  ok "Merged $BOOTSTRAP_ENV into $TARGET_ENV (existing values preserved)"
fi

# Final validation: every required v8 var has a real value
REQUIRED=(SENSOR_ID AGGREGATOR_URL AGGREGATOR_TOKEN IP_SALT)
missing=()
for var in "${REQUIRED[@]}"; do
  val="$(get_env_var "$var" "$TARGET_ENV")"
  if [[ -z "$val" || "$val" == "change-me" || "$val" == REPLACE* ]]; then
    missing+=("$var")
  fi
done
if (( ${#missing[@]} > 0 )); then
  echo
  warn "The following required .env vars are missing or placeholders:"
  for m in "${missing[@]}"; do echo "    - $m"; done
  echo
  die "Edit $TARGET_ENV (set at least the missing values), then rerun this script."
fi

SENSOR_ID=$(get_env_var SENSOR_ID "$TARGET_ENV")
ok ".env OK for sensor=$SENSOR_ID"

# ─────────────────────────────────────────────────────────────────────────────
# 3. GeoIP databases
# ─────────────────────────────────────────────────────────────────────────────
say "Checking GeoIP databases"
[[ -f "$SENSOR_ROOT/geoip/GeoLite2-Country.mmdb" ]] \
  || die "Missing $SENSOR_ROOT/geoip/GeoLite2-Country.mmdb — fetch from MaxMind (free GeoLite2 license)."
[[ -f "$SENSOR_ROOT/geoip/GeoLite2-ASN.mmdb" ]] \
  || die "Missing $SENSOR_ROOT/geoip/GeoLite2-ASN.mmdb — fetch from MaxMind (free GeoLite2 license)."
ok "GeoIP present"

# ─────────────────────────────────────────────────────────────────────────────
# 4. Clone/update repos
# ─────────────────────────────────────────────────────────────────────────────
say "Cloning/updating repos"
if [[ ! -d "$SENSOR_ROOT/beelzebub-fork/.git" ]]; then
  git clone -b "$BEELZEBUB_BRANCH" "$BEELZEBUB_REPO" "$SENSOR_ROOT/beelzebub-fork"
else
  git -C "$SENSOR_ROOT/beelzebub-fork" fetch origin
  git -C "$SENSOR_ROOT/beelzebub-fork" checkout "$BEELZEBUB_BRANCH"
  git -C "$SENSOR_ROOT/beelzebub-fork" reset --hard "origin/$BEELZEBUB_BRANCH"
fi
ok "beelzebub-fork @ $(git -C $SENSOR_ROOT/beelzebub-fork log --oneline -1)"

if [[ ! -d "$SENSOR_ROOT/honeypot.observer/.git" ]]; then
  git clone -b "$OBSERVER_BRANCH" "$OBSERVER_REPO" "$SENSOR_ROOT/honeypot.observer"
else
  git -C "$SENSOR_ROOT/honeypot.observer" fetch origin
  git -C "$SENSOR_ROOT/honeypot.observer" checkout "$OBSERVER_BRANCH"
  git -C "$SENSOR_ROOT/honeypot.observer" reset --hard "origin/$OBSERVER_BRANCH"
fi
ok "honeypot.observer @ $(git -C $SENSOR_ROOT/honeypot.observer log --oneline -1)"

# ─────────────────────────────────────────────────────────────────────────────
# 5. Canary configs: use rendered dir, or fall back to plain configs
# ─────────────────────────────────────────────────────────────────────────────
say "Checking canary configs"
CANARY_DIR="$SENSOR_ROOT/beelzebub-fork/configurations-rendered"
if [[ ! -d "$CANARY_DIR" ]]; then
  warn "No configurations-rendered/ — using plain configurations/ (no live canaries)."
  warn "See DOCS/CANARY_MINTING_FOR_OPERATORS.md in honeypot-research to mint your canaries."
  cp -r "$SENSOR_ROOT/beelzebub-fork/configurations" "$CANARY_DIR"
fi
ok "Canary config dir: $CANARY_DIR"

# ─────────────────────────────────────────────────────────────────────────────
# 6. Build images
# ─────────────────────────────────────────────────────────────────────────────
say "Building beelzebub-fork:latest"
docker build -t beelzebub-fork:latest --no-cache "$SENSOR_ROOT/beelzebub-fork" 2>&1 | tail -3
ok "beelzebub-fork built"

say "Building honeypot-sensor-exporter:latest"
docker build -t honeypot-sensor-exporter:latest --no-cache "$SENSOR_ROOT/honeypot.observer/exporter" 2>&1 | tail -3
ok "exporter built"

# ─────────────────────────────────────────────────────────────────────────────
# 7. Network + volumes
# ─────────────────────────────────────────────────────────────────────────────
docker network create "$NETWORK" >/dev/null 2>&1 || true
docker volume create "$LOGS_VOLUME" >/dev/null 2>&1 || true
docker volume create "$DATA_VOLUME" >/dev/null 2>&1 || true
ok "network + volumes ready"

# ─────────────────────────────────────────────────────────────────────────────
# 8. Stop stock beelzebub if present
# ─────────────────────────────────────────────────────────────────────────────
stock_ids=$(docker ps -aq --filter ancestor=m4r10/beelzebub:v3.3.6 2>/dev/null)
if [[ -n "$stock_ids" ]]; then
  say "Stopping stock beelzebub containers"
  docker stop $stock_ids 2>/dev/null || true
  docker rm   $stock_ids 2>/dev/null || true
  ok "stock beelzebub removed (log volume preserved)"
fi

# Also stop any existing beelzebub / honeypot-exporter by name (clean slate)
docker rm -f beelzebub honeypot-exporter 2>/dev/null || true

# ─────────────────────────────────────────────────────────────────────────────
# 9. Run beelzebub
# ─────────────────────────────────────────────────────────────────────────────
say "Starting beelzebub"
docker run -d \
  --name beelzebub \
  --restart always \
  --network "$NETWORK" \
  -p 22:22 -p 23:23 -p 2222:2222 \
  -p 8080:8080 -p 8081:8081 \
  -p 3306:3306 -p 2112:2112 \
  -v "$LOGS_VOLUME:/var/log/beelzebub" \
  -v "$CANARY_DIR:/configurations:ro" \
  --env-file "$TARGET_ENV" \
  beelzebub-fork:latest >/dev/null

sleep 3
if ! docker ps --format '{{.Names}}' | grep -q '^beelzebub$'; then
  docker logs beelzebub --tail 20
  die "beelzebub failed to start — inspect logs above"
fi
ok "beelzebub running"

# ─────────────────────────────────────────────────────────────────────────────
# 10. Run exporter
# ─────────────────────────────────────────────────────────────────────────────
say "Starting honeypot-exporter"
docker run -d \
  --name honeypot-exporter \
  --restart unless-stopped \
  --network "$NETWORK" \
  -v "$LOGS_VOLUME:/var/log/beelzebub:ro" \
  -v "$SENSOR_ROOT/geoip:/geoip:ro" \
  -v "$DATA_VOLUME:/data" \
  --env-file "$TARGET_ENV" \
  honeypot-sensor-exporter:latest >/dev/null

sleep 4
if ! docker ps --format '{{.Names}}' | grep -q '^honeypot-exporter$'; then
  docker logs honeypot-exporter --tail 25
  die "honeypot-exporter failed to start — inspect logs above"
fi
ok "honeypot-exporter running"

# ─────────────────────────────────────────────────────────────────────────────
# 11. Verification
# ─────────────────────────────────────────────────────────────────────────────
say "Verifying"
docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Image}}'
echo
echo "--- beelzebub (last 8) ---"
docker logs beelzebub --tail 8 2>&1 | sed 's/^/  /'
echo "--- exporter (last 12) ---"
docker logs honeypot-exporter --tail 12 2>&1 | sed 's/^/  /'
echo
echo "Waiting 15s for heartbeat reach the aggregator..."
sleep 15
echo "--- aggregator health view for this sensor ---"
PUBLIC_URL="${AGGREGATOR_PUBLIC_URL:-${AGGREGATOR_URL}}"
curl -sf "${PUBLIC_URL}/health" | python3 -m json.tool 2>/dev/null | grep -A 7 "$SENSOR_ID" || \
  warn "curl ${PUBLIC_URL}/health failed or output unparseable"
echo

ok "Done. Sensor '$SENSOR_ID' is online."
echo
echo "Next steps:"
echo "  1. Monitor:     docker logs -f honeypot-exporter"
echo "  2. Health:      curl -sf ${PUBLIC_URL}/health | python3 -m json.tool"
echo "  3. Mint canaries: see DOCS/CANARY_MINTING_FOR_OPERATORS.md and register with the operator."
