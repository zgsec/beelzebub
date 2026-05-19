#!/usr/bin/env bash
# Integration test: brings up a temporary beelzebub-fork container and
# verifies MCP JSON-RPC handlers echo the request id correctly across
# multiple shapes (numeric, string, missing).
#
# Port 8001 (HTTP strategy): tests /mcp endpoint directly — returns 200
# Port 8000 (MCP strategy HTTP fallback): tests /mcp/recovery/operational-manifest
#   which returns 200 and has "id":1 hardcoded in its YAML handler.
#   Note: /mcp itself on port 8000 is handled by mcp-go (already correct).
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"

TMPDIR_TEST=$(mktemp -d)
trap 'docker stop bzb-id-echo-test 2>/dev/null || true; docker rm bzb-id-echo-test 2>/dev/null || true; rm -rf "$TMPDIR_TEST"' EXIT

echo "Building beelzebub-fork:test image..."
docker build -t beelzebub-fork:test "$REPO_DIR" > /dev/null

# Create minimal test core config (logs to /dev/null, avoids /var/log setup)
cat > "$TMPDIR_TEST/bzb-core.yaml" << 'CORE_EOF'
core:
  logging:
    debug: false
    debugReportCaller: false
    logDisableTimestamp: false
    logsPath: /dev/null
  tracings:
    rabbit-mq:
      enabled: false
      uri: ""
  prometheus:
    path: "/metrics"
    port: ":2112"
  beelzebub-cloud:
    enabled: false
    uri: ""
    auth-token: ""
CORE_EOF

# Use only the two MCP/OpenAI services to avoid http-8888 YAML parse error
mkdir -p "$TMPDIR_TEST/services"
cp "$REPO_DIR/configurations/services/openai-8001.yaml" "$TMPDIR_TEST/services/"
cp "$REPO_DIR/configurations/services/mcp-8000.yaml" "$TMPDIR_TEST/services/"

echo "Starting test container..."
docker run -d --name bzb-id-echo-test \
  -e MCP_CANARY_AWS_KEY=TEST_PLACEHOLDER_NOT_REAL \
  -e MCP_CANARY_AWS_SECRET=test-placeholder-secret \
  -e MCP_CANARY_DNS=test.example.invalid \
  -e MCP_CANARY_SLACK_DNS=slack.example.invalid \
  -e MCP_CANARY_REDIS_DNS=redis.example.invalid \
  -e MCP_CANARY_DB_PASS=testpass \
  -e MCP_CANARY_AWS_KEY_BACKUP=TEST_BACKUP_NOT_REAL \
  -e MCP_CANARY_WEB_URL=http://test.example.invalid/web \
  -e MCP_CANARY_DD_KEY=dd-test-key \
  -e MCP_CANARY_VAULT_TOKEN=hvs.testtoken \
  -e OPEN_AI_SECRET_KEY=test \
  -p 18000:8000 -p 18001:8001 \
  -v "$TMPDIR_TEST/bzb-core.yaml:/configurations/bzb-core.yaml:ro" \
  -v "$TMPDIR_TEST/services:/configurations/services:ro" \
  beelzebub-fork:test \
  -confCore /configurations/bzb-core.yaml \
  -confServices /configurations/services/ > /dev/null

sleep 4

PASS=0
FAIL=0

test_one() {
  local endpoint=$1
  local id_value=$2  # The id field value as a JSON token: "42", "\"req-abc\"", "null"
  local body
  if [[ "$id_value" == "null" ]]; then
    body='{"jsonrpc":"2.0","method":"initialize","params":{}}'  # no id field
    expected="null"
  else
    body="{\"jsonrpc\":\"2.0\",\"id\":$id_value,\"method\":\"initialize\",\"params\":{}}"
    expected=$id_value
  fi
  # Use -s without -f to capture non-2xx responses (e.g. 500 from error endpoints)
  resp=$(curl -s -X POST -H 'Content-Type: application/json' --data "$body" "$endpoint" 2>/dev/null || echo "REQUEST_FAIL")
  if [[ "$resp" == "REQUEST_FAIL" ]] || [[ -z "$resp" ]]; then
    echo "  FAIL: $endpoint id=$id_value expected=$expected — REQUEST_FAIL (no response)"
    FAIL=$((FAIL+1))
    return
  fi
  got=$(echo "$resp" | jq -c .id 2>/dev/null || echo "JSON_PARSE_FAIL")
  if [[ "$got" == "$expected" ]]; then
    echo "  OK: $endpoint id=$id_value → $got"
    PASS=$((PASS+1))
  else
    echo "  FAIL: $endpoint id=$id_value expected=$expected got=$got"
    echo "    raw response: ${resp:0:200}"
    FAIL=$((FAIL+1))
  fi
}

echo "Testing MCP id-echo on port 8001 /mcp (HTTP strategy — YAML handler, 200)..."
test_one "http://localhost:18001/mcp" "42"
test_one "http://localhost:18001/mcp" "\"req-abc\""
test_one "http://localhost:18001/mcp" "null"  # missing field → null

echo "Testing MCP id-echo on port 8000 /mcp/recovery/operational-manifest (MCP HTTP fallback — YAML handler, 200)..."
test_one "http://localhost:18000/mcp/recovery/operational-manifest" "42"
test_one "http://localhost:18000/mcp/recovery/operational-manifest" "\"req-abc\""
test_one "http://localhost:18000/mcp/recovery/operational-manifest" "null"

echo ""
echo "Results: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]] || exit 1
