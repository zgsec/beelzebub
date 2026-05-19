#!/usr/bin/env bash
# Verifies OpenClaw has been removed from all 3 repos (beelzebub + honeypot.observer + honeypot-research).
# Excludes: .git/, gitignored trees (out/, venv/, node_modules/), agent-v6-archive/,
# historical docs (strategy/, plans/, specs/), and dated record files (CHANGELOG/KNOWN_ISSUES/MEMORY).
# venv/ + node_modules/ excluded because scipy/sympy/matplotlib math constants
# spuriously match the literal number 18789.
set -euo pipefail

declare -a SEARCH_ROOTS=(
  ~/projects/beelzebub/
  ~/projects/honeypot-research/
  ~/projects/honeypot.observer/
)

HITS=$(grep -rln -iE 'openclaw|18789|OPENCLAW_CANARY' \
  --include='*.yaml' --include='*.yml' --include='*.go' \
  --include='*.py'   --include='*.sh' \
  "${SEARCH_ROOTS[@]}" 2>/dev/null \
  | grep -v '/\.git/' \
  | grep -v '/agent-v6-archive/' \
  | grep -v '/out/' \
  | grep -v '/venv/' \
  | grep -v '/\.venv/' \
  | grep -v '/node_modules/' \
  | grep -v '/docs/superpowers/plans/' \
  | grep -v '/docs/superpowers/specs/' \
  | grep -v '/docs/strategy/' \
  | grep -v '/CHANGELOG' \
  | grep -v '/KNOWN_ISSUES' \
  | grep -v '/MEMORY' \
  | grep -v 'test_no_openclaw' \
  | grep -v 'test_phase_b21_classify_mirror' \
  | grep -v 'classify_test' \
  || true)

if [[ -n "$HITS" ]]; then
  echo "FAIL: OpenClaw references remain in non-historical files:"
  echo "$HITS"
  exit 1
fi
echo "PASS: no OpenClaw references in tracked non-historical files"
