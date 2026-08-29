#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
BASE="cases/azure-devops-wiki-etag"
MUT="$BASE/mutations/ignore-supplied-etag"

# The real pinned projection must reproduce its preserving semantic lock.
./risu-verify check "$BASE"

# The synthetic semantic mutation must be a valid negative certificate (exit 10).
set +e
./risu-verify verify "$MUT"
verify_rc=$?
set -e
if [[ "$verify_rc" -ne 10 ]]; then
  echo "expected mutant semantic exit 10, got $verify_rc" >&2
  exit 1
fi

# The same mutation must break the preserving baseline lock (exit 40).
set +e
./risu-verify check "$MUT" --lock "$BASE/risu.lock.json"
lock_rc=$?
set -e
if [[ "$lock_rc" -ne 40 ]]; then
  echo "expected mutant lock exit 40, got $lock_rc" >&2
  exit 1
fi

echo "SEMANTIC_CI_DEMO: PASS"
