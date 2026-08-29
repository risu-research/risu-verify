#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

set +e
./risu-verify verify cases/github-create-update-sha-transition/before >/tmp/risu_hist_before.txt 2>&1
before_rc=$?
set -e
if [ "$before_rc" -ne 10 ]; then
  cat /tmp/risu_hist_before.txt
  echo "Expected BEFORE consequence-regression exit 10; got $before_rc" >&2
  exit 1
fi

./risu-verify check cases/github-create-update-sha-transition/after >/tmp/risu_hist_after.txt 2>&1

python - <<'PY'
import json, pathlib
root=pathlib.Path('.')
b=json.loads((root/'.risu/out/hist-github-create-update-sha-003-before/report.json').read_text())
a=json.loads((root/'.risu/out/hist-github-create-update-sha-003-after/report.json').read_text())
assert b['product_status']=='CONSEQUENCE_REGRESSION'
assert (b['structural']['C'],b['structural']['D'],b['structural']['O'])==('C0','NA','NA')
assert a['product_status']=='PRESERVED'
assert (a['structural']['C'],a['structural']['D'],a['structural']['O'])==('C1','D1','O1')
print('HISTORICAL_TRANSITION_DEMO: PASS')
print('BEFORE: CONSEQUENCE_REGRESSION C0/D-NA/O-NA')
print('AFTER:  PRESERVED C1/D1/O1')
PY
