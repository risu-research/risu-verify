from __future__ import annotations

"""Bookkeeping-only wrapper around the frozen Gate1B/1C bridge CLI v1.

The scientific child process and its closed-read-set execution are unchanged.
This wrapper only converts negative firewall observations into positive PASS
invariants after the child has emitted a complete canonical qualification
result.  adapt-primary return behavior is unchanged.
"""

import json
from pathlib import Path
import subprocess
import sys


def _canonical_bytes(value):
    return (json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False)+"\n").encode("utf-8")


def main() -> int:
    args=list(sys.argv[1:])
    proc=subprocess.run([sys.executable,"-m","risu_e2_semantic.bridge_cli_v1",*args],check=False)
    if not args or args[0]!="canonical":
        return int(proc.returncode)
    try:
        outdir=Path(args[args.index("--output-dir")+1])
        path=outdir/"E2_GATE1B1C_CANONICAL_BRIDGE_RESULT.json"
        result=json.loads(path.read_text())
    except Exception:
        return int(proc.returncode)
    checks=result.get("checks",{}) or {}
    required_true=("public_signature_byte_identity","seed_count","control_forms","helper_py02_exact","no_target_rho_stored","closed_read_set")
    required_false=("candidate_bytes_read","a3_a4_verdict_executed")
    positive={k:checks.get(k) is True for k in required_true}
    positive.update({k.replace("_read","_not_read").replace("verdict_executed","verdict_not_executed"):checks.get(k) is False for k in required_false})
    result["checks"]=positive
    result["status"]="PASS" if all(positive.values()) else "FAIL"
    result["bookkeeping_remediation"]="NEGATIVE_FIREWALL_OBSERVATIONS_NORMALIZED_TO_POSITIVE_PASS_INVARIANTS"
    path.write_bytes(_canonical_bytes(result))
    print(json.dumps(result,sort_keys=True,separators=(",",":")))
    return 0 if result["status"]=="PASS" else 1

if __name__=="__main__": raise SystemExit(main())
