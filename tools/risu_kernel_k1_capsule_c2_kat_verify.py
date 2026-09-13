#!/usr/bin/env python3
"""Fixed known-answer conformance test for C2 W5/W6.

Unlike the dynamic qualification oracles, this script does not derive expected
commitments. It checks exact fixture bytes against precomputed constants and
then requires both independent checkers to reproduce the frozen result.
"""

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path


def run(cmd, root):
    p=subprocess.run(cmd+["--claim",str(root/"claim.json"),"--certificate",str(root/"certificate.json"),"--artifact",str(root/"artifact.json"),"--program",str(root/"program.cap")],text=True,capture_output=True,check=True)
    return json.loads(p.stdout)


def main():
    ap=argparse.ArgumentParser();ap.add_argument("--w6",required=True);ap.add_argument("--output",required=True);args=ap.parse_args()
    root=Path("fixtures/k1_capsule_c2_kat");expected=json.loads((root/"expected.json").read_text());claim=json.loads((root/"claim.json").read_text());cert=json.loads((root/"certificate.json").read_text());program=(root/"program.cap").read_bytes();artifact=(root/"artifact.json").read_bytes()
    checks={
        "program_sha256": hashlib.sha256(program).hexdigest()==expected["program_sha256"],
        "artifact_id": "p:sha256:"+hashlib.sha256(artifact).hexdigest()==expected["artifact_id"],
        "claim_id_fixture": claim["claim_id"]==expected["claim_id"],
        "certificate_id_fixture": cert["certificate_id"]==expected["certificate_id"],
        "target_id_fixture": cert["target_id"]==expected["target_id"],
        "realize_fixture": cert["realize"]==expected["derived_realize"],
    }
    w5=run([sys.executable,"kernel/k1_checker_w5.py"],root);w6=run([args.w6],root)
    for name,x in [("w5",w5),("w6",w6)]:
        checks[name+"_accepted"]=x.get("proof_status")==expected["proof_status"] and x.get("semantic_claim")==expected["semantic_claim"]
        checks[name+"_target"]=x.get("target_id")==expected["target_id"]
        checks[name+"_certificate"]=x.get("certificate_id")==expected["certificate_id"]
        checks[name+"_relation"]=x.get("derived_realize")==expected["derived_realize"]
        checks[name+"_scope"]=x.get("assurance_scope")=="BOUNDED_HERMETIC_CAPSULE_EXHAUSTIVE" and x.get("implementation_binding") is True
    checks["cross_checker_exact"]=w5.get("target_id")==w6.get("target_id") and w5.get("derived_realize")==w6.get("derived_realize") and w5.get("certificate_id")==w6.get("certificate_id")
    out={"gate":"RISU_KERNEL_K1_CAPSULE_CLOSURE_C2_KAT","status":"PASS" if all(checks.values()) else "FAIL","checks":checks,"expected":expected}
    Path(args.output).write_text(json.dumps(out,sort_keys=True,indent=2)+"\n");print(json.dumps(out,sort_keys=True));return 0 if out["status"]=="PASS" else 1

if __name__=="__main__": raise SystemExit(main())
