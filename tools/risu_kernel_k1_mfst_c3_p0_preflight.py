#!/usr/bin/env python3
"""P0 baseline preflight for W12/W13 candidate promotion checkers."""
from __future__ import annotations
import json, subprocess, sys, tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
TOOLS=ROOT/"tools";sys.path.insert(0,str(TOOLS))
import risu_kernel_k1_mfst_c3_p0_fixture as fx
import risu_kernel_k1_mfst_c3_cert_q0_common as q

W12=ROOT/"kernel/k1_checker_w12_promotion.py"
W13=ROOT/"build/k1_checker_w13_promotion"

SOURCE_ARGS=[
 "--w10-source",str(ROOT/"kernel/k1_checker_w10_refinement_cert.py"),
 "--w11-source",str(ROOT/"kernel/k1_checker_w11_refinement_cert.go"),
 "--w7-model-source",str(ROOT/"kernel/k1_w7_model.py"),
 "--w7-exec-source",str(ROOT/"kernel/k1_w7_exec.py"),
 "--w7-source",str(ROOT/"kernel/k1_checker_w7.py"),
 "--w8-json-source",str(ROOT/"kernel/k1_w8_json.go"),
 "--w8-model-source",str(ROOT/"kernel/k1_w8_model.go"),
 "--w8-exec-source",str(ROOT/"kernel/k1_w8_exec.go"),
 "--w8-source",str(ROOT/"kernel/k1_checker_w8.go"),
 "--w5-source",str(ROOT/"kernel/k1_checker_w5.py"),
 "--w6-source",str(ROOT/"kernel/k1_checker_w6.go"),
]
def run_json(argv):
    p=subprocess.run([str(x) for x in argv],capture_output=True,text=True,check=True)
    return json.loads(p.stdout)
def common(b):
    return [
      "--claim",str(q.CLAIM),"--profile",str(b["profile"]),"--c3-certificate",str(b["c3_certificate"]),
      "--program",str(b["program"]),"--c2-artifact",str(b["artifact"]),
      "--promotion-artifact",str(b["promotion_artifact"]),"--outer-certificate",str(b["outer_certificate"]),
      "--w10",str(ROOT/"kernel/k1_checker_w10_refinement_cert.py"),
      "--w11",str(ROOT/"build/k1_checker_w11_refinement_cert"),
      "--w7",str(ROOT/"kernel/k1_checker_w7.py"),"--w8",str(ROOT/"build/k1_checker_w8"),
      "--w5",str(ROOT/"kernel/k1_checker_w5.py"),"--w6",str(ROOT/"build/k1_checker_w6"),
      *SOURCE_ARGS
    ]
def main():
    with tempfile.TemporaryDirectory() as s:
        b=fx.build(Path(q.BASE).read_bytes(),Path(s),"baseline")
        a=run_json([sys.executable,str(W12),*common(b)])
        c=run_json([str(W13),*common(b)])
        print("P0_PREFLIGHT_W12",json.dumps(a,sort_keys=True,separators=(",",":")))
        print("P0_PREFLIGHT_W13",json.dumps(c,sort_keys=True,separators=(",",":")))
        if a.get("proof_status")!="ACCEPTED" or c.get("proof_status")!="ACCEPTED":raise AssertionError((a,c))
        for k in ("promotion_artifact_id","outer_certificate_id","c3_certificate_id","c2_target_id","realize_pair_count"):
            if a.get(k)!=c.get(k):raise AssertionError(("W12/W13 disagreement",k,a.get(k),c.get(k)))
        if a.get("authority_created") is not False or c.get("authority_created") is not False:raise AssertionError("authority created")
        print("P0_PROMOTION_PREFLIGHT_PASS")
        print("AUTHORITY_CREATED false")
if __name__=="__main__":main()
