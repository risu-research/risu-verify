#!/usr/bin/env python3
"""Q0 candidate preflight: representation invariance of the actual certificate object."""
from __future__ import annotations
import json, subprocess, sys, tempfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
CLAIM=ROOT/"fixtures/k1_mfst_c3_f0/claim.json"
PROFILE=ROOT/"fixtures/k1_mfst_c3_f0/baseline.json"
FIX=ROOT/"tools/risu_kernel_k1_mfst_c3_cert_c0_fixture.py"
W10=ROOT/"kernel/k1_checker_w10_refinement_cert.py"
W11=ROOT/"build/k1_checker_w11_refinement_cert"
W7=ROOT/"kernel/k1_checker_w7.py"; W8=ROOT/"build/k1_checker_w8"
W5=ROOT/"kernel/k1_checker_w5.py"; W6=ROOT/"build/k1_checker_w6"

def run_json(argv):
    cp=subprocess.run([str(x) for x in argv],capture_output=True,text=True,check=True)
    return json.loads(cp.stdout)

def check(checker,cert,program,artifact):
    common=["--claim",str(CLAIM),"--profile",str(PROFILE),"--certificate",str(cert),
            "--program",str(program),"--artifact",str(artifact),"--w7",str(W7),"--w8",str(W8),
            "--w5",str(W5),"--w6",str(W6)]
    if checker=="w10": return run_json([sys.executable,str(W10)]+common)
    return run_json([str(W11)]+common)

def main():
    with tempfile.TemporaryDirectory() as s:
        td=Path(s); cert=td/"cert.json"; program=td/"program.cap"; artifact=td/"artifact.json"
        subprocess.run([sys.executable,str(FIX),"--claim",str(CLAIM),"--profile",str(PROFILE),
                        "--w7",str(W7),"--w8",str(W8),"--out",str(cert),
                        "--program_out",str(program),"--artifact_out",str(artifact)],check=True)
        base=json.loads(cert.read_text())
        a=check("w10",cert,program,artifact); b=check("w11",cert,program,artifact)
        if a.get("proof_status")!="ACCEPTED" or b.get("proof_status")!="ACCEPTED":
            raise AssertionError(("baseline candidate failed",a,b))
        # Q0 positive oracle: projected_REALIZE is a mathematical set in the C0 wire.
        # Reordering pairs changes neither its certificate transcript nor its semantic object.
        perm=dict(base); perm["projected_realize"]=list(reversed(base["projected_realize"]))
        # Keep the same certificate_id intentionally: transcript sorts the relation.
        if perm["projected_realize"]==base["projected_realize"]:
            raise AssertionError("baseline relation unexpectedly palindromic")
        pc=td/"relation-permuted.json"
        pc.write_text(json.dumps(perm,indent=2),encoding="utf-8")
        x=check("w10",pc,program,artifact); y=check("w11",pc,program,artifact)
        print("Q0_PRECHECK_RELATION_ORDER_W10",json.dumps(x,sort_keys=True,separators=(",",":")))
        print("Q0_PRECHECK_RELATION_ORDER_W11",json.dumps(y,sort_keys=True,separators=(",",":")))
        if x.get("proof_status")!="ACCEPTED" or y.get("proof_status")!="ACCEPTED":
            raise AssertionError(("Q0 positive representation oracle failed",x,y))
        if x.get("certificate_id")!=base["certificate_id"] or y.get("certificate_id")!=base["certificate_id"]:
            raise AssertionError(("certificate id not invariant",x,y,base["certificate_id"]))
        print("Q0_CANDIDATE_PREFLIGHT_PASS")
        print("AUTHORITY_CREATED false")
if __name__=="__main__": main()
