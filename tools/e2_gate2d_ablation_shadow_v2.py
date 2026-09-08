#!/usr/bin/env python3
from __future__ import annotations
import argparse,copy,json
from pathlib import Path
MAP={"E2_PREDICTED_PRESERVATION_EVIDENCE":"DEFINITIVE_PRESERVATION","E2_PREDICTED_REGRESSION_WITNESS":"DEFINITIVE_REGRESSION","E2_PREDICTED_ASSURANCE_INCOMPLETE":"INCOMPLETE"}
def cb(v):return (json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=False)+"\n").encode()
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--ablation",choices=["A1_PRIMARY_ONLY_NO_C1_PROMOTION_GATE","A2_C1_WITHOUT_AUTHORITY_SIDECARS","A3_C1_WITHOUT_CROSS_REPRESENTATION_EVIDENCE"],required=True);ap.add_argument("--input",required=True);ap.add_argument("--output",required=True);a=ap.parse_args()
 d=json.loads(Path(a.input).read_bytes())
 if a.ablation=="A1_PRIMARY_ONLY_NO_C1_PROMOTION_GATE":
  p=d.get("tentative_kernel_prediction");norm=MAP.get(p,"INCOMPLETE");native=str(p)
 else:
  from risu_e2_c1.semantics import _independent_semantic_eval
  x=copy.deepcopy(d.get("c1_semantic_slice",d))
  if a.ablation=="A2_C1_WITHOUT_AUTHORITY_SIDECARS":
   for b in x.get("bindings",[]) or []:
    b["binding_authority_receipts"]=[];b["projection_authority_receipts"]=[]
  else:
   for b in x.get("bindings",[]) or []:
    rep=dict(b.get("representation",{}) or {})
    if rep.get("required") is True:
     rep["closure_complete"]=False;rep["required_slot_present"]=False
    b["representation"]=rep
  r=_independent_semantic_eval(x);native=r["prediction"];norm=MAP.get(native,"INCOMPLETE")
 out={"schema":"risu.e2-gate2d-ablation-output/v0.1","ablation_id":a.ablation,"native_outcome":native,"normalized_outcome":norm}
 Path(a.output).write_bytes(cb(out))
if __name__=="__main__":main()
