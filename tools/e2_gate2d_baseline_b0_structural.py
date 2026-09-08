#!/usr/bin/env python3
from __future__ import annotations
import argparse,json
from pathlib import Path
from typing import Any
def cb(v):return (json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=False)+"\n").encode()
def leaves(x:Any,p="$"):
 out={}
 if isinstance(x,dict):
  for k in sorted(x):out.update(leaves(x[k],p+"."+str(k)))
 elif isinstance(x,list):
  out[p+".[]"]="array"
  for v in x: out.update(leaves(v,p+".[]"))
 else:out[p]=type(x).__name__
 return out
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--root",required=True);ap.add_argument("--manifest",required=True);ap.add_argument("--output",required=True);a=ap.parse_args()
 m=json.loads(Path(a.manifest).read_bytes());r=Path(a.root)
 pa=m.get("authoritative_contract_path");pp=m.get("projection_contract_path")
 if not pa or not pp:
  native="INAPPLICABLE";norm="INAPPLICABLE";detail={}
 else:
  A=leaves(json.loads((r/pa).read_bytes()));P=leaves(json.loads((r/pp).read_bytes()))
  missing=sorted(k for k in A if k not in P or A[k]!=P.get(k))
  extra=sorted(k for k in P if k not in A)
  native="DIFF" if missing or extra else "NO_DIFF"; norm="DEFINITIVE_REGRESSION" if native=="DIFF" else "DEFINITIVE_PRESERVATION"
  detail={"missing_or_type_changed":missing,"extra":extra}
 out={"schema":"risu.e2-gate2d-baseline-output/v0.1","baseline_id":"B0_STRUCTURAL_SCHEMA_DIFF","native_outcome":native,"normalized_outcome":norm,"details":detail}
 Path(a.output).write_bytes(cb(out))
if __name__=="__main__":main()
