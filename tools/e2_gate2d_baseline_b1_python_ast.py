#!/usr/bin/env python3
from __future__ import annotations
import argparse,ast,json
from pathlib import Path
def cb(v):return (json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=False)+"\n").encode()
def names(node):return {x.id for x in ast.walk(node) if isinstance(x,ast.Name)}
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--root",required=True);ap.add_argument("--manifest",required=True);ap.add_argument("--output",required=True);a=ap.parse_args()
 m=json.loads(Path(a.manifest).read_bytes());r=Path(a.root);paths=list(m.get("python_source_paths",[]) or []);req=sorted(set(map(str,m.get("required_identifiers",[]) or [])))
 if not paths or not req:
  native="INAPPLICABLE";norm="INAPPLICABLE";details={}
 else:
  guard=set();sink=set();err=[]
  for p in paths:
   try:t=ast.parse((r/p).read_text())
   except Exception as e:err.append(p+":"+type(e).__name__);continue
   for n in ast.walk(t):
    if isinstance(n,(ast.If,ast.While,ast.Assert,ast.IfExp,ast.Compare)):guard|=names(n.test if hasattr(n,"test") else n)
    if isinstance(n,ast.Call):
     for x in list(n.args)+[k.value for k in n.keywords]:sink|=names(x)
  if err:
   native="UNKNOWN";norm="INCOMPLETE"
  else:
   good=[x for x in req if x in guard and x in sink]
   native="FLOW_FOUND" if len(good)==len(req) else "FLOW_BROKEN";norm="DEFINITIVE_PRESERVATION" if native=="FLOW_FOUND" else "DEFINITIVE_REGRESSION"
  details={"required_identifiers":req,"guard_identifiers":sorted(guard),"call_argument_identifiers":sorted(sink),"parse_errors":err}
 out={"schema":"risu.e2-gate2d-baseline-output/v0.1","baseline_id":"B1_AST_SYNTACTIC_DATAFLOW","native_outcome":native,"normalized_outcome":norm,"details":details}
 Path(a.output).write_bytes(cb(out))
if __name__=="__main__":main()
