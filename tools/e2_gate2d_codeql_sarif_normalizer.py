#!/usr/bin/env python3
from __future__ import annotations
import argparse,json
from pathlib import Path
def cb(v):return (json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=False)+"\n").encode()
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--sarif",required=True);ap.add_argument("--output",required=True);a=ap.parse_args()
 try:
  d=json.loads(Path(a.sarif).read_bytes());runs=list(d.get("runs",[]) or []);results=[]
  for r in runs:results.extend(list(r.get("results",[]) or []))
  native="ONE_OR_MORE_ALERTS" if results else "ZERO_ALERTS";norm="DEFINITIVE_REGRESSION" if results else "INCOMPLETE"
  detail={"alert_count":len(results),"rule_ids":sorted(set(str(x.get("ruleId","")) for x in results if x.get("ruleId")))}
 except Exception as e:
  native="ENGINE_ERROR";norm="BASELINE_INVALID";detail={"error_type":type(e).__name__}
 out={"schema":"risu.e2-gate2d-baseline-output/v0.1","baseline_id":"B2_STRONG_STATIC_DATAFLOW","native_outcome":native,"normalized_outcome":norm,"details":detail}
 Path(a.output).write_bytes(cb(out))
if __name__=="__main__":main()
