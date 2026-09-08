#!/usr/bin/env python3
from __future__ import annotations
import argparse,json,hashlib
from pathlib import Path
def cb(v):return (json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=False)+"\n").encode()
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--authoritative",required=False);ap.add_argument("--projection",required=False);ap.add_argument("--output",required=True);a=ap.parse_args()
 if not a.authoritative or not a.projection:
  native="INAPPLICABLE";norm="INAPPLICABLE";detail={}
 else:
  A=json.loads(Path(a.authoritative).read_bytes());P=json.loads(Path(a.projection).read_bytes());same=cb(A)==cb(P)
  native="NO_DIFF" if same else "BEHAVIOR_DIFF";norm="DEFINITIVE_PRESERVATION" if same else "DEFINITIVE_REGRESSION"
  detail={"authoritative_sha256":hashlib.sha256(cb(A)).hexdigest(),"projection_sha256":hashlib.sha256(cb(P)).hexdigest()}
 out={"schema":"risu.e2-gate2d-baseline-output/v0.1","baseline_id":"B4_EXECUTION_ONLY_DIFFERENTIAL","native_outcome":native,"normalized_outcome":norm,"details":detail}
 Path(a.output).write_bytes(cb(out))
if __name__=="__main__":main()
