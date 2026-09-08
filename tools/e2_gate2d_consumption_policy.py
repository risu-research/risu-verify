#!/usr/bin/env python3
from __future__ import annotations
import argparse,json
from pathlib import Path
def cb(v):return (json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=False)+"\n").encode()
def classify(d):
 if d.get("post_repair_same_heldout") is True:return "POST_EXPOSURE_DIAGNOSTIC_ONLY"
 semantic=int(d.get("full_system_semantic_execution_count",0) or 0)+int(d.get("baseline_execution_count",0) or 0)+int(d.get("ablation_execution_count",0) or 0)
 if semantic>0 or int(d.get("machine_prediction_count",0) or 0)>0 or d.get("truth_read") is True or d.get("raw_human_exposure") is True:return "NO_CLEAN_RERUN"
 if d.get("opaque_staging_only") is True and d.get("truth_read") is not True and d.get("raw_human_exposure") is not True:return "RETRY_ELIGIBLE"
 if d.get("source_bytes_read") is not True and d.get("truth_read") is not True and semantic==0:return "RETRY_ELIGIBLE"
 return "NO_CLEAN_RERUN"
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--input",required=True);ap.add_argument("--output",required=True);a=ap.parse_args()
 d=json.loads(Path(a.input).read_bytes());o={"schema":"risu.e2-gate2d-heldout-consumption-policy/v0.1","decision":classify(d)}
 Path(a.output).write_bytes(cb(o))
if __name__=="__main__":main()
