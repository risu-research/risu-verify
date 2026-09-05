#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
from risu_e1.engine import write_outputs, verify_output_dir

ROOT=Path(__file__).resolve().parents[1]
FREEZE=ROOT/"experiments"/"risu-diff-e1"/"E1_FREEZE.json"

def engine_identity()->dict:
    data=json.loads(FREEZE.read_text())
    return {
        "freeze_id":data["freeze_id"],
        "protocol_commit":data["protocol_commit"],
        "engine_identity_digest":data["engine_identity_digest"],
        "identity_authority":"repository-canonical-git-bytes",
    }

def main()->int:
    p=argparse.ArgumentParser(description="Run frozen RISU Diff E1 machine-first structural prediction core.")
    p.add_argument("packet_dir",type=Path);p.add_argument("output_dir",type=Path)
    args=p.parse_args()
    try:
        write_outputs(args.packet_dir,args.output_dir,engine_identity())
        verified=verify_output_dir(args.output_dir)
        pred=json.loads((args.output_dir/"E1_PREDICTION.json").read_text())
    except Exception as exc:
        print(json.dumps({"status":"E1_INFRASTRUCTURE_FAILURE","consequence_authority":False,"error_type":type(exc).__name__,"error":str(exc)},sort_keys=True),file=sys.stderr)
        return 20
    print(json.dumps({"status":"PASS","prediction":pred["prediction"],"seal_digest":verified["seal_digest"],"canonical_scientific_authority":False},sort_keys=True))
    return 0
if __name__=="__main__":
    raise SystemExit(main())
