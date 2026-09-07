#!/usr/bin/env python3
from __future__ import annotations

"""Stage the exact opaque Candidate-58 source capsule without semantic metadata.

This is the standalone form of the already-used blind-58 source-only staging
algorithm. The caller must make qualification JSON/JSONL metadata unreadable
before invocation. Only source files matching the frozen six seed basenames are
read. Resolution is by (seed_id, language, SHA-256) and output names are opaque
transport_case_id values.
"""

import argparse, hashlib, json, re
from pathlib import Path
from typing import Any

SCHEMA="risu.e2-candidate58-source-only-staging-receipt/v0.1"
MANIFEST_SCHEMA="risu.e2-sanitized-opaque-58-admission-manifest/v0.1"
PATTERN=re.compile(r"^(SYN-(?:PY|GO|TS)-0[12])\.(py|go|mjs|js|ts)$")
LANG={"py":"python","go":"go","mjs":"typescript_javascript","js":"typescript_javascript","ts":"typescript_javascript"}
SUFFIX={"python":".py","go":".go","typescript_javascript":".mjs"}


def canon(value:Any)->bytes:return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
def sha(raw:bytes)->str:return hashlib.sha256(raw).hexdigest()

def main()->int:
    ap=argparse.ArgumentParser();ap.add_argument("--manifest",required=True);ap.add_argument("--cells-dir",required=True);ap.add_argument("--output-dir",required=True);ap.add_argument("--receipt",required=True);a=ap.parse_args()
    manifest_raw=Path(a.manifest).read_bytes(); manifest=json.loads(manifest_raw)
    if manifest.get("schema")!=MANIFEST_SCHEMA or manifest.get("semantic_authority") is not False or manifest.get("case_count")!=58 or len(manifest.get("cases",[]))!=58:raise ValueError("sanitized manifest mismatch")
    cells=Path(a.cells_dir).resolve(strict=True); output=Path(a.output_dir); output.mkdir(parents=True,exist_ok=True)
    lookup={}; source_count=0
    for path in cells.rglob("*"):
        match=PATTERN.fullmatch(path.name)
        if not match or not path.is_file():continue
        raw=path.read_bytes();source_count+=1;key=(match.group(1),LANG[match.group(2)],sha(raw));lookup.setdefault(key,[]).append(raw)
    if source_count!=58:raise ValueError(f"expected exactly 58 source files, got {source_count}")
    rows=[]
    for row in sorted(manifest["cases"],key=lambda x:x["transport_case_id"]):
        key=(row["seed_id"],row["language"],row["candidate_source_sha256"]); values=lookup.get(key,[])
        if len(values)!=1:raise ValueError("opaque admission source resolution is not unique")
        raw=values[0]; target=output/(row["transport_case_id"]+SUFFIX[row["language"]]);target.write_bytes(raw)
        rows.append({"transport_case_id":row["transport_case_id"],"candidate_source_sha256":row["candidate_source_sha256"],"language":row["language"],"seed_id":row["seed_id"],"staged_source_sha256":sha(raw)})
    receipt={"schema":SCHEMA,"status":"PASS","case_count":58,"source_file_count_read":58,"original_cell_path_emitted":False,"cell_json_read":False,"mutation_truth_read":False,"expected_e2_prediction_read":False,"mutation_operator_metadata_read":False,"candidate_source_bytes_emitted_in_receipt":False,"resolution_basis":"SEED_LANGUAGE_SHA256_TO_OPAQUE_ID","rows":rows}
    receipt["receipt_digest_sha256"]=sha(canon(receipt));Path(a.receipt).write_bytes(canon(receipt));print(json.dumps({"status":"PASS","case_count":58,"receipt_sha256":sha(canon(receipt))},sort_keys=True,separators=(",",":")));return 0
if __name__=="__main__":raise SystemExit(main())
