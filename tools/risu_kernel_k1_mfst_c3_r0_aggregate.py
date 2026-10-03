#!/usr/bin/env python3
"""Aggregate verifier for exhaustive R0 W9 crossed-reference shards."""
from __future__ import annotations
import argparse, hashlib, json
from pathlib import Path

ROOT = "c731db89e79e75f4d22f38788aded1a9c9e70572467615da448b7e1c9ce93346"
SHARDS = 16
SIZE = 1152
TOTAL = 18432
POINTS = 73728

def canon(x):
    return json.dumps(x, sort_keys=True, separators=(",",":"), ensure_ascii=True).encode()

def main():
    a=argparse.ArgumentParser()
    a.add_argument("--input",required=True)
    a.add_argument("--veto",required=True)
    a.add_argument("--output",required=True)
    x=a.parse_args()
    d=Path(x.input)
    files=sorted(d.glob("r0-shard-*.json"))
    if len(files)!=SHARDS:
        raise SystemExit(f"expected {SHARDS} shard summaries, got {len(files)}")
    rows=[json.loads(p.read_text()) for p in files]
    by={r["shard"]:r for r in rows}
    if set(by)!=set(range(SHARDS)):
        raise SystemExit("shard inventory mismatch")
    compiler_blobs={r["compiler_blob"] for r in rows}
    if len(compiler_blobs)!=1 or "" in compiler_blobs:
        raise SystemExit("compiler blob mismatch")
    desc=pts=0
    max_prog=max_gas=0
    digest=hashlib.sha256()
    for i in range(SHARDS):
        r=by[i]
        if r["w9_root"]!=ROOT or r["authority_created"] is not False:
            raise SystemExit("root/authority")
        if r["start_index"]!=i*SIZE or r["stop_index_exclusive"]!=(i+1)*SIZE:
            raise SystemExit("range gap/overlap")
        if r["descriptor_count"]!=SIZE or r["point_trace_comparisons"]!=SIZE*4:
            raise SystemExit("count")
        for k in ("w9_mismatches","w7_w8_direct_disagreements","cross_replay_disagreements","w5_w6_downstream_disagreements"):
            if r[k]!=0:
                raise SystemExit(f"nonzero {k} shard {i}")
        desc += r["descriptor_count"]; pts += r["point_trace_comparisons"]
        max_prog=max(max_prog,r["max_c2_program_bytes"]); max_gas=max(max_gas,r["max_c2_gas"])
        digest.update(canon(r)+b"\n")
    if desc!=TOTAL or pts!=POINTS:
        raise SystemExit("aggregate counts")
    veto=json.loads(Path(x.veto).read_text())
    if veto["w9_root"]!=ROOT or veto["authority_created"] is not False:
        raise SystemExit("veto root")
    if veto["common_mode_veto_controls_passed"]!=4 or len(veto["controls"])!=4:
        raise SystemExit("veto count")
    for c in veto["controls"]:
        if c["ordinary_crossed_square"]!="PASS" or c["w5_w6_downstream"]!="PASS" or c["w9_exact_trace_veto"]!="PASS":
            raise SystemExit("veto failure")
    digest.update(canon(veto)+b"\n")
    out={
        "gate":"risu.k1.mfst.c3.reference-r0.cross-gate/v1",
        "status":"PASS",
        "authority_created":False,
        "w9_root":ROOT,
        "compiler_blob":next(iter(compiler_blobs)),
        "shards":SHARDS,
        "descriptor_count":desc,
        "point_trace_comparisons":pts,
        "w9_mismatches":0,
        "w7_w8_direct_disagreements":0,
        "cross_replay_disagreements":0,
        "w5_w6_downstream_disagreements":0,
        "common_mode_veto_controls_passed":4,
        "max_c2_program_bytes":max_prog,
        "max_c2_gas":max_gas,
        "aggregate_digest":digest.hexdigest(),
        "shard_digests":{str(i):by[i]["shard_digest"] for i in range(SHARDS)}
    }
    Path(x.output).write_bytes(canon(out)+b"\n")
    print("R0_ORTHOGONAL_REFERENCE_PASS",desc,pts)
    print("R0_COMMON_MODE_VETO_TOTAL_PASS",4)
    print("R0_AGGREGATE_DIGEST",out["aggregate_digest"])
    print("R0_MAX_C2",max_prog,max_gas)
    print("AUTHORITY_CREATED false")

if __name__=="__main__": main()
