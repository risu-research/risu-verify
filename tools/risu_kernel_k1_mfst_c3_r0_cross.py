#!/usr/bin/env python3
"""R0 exhaustive W9-vs-W7/W8 crossed reference runner."""
from __future__ import annotations
import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))

import risu_kernel_k1_mfst_c3_crossed_gate as crossed
import risu_kernel_k1_mfst_c3_r0_compiler as compiler

W0 = "w:sha256:" + "1" * 64
W1 = "w:sha256:" + "2" * 64
W9_ROOT = "c731db89e79e75f4d22f38788aded1a9c9e70572467615da448b7e1c9ce93346"
TOTAL = 18432
SHARD_SIZE = 1152

def canon(x):
    return json.dumps(x, sort_keys=True, separators=(",",":"), ensure_ascii=True).encode("utf-8")

def load_reference(path):
    rows = []
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for line in f:
            if not line.endswith(b"\n"):
                raise AssertionError("reference line missing LF")
            h.update(line)
            rows.append(json.loads(line))
    if len(rows) != TOTAL:
        raise AssertionError(("reference count", len(rows)))
    if h.hexdigest() != W9_ROOT:
        raise AssertionError(("reference root", h.hexdigest()))
    for i, r in enumerate(rows):
        want = f"R0-{i:05d}"
        if r.get("descriptor_id") != want:
            raise AssertionError(("reference id", i, r.get("descriptor_id"), want))
    return rows

def expected_trace(record):
    out = []
    for p in record["point_traces"]:
        if p["world_symbol"] == "W0":
            w = W0
        elif p["world_symbol"] == "W1":
            w = W1
        else:
            raise AssertionError(("world symbol", p))
        if p["x_symbol"] == "X0":
            x = "v0"
        elif p["x_symbol"] == "X1":
            x = "v1"
        else:
            raise AssertionError(("x symbol", p))
        out.append({"point":{"@world":w,"x":x},"payloads":list(p["payloads"])})
    return out

def compiler_contract(profile, record):
    if set(profile) != {"wire","kind","claim_id","boundary","state","tables","entry","blocks"}:
        raise AssertionError("compiler top-level shape")
    if profile["wire"] != "risu.k1.c3.mfst/v1" or profile["kind"] != "mediated_finite_state_transducer":
        raise AssertionError("compiler wire")
    if profile["boundary"] != {"worlds":[W0,W1],"slots":{"x":["v0","v1"]}}:
        raise AssertionError("compiler boundary")
    if len(profile["state"]) != 1 or profile["state"][0]["name"] != "q" or profile["state"][0]["domain"] != ["v0","v1"]:
        raise AssertionError("compiler state")
    if profile["entry"] != "entry" or [b["label"] for b in profile["blocks"]] != ["entry","T","F"]:
        raise AssertionError("compiler blocks")
    if profile["blocks"][1]["term"] != {"op":"HALT"} or profile["blocks"][2]["term"] != {"op":"HALT"}:
        raise AssertionError("compiler halt")
    if not profile["blocks"][1]["ops"] or not profile["blocks"][2]["ops"]:
        raise AssertionError("compiler terminal effects")
    if any(o.get("op") != "EMIT_HEX" for b in profile["blocks"][1:] for o in b["ops"]):
        raise AssertionError("compiler terminal op")
    # Exact table cardinality follows the frozen update family.
    table_update = record["update"].endswith("_TABLE")
    if len(profile["tables"]) != (1 if table_update else 0):
        raise AssertionError(("compiler table count", record["descriptor_id"]))

def compare_one(record, raw):
    expected = expected_trace(record)
    got = crossed.full_chain(record["descriptor_id"], raw, require_allowed=True)
    if got["trace"] != expected:
        raise AssertionError((record["descriptor_id"], "W9 versus crossed direct trace mismatch", expected, got["trace"]))
    # full_chain already enforces W7==W8, both crossed replay directions,
    # exact CBTNF/artifact equality, and W5/W6 reconstruction on both paths.
    return got, expected

def run_shard(ref, shard, summary_path, compiler_blob):
    if shard < 0 or shard >= 16:
        raise AssertionError("shard")
    start = shard * SHARD_SIZE
    stop = start + SHARD_SIZE
    digest = hashlib.sha256()
    uniq_prog = set()
    uniq_trace = set()
    uniq_sem = set()
    point_count = 0
    max_prog = 0
    max_gas = 0
    for off, record in enumerate(ref[start:stop]):
        profile = compiler.compile_descriptor(record)
        compiler_contract(profile, record)
        raw = compiler.compile_bytes(record)
        got, expected = compare_one(record, raw)
        point_count += len(expected)
        uniq_prog.add(got["r7"]["c2_program_sha256"])
        uniq_trace.add(got["r7"]["trace_map_id"])
        uniq_sem.add(got["r7"]["c3_semantic_id"])
        max_prog = max(max_prog, got["r7"]["c2_program_bytes"])
        max_gas = max(max_gas, got["r7"]["c2_derived_gas"])
        digest.update(canon({
            "descriptor_id":record["descriptor_id"],
            "profile_sha256":hashlib.sha256(raw).hexdigest(),
            "trace_map_id":got["r7"]["trace_map_id"],
            "c2_program_sha256":got["r7"]["c2_program_sha256"],
            "c2_target_id":got["r7"]["c2_target_id"],
            "expected":expected,
        }) + b"\n")
        if (off + 1) % 128 == 0:
            print("R0_CROSS_PROGRESS", shard, off + 1)
    summary = {
        "gate":"risu.k1.mfst.c3.reference-r0.cross-gate/v1",
        "authority_created":False,
        "w9_root":W9_ROOT,
        "compiler_blob":compiler_blob,
        "shard":shard,
        "start_index":start,
        "stop_index_exclusive":stop,
        "descriptor_count":stop-start,
        "point_trace_comparisons":point_count,
        "w9_mismatches":0,
        "w7_w8_direct_disagreements":0,
        "cross_replay_disagreements":0,
        "w5_w6_downstream_disagreements":0,
        "unique_c2_programs":len(uniq_prog),
        "unique_trace_map_ids":len(uniq_trace),
        "unique_semantic_ids":len(uniq_sem),
        "max_c2_program_bytes":max_prog,
        "max_c2_gas":max_gas,
        "shard_digest":digest.hexdigest(),
    }
    Path(summary_path).parent.mkdir(parents=True, exist_ok=True)
    Path(summary_path).write_bytes(canon(summary)+b"\n")
    print("R0_CROSS_SHARD_PASS", shard, stop-start, point_count, digest.hexdigest())
    print("AUTHORITY_CREATED false")

def run_veto(ref, summary_path):
    controls = [
        ("R0-VETO-PREDICATE-FLIP","R0-00001","predicate_flip"),
        ("R0-VETO-PREFIX-DROP","R0-00065","prefix_drop"),
        ("R0-VETO-EFFECT-ORDER","R0-00017","effect_order"),
        ("R0-VETO-TABLE-ROW","R0-04865","table_row"),
    ]
    by_id = {r["descriptor_id"]:r for r in ref}
    results = []
    for cid, rid, mutation in controls:
        record = by_id[rid]
        good_raw = compiler.compile_bytes(record)
        good, expected = compare_one(record, good_raw)
        bad_profile = compiler.compile_descriptor(record, mutation=mutation)
        bad_raw = json.dumps(bad_profile, sort_keys=True, separators=(",",":"), ensure_ascii=True).encode("utf-8")
        # This must remain a completely self-consistent ordinary crossed square.
        bad = crossed.full_chain(cid, bad_raw, require_allowed=True)
        if bad["trace"] == expected:
            raise AssertionError((cid, "W9 failed to veto mutated common-mode object"))
        same_realize = bad["realize"] == good["realize"]
        if cid == "R0-VETO-EFFECT-ORDER" and not same_realize:
            raise AssertionError((cid, "effect-order control unexpectedly changed K1 set projection"))
        results.append({
            "id":cid,
            "descriptor_id":rid,
            "mutation":mutation,
            "ordinary_crossed_square":"PASS",
            "w5_w6_downstream":"PASS",
            "w9_exact_trace_veto":"PASS",
            "k1_realize_same_as_good":same_realize,
        })
        print("R0_COMMON_MODE_VETO_PASS", cid, rid, mutation, "K1_SAME", str(same_realize).lower())
    out = {
        "gate":"risu.k1.mfst.c3.reference-r0.cross-gate/v1",
        "authority_created":False,
        "w9_root":W9_ROOT,
        "common_mode_veto_controls_passed":len(results),
        "controls":results,
    }
    Path(summary_path).parent.mkdir(parents=True, exist_ok=True)
    Path(summary_path).write_bytes(canon(out)+b"\n")
    print("R0_COMMON_MODE_VETO_TOTAL_PASS", len(results))
    print("AUTHORITY_CREATED false")

def main():
    a=argparse.ArgumentParser()
    a.add_argument("--reference",required=True)
    a.add_argument("--summary",required=True)
    a.add_argument("--shard",type=int)
    a.add_argument("--compiler-blob",default="")
    a.add_argument("--veto-controls",action="store_true")
    x=a.parse_args()
    ref=load_reference(x.reference)
    if x.veto_controls:
        run_veto(ref,x.summary)
    else:
        if x.shard is None:
            raise SystemExit("--shard required")
        run_shard(ref,x.shard,x.summary,x.compiler_blob)

if __name__=="__main__":
    main()
