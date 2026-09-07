#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Mapping, Sequence

PROTOCOL_SCHEMA="risu.e2-gate2c4-projection-shape-triangulation-protocol/v0.1"
TAXONOMY=[
 "TRACE_INPUT_INTEGRITY_FAILURE","CANONICAL_PROJECTION_SHAPE_UNRESOLVED","C1_PROJECTION_SHAPE_UNRESOLVED",
 "PRIMARY_PROJECTION_SHAPE_UNRESOLVED","C1_VS_CANONICAL_SHAPE_MISMATCH","PRIMARY_VS_CANONICAL_SHAPE_MISMATCH",
 "C1_VS_PRIMARY_SHAPE_MISMATCH","THREE_WAY_PROJECTION_SHAPE_MATCH",
]
ROLES=("BOUND_VALUE:expected_coordinate","BOUND_VALUE:current_coordinate")
SLOT={"BOUND_VALUE:expected_coordinate":"expected_coordinate","BOUND_VALUE:current_coordinate":"current_coordinate"}


def cb(v:Any)->bytes:return (json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=False)+"\n").encode()
def readj(p:Path)->Any:return json.loads(p.read_bytes())

def classify(canonical:Sequence[str]|None,c1:Sequence[str]|None,primary:Sequence[str]|None)->str:
    if canonical is None:return "CANONICAL_PROJECTION_SHAPE_UNRESOLVED"
    if c1 is None:return "C1_PROJECTION_SHAPE_UNRESOLVED"
    if primary is None:return "PRIMARY_PROJECTION_SHAPE_UNRESOLVED"
    if list(c1)!=list(canonical):return "C1_VS_CANONICAL_SHAPE_MISMATCH"
    if list(primary)!=list(canonical):return "PRIMARY_VS_CANONICAL_SHAPE_MISMATCH"
    if list(c1)!=list(primary):return "C1_VS_PRIMARY_SHAPE_MISMATCH"
    return "THREE_WAY_PROJECTION_SHAPE_MATCH"

def canonical_shape(profiles:Mapping[str,Any],role:str)->list[str]|None:
    rows=[p for p in profiles.get("profiles",[]) or [] if p.get("seed_id")=="SYN-PY-01"]
    if len(rows)!=1:return None
    rr=(rows[0].get("source_roles",{}) or {}).get(role,{}) or {}; shapes=rr.get("lineage_edge_shapes",[]) or []
    if len(shapes)!=1 or not isinstance(shapes[0],list):return None
    shape=[str(x) for x in shapes[0]]
    return shape if all(x in {"DERIVES","CARRIES"} for x in shape) else None

def c1_shape(row:Mapping[str,Any],role:str)->list[str]|None:
    prim=row.get("primitive",{}) or {}; vals=[prim.get("left_origin"),prim.get("right_origin")]; found=[]
    for raw in vals:
        if not isinstance(raw,str):continue
        if raw==role:found.append([]);continue
        prefix=role+".slot:"
        if raw.startswith(prefix):
            tail=raw[len(role):]
            parts=tail.split(".slot:")[1:]
            if parts and all(x and "." not in x for x in parts):found.append(["DERIVES"]*len(parts))
    return found[0] if len(found)==1 else None

def primary_shape(doc:Mapping[str,Any],role:str)->list[str]|None:
    bid="GUARD_SLOT:"+SLOT[role]
    rows=[b for b in doc.get("bindings",[]) or [] if b.get("binding_id")==bid]
    if len(rows)!=1:return None
    paths=[p for p in rows[0].get("lineage_paths",[]) or [] if p.get("origin")==role]
    if len(paths)!=1:return None
    edges=paths[0].get("edges",[]) or []
    shape=[]
    for e in edges:
        if e.get("primary_edge_id") is None:continue
        kind=str(e.get("kind"))
        if kind not in {"DERIVES","CARRIES"}:return None
        shape.append(kind)
    return shape

def integrity_failure(case_id:str,role:str,reasons:list[str],population:str)->dict[str,Any]:
    return {"case_id":case_id,"role":role,"population":population,"taxonomy":"TRACE_INPUT_INTEGRITY_FAILURE","reasons":sorted(set(reasons)),"canonical_shape":None,"c1_shape":None,"primary_shape":None}

def diagnose(*,protocol:Mapping[str,Any],profiles:Mapping[str,Any],ledger:Mapping[str,Any],matrix:Mapping[str,Any],primary_docs:Mapping[str,Mapping[str,Any]])->tuple[dict[str,Any],dict[str,Any]]:
    if protocol.get("schema")!=PROTOCOL_SCHEMA:raise ValueError("protocol schema mismatch")
    pilot=str(protocol["population"]["pilot_case_id"]);confirm=[str(x) for x in protocol["population"]["confirmatory_case_ids"]];all_ids=[pilot]+confirm
    lrows={str(x["case_id"]):x for x in ledger.get("cases",[]) or []};mrows={str(x["case_id"]):x for x in matrix.get("cases",[]) or []}
    out=[]
    for cid in all_ids:
        pop="PILOT_DESCRIPTIVE" if cid==pilot else "CONFIRMATORY"
        for role in ROLES:
            bad=[]
            if cid not in lrows:bad.append("GATE2C3_LEDGER_CASE_MISSING")
            if cid not in mrows:bad.append("GATE2C2A_MATRIX_CASE_MISSING")
            if cid not in primary_docs:bad.append("PRIMARY_SEMANTIC_SLICE_MISSING")
            if cid in lrows and lrows[cid].get("taxonomy")!="WORLD_ROLE_VALUE_MISSING_LEFT":bad.append("GATE2C3_POPULATION_TAXONOMY_MISMATCH")
            if cid in mrows and mrows[cid].get("semantic_slice_sha256") is None:bad.append("MATRIX_SEMANTIC_SLICE_SHA_MISSING")
            if bad:
                out.append(integrity_failure(cid,role,bad,pop));continue
            cs=canonical_shape(profiles,role);c1s=c1_shape(lrows[cid],role);ps=primary_shape(primary_docs[cid],role);tax=classify(cs,c1s,ps)
            out.append({"case_id":cid,"role":role,"population":pop,"taxonomy":tax,"reasons":[],"canonical_shape":cs,"c1_shape":c1s,"primary_shape":ps})
    counts={k:0 for k in TAXONOMY};confirm_counts={k:0 for k in TAXONOMY};pilot_counts={k:0 for k in TAXONOMY}
    for r in out:
        counts[r["taxonomy"]]+=1;(confirm_counts if r["population"]=="CONFIRMATORY" else pilot_counts)[r["taxonomy"]]+=1
    success=confirm_counts["THREE_WAY_PROJECTION_SHAPE_MATCH"]==12 and sum(v for k,v in confirm_counts.items() if k!="THREE_WAY_PROJECTION_SHAPE_MATCH")==0
    summary={"schema":"risu.e2-gate2c4-projection-shape-triangulation-summary/v0.1","pilot_case_id":pilot,"confirmatory_case_count":6,"confirmatory_role_observation_count":12,"taxonomy_counts_all":counts,"taxonomy_counts_pilot":pilot_counts,"taxonomy_counts_confirmatory":confirm_counts,"confirmatory_success_condition_met":success,"interpretation":{"raw_source_reopened":False,"truth_used":False,"remediation":False,"repair_soundness_inferred":False}}
    ledger_out={"schema":"risu.e2-gate2c4-projection-shape-triangulation-ledger/v0.1","observations":out}
    return ledger_out,summary

def main()->int:
    ap=argparse.ArgumentParser();ap.add_argument("--protocol",required=True);ap.add_argument("--profiles",required=True);ap.add_argument("--gate2c3-ledger",required=True);ap.add_argument("--matrix",required=True);ap.add_argument("--primary-dir",required=True);ap.add_argument("--output",required=True);a=ap.parse_args()
    p=readj(Path(a.protocol));profiles=readj(Path(a.profiles));g=readj(Path(a.gate2c3_ledger));m=readj(Path(a.matrix));root=Path(a.primary_dir)
    ids=[str(p["population"]["pilot_case_id"])]+[str(x) for x in p["population"]["confirmatory_case_ids"]]
    docs={cid:readj(root/cid/"semantic_slice.json") for cid in ids}
    led,summ=diagnose(protocol=p,profiles=profiles,ledger=g,matrix=m,primary_docs=docs);out=Path(a.output);out.mkdir(parents=True,exist_ok=True)
    (out/"E2_GATE2C4_PROJECTION_SHAPE_TRIANGULATION_LEDGER.json").write_bytes(cb(led));(out/"E2_GATE2C4_PROJECTION_SHAPE_TRIANGULATION_SUMMARY.json").write_bytes(cb(summ));return 0
if __name__=="__main__":raise SystemExit(main())
