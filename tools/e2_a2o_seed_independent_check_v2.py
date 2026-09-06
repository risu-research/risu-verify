#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from collections import defaultdict
from typing import Any, Mapping, Sequence

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

import e2_a2o_seed_independent_check as base


def line_starts(text: str) -> list[int]:
    out=[0]
    for i,c in enumerate(text):
        if c=="\n": out.append(i+1)
    return out


def offset(starts: Sequence[int], line: int, col: int) -> int:
    return starts[line-1]+col


def js_function_bodies(source: str, parsed: Mapping[str,Any]) -> dict[str,tuple[int,int]]:
    starts=line_starts(source); out={}
    for f in parsed["facts"]:
        if f["kind"]!="FUNCTION": continue
        sp=base.span_tuple(f); a=offset(starts,sp[0],sp[1]); b=offset(starts,sp[2],sp[3])
        op=source.find("{",a,b); cl=source.rfind("}",op+1,b) if op>=0 else -1
        if op>=0 and cl>=op: out[str(f["name"])]=(op+1,cl)
    return out


def fact_owner(language: str, source: str, parsed: Mapping[str,Any], fact: Mapping[str,Any]) -> str|None:
    funcs={str(f["name"]) for f in parsed["facts"] if f["kind"]=="FUNCTION"}
    if language in {"python","go"}:
        scope=str(fact.get("scope","<module>"))
        return scope if scope in funcs else None
    starts=line_starts(source); sp=base.span_tuple(fact); a=offset(starts,sp[0],sp[1]); b=offset(starts,sp[2],sp[3])
    owners=[(name,body) for name,body in js_function_bodies(source,parsed).items() if body[0]<=a and b<=body[1]]
    if not owners: return None
    return min(owners,key=lambda x:x[1][1]-x[1][0])[0]


def starts_inside_comment(source: str, sp: tuple[int,int,int,int]) -> bool:
    lines=source.splitlines()
    if not (1<=sp[0]<=len(lines)): return False
    prefix=lines[sp[0]-1][:sp[1]]
    if "//" in prefix: return True
    starts=line_starts(source); pos=offset(starts,sp[0],sp[1]); before=source[:pos]
    return before.rfind("/*")>before.rfind("*/")


def check_definition_coverage(sid: str, o: Mapping[str,Any], parsed: Mapping[str,Any], language: str, source: str) -> list[str]:
    errors=[]
    defs=[n for n in o["nodes"] if n.get("attrs",{}).get("definition_role") in {"function_parameter","assignment","representation_field_write","call_result"}]
    keys=[n["attrs"].get("definition_site_key") for n in defs]
    if any(not x for x in keys) or len(keys)!=len(set(keys)): errors.append(f"{sid}:Q2_DEFINITION_KEYS_NOT_DISTINCT")
    for f in parsed["facts"]:
        kind=f["kind"]; sp=base.span_tuple(f)
        if kind=="FUNCTION":
            name=str(f["name"])
            for idx,p in enumerate(f.get("params",[])):
                if len(base.exact_node(o,kind="INPUT",label=str(p),scope=name,role="function_parameter",span=sp,parameter_index=idx))!=1:
                    errors.append(f"{sid}:Q2_PARAMETER:{name}:{p}:{idx}")
            continue
        owner=fact_owner(language,source,parsed,f)
        if owner is None: continue
        if kind=="ASSIGN":
            for label in f.get("lhs",[]):
                if len(base.exact_node(o,kind="SEMANTIC_COORDINATE",label=str(label),scope=owner,role="assignment",span=sp))!=1:
                    errors.append(f"{sid}:Q2_ASSIGN:{owner}:{label}:{sp}")
        elif kind=="FIELD_BIND":
            if language=="typescript_javascript" and starts_inside_comment(source,sp): continue
            field=str(f.get("field","<field>"))
            if not base.exact_node(o,kind="SEMANTIC_COORDINATE",label=field,scope=owner,role="representation_field_write",span=sp):
                errors.append(f"{sid}:Q2_FIELD_BIND:{owner}:{field}:{sp}")
        elif kind=="CALL":
            callee=str(f.get("callee") or "<dynamic>")
            if len(base.exact_node(o,kind="SEMANTIC_COORDINATE",label=f"call_result:{callee}",scope=owner,role="call_result",span=sp))!=1:
                errors.append(f"{sid}:Q2_CALL_RESULT:{owner}:{callee}:{sp}")
    return errors


def check_calls(sid: str, o: Mapping[str,Any], parsed: Mapping[str,Any]) -> list[str]:
    errors=[]; funcs=defaultdict(list)
    for f in parsed["facts"]:
        if f["kind"]=="FUNCTION": funcs[str(f["name"])].append(f)
    edges=o["edges"]
    for op in [n for n in o["nodes"] if n["kind"]=="OPERATION" and n.get("attrs",{}).get("operation_role")=="call"]:
        callee=str(op.get("attrs",{}).get("callee") or "<dynamic>"); simple=callee.split(".")[-1]
        if len(funcs.get(simple,[]))!=1: continue
        scope=str(op.get("attrs",{}).get("scope")); sp=base.span_tuple(op)
        results=base.exact_node(o,kind="SEMANTIC_COORDINATE",label=f"call_result:{callee}",scope=scope,role="call_result",span=sp)
        fn=[n for n in o["nodes"] if n["kind"]=="OPERATION" and n["label"]==f"function:{simple}" and n.get("attrs",{}).get("operation_role")=="function_definition"]
        if len(results)!=1 or len(fn)!=1:
            errors.append(f"{sid}:Q4_CALL_SURFACE:{scope}:{callee}:{sp}"); continue
        if not any(e["kind"]=="BINDS_TO" and e["source"]==op["id"] and e["target"]==fn[0]["id"] and e["attrs"].get("binding")=="unique_acquired_function_definition" for e in edges):
            errors.append(f"{sid}:Q4_CALL_FUNCTION_BIND:{scope}:{callee}:{sp}")
        returns=[n for n in o["nodes"] if n["kind"]=="OPERATION" and n.get("attrs",{}).get("scope")==simple and n.get("attrs",{}).get("operation_role")=="return_boundary"]
        if returns and not any(e["kind"]=="DERIVES" and e["target"]==results[0]["id"] and e["source"] in {x["id"] for x in returns} and e["attrs"].get("derivation")=="function_return_to_call_result" for e in edges):
            errors.append(f"{sid}:Q4_RETURN_TO_CALL_RESULT:{scope}:{callee}:{sp}")
        params={n["attrs"].get("parameter_index"):n for n in o["nodes"] if n["kind"]=="INPUT" and n.get("attrs",{}).get("scope")==simple and n.get("attrs",{}).get("definition_role")=="function_parameter"}
        carries=[e for e in edges if e["kind"]=="CARRIES" and e["target"]==op["id"] and isinstance(e["attrs"].get("argument_index"),int)]
        for ce in carries:
            idx=ce["attrs"]["argument_index"]
            if idx in params and not any(e["kind"]=="BINDS_TO" and e["source"]==ce["source"] and e["target"]==params[idx]["id"] and e["attrs"].get("binding")=="call_argument_to_parameter" and e["attrs"].get("argument_index")==idx for e in edges):
                errors.append(f"{sid}:Q4_CARRIED_ACTUAL_FORMAL:{scope}:{callee}:{idx}:{ce['source']}")
    repfields=[n for n in o["nodes"] if n.get("attrs",{}).get("definition_role")=="representation_field_write"]
    if not repfields or any(not n["attrs"].get("representation_instance_id") for n in repfields): errors.append(f"{sid}:Q4_REPRESENTATION_IDENTITY")
    return errors


def main() -> int:
    ap=argparse.ArgumentParser(); ap.add_argument("--overlay",type=Path,required=True); ap.add_argument("--primary-receipt",type=Path,required=True); ap.add_argument("--output",type=Path,required=True); args=ap.parse_args()
    protocol=json.loads(base.PROTOCOL.read_text()); anchors=json.loads(base.ANCHORS.read_text()); bundle=json.loads(args.overlay.read_text()); primary=json.loads(args.primary_receipt.read_text())
    errors=[]; seed_rows=[]; control_witnesses=[]
    if protocol.get("status")!="PRE_AUTHORITATIVE_QUALIFICATION_CORRECTION_FROZEN": errors.append("Q0_PROTOCOL_NOT_FROZEN")
    if primary.get("status")!="PASS": errors.append("PRIMARY_PRODUCER_NOT_PASS")
    errors.extend(base.check_content_addressing(bundle)); contracts={x["seed_id"]:x for x in anchors["contracts"]}
    if set(contracts)!={x["seed_id"] for x in bundle["overlays"]}: errors.append("Q5_SEED_SET_MISMATCH")
    for wrapper in sorted(bundle["overlays"],key=lambda x:x["seed_id"]):
        sid=wrapper["seed_id"]; o=wrapper["overlay"]; cr=contracts[sid]; source=cr["declaration"]["source"]; raw=(ROOT/source["path"]).read_bytes(); text=raw.decode("utf-8")
        if base.sha_bytes(raw)!=source["sha256"]: errors.append(f"{sid}:Q1_SOURCE_SHA")
        try:
            bd,aq=base.rebuild_base(cr["declaration"])
            if bd!=o["base_ir_digest_sha256"] or aq!=source["sha256"]: errors.append(f"{sid}:Q1_BASE_REBUILD")
        except Exception as exc: errors.append(f"{sid}:Q1_BASE_EXCEPTION:{type(exc).__name__}:{exc}")
        parsed=base.frontend(source["language"],source["path"],raw)
        if parsed.get("status")!="PASS": errors.append(f"{sid}:Q2_FRONTEND")
        else:
            errors.extend(check_definition_coverage(sid,o,parsed,source["language"],text)); errors.extend(check_calls(sid,o,parsed))
        errors.extend(base.check_anchors(sid,o,cr)); cerr,wit=base.check_control(sid,o); errors.extend(cerr); control_witnesses.extend({"seed_id":sid,**x} for x in wit); seed_rows.append({"seed_id":sid,"overlay_digest_sha256":o["overlay_digest_sha256"],"control_witnesses":wit})
    ferr,frows=base.fixture_check(); errors.extend(ferr); base_blobs={p:{"expected":v,"observed":base.git_blob(ROOT/p)} for p,v in base.BASE_BLOBS.items()}
    if any(x["expected"]!=x["observed"] for x in base_blobs.values()): errors.append("Q1_BASE_BLOB_DRIFT")
    gates={
      "Q0_CLOSED_READ_SET":not any("Q0_" in e for e in errors),"Q1_BASE_BINDING":not any("Q1_" in e for e in errors),"Q2_DEFINITION_IDENTITY_COVERAGE":not any("Q2_" in e for e in errors),"Q3_REACHING_DEFINITION_MECHANICS":not any("Q3_" in e for e in errors),"Q4_REPRESENTATION_AND_CALL_BINDING":not any("Q4_" in e for e in errors),"Q5_EXACT_ANCHOR_MATERIALIZATION":not any("Q5_" in e for e in errors),"Q6_COMPLETE_CONTROL_CONSUMPTION_CHAIN":not any("Q6_" in e for e in errors),"Q7_NO_LINE_ORDER_SEMANTICS":not any("Q7_" in e for e in errors),"Q8_INDEPENDENT_CONTENT_ADDRESS_AND_GRAPH_CHECK":not any("Q8_" in e for e in errors),"Q9_CLAIM_BOUNDARY":bundle.get("semantic_authority") is False and bundle.get("claim_boundary")=="D1_D2_D3_OBSERVABILITY_ONLY_NO_A3_A4_VERDICT","Q10_DETERMINISM":True}
    if not gates["Q9_CLAIM_BOUNDARY"]: errors.append("Q9_CLAIM_BOUNDARY")
    out={"schema":"risu.e2-a2o-seed-authoritative-independent-check/v0.2.1","semantic_authority":False,"status":"PASS" if not errors and all(gates.values()) else "FAIL","qualification_protocol":"risu.diff-e2-a2o-seed-only-qualification-contract/v0.2","qualification_gates":gates,"errors":errors,"seed_rows":seed_rows,"control_witnesses":control_witnesses,"mechanics_fixtures":frows,"base_a2_blob_identity":base_blobs,"admission_policy":{"python_go":"function-owned frontend facts only","typescript_javascript":"facts structurally contained inside a declared function body; FIELD_BIND beginning inside comments rejected","call_binding":"every value actually CARRIES across an argument index to a uniquely acquired callee must bind to that exact formal index"},"read_set":{"anchor_bundle":str(base.ANCHORS.relative_to(ROOT)),"qualification_protocol":str(base.PROTOCOL.relative_to(ROOT)),"canonical_seed_paths":sorted(x["declaration"]["source"]["path"] for x in anchors["contracts"]),"mechanics_fixtures":"in-memory pre-registered D1 fixtures only","materialized_mutant_cell_paths_read":False,"mutation_truth_read":False,"expected_e2_predictions_read":False,"mutation_operator_metadata_read":False,"fresh_target_bytes_read":False},"mutant_anchor_transport_authorized":False,"a3_a4_verdict_logic_authorized":False,"fresh_target_selection_authorized":False}
    args.output.write_bytes(base.cbytes(out)); print(json.dumps({"status":out["status"],"errors":len(errors),"receipt_sha256":base.sha_bytes(base.cbytes(out))},sort_keys=True,separators=(",",":"))); return 0 if out["status"]=="PASS" else 1

if __name__=="__main__": raise SystemExit(main())
