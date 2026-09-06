#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Mapping, Sequence, Tuple

from risu_e2.acquisition import AcquiredFile
from risu_e2.frontend_js_v3 import extract as extract_js
from risu_e2.ir_v3 import build_ir as build_ir_v3
from risu_e2.overlay_control import _control_functions, _stmt_walk

SCHEMA="risu.e2-a3-a4-candidate-observability-remediation-v0.3-primary-prospective/v0.1"


def canonical(x: Any) -> bytes:
    return (json.dumps(x,sort_keys=True,separators=(",",":"),ensure_ascii=False)+"\n").encode()


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def span(f: Mapping[str,Any]) -> Tuple[int,int,int,int]:
    s=f["span"]
    return int(s["start_line"]),int(s["start_col"]),int(s["end_line"]),int(s["end_col"])


def starts(src: str) -> list[int]:
    z=[0]
    for i,c in enumerate(src):
        if c=="\n": z.append(i+1)
    return z


def subslice(src: str, sp: Sequence[int]) -> str:
    z=starts(src)
    return src[z[int(sp[0])-1]+int(sp[1]):z[int(sp[2])-1]+int(sp[3])]


def contains(outer: Sequence[int], inner: Sequence[int]) -> bool:
    return (int(outer[0]),int(outer[1])) <= (int(inner[0]),int(inner[1])) and (int(inner[2]),int(inner[3])) <= (int(outer[2]),int(outer[3]))


def structural_return_spans(src: str, facts: Sequence[Mapping[str,Any]]) -> set[Tuple[int,int,int,int]]:
    funcs=[f for f in facts if f.get("kind")=="FUNCTION"]
    controls=_control_functions(src,"typescript_javascript",funcs)
    out=set()
    for row in controls.values():
        for stmt in _stmt_walk(row.get("stmts",[])):
            if stmt.kind=="RETURN": out.add(tuple(stmt.span))
    return out


def representations(src: str, facts: Sequence[Mapping[str,Any]]) -> list[Dict[str,Any]]:
    structural=structural_return_spans(src,facts)
    fields=[f for f in facts if f.get("kind")=="FIELD_BIND"]
    out=[]
    for r in facts:
        if r.get("kind")!="RETURN": continue
        rsp=span(r)
        if rsp not in structural: continue
        inside=[f for f in fields if contains(rsp,span(f))]
        if not inside: continue
        out.append({
            "return_span":list(rsp),
            "return_slice":subslice(src,rsp),
            "fields":sorted({str(f.get("field")) for f in inside}),
            "field_bind_count":len(inside),
        })
    return sorted(out,key=lambda x:(x["return_span"],x["fields"],x["field_bind_count"]))


def signature(src: str, facts: Sequence[Mapping[str,Any]]) -> list[Any]:
    reps=representations(src,facts)
    return [
        sum(f.get("kind")=="CALL" for f in facts),
        sum(f.get("kind")=="COMPARE" for f in facts),
        sum(f.get("kind")=="RETURN" for f in facts),
        len(reps),
        sorted(len(r["fields"]) for r in reps),
        sorted(int(r["field_bind_count"]) for r in reps),
    ]


def evaluate(case: Mapping[str,Any], go_helper: Path) -> Dict[str,Any]:
    fid=str(case["fixture_id"]); src=str(case["source"]); exp=dict(case["expected"]); errors=[]
    parsed=extract_js(src); facts=list(parsed.get("facts",[]))
    if parsed.get("status")!="PASS": errors.append(f"frontend:{parsed.get('status')}:{parsed.get('error')}")
    calls=[f for f in facts if f.get("kind")=="CALL"]
    compares=[f for f in facts if f.get("kind")=="COMPARE"]
    returns=[f for f in facts if f.get("kind")=="RETURN"]

    if "call_count" in exp and len(calls)!=int(exp["call_count"]): errors.append(f"call_count:{len(calls)}")
    for e in exp.get("expected_calls",[]):
        ok=any(str(f.get("callee"))==str(e["callee"]) and str(f.get("scope"))==str(e["scope"]) and subslice(src,span(f))==str(e["source_slice"]) for f in calls)
        if not ok: errors.append(f"expected_call_missing:{e}")

    if "compare_count" in exp and len(compares)!=int(exp["compare_count"]): errors.append(f"compare_count:{len(compares)}")
    for e in exp.get("expected_compares",[]):
        ok=any(
            str(f.get("scope"))==str(e["scope"])
            and list(map(str,f.get("operators",[])))==[str(e["operator"])]
            and [[str(x) for x in g] for g in f.get("operands",[])]==[[str(x) for x in g] for g in e["operands"]]
            and subslice(src,span(f))==str(e["source_slice"])
            for f in compares
        )
        if not ok: errors.append(f"expected_compare_missing:{e}")

    for wanted in exp.get("expected_return_slices",[]):
        got=sum(subslice(src,span(f))==str(wanted) for f in returns)
        if got!=1: errors.append(f"return_not_exactly_once:{wanted}:{got}")

    reps=representations(src,facts)
    for e in exp.get("representations_exact",[]):
        target=str(e["return_slice"])
        rows=[r for r in reps if r["return_slice"]==target]
        if len(rows)!=1:
            errors.append(f"representation_not_unique:{target}:{len(rows)}")
            continue
        row=rows[0]
        if str(e.get("representation_owner_relation"))=="EQUAL":
            ret=[f for f in returns if subslice(src,span(f))==target]
            if len(ret)!=1 or list(span(ret[0]))!=row["return_span"]:
                errors.append(f"owner_relation_not_equal:{target}")
        if row["fields"]!=sorted(map(str,e["fields_exact"])):
            errors.append(f"representation_fields:{target}:{row['fields']}")
        if int(row["field_bind_count"])!=int(e["field_bind_count_exact"]):
            errors.append(f"representation_field_bind_count:{target}:{row['field_bind_count']}")

    raw=src.encode()
    af=AcquiredFile(path="fixture.ts",language="typescript_javascript",sha256=sha(raw),data=raw,selection_round=0,selection_reasons=("V0_3_PROSPECTIVE",))
    ir,irstatus=build_ir_v3([af],acquisition_doc={"status":"PASS","reason":"V0_3_PROSPECTIVE"},go_helper_path=go_helper)
    if irstatus.get("status")!="PASS" or irstatus.get("frontend_surface_version")!="v0.3" or irstatus.get("python_frontend_surface_version")!="v0.2-reused":
        errors.append(f"ir_v3_status:{irstatus}")
    if not ir.get("ir_digest_sha256"): errors.append("missing_ir_digest")

    return {
        "fixture_id":fid,"variant_of":case.get("variant_of"),"obligation_ids":list(case.get("obligation_ids",[])),
        "source_sha256":sha(raw),"parser":parsed.get("parser"),"fact_counts":{k:sum(f.get("kind")==k for f in facts) for k in ["FUNCTION","CALL","COMPARE","RETURN","ASSIGN","FIELD_BIND"]},
        "abstract_signature":signature(src,facts),"ir_digest_sha256":ir.get("ir_digest_sha256"),
        "ir_frontend_digest_sha256":irstatus.get("frontend_digest_sha256"),"passed":not errors,"errors":errors,
    }


def specialization(root: Path) -> Dict[str,Any]:
    paths=["risu_e2/frontend_js_v3.py","risu_e2/ir_v3.py"]
    forbidden=["V3B","V3M","V2B","V2M","CQ_","JS_CALL_RESERVED_KEYWORD_PARENTHESIS_FALSE_POSITIVE","JS_OBJECT_SHORTHAND_RHS_IDENTIFIER_FALSE_POSITIVE"]
    hits=[]
    for rel in paths:
        text=(root/rel).read_text()
        for lit in forbidden:
            if lit in text: hits.append({"path":rel,"kind":"FORBIDDEN_LITERAL","value":lit})
        tree=ast.parse(text)
        for n in ast.walk(tree):
            if isinstance(n,ast.Compare):
                t=(ast.get_source_segment(text,n) or "").lower()
                if ("sha256" in t or "source_sha" in t) and any(isinstance(o,(ast.Eq,ast.NotEq,ast.In,ast.NotIn)) for o in n.ops):
                    hits.append({"path":rel,"kind":"SOURCE_HASH_BRANCH","value":t[:180]})
    return {"status":"PASS" if not hits else "FAIL","paths":paths,"hits":hits}


def main() -> int:
    ap=argparse.ArgumentParser()
    ap.add_argument("--protocol",required=True); ap.add_argument("--corpus",required=True)
    ap.add_argument("--scientific-root",required=True); ap.add_argument("--go-helper",required=True); ap.add_argument("--output",required=True)
    a=ap.parse_args()
    protocol=json.loads(Path(a.protocol).read_text()); corpus=json.loads(Path(a.corpus).read_text())
    rows=[evaluate(c,Path(a.go_helper)) for c in corpus["cases"]]
    idx={r["fixture_id"]:r for r in rows}; variant_errors=[]
    for base,var in corpus["metamorphic_contract"]["explicit_variant_pairs"]:
        if base not in idx or var not in idx or idx[base]["abstract_signature"]!=idx[var]["abstract_signature"]:
            variant_errors.append([base,var])
    sp=specialization(Path(a.scientific_root))
    ok=len(rows)==24 and sum(r["passed"] for r in rows)==24 and not variant_errors and sp["status"]=="PASS"
    doc={
      "schema":SCHEMA,"status":"PASS" if ok else "FAIL","case_count":len(rows),"passed_case_count":sum(r["passed"] for r in rows),
      "failed_fixture_ids":[r["fixture_id"] for r in rows if not r["passed"]],"variant_pair_failures":variant_errors,
      "specialization_scan":sp,"protocol_schema":protocol.get("schema"),"corpus_schema":corpus.get("schema"),
      "read_set_attestation":{"frozen_48_bytes":False,"candidate_58_bytes":False,"fresh_target_bytes":False},
      "semantic_verdicts_emitted":False,"rows":rows,
    }
    raw=canonical(doc); Path(a.output).write_bytes(raw)
    print(json.dumps({"status":doc["status"],"cases":len(rows),"passed":doc["passed_case_count"],"failed":doc["failed_fixture_ids"],"variant_failures":variant_errors,"sha256":sha(raw),"bytes":len(raw)},sort_keys=True,separators=(",",":")))
    return 0


if __name__=="__main__":
    raise SystemExit(main())
