#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Mapping, Sequence, Tuple

from risu_e2.frontend_js_v2 import extract as extract_js
from risu_e2.frontend_python_v2 import extract as extract_python
from risu_e2.overlay_control import _control_functions, _stmt_walk
from risu_e2.acquisition import AcquiredFile
from risu_e2.ir_v2 import build_ir as build_ir_v2

SCHEMA = "risu.e2-a3-a4-candidate-observability-remediation-v0.2-primary-microqualification/v0.1"


def canonical(obj: Any) -> bytes:
    return (json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def span_tuple(f: Mapping[str, Any]) -> Tuple[int,int,int,int]:
    s=f["span"]
    return (int(s["start_line"]),int(s["start_col"]),int(s["end_line"]),int(s["end_col"]))


def line_starts(source: str) -> list[int]:
    out=[0]
    for i,c in enumerate(source):
        if c=="\n": out.append(i+1)
    return out


def offset(starts: Sequence[int], line: int, col: int) -> int:
    return starts[line-1]+col


def slice_for_span(source: str, sp: Sequence[int]) -> str:
    starts=line_starts(source)
    return source[offset(starts,int(sp[0]),int(sp[1])):offset(starts,int(sp[2]),int(sp[3]))]


def contains(outer: Sequence[int], inner: Sequence[int]) -> bool:
    a=(int(outer[0]),int(outer[1])); b=(int(outer[2]),int(outer[3]))
    c=(int(inner[0]),int(inner[1])); d=(int(inner[2]),int(inner[3]))
    return a <= c and d <= b


def unique_slice_span(source: str, needle: str) -> Tuple[int,int,int,int]:
    first=source.find(needle)
    if first < 0 or source.find(needle, first+1) >= 0:
        raise ValueError(f"source_slice_not_unique:{needle!r}")
    starts=line_starts(source)
    import bisect
    def pos(o: int) -> Tuple[int,int]:
        li=bisect.bisect_right(starts,o)-1
        return li+1,o-starts[li]
    sl,sc=pos(first); el,ec=pos(first+len(needle))
    return (sl,sc,el,ec)


def fact_slice(source: str, fact: Mapping[str,Any]) -> str:
    return slice_for_span(source,span_tuple(fact))


def call_matches(source: str, facts: Sequence[Mapping[str,Any]], expected: Mapping[str,Any]) -> bool:
    return any(
        f.get("kind")=="CALL"
        and str(f.get("callee"))==str(expected["callee"])
        and str(f.get("scope"))==str(expected["scope"])
        and fact_slice(source,f)==str(expected["source_slice"])
        for f in facts
    )


def compare_matches(source: str, facts: Sequence[Mapping[str,Any]], expected: Mapping[str,Any]) -> bool:
    return any(
        f.get("kind")=="COMPARE"
        and str(f.get("scope"))==str(expected["scope"])
        and list(map(str,f.get("operators",[])))==[str(expected["operator"])]
        and [[str(x) for x in grp] for grp in f.get("operands",[])]==[[str(x) for x in grp] for grp in expected["operands"]]
        and fact_slice(source,f)==str(expected["source_slice"])
        for f in facts
    )


def return_stmt_spans(source: str, language: str, facts: Sequence[Mapping[str,Any]]) -> list[Tuple[int,int,int,int]]:
    funcs=[f for f in facts if f.get("kind")=="FUNCTION"]
    controls=_control_functions(source,language,funcs)
    out=[]
    for row in controls.values():
        for s in _stmt_walk(row.get("stmts",[])):
            if s.kind=="RETURN": out.append(tuple(s.span))
    return sorted(set(out))


def representation_owner_rows(source: str, language: str, facts: Sequence[Mapping[str,Any]]) -> list[Dict[str,Any]]:
    returns=[f for f in facts if f.get("kind")=="RETURN"]
    fields=[f for f in facts if f.get("kind")=="FIELD_BIND"]
    stmt_spans=return_stmt_spans(source,language,facts)
    rows=[]
    for r in returns:
        rsp=span_tuple(r)
        if rsp not in stmt_spans: continue
        inside=[f for f in fields if contains(rsp,span_tuple(f))]
        if not inside: continue
        rows.append({"return_span":list(rsp),"return_slice":fact_slice(source,r),
                     "fields":sorted(set(str(f.get("field")) for f in inside))})
    return rows


def abstract_signature(source: str, language: str, facts: Sequence[Mapping[str,Any]]) -> Dict[str,Any]:
    reps=representation_owner_rows(source,language,facts)
    return {
        "calls":sum(1 for f in facts if f.get("kind")=="CALL"),
        "compares":sum(1 for f in facts if f.get("kind")=="COMPARE"),
        "returns":sum(1 for f in facts if f.get("kind")=="RETURN"),
        "representations":len(reps),
        "representation_field_arities":sorted(len(r["fields"]) for r in reps),
    }


def specialization_scan(scientific_root: Path) -> Dict[str,Any]:
    paths=["risu_e2/frontend_js_v2.py","risu_e2/frontend_python_v2.py","risu_e2/ir_v2.py"]
    forbidden_literals=["V2B","V2M","CQ_","FRONTEND_OBSERVABILITY_GAP",
                        "MICROQUALIFICATION_EXPECTATION_NOT_MET",
                        "E2_A3_A4_CANDIDATE_OBSERVABILITY_REMEDIATION_V0_2_MICROQUALIFICATION_CORPUS"]
    hits=[]
    for rel in paths:
        p=scientific_root/rel
        text=p.read_text()
        for lit in forbidden_literals:
            if lit in text: hits.append({"path":rel,"kind":"FORBIDDEN_LITERAL","value":lit})
        try:
            tree=ast.parse(text)
        except SyntaxError as exc:
            hits.append({"path":rel,"kind":"PYTHON_PARSE_FAILURE","value":str(exc)})
            continue
        for node in ast.walk(tree):
            if isinstance(node,ast.Compare):
                segment=ast.get_source_segment(text,node) or ""
                low=segment.lower()
                if ("sha256" in low or "source_sha" in low) and any(isinstance(op,(ast.Eq,ast.NotEq,ast.In,ast.NotIn)) for op in node.ops):
                    hits.append({"path":rel,"kind":"SOURCE_HASH_BRANCH","value":segment[:200]})
    return {"status":"PASS" if not hits else "FAIL","paths":paths,"hits":hits}


def evaluate_case(case: Mapping[str,Any], go_helper: Path) -> Dict[str,Any]:
    fid=str(case["fixture_id"]); language=str(case["language"]); source=str(case["source"])
    exp=dict(case["expected"]); errors=[]
    parsed=extract_python(source) if language=="python" else extract_js(source)
    facts=list(parsed.get("facts",[]))
    if parsed.get("status")!="PASS":
        errors.append(f"frontend_status:{parsed.get('status')}:{parsed.get('error')}")
    def check_unique(obj: Any) -> None:
        if isinstance(obj,dict):
            for k,v in obj.items():
                if k in {"source_slice","return_slice"} and isinstance(v,str):
                    try: unique_slice_span(source,v)
                    except Exception as exc: errors.append(f"nonunique_slice:{v!r}:{exc}")
                else: check_unique(v)
        elif isinstance(obj,list):
            for v in obj: check_unique(v)
    check_unique(exp)

    funcs=sorted(str(f.get("name")) for f in facts if f.get("kind")=="FUNCTION")
    calls=[f for f in facts if f.get("kind")=="CALL"]
    compares=[f for f in facts if f.get("kind")=="COMPARE"]
    returns=[f for f in facts if f.get("kind")=="RETURN"]
    assigns=[f for f in facts if f.get("kind")=="ASSIGN"]

    if "function_names_exact" in exp and funcs != sorted(map(str,exp["function_names_exact"])):
        errors.append(f"function_names:{funcs}")
    if "call_count" in exp and len(calls)!=int(exp["call_count"]):
        errors.append(f"call_count:{len(calls)}")
    for e in exp.get("expected_calls",[]):
        if not call_matches(source,facts,e): errors.append(f"expected_call_missing:{e}")
    for s in exp.get("forbidden_call_slices",[]):
        if any(fact_slice(source,f)==s for f in calls): errors.append(f"forbidden_call_present:{s}")
    if "compare_count" in exp and len(compares)!=int(exp["compare_count"]):
        errors.append(f"compare_count:{len(compares)}")
    for e in exp.get("expected_compares",[]):
        if not compare_matches(source,facts,e): errors.append(f"expected_compare_missing:{e}")
    for s in exp.get("forbidden_compare_slices",[]):
        if any(fact_slice(source,f)==s for f in compares): errors.append(f"forbidden_compare_present:{s}")
    for s in exp.get("expected_return_slices",[]):
        if sum(1 for f in returns if fact_slice(source,f)==s)!=1: errors.append(f"return_slice_not_exactly_once:{s}")
    if "call_count_in_scope" in exp:
        for scope,count in exp["call_count_in_scope"].items():
            got=sum(1 for f in calls if str(f.get("scope"))==str(scope))
            if got!=int(count): errors.append(f"call_count_in_scope:{scope}:{got}")
    for e in exp.get("expected_assignments",[]):
        lhs=sorted(map(str,e["lhs"])); required=set(map(str,e.get("rhs_contains",[])))
        ok=False
        for f in assigns:
            if sorted(map(str,f.get("lhs",[])))==lhs and required.issubset(set(map(str,f.get("rhs",[])))):
                ok=True; break
        if not ok: errors.append(f"assignment_missing:{e}")

    reps=representation_owner_rows(source,language,facts)
    if "representation_owner_count" in exp and len(reps)!=int(exp["representation_owner_count"]):
        errors.append(f"representation_owner_count:{len(reps)}")
    for e in exp.get("object_return_relations",[]):
        target=str(e["return_slice"]); required=set(map(str,e.get("fields",[])))
        candidates=[r for r in reps if r["return_slice"]==target]
        if len(candidates)!=1:
            errors.append(f"representation_owner_not_unique:{target}:{len(candidates)}")
            continue
        rr=candidates[0]
        if str(e.get("representation_owner_relation"))=="EQUAL":
            ret=[f for f in returns if fact_slice(source,f)==target]
            if len(ret)!=1 or list(span_tuple(ret[0]))!=rr["return_span"]:
                errors.append(f"representation_return_span_not_equal:{target}")
        if not required.issubset(set(rr["fields"])):
            errors.append(f"representation_fields_missing:{target}:{sorted(required-set(rr['fields']))}")

    raw=source.encode()
    af=AcquiredFile(path=("fixture.py" if language=="python" else "fixture.ts"),
                    language=language,sha256=sha256_bytes(raw),data=raw,
                    selection_round=0,selection_reasons=("V0_2_MICROQUALIFICATION",))
    ir,irstatus=build_ir_v2([af],acquisition_doc={"status":"PASS","reason":"V0_2_MICROQUALIFICATION"},
                            go_helper_path=go_helper)
    if irstatus.get("status")!="PASS" or irstatus.get("frontend_surface_version")!="v0.2":
        errors.append(f"ir_v2_status:{irstatus}")
    if ir.get("schema") is None or not ir.get("ir_digest_sha256"):
        errors.append("ir_v2_missing_identity")

    return {
        "fixture_id":fid,
        "variant_of":case.get("variant_of"),
        "obligation_ids":list(case.get("obligation_ids",[])),
        "language":language,
        "source_sha256":sha256_bytes(raw),
        "frontend_status":parsed.get("status"),
        "parser":parsed.get("parser"),
        "fact_counts":{k:sum(1 for f in facts if f.get("kind")==k)
                       for k in ["FUNCTION","CALL","COMPARE","RETURN","ASSIGN","FIELD_BIND"]},
        "abstract_signature":abstract_signature(source,language,facts),
        "ir_digest_sha256":ir.get("ir_digest_sha256"),
        "ir_frontend_digest_sha256":irstatus.get("frontend_digest_sha256"),
        "passed":not errors,
        "errors":errors,
    }


def main() -> int:
    ap=argparse.ArgumentParser()
    ap.add_argument("--protocol",required=True)
    ap.add_argument("--corpus",required=True)
    ap.add_argument("--scientific-root",required=True)
    ap.add_argument("--go-helper",required=True)
    ap.add_argument("--output",required=True)
    args=ap.parse_args()
    protocol=json.loads(Path(args.protocol).read_text())
    corpus=json.loads(Path(args.corpus).read_text())
    rows=[evaluate_case(c,Path(args.go_helper)) for c in corpus["cases"]]
    byid={r["fixture_id"]:r for r in rows}
    variant_errors=[]
    for base,var in corpus["metamorphic_contract"]["explicit_variant_pairs"]:
        if base not in byid or var not in byid:
            variant_errors.append(f"missing_variant_pair:{base}:{var}")
        elif byid[base]["abstract_signature"]!=byid[var]["abstract_signature"]:
            variant_errors.append(f"abstract_signature_mismatch:{base}:{var}")
    spec=specialization_scan(Path(args.scientific_root))
    status="PASS" if len(rows)==24 and all(r["passed"] for r in rows) and not variant_errors and spec["status"]=="PASS" else "FAIL"
    doc={
        "schema":SCHEMA,"status":status,"case_count":len(rows),
        "passed_case_count":sum(1 for r in rows if r["passed"]),
        "failed_fixture_ids":[r["fixture_id"] for r in rows if not r["passed"]],
        "variant_invariance_status":"PASS" if not variant_errors else "FAIL",
        "variant_errors":variant_errors,
        "specialization_scan":spec,
        "protocol_schema":protocol.get("schema"),
        "corpus_schema":corpus.get("schema"),
        "read_set_attestation":{
            "candidate_58_bytes":False,"sanitized_58_manifest":False,"raw_blind_58_transport":False,
            "mutation_truth":False,"operator_metadata":False,"expected_e2_predictions":False,
            "fresh_target_bytes":False,"frozen_48_corpus":False,
        },
        "semantic_verdicts_emitted":False,
        "rows":rows,
    }
    raw=canonical(doc); Path(args.output).write_bytes(raw)
    print(json.dumps({"status":status,"cases":len(rows),"passed":doc["passed_case_count"],
                      "failed":doc["failed_fixture_ids"],"sha256":sha256_bytes(raw),"bytes":len(raw)},
                     sort_keys=True,separators=(",",":")))
    return 0


if __name__=="__main__":
    raise SystemExit(main())
