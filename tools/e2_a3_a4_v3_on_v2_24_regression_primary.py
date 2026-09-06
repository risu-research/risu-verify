#!/usr/bin/env python3
from __future__ import annotations

import argparse, ast, bisect, hashlib, json
from pathlib import Path
from typing import Any, Dict, Mapping, Sequence, Tuple

from risu_e2.acquisition import AcquiredFile
from risu_e2.frontend_js_v3 import extract as extract_js
from risu_e2.frontend_python_v2 import extract as extract_python
from risu_e2.ir_v3 import build_ir as build_ir_v3
from risu_e2.overlay_control import _control_functions, _stmt_walk

SCHEMA="risu.e2-a3-a4-v0.3-on-frozen-v0.2-24-primary-regression/v0.1"

def enc(x: Any)->bytes: return (json.dumps(x,sort_keys=True,separators=(",",":"),ensure_ascii=False)+"\n").encode()
def h(b: bytes)->str: return hashlib.sha256(b).hexdigest()
def st(f: Mapping[str,Any])->Tuple[int,int,int,int]:
    s=f["span"]; return int(s["start_line"]),int(s["start_col"]),int(s["end_line"]),int(s["end_col"])
def starts(src: str)->list[int]:
    z=[0]
    for i,c in enumerate(src):
        if c=="\n": z.append(i+1)
    return z
def sub(src: str, sp: Sequence[int])->str:
    z=starts(src); return src[z[int(sp[0])-1]+int(sp[1]):z[int(sp[2])-1]+int(sp[3])]
def contains(a: Sequence[int],b: Sequence[int])->bool:
    return (int(a[0]),int(a[1])) <= (int(b[0]),int(b[1])) and (int(b[2]),int(b[3])) <= (int(a[2]),int(a[3]))
def unique_span(src: str, needle: str)->Tuple[int,int,int,int]:
    a=src.find(needle)
    if a<0 or src.find(needle,a+1)>=0: raise ValueError(f"source_slice_not_unique:{needle!r}")
    z=starts(src)
    def p(o:int)->Tuple[int,int]:
        i=bisect.bisect_right(z,o)-1; return i+1,o-z[i]
    sl,sc=p(a); el,ec=p(a+len(needle)); return sl,sc,el,ec

def return_stmt_spans(src: str, lang: str, facts: Sequence[Mapping[str,Any]])->set[Tuple[int,int,int,int]]:
    funcs=[f for f in facts if f.get("kind")=="FUNCTION"]
    controls=_control_functions(src,lang,funcs); out=set()
    for row in controls.values():
        for s in _stmt_walk(row.get("stmts",[])):
            if s.kind=="RETURN": out.add(tuple(s.span))
    return out

def reps(src: str, lang: str, facts: Sequence[Mapping[str,Any]])->list[Dict[str,Any]]:
    structural=return_stmt_spans(src,lang,facts); fields=[f for f in facts if f.get("kind")=="FIELD_BIND"]; out=[]
    for r in facts:
        if r.get("kind")!="RETURN" or st(r) not in structural: continue
        inside=[f for f in fields if contains(st(r),st(f))]
        if not inside: continue
        out.append({"return_span":list(st(r)),"return_slice":sub(src,st(r)),"fields":sorted(set(str(f.get("field")) for f in inside))})
    return out

def signature(src: str, lang: str, facts: Sequence[Mapping[str,Any]])->Dict[str,Any]:
    rr=reps(src,lang,facts)
    return {"calls":sum(f.get("kind")=="CALL" for f in facts),"compares":sum(f.get("kind")=="COMPARE" for f in facts),"returns":sum(f.get("kind")=="RETURN" for f in facts),"representations":len(rr),"representation_field_arities":sorted(len(r["fields"]) for r in rr)}

def evaluate(case: Mapping[str,Any], go_helper: Path)->Dict[str,Any]:
    fid=str(case["fixture_id"]); lang=str(case["language"]); src=str(case["source"]); exp=dict(case["expected"]); bad=[]
    parsed=extract_python(src) if lang=="python" else extract_js(src); facts=list(parsed.get("facts",[]))
    if parsed.get("status")!="PASS": bad.append(f"frontend_status:{parsed.get('status')}:{parsed.get('error')}")
    def walk(v: Any)->None:
        if isinstance(v,dict):
            for k,x in v.items():
                if k in {"source_slice","return_slice"} and isinstance(x,str):
                    try: unique_span(src,x)
                    except Exception as e: bad.append(f"nonunique_slice:{x!r}:{e}")
                else: walk(x)
        elif isinstance(v,list):
            for x in v: walk(x)
    walk(exp)
    funcs=sorted(str(f.get("name")) for f in facts if f.get("kind")=="FUNCTION")
    calls=[f for f in facts if f.get("kind")=="CALL"]; cmps=[f for f in facts if f.get("kind")=="COMPARE"]; rets=[f for f in facts if f.get("kind")=="RETURN"]; assigns=[f for f in facts if f.get("kind")=="ASSIGN"]
    if "function_names_exact" in exp and funcs!=sorted(map(str,exp["function_names_exact"])): bad.append(f"function_names:{funcs}")
    if "call_count" in exp and len(calls)!=int(exp["call_count"]): bad.append(f"call_count:{len(calls)}")
    for e in exp.get("expected_calls",[]):
        if not any(str(f.get("callee"))==str(e["callee"]) and str(f.get("scope"))==str(e["scope"]) and sub(src,st(f))==str(e["source_slice"]) for f in calls): bad.append(f"expected_call_missing:{e}")
    for s in exp.get("forbidden_call_slices",[]):
        if any(sub(src,st(f))==s for f in calls): bad.append(f"forbidden_call_present:{s}")
    if "compare_count" in exp and len(cmps)!=int(exp["compare_count"]): bad.append(f"compare_count:{len(cmps)}")
    for e in exp.get("expected_compares",[]):
        if not any(str(f.get("scope"))==str(e["scope"]) and list(map(str,f.get("operators",[])))==[str(e["operator"])] and [[str(x) for x in g] for g in f.get("operands",[])]==[[str(x) for x in g] for g in e["operands"]] and sub(src,st(f))==str(e["source_slice"]) for f in cmps): bad.append(f"expected_compare_missing:{e}")
    for s in exp.get("forbidden_compare_slices",[]):
        if any(sub(src,st(f))==s for f in cmps): bad.append(f"forbidden_compare_present:{s}")
    for s in exp.get("expected_return_slices",[]):
        if sum(sub(src,st(f))==s for f in rets)!=1: bad.append(f"return_slice_not_exactly_once:{s}")
    for scope,count in exp.get("call_count_in_scope",{}).items():
        got=sum(str(f.get("scope"))==str(scope) for f in calls)
        if got!=int(count): bad.append(f"call_count_in_scope:{scope}:{got}")
    for e in exp.get("expected_assignments",[]):
        lhs=sorted(map(str,e["lhs"])); req=set(map(str,e.get("rhs_contains",[])))
        if not any(sorted(map(str,f.get("lhs",[])))==lhs and req.issubset(set(map(str,f.get("rhs",[]))) for f in assigns): bad.append(f"assignment_missing:{e}")
    rr=reps(src,lang,facts)
    if "representation_owner_count" in exp and len(rr)!=int(exp["representation_owner_count"]): bad.append(f"representation_owner_count:{len(rr)}")
    for e in exp.get("object_return_relations",[]):
        target=str(e["return_slice"]); req=set(map(str,e.get("fields",[]))); rows=[r for r in rr if r["return_slice"]==target]
        if len(rows)!=1: bad.append(f"representation_owner_not_unique:{target}:{len(rows)}"); continue
        row=rows[0]
        if str(e.get("representation_owner_relation"))=="EQUAL":
            ret=[f for f in rets if sub(src,st(f))==target]
            if len(ret)!=1 or list(st(ret[0]))!=row["return_span"]: bad.append(f"representation_return_span_not_equal:{target}")
        if not req.issubset(set(row["fields"])): bad.append(f"representation_fields_missing:{target}:{sorted(req-set(row['fields']))}")
    raw=src.encode(); af=AcquiredFile(path=("fixture.py" if lang=="python" else "fixture.ts"),language=lang,sha256=h(raw),data=raw,selection_round=0,selection_reasons=("V0_2_24_REGRESSION",))
    ir,irstatus=build_ir_v3([af],acquisition_doc={"status":"PASS","reason":"V0_2_24_REGRESSION"},go_helper_path=go_helper)
    if irstatus.get("status")!="PASS" or irstatus.get("frontend_surface_version")!="v0.3": bad.append(f"ir_v3_status:{irstatus}")
    if not ir.get("schema") or not ir.get("ir_digest_sha256"): bad.append("ir_v3_missing_identity")
    return {"fixture_id":fid,"variant_of":case.get("variant_of"),"obligation_ids":list(case.get("obligation_ids",[])),"language":lang,"source_sha256":h(raw),"frontend_status":parsed.get("status"),"parser":parsed.get("parser"),"fact_counts":{k:sum(f.get("kind")==k for f in facts) for k in ["FUNCTION","CALL","COMPARE","RETURN","ASSIGN","FIELD_BIND"]},"abstract_signature":signature(src,lang,facts),"ir_digest_sha256":ir.get("ir_digest_sha256"),"ir_frontend_digest_sha256":irstatus.get("frontend_digest_sha256"),"passed":not bad,"errors":bad}

def scan(root: Path)->Dict[str,Any]:
    paths=["risu_e2/frontend_js_v3.py","risu_e2/frontend_python_v2.py","risu_e2/ir_v3.py"]; forbidden=["V3B","V3M","V2B","V2M","CQ_","FRONTEND_OBSERVABILITY_GAP","MICROQUALIFICATION_EXPECTATION_NOT_MET"]; hits=[]
    for rel in paths:
        text=(root/rel).read_text()
        for lit in forbidden:
            if lit in text: hits.append({"path":rel,"kind":"FORBIDDEN_LITERAL","value":lit})
        tree=ast.parse(text)
        for n in ast.walk(tree):
            if isinstance(n,ast.Compare):
                t=(ast.get_source_segment(text,n) or "").lower()
                if ("sha256" in t or "source_sha" in t) and any(isinstance(o,(ast.Eq,ast.NotEq,ast.In,ast.NotIn)) for o in n.ops): hits.append({"path":rel,"kind":"SOURCE_HASH_BRANCH","value":t[:180]})
    return {"status":"PASS" if not hits else "FAIL","paths":paths,"hits":hits}

def main()->int:
    p=argparse.ArgumentParser(); p.add_argument("--protocol",required=True); p.add_argument("--corpus",required=True); p.add_argument("--scientific-root",required=True); p.add_argument("--go-helper",required=True); p.add_argument("--output",required=True); a=p.parse_args()
    protocol=json.loads(Path(a.protocol).read_text()); corpus=json.loads(Path(a.corpus).read_text()); rows=[evaluate(c,Path(a.go_helper)) for c in corpus["cases"]]; idx={r["fixture_id"]:r for r in rows}; variant=[]
    for base,var in corpus["metamorphic_contract"]["explicit_variant_pairs"]:
        if base not in idx or var not in idx: variant.append(f"missing_variant_pair:{base}:{var}")
        elif idx[base]["abstract_signature"]!=idx[var]["abstract_signature"]: variant.append(f"abstract_signature_mismatch:{base}:{var}")
    sp=scan(Path(a.scientific_root)); ok=len(rows)==24 and all(r["passed"] for r in rows) and not variant and sp["status"]=="PASS"
    doc={"schema":SCHEMA,"status":"PASS" if ok else "FAIL","case_count":len(rows),"passed_case_count":sum(r["passed"] for r in rows),"failed_fixture_ids":[r["fixture_id"] for r in rows if not r["passed"]],"variant_invariance_status":"PASS" if not variant else "FAIL","variant_errors":variant,"specialization_scan":sp,"regression_protocol_schema":protocol.get("schema"),"corpus_schema":corpus.get("schema"),"read_set_attestation":{"candidate_58_bytes":False,"frozen_48_bytes":False,"fresh_target_bytes":False},"semantic_verdicts_emitted":False,"claim_scope":"NON_PROSPECTIVE_REGRESSION_ONLY","rows":rows}
    raw=enc(doc); Path(a.output).write_bytes(raw); print(json.dumps({"status":doc["status"],"cases":len(rows),"passed":doc["passed_case_count"],"failed":doc["failed_fixture_ids"],"variant_errors":variant,"sha256":h(raw),"bytes":len(raw)},sort_keys=True,separators=(",",":"))); return 0
if __name__=="__main__": raise SystemExit(main())
