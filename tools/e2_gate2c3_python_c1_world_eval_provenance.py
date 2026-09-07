#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Mapping, Sequence

PROTOCOL_SCHEMA="risu.e2-gate2c3-python-c1-world-evaluation-provenance-protocol/v0.1"
MATRIX_SCHEMA="risu.e2-candidate58-machine-prediction-matrix/v0.1"
C1_SCHEMA="risu.e2-c1-recheck/v0.1"
PATTERN=re.compile(r"^(SYN-(?:PY|GO|TS)-0[12])\.(py|go|mjs|js|ts)$")
LANG={"py":"python","go":"go","mjs":"typescript_javascript","js":"typescript_javascript","ts":"typescript_javascript"}
TAXONOMY=[
 "TRACE_INPUT_INTEGRITY_FAILURE","COMPARE_SHAPE_UNRESOLVED","LEFT_ORIGIN_UNRESOLVED","LEFT_ORIGIN_NONUNIQUE",
 "RIGHT_ORIGIN_UNRESOLVED","RIGHT_ORIGIN_NONUNIQUE","WORLD_ROLE_VALUE_MISSING_BOTH","WORLD_ROLE_VALUE_MISSING_LEFT",
 "WORLD_ROLE_VALUE_MISSING_RIGHT","FROZEN_REASON_INCONSISTENT",
]

def cb(v:Any)->bytes:return (json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=False)+"\n").encode()
def sha(raw:bytes)->str:return hashlib.sha256(raw).hexdigest()
def readj(p:Path)->Any:return json.loads(p.read_bytes())
def span(n:ast.AST)->tuple[int,int,int,int]:return (int(n.lineno),int(n.col_offset),int(n.end_lineno),int(n.end_col_offset))

def origins(expr:ast.AST,state:Mapping[str,set[str]])->set[str]|None:
    if isinstance(expr,ast.Name):return set(state.get(expr.id,set())) or None
    if isinstance(expr,ast.Constant):return {"CONST:"+hashlib.sha256(cb(expr.value)).hexdigest()[:16]}
    if isinstance(expr,ast.UnaryOp) and isinstance(expr.op,ast.Not):return origins(expr.operand,state)
    if isinstance(expr,ast.Attribute):
        base=origins(expr.value,state);return None if base is None else {f"{x}.slot:{expr.attr}" for x in base}
    if isinstance(expr,ast.Subscript):
        base=origins(expr.value,state)
        if base is None:return None
        key=ast.literal_eval(expr.slice) if isinstance(expr.slice,ast.Constant) else None
        return None if key is None else {f"{x}.slot:{key}" for x in base}
    return None

def role_state(fn:ast.FunctionDef|ast.AsyncFunctionDef,signature:Mapping[str,Any])->tuple[dict[str,set[str]],list[str]]:
    params=list(fn.args.posonlyargs)+list(fn.args.args)+list(fn.args.kwonlyargs); st={};bad=[];claimed=set()
    for role,spec in sorted((signature.get("source_roles",{}) or {}).items()):
        idx=spec.get("parameter_index")
        if not isinstance(idx,int) or idx<0 or idx>=len(params):bad.append(f"SOURCE_ROLE_PARAMETER_INDEX_INVALID:{role}");continue
        if idx in claimed:bad.append(f"SOURCE_ROLE_PARAMETER_INDEX_AMBIGUOUS:{idx}");continue
        claimed.add(idx);st[params[idx].arg]={str(role)}
    return st,bad

def apply_assign(stmt:ast.stmt,state:dict[str,set[str]])->tuple[dict[str,set[str]],str|None]:
    if isinstance(stmt,ast.Assign):targets=list(stmt.targets);value=stmt.value
    elif isinstance(stmt,ast.AnnAssign):targets=[stmt.target];value=stmt.value
    else:return state,"PREFIX_STATEMENT_OUTSIDE_MINIMAL_FRAGMENT"
    names=[]
    for t in targets:
        if isinstance(t,ast.Name):names.append(t.id)
        elif isinstance(t,(ast.Tuple,ast.List)):names.extend(x.id for x in t.elts if isinstance(x,ast.Name))
    if value is None or len(names)!=1:return state,"ASSIGNMENT_OUTSIDE_MINIMAL_FRAGMENT"
    o=origins(value,state)
    if o is None:return state,"ASSIGNMENT_RHS_ORIGIN_UNRESOLVED"
    nxt={k:set(v) for k,v in state.items()};nxt[names[0]]=set(o);return nxt,None

def exact_node(tree:ast.AST,typ:type[ast.AST],sp:Sequence[int])->list[ast.AST]:
    t=tuple(map(int,sp));return [n for n in ast.walk(tree) if isinstance(n,typ) and hasattr(n,"lineno") and span(n)==t]

def input_failure(case_id:str,reasons:list[str])->dict[str,Any]:
    return {"case_id":case_id,"taxonomy":"TRACE_INPUT_INTEGRITY_FAILURE","integrity_reasons":sorted(set(reasons)),"primitive":{}}

def diagnose_case(*,case_id:str,source:bytes,expected_source_sha256:str,adapter:Mapping[str,Any],semantic_slice:Mapping[str,Any],c1:Mapping[str,Any],matrix_row:Mapping[str,Any])->dict[str,Any]:
    bad=[]
    if sha(source)!=expected_source_sha256 or matrix_row.get("candidate_source_sha256")!=expected_source_sha256:bad.append("SOURCE_SHA_MISMATCH")
    if c1.get("schema")!=C1_SCHEMA or c1.get("reasons")!=["WORLD_GUARD_EVAL_UNRESOLVED:SYN-PY-01:effect"]:bad.append("FROZEN_C1_REASON_MISMATCH")
    if matrix_row.get("language")!="python" or matrix_row.get("tentative_kernel_prediction")!="E2_PREDICTED_PRESERVATION_EVIDENCE":bad.append("POPULATION_ROW_MISMATCH")
    if matrix_row.get("c1_report_sha256")!=sha(cb(c1)):bad.append("C1_REPORT_SHA_MISMATCH")
    if matrix_row.get("adapter_receipt_sha256")!=sha(cb(adapter)):bad.append("ADAPTER_SHA_MISMATCH")
    if matrix_row.get("semantic_slice_sha256")!=sha(cb(semantic_slice)):bad.append("SEMANTIC_SLICE_SHA_MISMATCH")
    signature=adapter.get("execution_signature") if isinstance(adapter,Mapping) else None
    contract=semantic_slice.get("source_contract") if isinstance(semantic_slice,Mapping) else None
    if not isinstance(signature,Mapping) or not isinstance(contract,Mapping):bad.append("CHECKER_INPUT_SURFACE_MISSING")
    if bad:return input_failure(case_id,bad)
    try:tree=ast.parse(source.decode("utf-8"))
    except Exception as e:return input_failure(case_id,["SOURCE_PARSE_FAILURE:"+type(e).__name__])
    fspan=contract.get("target_function_span",[]);gspan=((contract.get("anchors",{}) or {}).get("guard",{}) or {}).get("span",[])
    fns=exact_node(tree,ast.FunctionDef,fspan)+exact_node(tree,ast.AsyncFunctionDef,fspan)
    guards=exact_node(tree,ast.Compare,gspan)
    if len(fns)!=1 or len(guards)!=1:return input_failure(case_id,["TARGET_OR_GUARD_NOT_UNIQUE"])
    fn=fns[0];guard=guards[0]
    if len(guard.ops)!=1 or len(guard.comparators)!=1:
        return {"case_id":case_id,"taxonomy":"COMPARE_SHAPE_UNRESOLVED","integrity_reasons":[],"primitive":{"guard_span":list(gspan),"operator_count":len(guard.ops),"comparator_count":len(guard.comparators)}}
    state,sbad=role_state(fn,signature)
    if sbad:return input_failure(case_id,sbad)
    ifspan=contract.get("effective_if_span",[]);ifs=exact_node(fn,ast.If,ifspan)
    if len(ifs)!=1:return input_failure(case_id,["EFFECTIVE_IF_NOT_UNIQUE"])
    target_if=ifs[0]
    for stmt in fn.body:
        if stmt is target_if:break
        if isinstance(stmt,(ast.Assign,ast.AnnAssign)):
            state,why=apply_assign(stmt,state)
            if why:return input_failure(case_id,[why])
        elif isinstance(stmt,ast.Expr) and isinstance(stmt.value,ast.Constant):continue
        else:return input_failure(case_id,["PREFIX_STATEMENT_OUTSIDE_DIAGNOSTIC_FRAGMENT"])
    lo=origins(guard.left,state);ro=origins(guard.comparators[0],state)
    prim={"guard_span":list(gspan),"left_origins":sorted(lo) if lo is not None else None,"right_origins":sorted(ro) if ro is not None else None}
    if lo is None:return {"case_id":case_id,"taxonomy":"LEFT_ORIGIN_UNRESOLVED","integrity_reasons":[],"primitive":prim}
    if len(lo)!=1:return {"case_id":case_id,"taxonomy":"LEFT_ORIGIN_NONUNIQUE","integrity_reasons":[],"primitive":prim}
    if ro is None:return {"case_id":case_id,"taxonomy":"RIGHT_ORIGIN_UNRESOLVED","integrity_reasons":[],"primitive":prim}
    if len(ro)!=1:return {"case_id":case_id,"taxonomy":"RIGHT_ORIGIN_NONUNIQUE","integrity_reasons":[],"primitive":prim}
    worlds=[w for w in signature.get("worlds",[]) or [] if str(w.get("id"))=="SYN-PY-01:effect"]
    if len(worlds)!=1:return input_failure(case_id,["EFFECT_WORLD_NOT_UNIQUE"])
    vals=worlds[0].get("role_values",{}) or {};left=next(iter(lo));right=next(iter(ro));lm=left not in vals;rm=right not in vals
    prim.update({"left_origin":left,"right_origin":right,"effect_world_role_keys":sorted(map(str,vals.keys())),"left_key_present":not lm,"right_key_present":not rm})
    if lm and rm:tax="WORLD_ROLE_VALUE_MISSING_BOTH"
    elif lm:tax="WORLD_ROLE_VALUE_MISSING_LEFT"
    elif rm:tax="WORLD_ROLE_VALUE_MISSING_RIGHT"
    else:tax="FROZEN_REASON_INCONSISTENT"
    return {"case_id":case_id,"taxonomy":tax,"integrity_reasons":[],"primitive":prim}

def locate_selected_sources(*,cells_dir:Path,manifest:Mapping[str,Any],selected:set[str],output_dir:Path)->dict[str,Any]:
    rows={str(x["transport_case_id"]):x for x in manifest.get("cases",[]) or []};
    if set(selected)-set(rows):raise ValueError("selected case absent from admission")
    target={(str(rows[c]["seed_id"]),str(rows[c]["language"]),str(rows[c]["candidate_source_sha256"])):c for c in selected}
    found={};hashed=0
    for p in cells_dir.rglob("*"):
        m=PATTERN.fullmatch(p.name)
        if not m or not p.is_file():continue
        raw=p.read_bytes();hashed+=1;key=(m.group(1),LANG[m.group(2)],sha(raw));cid=target.get(key)
        if cid is not None:
            if cid in found:raise ValueError("selected opaque source resolution nonunique")
            found[cid]=(p,raw)
    if hashed!=58:raise ValueError(f"expected 58 source hashes, got {hashed}")
    if set(found)!=selected:raise ValueError("selected opaque source resolution incomplete")
    output_dir.mkdir(parents=True,exist_ok=True);out=[]
    for cid in sorted(selected):
        p,raw=found[cid];dst=output_dir/(cid+".py");dst.write_bytes(raw)
        out.append({"case_id":cid,"source_sha256":sha(raw),"source_path_localization_sha256":sha(str(p).encode())})
    return {"schema":"risu.e2-gate2c3-opaque-source-locator/v0.1","source_files_stream_hashed":hashed,"source_files_semantically_parsed":0,"selected_source_count":len(out),"nonselected_source_bytes_retained":False,"cell_json_read":False,"rows":out}

def run_real(args:argparse.Namespace)->int:
    protocol=readj(Path(args.protocol));matrix=readj(Path(args.matrix));root=Path(args.case_artifacts);sources=Path(args.sources);out=Path(args.output);out.mkdir(parents=True,exist_ok=True)
    if protocol.get("schema")!=PROTOCOL_SCHEMA:raise ValueError("protocol schema")
    selected=list(protocol["population"]["case_ids"]);mrows={str(x["case_id"]):x for x in matrix.get("cases",[]) or []}
    if len(selected)!=7 or any(c not in mrows for c in selected):raise ValueError("population binding")
    ledger=[]
    for cid in sorted(selected):
        d=root/cid
        adapter=readj(d/"adapter_receipt.json");ss=readj(d/"semantic_slice.json");c1=readj(d/"c1_report.json");src=(sources/(cid+".py")).read_bytes()
        ledger.append(diagnose_case(case_id=cid,source=src,expected_source_sha256=str(mrows[cid]["candidate_source_sha256"]),adapter=adapter,semantic_slice=ss,c1=c1,matrix_row=mrows[cid]))
    counts={k:0 for k in TAXONOMY}
    for r in ledger:counts[r["taxonomy"]]+=1
    summary={"schema":"risu.e2-gate2c3-python-c1-world-evaluation-provenance-summary/v0.1","case_count":7,"taxonomy_counts":counts,"taxonomy_case_ids":{k:[r["case_id"] for r in ledger if r["taxonomy"]==k] for k in TAXONOMY},"interpretation":{"c1_rerun":False,"truth_used":False,"remediation":False,"valid_c1_inferred":False}}
    (out/"E2_GATE2C3_WORLD_EVAL_PROVENANCE_LEDGER.json").write_bytes(cb({"schema":"risu.e2-gate2c3-ledger/v0.1","cases":ledger}))
    (out/"E2_GATE2C3_WORLD_EVAL_PROVENANCE_SUMMARY.json").write_bytes(cb(summary))
    return 0

def main()->int:
    ap=argparse.ArgumentParser();sub=ap.add_subparsers(dest="cmd",required=True)
    l=sub.add_parser("locate");l.add_argument("--cells-dir",required=True);l.add_argument("--manifest",required=True);l.add_argument("--protocol",required=True);l.add_argument("--output-sources",required=True);l.add_argument("--receipt",required=True)
    r=sub.add_parser("run");r.add_argument("--protocol",required=True);r.add_argument("--matrix",required=True);r.add_argument("--case-artifacts",required=True);r.add_argument("--sources",required=True);r.add_argument("--output",required=True)
    a=ap.parse_args()
    if a.cmd=="locate":
        p=readj(Path(a.protocol));sel=set(p["population"]["case_ids"]);rec=locate_selected_sources(cells_dir=Path(a.cells_dir),manifest=readj(Path(a.manifest)),selected=sel,output_dir=Path(a.output_sources));Path(a.receipt).write_bytes(cb(rec));return 0
    return run_real(a)
if __name__=="__main__":raise SystemExit(main())
