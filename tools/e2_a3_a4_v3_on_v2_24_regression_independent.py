#!/usr/bin/env python3
from __future__ import annotations

import argparse, ast, bisect, hashlib, json
from pathlib import Path
from typing import Any, Mapping, Sequence, Tuple

import risu_e2.frontend_js_v3 as js3
import risu_e2.frontend_python_v2 as py2
from risu_e2.overlay_control import _control_functions, _stmt_walk

SCHEMA="risu.e2-a3-a4-v0.3-on-frozen-v0.2-24-independent-regression/v0.1"
def enc(x: Any)->bytes: return (json.dumps(x,sort_keys=True,separators=(",",":"),ensure_ascii=False)+"\n").encode()
def h(b: bytes)->str: return hashlib.sha256(b).hexdigest()
def starts(src: str)->list[int]:
    z=[0]
    for i,c in enumerate(src):
        if c=="\n": z.append(i+1)
    return z
def st(f: Mapping[str,Any])->Tuple[int,int,int,int]:
    q=f["span"]; return int(q["start_line"]),int(q["start_col"]),int(q["end_line"]),int(q["end_col"])
def sub(src: str, sp: Sequence[int])->str:
    z=starts(src); return src[z[int(sp[0])-1]+int(sp[1]):z[int(sp[2])-1]+int(sp[3])]
def inside(a: Sequence[int],b: Sequence[int])->bool:
    return (int(a[0]),int(a[1])) <= (int(b[0]),int(b[1])) and (int(b[2]),int(b[3])) <= (int(a[2]),int(a[3]))
def needle(src: str, text: str)->Tuple[int,int,int,int]:
    a=src.find(text)
    if a<0 or src.find(text,a+1)>=0: raise AssertionError(f"needle_not_unique:{text!r}")
    z=starts(src)
    def p(o:int)->Tuple[int,int]: i=bisect.bisect_right(z,o)-1; return i+1,o-z[i]
    sl,sc=p(a); el,ec=p(a+len(text)); return sl,sc,el,ec

def desc(src: str, facts: Sequence[Mapping[str,Any]])->dict[str,list[dict[str,Any]]]:
    out={}
    for f in facts:
        k=str(f.get("kind")); d={"slice":sub(src,st(f)),"scope":str(f.get("scope","")),"span":list(st(f))}
        for x in ("callee","name","field"):
            if x in f: d[x]=f[x]
        if k=="COMPARE": d["operators"]=list(map(str,f.get("operators",[]))); d["operands"]=[[str(x) for x in g] for g in f.get("operands",[])]
        if k=="ASSIGN": d["lhs"]=list(map(str,f.get("lhs",[]))); d["rhs"]=list(map(str,f.get("rhs",[])))
        out.setdefault(k,[]).append(d)
    for v in out.values(): v.sort(key=lambda x:(x["span"],x.get("scope",""),repr(x)))
    return out

def owners(src: str, lang: str, facts: Sequence[Mapping[str,Any]])->list[dict[str,Any]]:
    funcs=[f for f in facts if f.get("kind")=="FUNCTION"]; controls=_control_functions(src,lang,funcs); structural=set()
    for row in controls.values():
        for s in _stmt_walk(row.get("stmts",[])):
            if s.kind=="RETURN": structural.add(tuple(s.span))
    fields=[f for f in facts if f.get("kind")=="FIELD_BIND"]; ans=[]
    for f in facts:
        if f.get("kind")!="RETURN" or st(f) not in structural: continue
        names=sorted({str(x.get("field")) for x in fields if inside(st(f),st(x))})
        if names: ans.append({"slice":sub(src,st(f)),"span":list(st(f)),"fields":names})
    return sorted(ans,key=lambda x:(x["span"],x["fields"]))
def sig(src: str, lang: str, facts: Sequence[Mapping[str,Any]])->list[Any]:
    d=desc(src,facts); r=owners(src,lang,facts); return [len(d.get("CALL",[])),len(d.get("COMPARE",[])),len(d.get("RETURN",[])),len(r),tuple(sorted(len(x["fields"]) for x in r))]

def check(case: Mapping[str,Any], facts: Sequence[Mapping[str,Any]])->list[str]:
    src=str(case["source"]); lang=str(case["language"]); e=dict(case["expected"]); d=desc(src,facts); bad=[]
    def walk(v: Any)->None:
        if isinstance(v,dict):
            for k,x in v.items():
                if k in {"source_slice","return_slice"} and isinstance(x,str):
                    try: needle(src,x)
                    except Exception as ex: bad.append(f"invalid_frozen_slice:{x!r}:{ex}")
                else: walk(x)
        elif isinstance(v,list):
            for x in v: walk(x)
    walk(e)
    if "function_names_exact" in e:
        got=sorted(str(x.get("name")) for x in d.get("FUNCTION",[]))
        if got!=sorted(map(str,e["function_names_exact"])): bad.append(f"function_names:{got}")
    if "call_count" in e and len(d.get("CALL",[]))!=int(e["call_count"]): bad.append(f"call_count:{len(d.get('CALL',[]))}")
    got_calls={(q["slice"],q["scope"],str(q.get("callee"))) for q in d.get("CALL",[])}
    for x in e.get("expected_calls",[]):
        w=(str(x["source_slice"]),str(x["scope"]),str(x["callee"]))
        if w not in got_calls: bad.append(f"call_missing:{w}")
    for s in e.get("forbidden_call_slices",[]):
        if any(q["slice"]==s for q in d.get("CALL",[])): bad.append(f"forbidden_call:{s}")
    if "compare_count" in e and len(d.get("COMPARE",[]))!=int(e["compare_count"]): bad.append(f"compare_count:{len(d.get('COMPARE',[]))}")
    got_cmp={(q["slice"],q["scope"],tuple(q["operators"]),tuple(tuple(g) for g in q["operands"])) for q in d.get("COMPARE",[])}
    for x in e.get("expected_compares",[]):
        w=(str(x["source_slice"]),str(x["scope"]),(str(x["operator"]),),tuple(tuple(map(str,g)) for g in x["operands"]))
        if w not in got_cmp: bad.append(f"compare_missing:{w}")
    for s in e.get("forbidden_compare_slices",[]):
        if any(q["slice"]==s for q in d.get("COMPARE",[])): bad.append(f"forbidden_compare:{s}")
    for s in e.get("expected_return_slices",[]):
        n=sum(q["slice"]==s for q in d.get("RETURN",[]))
        if n!=1: bad.append(f"return_cardinality:{s}:{n}")
    for scope,count in e.get("call_count_in_scope",{}).items():
        n=sum(q["scope"]==str(scope) for q in d.get("CALL",[]))
        if n!=int(count): bad.append(f"scope_call_count:{scope}:{n}")
    for x in e.get("expected_assignments",[]):
        wl=sorted(map(str,x["lhs"])); wr=set(map(str,x.get("rhs_contains",[])))
        if not any(sorted(q.get("lhs",[]))==wl and wr.issubset(set(q.get("rhs",[]))) for q in d.get("ASSIGN",[])): bad.append(f"assignment_missing:{x}")
    rr=owners(src,lang,facts)
    if "representation_owner_count" in e and len(rr)!=int(e["representation_owner_count"]): bad.append(f"representation_count:{len(rr)}")
    for x in e.get("object_return_relations",[]):
        rows=[r for r in rr if r["slice"]==str(x["return_slice"])]
        if len(rows)!=1: bad.append(f"representation_not_unique:{x['return_slice']}:{len(rows)}"); continue
        req=set(map(str,x.get("fields",[])))
        if not req.issubset(set(rows[0]["fields"])): bad.append(f"representation_fields:{sorted(req-set(rows[0]['fields']))}")
        esp=needle(src,str(x["return_slice"])); ret=[tuple(q["span"]) for q in d.get("RETURN",[]) if q["slice"]==str(x["return_slice"])]
        if str(x.get("representation_owner_relation"))=="EQUAL" and (ret!=[esp] or tuple(rows[0]["span"])!=esp): bad.append(f"owner_relation_not_equal:{x['return_slice']}")
    return bad

def scan(root: Path)->dict[str,Any]:
    rels=["risu_e2/frontend_js_v3.py","risu_e2/frontend_python_v2.py","risu_e2/ir_v3.py"]; forbidden=("V3B","V3M","V2B","V2M","CQ_","FRONTEND_OBSERVABILITY_GAP","MICROQUALIFICATION_EXPECTATION_NOT_MET"); hits=[]
    for rel in rels:
        text=(root/rel).read_text()
        for w in forbidden:
            if w in text: hits.append([rel,"literal",w])
        tree=ast.parse(text)
        for n in ast.walk(tree):
            if isinstance(n,ast.Compare):
                t=(ast.get_source_segment(text,n) or "").lower()
                if ("sha256" in t or "source_sha" in t) and any(isinstance(o,(ast.Eq,ast.NotEq,ast.In,ast.NotIn)) for o in n.ops): hits.append([rel,"hash_compare",t[:180]])
    return {"status":"PASS" if not hits else "FAIL","hits":hits}
def main()->int:
    p=argparse.ArgumentParser(); p.add_argument("--protocol",required=True); p.add_argument("--corpus",required=True); p.add_argument("--scientific-root",required=True); p.add_argument("--output",required=True); a=p.parse_args(); protocol=json.loads(Path(a.protocol).read_text()); corpus=json.loads(Path(a.corpus).read_text()); rows=[]
    for c in corpus["cases"]:
        src=str(c["source"]); lang=str(c["language"]); parsed=py2.extract(src) if lang=="python" else js3.extract(src); facts=list(parsed.get("facts",[])); bad=[]
        if parsed.get("status")!="PASS": bad.append(f"frontend:{parsed.get('status')}:{parsed.get('error')}")
        bad.extend(check(c,facts)); rows.append({"fixture_id":str(c["fixture_id"]),"variant_of":c.get("variant_of"),"language":lang,"obligation_ids":list(c.get("obligation_ids",[])),"source_sha256":h(src.encode()),"parser":parsed.get("parser"),"abstract_signature":sig(src,lang,facts),"passed":not bad,"errors":bad})
    idx={r["fixture_id"]:r for r in rows}; variant=[]
    for base,var in corpus["metamorphic_contract"]["explicit_variant_pairs"]:
        if base not in idx or var not in idx or idx[base]["abstract_signature"]!=idx[var]["abstract_signature"]: variant.append([base,var])
    sp=scan(Path(a.scientific_root)); ok=len(rows)==24 and all(r["passed"] for r in rows) and not variant and sp["status"]=="PASS"
    doc={"schema":SCHEMA,"status":"PASS" if ok else "FAIL","case_count":len(rows),"passed_case_count":sum(r["passed"] for r in rows),"failed_fixture_ids":[r["fixture_id"] for r in rows if not r["passed"]],"variant_pair_failures":variant,"specialization_scan":sp,"regression_protocol_schema":protocol.get("schema"),"corpus_schema":corpus.get("schema"),"independence_attestation":{"primary_adapter_imported":False,"primary_output_read":False,"expectations_recomputed_from_frozen_source_slices":True},"read_set_attestation":{"candidate_58_bytes":False,"frozen_48_bytes":False,"fresh_target_bytes":False},"semantic_verdicts_emitted":False,"claim_scope":"NON_PROSPECTIVE_REGRESSION_ONLY","rows":rows}
    raw=enc(doc); Path(a.output).write_bytes(raw); print(json.dumps({"status":doc["status"],"cases":len(rows),"passed":doc["passed_case_count"],"failed":doc["failed_fixture_ids"],"variant_failures":variant,"sha256":h(raw),"bytes":len(raw)},sort_keys=True,separators=(",",":"))); return 0
if __name__=="__main__": raise SystemExit(main())
