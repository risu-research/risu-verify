#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
import bisect
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Mapping, Sequence, Tuple

import risu_e2.frontend_js_v2 as js2
import risu_e2.frontend_python_v2 as py2
from risu_e2.overlay_control import _control_functions, _stmt_walk

SCHEMA="risu.e2-a3-a4-candidate-observability-remediation-v0.2-independent-microqualification/v0.1"


def enc(x: Any) -> bytes:
    return (json.dumps(x,sort_keys=True,separators=(",",":"),ensure_ascii=False)+"\n").encode()


def h(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def starts(src: str) -> list[int]:
    z=[0]
    for i,c in enumerate(src):
        if c=="\n": z.append(i+1)
    return z


def st(f: Mapping[str,Any]) -> Tuple[int,int,int,int]:
    q=f["span"]; return int(q["start_line"]),int(q["start_col"]),int(q["end_line"]),int(q["end_col"])


def sub(src: str, span: Sequence[int]) -> str:
    z=starts(src)
    return src[z[int(span[0])-1]+int(span[1]):z[int(span[2])-1]+int(span[3])]


def needle_span(src: str, needle: str) -> Tuple[int,int,int,int]:
    a=src.find(needle)
    if a<0 or src.find(needle,a+1)>=0: raise AssertionError(f"needle_not_unique:{needle!r}")
    z=starts(src)
    def p(o:int)->Tuple[int,int]:
        i=bisect.bisect_right(z,o)-1
        return i+1,o-z[i]
    sl,sc=p(a); el,ec=p(a+len(needle)); return sl,sc,el,ec


def inside(a: Sequence[int], b: Sequence[int]) -> bool:
    return (int(a[0]),int(a[1])) <= (int(b[0]),int(b[1])) and (int(b[2]),int(b[3])) <= (int(a[2]),int(a[3]))


def descriptors(src: str, facts: Sequence[Mapping[str,Any]]) -> Dict[str,list[Dict[str,Any]]]:
    out={}
    for f in facts:
        kind=str(f.get("kind")); d={"slice":sub(src,st(f)),"scope":str(f.get("scope","")),"span":list(st(f))}
        for k in ("callee","name","field"):
            if k in f: d[k]=f[k]
        if kind=="COMPARE":
            d["operators"]=list(map(str,f.get("operators",[])))
            d["operands"]=[[str(x) for x in g] for g in f.get("operands",[])]
        if kind=="ASSIGN":
            d["lhs"]=list(map(str,f.get("lhs",[]))); d["rhs"]=list(map(str,f.get("rhs",[])))
        out.setdefault(kind,[]).append(d)
    for v in out.values(): v.sort(key=lambda x:(x["span"],x.get("scope",""),repr(x)))
    return out


def return_owners(src: str, lang: str, facts: Sequence[Mapping[str,Any]]) -> list[Dict[str,Any]]:
    functions=[f for f in facts if f.get("kind")=="FUNCTION"]
    controls=_control_functions(src,lang,functions)
    structural=set()
    for row in controls.values():
        for stmt in _stmt_walk(row.get("stmts",[])):
            if stmt.kind=="RETURN": structural.add(tuple(stmt.span))
    fields=[f for f in facts if f.get("kind")=="FIELD_BIND"]
    ans=[]
    for f in facts:
        if f.get("kind")!="RETURN": continue
        r=st(f)
        if r not in structural: continue
        names=sorted({str(x.get("field")) for x in fields if inside(r,st(x))})
        if names: ans.append({"slice":sub(src,r),"span":list(r),"fields":names})
    return sorted(ans,key=lambda x:(x["span"],x["fields"]))


def signature(src: str, lang: str, facts: Sequence[Mapping[str,Any]]) -> tuple:
    d=descriptors(src,facts); reps=return_owners(src,lang,facts)
    return (len(d.get("CALL",[])),len(d.get("COMPARE",[])),len(d.get("RETURN",[])),
            len(reps),tuple(sorted(len(r["fields"]) for r in reps)))


def assert_expectations(case: Mapping[str,Any], facts: Sequence[Mapping[str,Any]]) -> list[str]:
    src=str(case["source"]); e=dict(case["expected"]); d=descriptors(src,facts); bad=[]
    def walk(v: Any) -> None:
        if isinstance(v,dict):
            for k,x in v.items():
                if k in {"source_slice","return_slice"} and isinstance(x,str):
                    try: needle_span(src,x)
                    except Exception as ex: bad.append(f"invalid_frozen_slice:{x!r}:{ex}")
                else: walk(x)
        elif isinstance(v,list):
            for x in v: walk(x)
    walk(e)

    if "function_names_exact" in e:
        got=sorted(str(x.get("name")) for x in d.get("FUNCTION",[]))
        if got!=sorted(map(str,e["function_names_exact"])): bad.append(f"function_names:{got}")
    if "call_count" in e and len(d.get("CALL",[]))!=int(e["call_count"]):
        bad.append(f"call_count:{len(d.get('CALL',[]))}")
    for x in e.get("expected_calls",[]):
        wanted=(str(x["source_slice"]),str(x["scope"]),str(x["callee"]))
        got={(str(q["slice"]),str(q["scope"]),str(q.get("callee"))) for q in d.get("CALL",[])}
        if wanted not in got: bad.append(f"call_missing:{wanted}")
    for s in e.get("forbidden_call_slices",[]):
        if any(q["slice"]==s for q in d.get("CALL",[])): bad.append(f"forbidden_call:{s}")
    if "compare_count" in e and len(d.get("COMPARE",[]))!=int(e["compare_count"]):
        bad.append(f"compare_count:{len(d.get('COMPARE',[]))}")
    observed_comp={(q["slice"],q["scope"],tuple(q["operators"]),tuple(tuple(g) for g in q["operands"])) for q in d.get("COMPARE",[])}
    for x in e.get("expected_compares",[]):
        wanted=(str(x["source_slice"]),str(x["scope"]),(str(x["operator"]),),tuple(tuple(map(str,g)) for g in x["operands"]))
        if wanted not in observed_comp: bad.append(f"compare_missing:{wanted}")
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
        if not any(sorted(q.get("lhs",[]))==wl and wr.issubset(set(q.get("rhs",[]))) for q in d.get("ASSIGN",[])):
            bad.append(f"assignment_missing:{x}")

    reps=return_owners(src,str(case["language"]),facts)
    if "representation_owner_count" in e and len(reps)!=int(e["representation_owner_count"]):
        bad.append(f"representation_count:{len(reps)}")
    for x in e.get("object_return_relations",[]):
        rows=[r for r in reps if r["slice"]==str(x["return_slice"])]
        if len(rows)!=1:
            bad.append(f"representation_not_unique:{x['return_slice']}:{len(rows)}"); continue
        required=set(map(str,x.get("fields",[])))
        if not required.issubset(set(rows[0]["fields"])): bad.append(f"representation_fields:{sorted(required-set(rows[0]['fields']))}")
        esp=needle_span(src,str(x["return_slice"]))
        return_spans=[tuple(q["span"]) for q in d.get("RETURN",[]) if q["slice"]==str(x["return_slice"])]
        if str(x.get("representation_owner_relation"))=="EQUAL" and (return_spans!=[esp] or tuple(rows[0]["span"])!=esp):
            bad.append(f"owner_relation_not_equal:{x['return_slice']}")
    return bad


def scan(root: Path) -> Dict[str,Any]:
    rels=["risu_e2/frontend_js_v2.py","risu_e2/frontend_python_v2.py","risu_e2/ir_v2.py"]
    forbidden=("V2B","V2M","CQ_","FRONTEND_OBSERVABILITY_GAP","MICROQUALIFICATION_EXPECTATION_NOT_MET",
               "E2_A3_A4_CANDIDATE_OBSERVABILITY_REMEDIATION_V0_2_MICROQUALIFICATION_CORPUS")
    hits=[]
    for rel in rels:
        text=(root/rel).read_text()
        for word in forbidden:
            if word in text: hits.append([rel,"literal",word])
        tree=ast.parse(text)
        for n in ast.walk(tree):
            if isinstance(n,ast.Compare):
                t=(ast.get_source_segment(text,n) or "").lower()
                if ("source_sha" in t or "sha256" in t) and any(isinstance(o,(ast.Eq,ast.NotEq,ast.In,ast.NotIn)) for o in n.ops):
                    hits.append([rel,"hash_compare",t[:160]])
    return {"status":"PASS" if not hits else "FAIL","hits":hits}


def main()->int:
    p=argparse.ArgumentParser()
    p.add_argument("--protocol",required=True); p.add_argument("--corpus",required=True)
    p.add_argument("--scientific-root",required=True); p.add_argument("--output",required=True)
    a=p.parse_args()
    protocol=json.loads(Path(a.protocol).read_text()); corpus=json.loads(Path(a.corpus).read_text())
    rows=[]
    for c in corpus["cases"]:
        src=str(c["source"]); lang=str(c["language"])
        parsed=py2.extract(src) if lang=="python" else js2.extract(src)
        facts=list(parsed.get("facts",[])); bad=[]
        if parsed.get("status")!="PASS": bad.append(f"frontend:{parsed.get('status')}:{parsed.get('error')}")
        bad.extend(assert_expectations(c,facts))
        rows.append({"fixture_id":str(c["fixture_id"]),"variant_of":c.get("variant_of"),"language":lang,
                     "obligation_ids":list(c.get("obligation_ids",[])),"source_sha256":h(src.encode()),
                     "parser":parsed.get("parser"),"abstract_signature":list(signature(src,lang,facts)),
                     "passed":not bad,"errors":bad})
    index={r["fixture_id"]:r for r in rows}; variant_bad=[]
    for base,var in corpus["metamorphic_contract"]["explicit_variant_pairs"]:
        if base not in index or var not in index or index[base]["abstract_signature"]!=index[var]["abstract_signature"]:
            variant_bad.append([base,var])
    sp=scan(Path(a.scientific_root))
    ok=len(rows)==24 and all(r["passed"] for r in rows) and not variant_bad and sp["status"]=="PASS"
    doc={"schema":SCHEMA,"status":"PASS" if ok else "FAIL","case_count":len(rows),
         "passed_case_count":sum(r["passed"] for r in rows),
         "failed_fixture_ids":[r["fixture_id"] for r in rows if not r["passed"]],
         "variant_pair_failures":variant_bad,"specialization_scan":sp,
         "protocol_schema":protocol.get("schema"),"corpus_schema":corpus.get("schema"),
         "independence_attestation":{"primary_checker_imported":False,"primary_output_read":False,
                                     "expectations_recomputed_from_frozen_source_slices":True},
         "read_set_attestation":{"candidate_58_bytes":False,"sanitized_58_manifest":False,
             "raw_blind_58_transport":False,"mutation_truth":False,"operator_metadata":False,
             "expected_e2_predictions":False,"fresh_target_bytes":False,"frozen_48_corpus":False},
         "semantic_verdicts_emitted":False,"rows":rows}
    raw=enc(doc); Path(a.output).write_bytes(raw)
    print(json.dumps({"status":doc["status"],"cases":len(rows),"passed":doc["passed_case_count"],
                      "failed":doc["failed_fixture_ids"],"sha256":h(raw),"bytes":len(raw)},
                     sort_keys=True,separators=(",",":")))
    return 0


if __name__=="__main__":
    raise SystemExit(main())
