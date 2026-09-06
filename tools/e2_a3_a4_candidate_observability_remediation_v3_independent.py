#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping, Sequence, Tuple

import risu_e2.frontend_js_v3 as js3
from risu_e2.overlay_control import _control_functions, _stmt_walk

SCHEMA="risu.e2-a3-a4-candidate-observability-remediation-v0.3-independent-prospective/v0.1"


def enc(x: Any) -> bytes:
    return (json.dumps(x,sort_keys=True,separators=(",",":"),ensure_ascii=False)+"\n").encode()


def h(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def st(f: Mapping[str,Any]) -> Tuple[int,int,int,int]:
    s=f["span"]; return int(s["start_line"]),int(s["start_col"]),int(s["end_line"]),int(s["end_col"])


def starts(src: str) -> list[int]:
    z=[0]
    for i,c in enumerate(src):
        if c=="\n": z.append(i+1)
    return z


def piece(src: str, sp: Sequence[int]) -> str:
    z=starts(src)
    return src[z[int(sp[0])-1]+int(sp[1]):z[int(sp[2])-1]+int(sp[3])]


def inside(a: Sequence[int], b: Sequence[int]) -> bool:
    return (int(a[0]),int(a[1])) <= (int(b[0]),int(b[1])) and (int(b[2]),int(b[3])) <= (int(a[2]),int(a[3]))


def return_owners(src: str, facts: Sequence[Mapping[str,Any]]) -> list[dict[str,Any]]:
    funcs=[f for f in facts if f.get("kind")=="FUNCTION"]
    controls=_control_functions(src,"typescript_javascript",funcs)
    structural=set()
    for row in controls.values():
        for stmt in _stmt_walk(row.get("stmts",[])):
            if stmt.kind=="RETURN": structural.add(tuple(stmt.span))
    fields=[f for f in facts if f.get("kind")=="FIELD_BIND"]
    ans=[]
    for f in facts:
        if f.get("kind")!="RETURN": continue
        rsp=st(f)
        if rsp not in structural: continue
        owned=[x for x in fields if inside(rsp,st(x))]
        if not owned: continue
        ans.append({"slice":piece(src,rsp),"span":list(rsp),"fields":sorted({str(x.get("field")) for x in owned}),"field_bind_count":len(owned)})
    return sorted(ans,key=lambda x:(x["span"],x["fields"],x["field_bind_count"]))


def sig(src: str, facts: Sequence[Mapping[str,Any]]) -> list[Any]:
    reps=return_owners(src,facts)
    return [
        sum(f.get("kind")=="CALL" for f in facts),
        sum(f.get("kind")=="COMPARE" for f in facts),
        sum(f.get("kind")=="RETURN" for f in facts),
        len(reps),
        sorted(len(r["fields"]) for r in reps),
        sorted(r["field_bind_count"] for r in reps),
    ]


def check(case: Mapping[str,Any], facts: Sequence[Mapping[str,Any]]) -> list[str]:
    src=str(case["source"]); e=dict(case["expected"]); bad=[]
    calls=[f for f in facts if f.get("kind")=="CALL"]; compares=[f for f in facts if f.get("kind")=="COMPARE"]; returns=[f for f in facts if f.get("kind")=="RETURN"]
    if "call_count" in e and len(calls)!=int(e["call_count"]): bad.append(f"call_count:{len(calls)}")
    got_calls={(str(f.get("callee")),str(f.get("scope")),piece(src,st(f))) for f in calls}
    for x in e.get("expected_calls",[]):
        w=(str(x["callee"]),str(x["scope"]),str(x["source_slice"]))
        if w not in got_calls: bad.append(f"call_missing:{w}")
    if "compare_count" in e and len(compares)!=int(e["compare_count"]): bad.append(f"compare_count:{len(compares)}")
    got_cmp={(str(f.get("scope")),tuple(map(str,f.get("operators",[]))),tuple(tuple(map(str,g)) for g in f.get("operands",[])),piece(src,st(f))) for f in compares}
    for x in e.get("expected_compares",[]):
        w=(str(x["scope"]),(str(x["operator"]),),tuple(tuple(map(str,g)) for g in x["operands"]),str(x["source_slice"]))
        if w not in got_cmp: bad.append(f"compare_missing:{w}")
    for wanted in e.get("expected_return_slices",[]):
        n=sum(piece(src,st(f))==str(wanted) for f in returns)
        if n!=1: bad.append(f"return_cardinality:{wanted}:{n}")
    reps=return_owners(src,facts)
    for x in e.get("representations_exact",[]):
        rows=[r for r in reps if r["slice"]==str(x["return_slice"])]
        if len(rows)!=1:
            bad.append(f"representation_not_unique:{x['return_slice']}:{len(rows)}"); continue
        row=rows[0]
        if row["fields"]!=sorted(map(str,x["fields_exact"])): bad.append(f"representation_fields:{row['fields']}")
        if int(row["field_bind_count"])!=int(x["field_bind_count_exact"]): bad.append(f"field_bind_count:{row['field_bind_count']}")
        ret=[f for f in returns if piece(src,st(f))==str(x["return_slice"])]
        if str(x.get("representation_owner_relation"))=="EQUAL" and (len(ret)!=1 or list(st(ret[0]))!=row["span"]):
            bad.append(f"owner_not_equal:{x['return_slice']}")
    return bad


def scan(root: Path) -> dict[str,Any]:
    rels=["risu_e2/frontend_js_v3.py","risu_e2/ir_v3.py"]
    forbidden=("V3B","V3M","V2B","V2M","CQ_","JS_CALL_RESERVED_KEYWORD_PARENTHESIS_FALSE_POSITIVE","JS_OBJECT_SHORTHAND_RHS_IDENTIFIER_FALSE_POSITIVE")
    hits=[]
    for rel in rels:
        text=(root/rel).read_text()
        for word in forbidden:
            if word in text: hits.append([rel,"literal",word])
        tree=ast.parse(text)
        for n in ast.walk(tree):
            if isinstance(n,ast.Compare):
                t=(ast.get_source_segment(text,n) or "").lower()
                if ("sha256" in t or "source_sha" in t) and any(isinstance(o,(ast.Eq,ast.NotEq,ast.In,ast.NotIn)) for o in n.ops):
                    hits.append([rel,"hash_compare",t[:180]])
    return {"status":"PASS" if not hits else "FAIL","hits":hits}


def main() -> int:
    p=argparse.ArgumentParser()
    p.add_argument("--protocol",required=True); p.add_argument("--corpus",required=True); p.add_argument("--scientific-root",required=True); p.add_argument("--output",required=True)
    a=p.parse_args()
    protocol=json.loads(Path(a.protocol).read_text()); corpus=json.loads(Path(a.corpus).read_text())
    rows=[]
    for c in corpus["cases"]:
        src=str(c["source"]); parsed=js3.extract(src); facts=list(parsed.get("facts",[])); bad=[]
        if parsed.get("status")!="PASS": bad.append(f"frontend:{parsed.get('status')}:{parsed.get('error')}")
        bad.extend(check(c,facts))
        rows.append({"fixture_id":str(c["fixture_id"]),"variant_of":c.get("variant_of"),"obligation_ids":list(c.get("obligation_ids",[])),
                     "source_sha256":h(src.encode()),"parser":parsed.get("parser"),"abstract_signature":sig(src,facts),"passed":not bad,"errors":bad})
    idx={r["fixture_id"]:r for r in rows}; variant_bad=[]
    for base,var in corpus["metamorphic_contract"]["explicit_variant_pairs"]:
        if base not in idx or var not in idx or idx[base]["abstract_signature"]!=idx[var]["abstract_signature"]:
            variant_bad.append([base,var])
    sp=scan(Path(a.scientific_root))
    ok=len(rows)==24 and sum(r["passed"] for r in rows)==24 and not variant_bad and sp["status"]=="PASS"
    doc={"schema":SCHEMA,"status":"PASS" if ok else "FAIL","case_count":len(rows),"passed_case_count":sum(r["passed"] for r in rows),
         "failed_fixture_ids":[r["fixture_id"] for r in rows if not r["passed"]],"variant_pair_failures":variant_bad,"specialization_scan":sp,
         "protocol_schema":protocol.get("schema"),"corpus_schema":corpus.get("schema"),
         "independence_attestation":{"primary_checker_imported":False,"primary_output_read":False,"expectations_recomputed_from_frozen_source":True},
         "read_set_attestation":{"frozen_48_bytes":False,"candidate_58_bytes":False,"fresh_target_bytes":False},
         "semantic_verdicts_emitted":False,"rows":rows}
    raw=enc(doc); Path(a.output).write_bytes(raw)
    print(json.dumps({"status":doc["status"],"cases":len(rows),"passed":doc["passed_case_count"],"failed":doc["failed_fixture_ids"],"variant_failures":variant_bad,"sha256":h(raw),"bytes":len(raw)},sort_keys=True,separators=(",",":")))
    return 0


if __name__=="__main__":
    raise SystemExit(main())
