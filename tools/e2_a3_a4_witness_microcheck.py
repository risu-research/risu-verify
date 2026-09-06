#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json
from pathlib import Path

LANGS=("python","go","typescript_javascript")
IDENTITY={"comparison_result_to_return","function_return_to_call_result","call_result_to_assignment","call_argument_to_parameter","control_predicate_result_consumption"}

def cb(x): return (json.dumps(x,sort_keys=True,separators=(",",":"),ensure_ascii=False)+"\n").encode()
def sha(b): return hashlib.sha256(b).hexdigest()
def fsha(p): return sha(Path(p).read_bytes())
def digest(x): return sha(cb(x))

def classify(v):
    if v["transport"]!="COMPLETE": return "ASSURANCE_INCOMPLETE"
    if not v["anchors_ok"] or not v["effect_unique"] or not v["control_complete"]: return "ASSURANCE_INCOMPLETE"
    if v["guard_form"]=="HELPER_CONTROL" and any(x not in IDENTITY for x in v["helper"]): return "ASSURANCE_INCOMPLETE"
    w=False
    if v["bindings"]!={"expected":"expected","current":"current"}: w=True
    for p in v["entry_effect_paths"]:
        if "EFFECT" in p and ("GUARD" not in p or p.index("EFFECT")<p.index("GUARD")): w=True
    rp="true" if v["rejection_polarity"] else "false"; ep="true" if v["effect_polarity"] else "false"; r=v["branches"][rp]; e=v["branches"][ep]
    if "EFFECT" in r and ("REJECTION" not in r or r.index("EFFECT")<r.index("REJECTION")): w=True
    if "EFFECT" in r and "REJECTION" in e and "EFFECT" not in e: w=True
    if w: return "REGRESSION_WITNESS"
    ok=v["universal_dataflow"] and v["outcomes_distinct"] and v["provenance_complete"] and all("GUARD" in p and p.index("GUARD")<p.index("EFFECT") for p in v["entry_effect_paths"] if "EFFECT" in p) and "EFFECT" in e and "SUCCESS" in e and e.index("EFFECT")<e.index("SUCCESS") and "REJECTION" in r and "EFFECT" not in r
    return "PRESERVATION_EVIDENCE" if ok else "ASSURANCE_INCOMPLETE"

def shape(fx):
    f=fx["family_id"]; p=fx["primary_view"]; c=fx["checker_view"]
    if f=="VQ_DIRECT_STABLE": assert p["guard_form"]=="DIRECT_CONTROL"
    elif f=="VQ_HELPER_STABLE_IDENTITY": assert p["guard_form"]=="HELPER_CONTROL" and set(p["helper"])<=IDENTITY
    elif f=="VQ_HELPER_NEGATED": assert "logical_negation" in p["helper"]
    elif f=="VQ_WRONG_BINDING": assert p["bindings"]["expected"]=="current" and not p["definite_overwrite"]
    elif f=="VQ_DEFINITE_OVERWRITE": assert p["definite_overwrite"] and p["bindings"]["expected"]=="other"
    elif f=="VQ_GUARD_BYPASS": assert any("EFFECT" in x and "GUARD" not in x for x in p["entry_effect_paths"])
    elif f=="VQ_EFFECT_BEFORE_GUARD": assert any("EFFECT" in x and "GUARD" in x and x.index("EFFECT")<x.index("GUARD") for x in p["entry_effect_paths"])
    elif f=="VQ_REJECTION_FALLBACK": assert p["branches"]["true"].index("EFFECT")<p["branches"]["true"].index("REJECTION")
    elif f=="VQ_POLARITY_INVERSION": assert "REJECTION" in p["branches"]["false"] and "EFFECT" in p["branches"]["true"]
    elif f=="VQ_TRANSPORT_AMBIGUOUS": assert p["transport"]=="INCOMPLETE" and "AMBIGUOUS" in p["transport_reason"]
    elif f=="VQ_CONTROL_INCOMPLETE": assert p["control_complete"] is False
    elif f=="VQ_ANCHOR_DELETED_NO_REPLACEMENT_PROOF": assert p["transport"]=="INCOMPLETE" and p["anchors_ok"] is False
    elif f=="VQ_PRESERVING_WRAPPER_REFACTOR": assert p["wrapper_depth"]>0 and set(p["helper"])<=IDENTITY
    elif f=="VQ_CHECKER_DISAGREEMENT": assert p["control_complete"] is True and c["control_complete"] is False
    else: raise AssertionError(f)

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--prereg",required=True); ap.add_argument("--bundle",required=True); ap.add_argument("--primary",required=True); ap.add_argument("--receipt",required=True); a=ap.parse_args()
    pre=json.load(open(a.prereg)); b=json.load(open(a.bundle)); p=json.load(open(a.primary)); errs=[]
    expected={x["id"]:x["expected"] for x in pre["preimplementation_witness_microqualification"]["required_fixture_families"]}
    pmap={x["case_id"]:x for x in p["rows"]}; rows=[]; ids=set()
    if len(expected)!=14 or b.get("case_count")!=42: errs.append("AUTHORITY_COUNT")
    for fx in b.get("cases",[]):
        try:
            core=dict(fx); d=core.pop("fixture_digest_sha256"); assert d==digest(core); assert fx["language"] in LANGS; shape(fx)
        except Exception as e:
            errs.append("FIXTURE:"+fx.get("case_id","?")+":"+type(e).__name__); continue
        ids.add(fx["case_id"]); po=classify(fx["primary_view"]); co=classify(fx["checker_view"]); final=po if po==co else "ASSURANCE_INCOMPLETE"
        if pmap.get(fx["case_id"],{}).get("primary_outcome")!=po: errs.append("PRIMARY_RECOMPUTE:"+fx["case_id"])
        if final!=fx["expected"] or final!=expected[fx["family_id"]]: errs.append("EXPECTED:"+fx["case_id"])
        if fx["family_id"]=="VQ_CHECKER_DISAGREEMENT" and po==co: errs.append("DISAGREEMENT_MISSING:"+fx["case_id"])
        if fx["family_id"]!="VQ_CHECKER_DISAGREEMENT" and po!=co: errs.append("UNEXPECTED_DISAGREEMENT:"+fx["case_id"])
        rows.append({"case_id":fx["case_id"],"family_id":fx["family_id"],"language":fx["language"],"primary_outcome":po,"checker_outcome":co,"composed_outcome":final})
    if len(ids)!=42: errs.append("UNIQUE_CASE_IDS")
    for f in expected:
        if sum(r["family_id"]==f for r in rows)!=3: errs.append("LANGUAGE_COVERAGE:"+f)
    rec={"schema":"risu.e2-a3-a4-witness-microqualification-independent/v0.1","status":"PASS" if not errs else "FAIL","errors":errs,"family_count":14,"case_count":42,"bundle_sha256":fsha(a.bundle),"primary_receipt_sha256":fsha(a.primary),"rows":rows,"firewall":{"primary_module_imported":False,"candidate_or_mutant_bytes_read":False,"mutation_truth_read":False,"operator_metadata_read":False,"fresh_target_bytes_read":False,"58_case_a3_a4_predictions_emitted":False}}
    Path(a.receipt).write_bytes(cb(rec)); print(json.dumps({"status":rec["status"],"errors":errs,"case_count":42},sort_keys=True,separators=(",",":"))); raise SystemExit(0 if not errs else 1)
if __name__=="__main__": main()
