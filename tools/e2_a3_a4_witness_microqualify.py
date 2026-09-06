#!/usr/bin/env python3
from __future__ import annotations
import argparse, copy, hashlib, json
from pathlib import Path

SIG_SHA="7a652a508d53960dc0fcdb8860b9d358165f6a6c96b050e6b962edccc2a4549f"
LANGS=("python","go","typescript_javascript")
IDENTITY={"comparison_result_to_return","function_return_to_call_result","call_result_to_assignment","call_argument_to_parameter","control_predicate_result_consumption"}

def cb(x): return (json.dumps(x,sort_keys=True,separators=(",",":"),ensure_ascii=False)+"\n").encode()
def sha(b): return hashlib.sha256(b).hexdigest()
def fsha(p): return sha(Path(p).read_bytes())
def digest(x): return sha(cb(x))

def stable(form="DIRECT_CONTROL"):
    return {"transport":"COMPLETE","transport_reason":None,"anchors_ok":True,"control_complete":True,"effect_unique":True,"guard_form":form,"helper":[] if form=="DIRECT_CONTROL" else ["comparison_result_to_return","function_return_to_call_result","control_predicate_result_consumption"],"bindings":{"expected":"expected","current":"current"},"definite_overwrite":False,"entry_effect_paths":[["ENTRY","GUARD","EFFECT","SUCCESS"]],"branches":{"false":["GUARD","EFFECT","SUCCESS"],"true":["GUARD","REJECTION"]},"effect_polarity":False,"rejection_polarity":True,"universal_dataflow":True,"outcomes_distinct":True,"provenance_complete":True,"wrapper_depth":0}

def views(fid):
    v=stable()
    if fid=="VQ_HELPER_STABLE_IDENTITY": v=stable("HELPER_CONTROL")
    elif fid=="VQ_HELPER_NEGATED": v=stable("HELPER_CONTROL"); v["helper"].insert(1,"logical_negation")
    elif fid=="VQ_WRONG_BINDING": v["bindings"]["expected"]="current"
    elif fid=="VQ_DEFINITE_OVERWRITE": v["bindings"]["expected"]="other"; v["definite_overwrite"]=True
    elif fid=="VQ_GUARD_BYPASS": v["entry_effect_paths"]=[["ENTRY","EFFECT","SUCCESS"]]
    elif fid=="VQ_EFFECT_BEFORE_GUARD": v["entry_effect_paths"]=[["ENTRY","EFFECT","GUARD","SUCCESS"]]
    elif fid=="VQ_REJECTION_FALLBACK": v["branches"]["true"]=["GUARD","EFFECT","REJECTION"]
    elif fid=="VQ_POLARITY_INVERSION": v["branches"]={"false":["GUARD","REJECTION"],"true":["GUARD","EFFECT","SUCCESS"]}
    elif fid=="VQ_TRANSPORT_AMBIGUOUS": v["transport"]="INCOMPLETE"; v["transport_reason"]="TRANSPORT_AMBIGUOUS_MULTIPLE_CANDIDATES"
    elif fid=="VQ_CONTROL_INCOMPLETE": v["control_complete"]=False
    elif fid=="VQ_ANCHOR_DELETED_NO_REPLACEMENT_PROOF": v["transport"]="INCOMPLETE"; v["transport_reason"]="ANCHOR_ABSENT_BY_EDIT_LINEAGE_NO_SEPARATE_VIOLATION_PROOF"; v["anchors_ok"]=False
    elif fid=="VQ_PRESERVING_WRAPPER_REFACTOR": v=stable("HELPER_CONTROL"); v["wrapper_depth"]=4; v["helper"]=["call_argument_to_parameter","comparison_result_to_return","function_return_to_call_result","call_result_to_assignment","control_predicate_result_consumption"]
    elif fid=="VQ_CHECKER_DISAGREEMENT": c=copy.deepcopy(v); c["control_complete"]=False; return v,c
    elif fid!="VQ_DIRECT_STABLE": raise ValueError(fid)
    return v,copy.deepcopy(v)

def classify(v):
    if v["transport"]!="COMPLETE": return "ASSURANCE_INCOMPLETE",[v["transport_reason"]],[]
    if not v["anchors_ok"]: return "ASSURANCE_INCOMPLETE",["ANCHOR_ROLE_INCOMPATIBLE"],[]
    if not v["effect_unique"]: return "ASSURANCE_INCOMPLETE",["EFFECT_INVOCATION_UNRESOLVED"],[]
    if not v["control_complete"]: return "ASSURANCE_INCOMPLETE",["CONTROL_INCOMPLETE"],[]
    if v["guard_form"]=="HELPER_CONTROL" and any(x not in IDENTITY for x in v["helper"]): return "ASSURANCE_INCOMPLETE",["HELPER_PREDICATE_POLARITY_UNPROVEN"],[]
    w=[]
    if v["bindings"]!={"expected":"expected","current":"current"}: w.append("A3_R2_DEFINITE_OVERWRITE_TO_WRONG_CARRIER" if v["definite_overwrite"] else "A3_R1_WRONG_BINDING_IDENTITY")
    for p in v["entry_effect_paths"]:
        if "EFFECT" not in p: continue
        if "GUARD" not in p: w.append("A4_R1_GUARD_BYPASS")
        elif p.index("EFFECT")<p.index("GUARD"): w.append("A4_R2_EFFECT_BEFORE_GUARD")
    rp="true" if v["rejection_polarity"] else "false"; ep="true" if v["effect_polarity"] else "false"
    r=v["branches"][rp]; e=v["branches"][ep]
    if "EFFECT" in r and ("REJECTION" not in r or r.index("EFFECT")<r.index("REJECTION")): w.append("A4_R3_REJECTION_BRANCH_REACHES_EFFECT")
    if "EFFECT" in r and "EFFECT" in e: w.append("A4_R4_EFFECT_ON_BOTH_POLARITIES")
    if "EFFECT" in r and "REJECTION" in e and "EFFECT" not in e: w.append("A4_R5_POLARITY_INVERSION")
    w=sorted(set(w))
    if w: return "REGRESSION_WITNESS",[],w
    ok=v["universal_dataflow"] and v["outcomes_distinct"] and v["provenance_complete"] and all("GUARD" in p and p.index("GUARD")<p.index("EFFECT") for p in v["entry_effect_paths"] if "EFFECT" in p) and "EFFECT" in e and "SUCCESS" in e and e.index("EFFECT")<e.index("SUCCESS") and "REJECTION" in r and "EFFECT" not in r
    return ("PRESERVATION_EVIDENCE",[],[f"A3_P{i}" for i in range(1,6)]+[f"A4_P{i}" for i in range(1,8)]) if ok else ("ASSURANCE_INCOMPLETE",["UNPROVEN_PRESERVATION_OBLIGATION"],[])

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--prereg",required=True); ap.add_argument("--signatures",required=True); ap.add_argument("--bundle",required=True); ap.add_argument("--receipt",required=True); a=ap.parse_args()
    if fsha(a.signatures)!=SIG_SHA: raise SystemExit("signature sha mismatch")
    pre=json.load(open(a.prereg)); sig=json.load(open(a.signatures))
    if sig.get("seed_count")!=6 or sig.get("semantic_authority") is not False: raise SystemExit("signature authority malformed")
    fams=pre["preimplementation_witness_microqualification"]["required_fixture_families"]
    if len(fams)!=14 or len({x["id"] for x in fams})!=14: raise SystemExit("fixture authority malformed")
    cases=[]; rows=[]
    for f in fams:
        for lang in LANGS:
            p,c=views(f["id"]); cid=f["id"]+"::"+lang
            fx={"case_id":cid,"family_id":f["id"],"language":lang,"expected":f["expected"],"shape":f["shape"],"syntax_support":"REPRESENTABLE","primary_view":p,"checker_view":c}
            fx["fixture_digest_sha256"]=digest(fx); cases.append(fx)
            out,reasons,proof=classify(p)
            pass_pre=(out=="PRESERVATION_EVIDENCE") if f["id"]=="VQ_CHECKER_DISAGREEMENT" else (out==f["expected"])
            rows.append({"case_id":cid,"family_id":f["id"],"language":lang,"primary_outcome":out,"reason_codes":reasons,"proof_items":proof,"prechecker_pass":pass_pre})
    bundle={"schema":"risu.e2-a3-a4-witness-microfixture-bundle/v0.1","family_count":14,"language_count":3,"case_count":42,"semantic_authority":False,"canonical_signature_sha256":SIG_SHA,"cases":cases,"firewall":{"candidate_or_mutant_bytes_read":False,"mutation_truth_read":False,"operator_metadata_read":False,"fresh_target_bytes_read":False,"58_case_a3_a4_predictions_emitted":False}}
    bundle["bundle_digest_sha256"]=digest(bundle); Path(a.bundle).write_bytes(cb(bundle))
    rec={"schema":"risu.e2-a3-a4-witness-microqualification-primary/v0.1","status":"PASS" if all(x["prechecker_pass"] for x in rows) else "FAIL","case_count":42,"family_count":14,"bundle_sha256":fsha(a.bundle),"bundle_digest_sha256":bundle["bundle_digest_sha256"],"rows":rows,"firewall":bundle["firewall"]}
    Path(a.receipt).write_bytes(cb(rec)); print(json.dumps({"status":rec["status"],"case_count":42},sort_keys=True,separators=(",",":"))); raise SystemExit(0 if rec["status"]=="PASS" else 1)
if __name__=="__main__": main()
