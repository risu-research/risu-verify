#!/usr/bin/env python3
from __future__ import annotations
import argparse,json
from pathlib import Path
from typing import Any,Mapping
P="DEFINITIVE_PRESERVATION"; R="DEFINITIVE_REGRESSION"; I="INCOMPLETE"; EI="EVALUATION_INVALID"
TP="TRUTH_PRESERVATION"; TR="TRUTH_REGRESSION"; TI="TRUTH_EPISTEMICALLY_INSUFFICIENT"
def cb(v:Any)->bytes:return (json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=False)+"\n").encode()
def rj(p:Path)->Any:return json.loads(p.read_bytes())
def rat(n,d):return {"numerator":n,"denominator":d,"value":None if d==0 else n/d}
def de(x):return x in {P,R}
def ok(p,t):return (p==P and t==TP) or (p==R and t==TR) or (p==I and t==TI)
def comp(outputs,rows,invalid):
    ids=[];bad=[];v={}
    for u in sorted(rows):
      x=outputs.get(u,"INAPPLICABLE")
      if x=="INAPPLICABLE":continue
      if x==invalid:bad.append(u);continue
      ids.append(u);v[u]=x
    d=sum(de(v[u]) for u in ids); treg=sum(rows[u]["truth"]["outcome"]==TR for u in ids)
    pp=sum(v[u]==P for u in ids);pr=sum(v[u]==R for u in ids)
    cr=sum(v[u]==R and rows[u]["truth"]["outcome"]==TR for u in ids)
    cp=sum(v[u]==P and rows[u]["truth"]["outcome"]==TP for u in ids)
    return {"applicable_count":len(ids),"invalid_count":len(bad),
      "definitive_coverage_on_applicable":rat(d,len(ids)),
      "exact_outcome_accuracy_on_applicable":rat(sum(ok(v[u],rows[u]["truth"]["outcome"]) for u in ids),len(ids)),
      "unsafe_false_stability_count":sum(v[u]==P and rows[u]["truth"]["outcome"]==TR for u in ids),
      "false_regression_count":sum(v[u]==R and rows[u]["truth"]["outcome"]==TP for u in ids),
      "regression_recall":rat(cr,treg),"preservation_precision":rat(cp,pp),"regression_precision":rat(cr,pr),
      "applicable_unit_ids":ids,"invalid_unit_ids":bad}
EXPECTED_BASELINES={"B0_STRUCTURAL_SCHEMA_DIFF","B1_AST_SYNTACTIC_DATAFLOW","B2_STRONG_STATIC_DATAFLOW","B3A_GPT56_SOL_FRONTIER","B3B_CLAUDE_OPUS45_DATED","B4_EXECUTION_ONLY_DIFFERENTIAL"}
EXPECTED_ABLATIONS={"A1_PRIMARY_ONLY_NO_C1_PROMOTION_GATE","A2_C1_WITHOUT_AUTHORITY_SIDECARS","A3_C1_WITHOUT_CROSS_REPRESENTATION_EVIDENCE"}
def recompute(doc:Mapping[str,Any])->dict[str,Any]:
    raw=list(doc.get("units",[]) or []); rows={}
    dup=False
    for x in raw:
      u=str(x.get("unit_id",""))
      if not u or u in rows:
       dup=True
       if not u:u="__EMPTY_UNIT_ID_"+str(len(rows))
       if u in rows:continue
      rows[u]=x
    ordered=[rows[u] for u in sorted(rows)]
    integ=dict(doc.get("integrity",{}) or {}); failures=[]
    z=["early_truth_read_count","heldout_replacement_count","heldout_drop_count","duplicate_unit_count","raw_source_log_exposure_count","full_system_dual_replay_mismatch_count","evaluator_dual_replay_mismatch_count","semantic_snapshot_identity_mismatch_count","post_freeze_metric_definition_change_count","post_freeze_support_boundary_change_count"]
    if len(ordered)!=10:failures.append("HELDOUT_UNIT_COUNT")
    if dup:failures.append("DUPLICATE_UNIT")
    for k in z:
      if int(integ.get(k,0) or 0)!=0:failures.append(k)
    for x in ordered:
      u=str(x.get("unit_id"))
      if x.get("truth",{}).get("admissible") is not True or x.get("truth",{}).get("outcome") not in {TP,TR,TI}:failures.append("GOLD_INVALID:"+u)
      if x.get("system",{}).get("outcome")==EI:failures.append("FULL_SYSTEM_EVALUATION_INVALID:"+u)
    unsafe=sum(x["system"]["outcome"]==P and x["truth"]["outcome"]==TR for x in ordered)
    unsupported=sum(de(x["system"]["outcome"]) and x.get("support_eligible") is not True for x in ordered)
    unresolved=sum(de(x["system"]["outcome"]) and x["system"].get("authority_status") in {"UNRESOLVED","AMBIGUOUS"} for x in ordered)
    disag=sum(de(x["system"]["outcome"]) and x["system"].get("checker_agreement") is not True for x in ordered)
    badc=sum(de(x["system"]["outcome"]) and not(x["system"].get("c1_checker_output")=="VALID_C1" and x["system"].get("assurance_level")=="C1_INDEPENDENT_SOURCE_EVIDENCE") for x in ordered)
    epi=sum(de(x["system"]["outcome"]) and x["truth"]["outcome"]==TI for x in ordered)
    mono=0
    for e in list(doc.get("information_removal_edges",[]) or []):
      pa=str(e.get("parent_unit_id",""));ch=str(e.get("child_unit_id",""))
      if pa not in rows or ch not in rows:
       failures.append("UNKNOWN_INFORMATION_REMOVAL_EDGE");continue
      a=rows[pa]["system"]["outcome"];b=rows[ch]["system"]["outcome"]
      mono+=int((1 if de(b) else 0)>(1 if de(a) else 0))
    hard={"unsafe_false_stability":unsafe,"unsupported_definitive_promotion":unsupported,"ambiguous_or_unresolved_authority_definitive_promotion":unresolved,"checker_disagreement_definitive_promotion":disag,"invalid_certificate_definitive_promotion":badc,"epistemic_overclaim":epi,"information_removal_monotonicity_violation":mono}
    n=len(ordered);dec=sum(x["truth"]["outcome"] in {TP,TR} for x in ordered); trn=sum(x["truth"]["outcome"]==TR for x in ordered); tpn=sum(x["truth"]["outcome"]==TP for x in ordered); tin=sum(x["truth"]["outcome"]==TI for x in ordered)
    dn=sum(de(x["system"]["outcome"]) for x in ordered); inn=sum(x["system"]["outcome"]==I for x in ordered)
    pp=sum(x["system"]["outcome"]==P for x in ordered);pr=sum(x["system"]["outcome"]==R for x in ordered)
    cd=sum(de(x["system"]["outcome"]) and ok(x["system"]["outcome"],x["truth"]["outcome"]) for x in ordered)
    cr=sum(x["system"]["outcome"]==R and x["truth"]["outcome"]==TR for x in ordered);cp=sum(x["system"]["outcome"]==P and x["truth"]["outcome"]==TP for x in ordered)
    ia=sum(x["system"]["outcome"]==I and x["truth"]["outcome"]==TI for x in ordered)
    util={"definitive_coverage":rat(dn,n),"incomplete_rate":rat(inn,n),"exact_outcome_accuracy":rat(sum(ok(x["system"]["outcome"],x["truth"]["outcome"]) for x in ordered),n),"decidable_definitive_coverage":rat(sum(de(x["system"]["outcome"]) and x["truth"]["outcome"] in {TP,TR} for x in ordered),dec),"definitive_accuracy_on_decidable_truth":rat(cd,sum(de(x["system"]["outcome"]) and x["truth"]["outcome"] in {TP,TR} for x in ordered)),"regression_recall":rat(cr,trn),"preservation_recall":rat(cp,tpn),"preservation_precision":rat(cp,pp),"regression_precision":rat(cr,pr),"false_regression_count":sum(x["system"]["outcome"]==R and x["truth"]["outcome"]==TP for x in ordered),"epistemic_abstention_recall":rat(ia,tin),"provenance_completeness":rat(sum(x["system"].get("provenance_complete") is True for x in ordered),n)}
    strata={"truth_decidable_count":dec,"truth_regression_count":trn,"truth_preservation_count":tpn,"truth_epistemically_insufficient_count":tin}
    bs={}
    bdocs=(doc.get("baselines",{}) or {})
    if set(bdocs)!=EXPECTED_BASELINES:failures.append("BASELINE_REGISTRY_SET_MISMATCH")
    for bid,b in sorted(bdocs.items()):
      m=comp(b.get("unit_outputs",{}) or {},rows,"BASELINE_INVALID")
      if m["invalid_count"]:failures.append("BASELINE_EXECUTION_INVALID:"+bid)
      bs[bid]=m
    ab={}
    adocs=(doc.get("ablations",{}) or {})
    if set(adocs)!=EXPECTED_ABLATIONS:failures.append("ABLATION_REGISTRY_SET_MISMATCH")
    for aid,a in sorted(adocs.items()):
      m=comp(a.get("unit_outputs",{}) or {},rows,"ABLATION_INVALID")
      if m["invalid_count"]:failures.append("ABLATION_EXECUTION_INVALID:"+aid)
      ab[aid]=m
    if (doc.get("claim_flags",{}) or {}).get("forbidden_population_claim") is True:failures.append("FORBIDDEN_POPULATION_CLAIM")
    hn={k:v for k,v in hard.items() if v}
    sp=dec>0 and tin>0; nt=(not failures and not hn and sp and cd>=1 and ia>=1)
    if failures:cl="FAIL_EVALUATION_INTEGRITY"
    elif hn:cl="FAIL_HARD_SAFETY"
    elif not sp:cl="PASS_HARD_SAFETY_NONTRIVIALITY_UNTESTABLE"
    elif nt:cl="PASS_NONTRIVIAL_SELECTIVE_SAFETY"
    else:cl="PASS_HARD_SAFETY_ONLY"
    return {"schema":"risu.e2-gate2d-evaluation-result/v0.1","classification":cl,"integrity":{"status":"PASS" if not failures else "FAIL","failures":sorted(set(failures))},"system":{"hard_safety":hard,"utility":util,"strata":strata},"baselines":bs,"ablations":ab,"nontrivial_selectivity":{"strata_present":sp,"demonstrated":nt},"claim_boundaries":{"population_generalization_authorized":False,"p_value_authorized":False,"confidence_interval_authorized":False}}
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--input",required=True);ap.add_argument("--result",required=True);ap.add_argument("--output",required=True);a=ap.parse_args()
 doc=rj(Path(a.input));got=rj(Path(a.result));exp=recompute(doc);passed=(got==exp)
 out={"schema":"risu.e2-gate2d-evaluation-independent-check/v0.1","status":"PASS" if passed else "FAIL","exact_result_match":passed,"checker_imports_evaluator":False,"classification":exp["classification"]}
 Path(a.output).write_bytes(cb(out));print(json.dumps(out,sort_keys=True,separators=(",",":")))
 if not passed:raise SystemExit(2)
if __name__=="__main__":main()
