#!/usr/bin/env python3
from __future__ import annotations

"""Gate 2B.3 guard-scope provenance attribution (stdlib only).

No RISU semantic/kernel/adapter/C1 code is imported or executed. Real mode is
restricted to the frozen Gate2B2 ledger plus exact manifest-bound overlay/path
members selected by opaque case id. Synthetic qualification lives in the
separate frozen self-test harness.
"""
import argparse, hashlib, json, re
from collections import Counter
from pathlib import Path
from typing import Any, Mapping

PROTOCOL_SCHEMA="risu.e2-candidate58-gate2b3-guard-scope-provenance-attribution-protocol/v0.1"
LEDGER_SCHEMA="risu.e2-candidate58-gate2b2-closure-provenance-ledger/v0.1"
OVERLAY_SCHEMA="risu.e2-observability-overlay/v0.1"
PATH_SCHEMAS={"risu.e2-path-observability/v0.1","risu.e2-path-observability/v0.2"}
EXPECTED_CASE_COUNT=39
EXPECTED_GATE2B2_LEDGER_SHA256="da53c72af39adba927b56fbeaf52922245bb503f8b6b5a14c45ce157fed5e2a2"
EXPECTED_BUNDLE_MANIFEST_SHA256="c5030f084936c186b1d320b02ad8bf1e1648bbc9e97ad78b33db81fb9a6bd217"
EXPECTED_BUNDLE_FILE_COUNT=946
HEX64=re.compile(r"^[0-9a-f]{64}$")
ALLOWED_HELPER_DERIVATIONS={"comparison_result_to_return","function_return_to_call_result","call_result_to_assignment","call_result"}
TAXONOMY=(
 "TRACE_EVIDENCE_INCOMPLETE",
 "FROZEN_CHAIN_INCONSISTENT",
 "ANCHOR_IDENTITY_OR_EFFECTIVE_GUARD_ASSOCIATION_UNRESOLVED",
 "UPSTREAM_STRUCTURED_SCOPE_UNRESOLVED_OR_AMBIGUOUS",
 "GUARD_SCOPE_CARRIER_SURVIVAL_FAILURE",
 "ATTRIBUTION_INCOMPLETE_NO_CAUSAL_CLAIM",
)

def cbytes(v:Any)->bytes:return (json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=False)+"\n").encode()
def sha(raw:bytes)->str:return hashlib.sha256(raw).hexdigest()
def shafile(p:Path)->str:return sha(p.read_bytes())
def load(p:Path)->Any:return json.loads(p.read_text(encoding="utf-8"))
def write(p:Path,v:Any)->str:
 raw=cbytes(v);p.write_bytes(raw);return sha(raw)
def valid_id(x:str)->bool:return bool(HEX64.fullmatch(x))
def rows(x:Any)->list[Mapping[str,Any]]:return [r for r in x if isinstance(r,Mapping)] if isinstance(x,list) else []

def _bound(root:Path,manifest:Mapping[str,Any],rel:str)->tuple[bool,Mapping[str,Any],str|None]:
 ms=[r for r in rows(manifest.get("files",[])) if r.get("path")==rel]
 if len(ms)!=1 or not isinstance(ms[0].get("sha256"),str) or not valid_id(ms[0]["sha256"]):return False,{},None
 p=root/rel
 try:
  rr=root.resolve(strict=True); rp=p.resolve(strict=True)
  if rp!=rr and rr not in rp.parents:return False,{},None
  raw=rp.read_bytes()
 except (OSError,RuntimeError):return False,{},None
 actual=sha(raw)
 if actual!=ms[0]["sha256"]:return False,{},actual
 try:o=json.loads(raw.decode())
 except (UnicodeDecodeError,json.JSONDecodeError):return False,{},actual
 return isinstance(o,Mapping),o if isinstance(o,Mapping) else {},actual

def _nodes(o:Mapping[str,Any])->list[Mapping[str,Any]]:return rows(o.get("nodes",[]))
def _edges(o:Mapping[str,Any])->list[Mapping[str,Any]]:return rows(o.get("edges",[]))
def _branch(o:Mapping[str,Any],gid:str)->bool:
 ps=set()
 for e in _edges(o):
  if e.get("kind")=="GUARDS" and e.get("source")==gid:
   a=e.get("attrs",{}); p=a.get("branch_polarity") if isinstance(a,Mapping) else None
   if isinstance(p,bool):ps.add(p)
 return ps=={True,False}
def _anchor(o:Mapping[str,Any])->tuple[bool,Mapping[str,Any]|None]:
 a=[n for n in _nodes(o) if isinstance(n.get("attrs",{}),Mapping) and n["attrs"].get("anchor_role")=="GUARD_COMPARISON"]
 return len(a)==1,a[0] if len(a)==1 else None
def _scope_absent(a:Mapping[str,Any]|None)->bool:
 if a is None:return False
 x=a.get("attrs",{}); s=x.get("scope") if isinstance(x,Mapping) else None
 return s is None or s==""

def _helper_consumers(o:Mapping[str,Any],start:str)->tuple[set[str],bool]:
 es=_edges(o); out:dict[str,list[Mapping[str,Any]]]={}
 for e in es:
  if isinstance(e.get("source"),str):out.setdefault(e["source"],[]).append(e)
 seen={start}; stack=[start]; consumers:set[str]=set(); bad=False
 while stack:
  cur=stack.pop()
  for e in out.get(cur,[]):
   kind=e.get("kind"); a=e.get("attrs",{}); a=a if isinstance(a,Mapping) else {}; t=e.get("target")
   if not isinstance(t,str) or not t:continue
   if kind=="DERIVES":
    d=a.get("derivation")
    if d and d not in ALLOWED_HELPER_DERIVATIONS:bad=True;continue
    if t not in seen:seen.add(t);stack.append(t)
   elif kind=="BINDS_TO" and a.get("binding")=="call_argument_to_parameter" and t not in seen:seen.add(t);stack.append(t)
  for e in es:
   t=e.get("target")
   if e.get("kind")=="COMPARES" and e.get("source")==cur and isinstance(t,str) and _branch(o,t):consumers.add(t)
 return consumers,bad

def _effective(o:Mapping[str,Any],p:Mapping[str,Any],aid:str|None)->tuple[bool,str|None,str|None]:
 e=p.get("effective_guard_observability",{}); e=e if isinstance(e,Mapping) else {}
 form=e.get("form") if isinstance(e.get("form"),str) else None; gid=e.get("guard_id") if isinstance(e.get("guard_id"),str) and e.get("guard_id") else None
 if not aid or not gid:return False,form,gid
 if form=="DIRECT_CONTROL":return gid==aid and _branch(o,aid),form,gid
 if form=="HELPER_CONTROL":
  cs,bad=_helper_consumers(o,aid);return len(cs)==1 and not bad and next(iter(cs))==gid,form,gid
 return False,form,gid

def _span(v:Any)->tuple[int,int,int,int]|None:
 return tuple(v) if isinstance(v,list) and len(v)==4 and all(isinstance(x,int) for x in v) else None

def _upstream(o:Mapping[str,Any],p:Mapping[str,Any],gid:str|None)->tuple[bool,list[str],list[list[int]],list[bool]]:
 if not gid:return False,[],[],[]
 ss=[]
 for s in rows(p.get("path_states",[])):
  t=s.get("transition",{});t=t if isinstance(t,Mapping) else {}
  if t.get("kind")=="STRUCTURED_BRANCH" and t.get("guard_id")==gid:ss.append(s)
 if not ss:return False,[],[],[]
 scopes=sorted({s["scope"] for s in ss if isinstance(s.get("scope"),str) and s.get("scope")})
 spans=sorted({_span(s.get("transition",{}).get("statement_span")) for s in ss if isinstance(s.get("transition",{}),Mapping)}-{None})
 pols={s.get("transition",{}).get("polarity") for s in ss if isinstance(s.get("transition",{}),Mapping)} & {True,False}
 if len(scopes)!=1 or len(spans)!=1 or pols!={True,False}:return False,scopes,[list(x) for x in spans],sorted(pols)
 sc=scopes[0]; pc=p.get("control_scope_completeness",{})
 if not isinstance(pc,Mapping) or pc.get(sc)!="COMPLETE" or p.get("material_control_complete") is not True:return False,scopes,[list(x) for x in spans],sorted(pols)
 matches=[r for r in rows(o.get("control_completeness",[])) if r.get("scope")==sc and r.get("status")=="COMPLETE"]
 return len(matches)==1,scopes,[list(x) for x in spans],sorted(pols)

def _deficit(r:Mapping[str,Any])->bool:
 return "GUARD_SCOPE_UNRESOLVED" in (r.get("primitive_atom_prefixes",[]) or []) and "F_UNRESOLVED:GUARD_SCOPE_UNRESOLVED" in (r.get("exact_F_admission_reasons",[]) or [])

def classify_case(r:Mapping[str,Any],manifest:Mapping[str,Any],root:Path)->dict[str,Any]:
 cid=str(r.get("case_id","")); orl=f"prepared/evidence/{cid}.overlay.json"; prl=f"prepared/evidence/{cid}.path.json"
 tc=valid_id(cid); oo:Mapping[str,Any]={}; pp:Mapping[str,Any]={}; osh=psh=None
 if tc:
  ok1,oo,osh=_bound(root,manifest,orl);ok2,pp,psh=_bound(root,manifest,prl);tc=ok1 and ok2
 if tc:tc=oo.get("schema")==OVERLAY_SCHEMA and pp.get("schema") in PATH_SCHEMAS and isinstance(oo.get("overlay_digest_sha256"),str) and pp.get("base_overlay_digest_sha256")==oo.get("overlay_digest_sha256")
 d=_deficit(r); au=False;a=None; aid=None; absent=False; eff=False; form=None; gid=None; up=False; scopes=[];spans=[];pols=[]; noamb=False
 if tc:
  au,a=_anchor(oo)
  if au and a is not None:
   aid=a.get("id") if isinstance(a.get("id"),str) and a.get("id") else None;absent=_scope_absent(a);eff,form,gid=_effective(oo,pp,aid)
   if eff:up,scopes,spans,pols=_upstream(oo,pp,gid);noamb=up and len(scopes)==1 and len(spans)==1
 carrier=d and tc and au and absent and eff and up and noamb
 if not tc:cls=TAXONOMY[0]
 elif not d or (au and not absent):cls=TAXONOMY[1]
 elif not au or not eff:cls=TAXONOMY[2]
 elif not up or not noamb:cls=TAXONOMY[3]
 elif carrier:cls=TAXONOMY[4]
 else:cls=TAXONOMY[5]
 return {"case_id":cid,"gate2b2_primitive_atom_prefixes":sorted(map(str,r.get("primitive_atom_prefixes",[]) or [])),"gate2b2_F_unresolved_atom_instances":sorted(map(str,r.get("F_unresolved_atom_instances",[]) or [])),"manifest_bound_overlay":{"path":orl,"sha256":osh},"manifest_bound_path_observability":{"path":prl,"sha256":psh},"anchored_guard_id":aid,"anchored_guard_scope_absent":absent,"effective_guard_form":form,"effective_guard_id":gid,"structured_branch_scope_values":scopes,"structured_branch_statement_spans":spans,"structured_branch_polarities":pols,"predicates":{"P_GATE2B2_SCOPE_DEFICIT":d,"P_TRACE_COMPLETE":tc,"P_ANCHORED_GUARD_EXISTS_UNIQUE":au,"P_ANCHORED_GUARD_SCOPE_ABSENT":absent,"P_EFFECTIVE_GUARD_ASSOCIATION_UNIQUE":eff,"P_UPSTREAM_STRUCTURED_SCOPE_UNIQUE":up,"P_NO_EARLIER_SCOPE_AMBIGUITY":noamb,"P_GUARD_SCOPE_CARRIER_SURVIVAL_FAILURE":carrier},"causal_taxonomy_id":cls}

def analyze_population(ledger:Mapping[str,Any],manifest:Mapping[str,Any],root:Path)->tuple[dict[str,Any],dict[str,Any]]:
 if ledger.get("schema")!=LEDGER_SCHEMA:raise ValueError("Gate2B2 ledger schema mismatch")
 rs=ledger.get("rows",[])
 if not isinstance(rs,list) or len(rs)!=39:raise ValueError("Gate2B3 population must be exact frozen 39")
 ids=[str(r.get("case_id","")) for r in rs if isinstance(r,Mapping)]
 if len(ids)!=39 or len(set(ids))!=39 or any(not valid_id(x) for x in ids):raise ValueError("Gate2B3 population case-id integrity failure")
 if any(not isinstance(r,Mapping) or not _deficit(r) for r in rs):raise ValueError("Gate2B3 selector integrity failure")
 out=[classify_case(r,manifest,root) for r in sorted(rs,key=lambda x:str(x["case_id"]))]; c=Counter(x["causal_taxonomy_id"] for x in out)
 summary={"schema":"risu.e2-candidate58-gate2b3-guard-scope-attribution-summary/v0.1","status":"GATE2B3_GUARD_SCOPE_ATTRIBUTION_PROFILE_NOT_COVERAGE_GAIN","case_count":39,"causal_taxonomy_counts":{k:c.get(k,0) for k in TAXONOMY},"trace_complete_count":sum(x["predicates"]["P_TRACE_COMPLETE"] for x in out),"unique_effective_guard_association_count":sum(x["predicates"]["P_EFFECTIVE_GUARD_ASSOCIATION_UNIQUE"] for x in out),"unique_upstream_structured_scope_count":sum(x["predicates"]["P_UPSTREAM_STRUCTURED_SCOPE_UNIQUE"] for x in out),"guard_scope_carrier_survival_failure_count":c[TAXONOMY[4]],"guard_scope_carrier_survival_failure_fraction":{"numerator":c[TAXONOMY[4]],"denominator":39},"interpretation_boundary":{"attribution_is_not_remediation_success":True,"definitive_coverage_gain_inferred":False,"cooccurring_gate2b2_deficits_collapsed":False,"truth_source_operator_inference_used":False}}
 return {"schema":"risu.e2-candidate58-gate2b3-guard-scope-attribution-ledger/v0.1","status":"GATE2B3_FROZEN_PREDICATE_ATTRIBUTION_NOT_REMEDIATION","case_count":39,"rows":out},summary

def validate_protocol(p:Mapping[str,Any])->None:
 if p.get("schema")!=PROTOCOL_SCHEMA:raise ValueError("Gate2B3 protocol schema mismatch")
 t=p.get("causal_taxonomy",{}); rr=t.get("first_match_order",[]) if isinstance(t,Mapping) else []
 ids=tuple(r.get("id") for r in rr if isinstance(r,Mapping)) if isinstance(rr,list) else ()
 if not isinstance(t,Mapping) or t.get("mutually_exclusive") is not True or ids!=TAXONOMY:raise ValueError("Gate2B3 taxonomy contract mismatch")

def main()->int:
 a=argparse.ArgumentParser();
 for n in ("protocol","gate2b2-ledger","bundle-content-manifest","evidence-root","output-dir"):a.add_argument("--"+n,type=Path,required=True)
 x=a.parse_args();validate_protocol(load(x.protocol))
 if shafile(x.gate2b2_ledger)!=EXPECTED_GATE2B2_LEDGER_SHA256:raise ValueError("Gate2B2 ledger SHA256 mismatch")
 if shafile(x.bundle_content_manifest)!=EXPECTED_BUNDLE_MANIFEST_SHA256:raise ValueError("bundle manifest SHA256 mismatch")
 l=load(x.gate2b2_ledger);m=load(x.bundle_content_manifest)
 if m.get("file_count")!=946 or len(m.get("files",[]) or [])!=946:raise ValueError("bundle manifest population mismatch")
 ol,os=analyze_population(l,m,x.evidence_root);x.output_dir.mkdir(parents=True,exist_ok=False);ls=write(x.output_dir/"E2_CANDIDATE58_GATE2B3_GUARD_SCOPE_ATTRIBUTION_LEDGER.json",ol);ss=write(x.output_dir/"E2_CANDIDATE58_GATE2B3_GUARD_SCOPE_ATTRIBUTION_SUMMARY.json",os)
 rec={"schema":"risu.e2-candidate58-gate2b3-diagnostic-receipt/v0.1","status":"FIRST_COMPLETE_GATE2B3_LOGICAL_OUTPUT","inputs":{"protocol_sha256":shafile(x.protocol),"gate2b2_ledger_sha256":shafile(x.gate2b2_ledger),"bundle_content_manifest_sha256":shafile(x.bundle_content_manifest)},"outputs":{"guard_scope_attribution_ledger_sha256":ls,"guard_scope_attribution_summary_sha256":ss},"scientific_firewall":{"candidate_source_read":False,"semantic_slice_read":False,"adapter_receipt_read":False,"kernel_result_read":False,"certificate_or_c1_read":False,"gate2a_truth_join_input":False,"truth_or_operator_read":False,"epistemic10_read":False,"fresh_heldout_read":False,"semantic_engine_kernel_adapter_or_c1_rerun":False,"remediation":False}}
 write(x.output_dir/"E2_CANDIDATE58_GATE2B3_DIAGNOSTIC_RECEIPT.json",rec);return 0
if __name__=="__main__":raise SystemExit(main())
