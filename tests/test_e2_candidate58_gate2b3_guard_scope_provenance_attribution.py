#!/usr/bin/env python3
from __future__ import annotations
"""Adversarial synthetic qualification for the frozen Gate2B3 analyzer."""
import argparse, ast, hashlib, importlib.util, json, sys, tempfile
from collections import Counter
from pathlib import Path
from typing import Any

ROOT=Path(__file__).resolve().parents[1]
ANALYZER=ROOT/"tools/e2_candidate58_gate2b3_guard_scope_provenance_attribution.py"
spec=importlib.util.spec_from_file_location("g2b3",ANALYZER);assert spec and spec.loader
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

def docs(**kw:Any)->tuple[dict[str,Any],dict[str,Any]]:
 scope=kw.get("anchor_scope"); nodes=[]
 if not kw.get("missing_anchor"):
  a={"anchor_role":"GUARD_COMPARISON"};
  if scope is not None:a["scope"]=scope
  nodes=[{"id":"ga","kind":"GUARD","attrs":a}]
  if kw.get("duplicate_anchor"):nodes.append({"id":"ga2","kind":"GUARD","attrs":{"anchor_role":"GUARD_COMPARISON"}})
 pols=kw.get("polarities",(True,False)); edges=[{"id":f"g{i}","kind":"GUARDS","source":"ga","target":f"s{i}","attrs":{"branch_polarity":p}} for i,p in enumerate(pols)]
 od="a"*64;o={"schema":kw.get("overlay_schema",m.OVERLAY_SCHEMA),"overlay_digest_sha256":od,"nodes":nodes,"edges":edges,"control_completeness":[{"scope":"fn:m","status":kw.get("overlay_complete","COMPLETE")} ]}
 scopes=kw.get("scopes",("fn:m","fn:m"));spans=kw.get("spans",((10,0,12,1),(10,0,12,1)));gid=kw.get("effective_id","ga")
 states=[]
 for i,p in enumerate(pols):
  sc=scopes[min(i,len(scopes)-1)] if scopes else ""; sp=list(spans[min(i,len(spans)-1)]) if spans else None
  states.append({"path_state_id":f"p{i}","scope":sc,"transition":{"kind":"STRUCTURED_BRANCH","guard_id":gid,"polarity":p,"statement_span":sp}})
 q={"schema":kw.get("path_schema","risu.e2-path-observability/v0.1"),"base_overlay_digest_sha256":od,"effective_guard_observability":{"form":kw.get("form","DIRECT_CONTROL"),"guard_id":gid},"path_states":states,"control_scope_completeness":{"fn:m":kw.get("path_complete","COMPLETE")},"material_control_complete":kw.get("material_complete",True)}
 return o,q

def helper(**kw:Any)->tuple[dict[str,Any],dict[str,Any]]:
 o,q=docs(polarities=(),form="HELPER_CONTROL",effective_id="wrong" if kw.get("id_disagree") else "ge")
 o["nodes"] += [{"id":"mid","kind":"VALUE","attrs":{}},{"id":"ge","kind":"GUARD","attrs":{}}]
 if kw.get("multi"):o["nodes"].append({"id":"ge2","kind":"GUARD","attrs":{}})
 d="bad_transform" if kw.get("bad") else "comparison_result_to_return"
 o["edges"]=[{"id":"d","kind":"DERIVES","source":"ga","target":"mid","attrs":{"derivation":d}},{"id":"c","kind":"COMPARES","source":"mid","target":"ge","attrs":{}},{"id":"t","kind":"GUARDS","source":"ge","target":"t","attrs":{"branch_polarity":True}},{"id":"f","kind":"GUARDS","source":"ge","target":"f","attrs":{"branch_polarity":False}}]
 if kw.get("multi"):o["edges"] += [{"id":"c2","kind":"COMPARES","source":"mid","target":"ge2","attrs":{}},{"id":"2t","kind":"GUARDS","source":"ge2","target":"t2","attrs":{"branch_polarity":True}},{"id":"2f","kind":"GUARDS","source":"ge2","target":"f2","attrs":{"branch_polarity":False}}]
 gid="wrong" if kw.get("id_disagree") else "ge";q["path_states"]=[{"path_state_id":"ht","scope":"fn:m","transition":{"kind":"STRUCTURED_BRANCH","guard_id":gid,"polarity":True,"statement_span":[20,0,22,1]}},{"path_state_id":"hf","scope":"fn:m","transition":{"kind":"STRUCTURED_BRANCH","guard_id":gid,"polarity":False,"statement_span":[20,0,22,1]}}]
 return o,q

def row(cid:str,deficit:bool=True)->dict[str,Any]:
 p=["GUARD_SCOPE_UNRESOLVED"] if deficit else ["GUARD_OPERATOR_UNRESOLVED"]
 return {"case_id":cid,"primitive_atom_prefixes":p,"F_unresolved_atom_instances":p,"exact_F_admission_reasons":["F_SCOPE_NOT_COMPLETE",f"F_UNRESOLVED:{p[0]}"]}

def materialize(root:Path,cid:str,o:dict[str,Any],p:dict[str,Any],mut:str|None=None)->dict[str,Any]:
 d=root/"prepared/evidence";d.mkdir(parents=True,exist_ok=True);orx=f"prepared/evidence/{cid}.overlay.json";prx=f"prepared/evidence/{cid}.path.json";ob=m.cbytes(o);pb=m.cbytes(p);(root/orx).write_bytes(ob);(root/prx).write_bytes(pb)
 fs=[{"path":orx,"sha256":m.sha(ob)},{"path":prx,"sha256":m.sha(pb)}]
 if mut=="missing":fs=fs[:1]
 elif mut=="dup":fs.append(dict(fs[0]))
 elif mut=="digest":fs[0]["sha256"]="0"*64
 return {"file_count":len(fs),"files":fs}

def one(sid:str,expect:str,d:tuple[dict[str,Any],dict[str,Any]],**kw:Any)->dict[str,Any]:
 with tempfile.TemporaryDirectory(prefix="risu-g2b3-synth-") as td:
  root=Path(td);cid="x"*64 if kw.get("bad_id") else m.sha(sid.encode());o,p=d
  if kw.get("overlay_mismatch"):p=dict(p);p["base_overlay_digest_sha256"]="b"*64
  man=materialize(root,cid,o,p,kw.get("manifest_mut"));got=m.classify_case(row(cid,kw.get("deficit",True)),man,root)["causal_taxonomy_id"]
  if got!=expect:raise AssertionError(f"{sid}: {expect} != {got}")
  return {"scenario_id":sid,"expected_taxonomy_id":expect,"actual_taxonomy_id":got,"passed":True}

def import_firewall()->dict[str,Any]:
 t=ast.parse(ANALYZER.read_text());roots=set()
 for n in ast.walk(t):
  if isinstance(n,ast.Import):roots.update(a.name.split('.',1)[0] for a in n.names)
  elif isinstance(n,ast.ImportFrom) and n.module:roots.add(n.module.split('.',1)[0])
 bad=sorted(x for x in roots if x not in sys.stdlib_module_names and x!="__future__");risu=sorted(x for x in roots if x.startswith("risu"))
 return {"import_roots":sorted(roots),"disallowed_non_stdlib_import_roots":bad,"forbidden_risu_import_roots":risu,"pass":not bad and not risu}

def run()->dict[str,Any]:
 T=m.TAXONOMY; specs=[
  ("S01_DIRECT_PASS",T[4],docs(),{}),("S02_HELPER_PASS",T[4],helper(),{}),("S03_ANCHOR_SCOPE_INCONSISTENT",T[1],docs(anchor_scope="fn:m"),{}),("S04_MISSING_ANCHOR",T[2],docs(missing_anchor=True),{}),("S05_DUPLICATE_ANCHOR",T[2],docs(duplicate_anchor=True),{}),("S06_CONFLICTING_SCOPE",T[3],docs(scopes=("fn:a","fn:b")),{}),("S07_ONE_POLARITY",T[2],docs(polarities=(True,)),{}),("S08_PATH_CONTROL_INCOMPLETE",T[3],docs(path_complete="INCOMPLETE"),{}),("S09_OVERLAY_DIGEST_MISMATCH",T[0],docs(),{"overlay_mismatch":True}),("S10_MISSING_MANIFEST_MEMBER",T[0],docs(),{"manifest_mut":"missing"}),("S11_HELPER_MULTI_CONSUMER",T[2],helper(multi=True),{}),("S12_HELPER_BAD_TRANSFORM",T[2],helper(bad=True),{}),("S13_HELPER_ID_DISAGREE",T[2],helper(id_disagree=True),{}),("S14_WRONG_OVERLAY_SCHEMA",T[0],docs(overlay_schema="wrong"),{}),("S15_WRONG_PATH_SCHEMA",T[0],docs(path_schema="wrong"),{}),("S16_BAD_CASE_ID",T[0],docs(),{"bad_id":True}),("S17_MISSING_SPAN",T[3],docs(spans=((),())),{}),("S18_UNKNOWN_EFFECTIVE_FORM",T[2],docs(form="UNPROVEN"),{}),("S19_DUP_MANIFEST_MEMBER",T[0],docs(),{"manifest_mut":"dup"}),("S20_MANIFEST_DIGEST_MISMATCH",T[0],docs(),{"manifest_mut":"digest"}),("S21_SCOPE_DEFICIT_ABSENT",T[1],docs(),{"deficit":False}),("S22_MATERIAL_CONTROL_FALSE",T[3],docs(material_complete=False),{}),("S23_OVERLAY_CONTROL_INCOMPLETE",T[3],docs(overlay_complete="INCOMPLETE"),{}),("S24_CONFLICTING_SPANS",T[3],docs(spans=((10,0,12,1),(11,0,13,1))),{})]
 out=[one(s,e,d,**k) for s,e,d,k in specs];fw=import_firewall()
 if not fw["pass"]:raise AssertionError(fw)
 try:m.analyze_population({"schema":m.LEDGER_SCHEMA,"rows":[]},{"files":[]},Path("."))
 except ValueError:pop=True
 else:pop=False
 if not pop:raise AssertionError("non-39 population did not fail closed")
 c=Counter(x["actual_taxonomy_id"] for x in out)
 return {"schema":"risu.e2-candidate58-gate2b3-synthetic-self-test/v0.1","status":"PASS","scenario_count":len(out),"all_passed":True,"scenarios":out,"taxonomy_counts":{x:c.get(x,0) for x in T},"stdlib_import_firewall":fw,"population_fail_closed_test":pop,"scientific_firewall":{"synthetic_temporary_directory_only":True,"candidate58_real_overlay_or_path_read":False,"candidate_source_read":False,"semantic_slice_kernel_certificate_c1_read":False,"truth_operator_epistemic10_read":False,"fresh_heldout_read":False,"semantic_kernel_adapter_c1_rerun":False,"remediation":False}}

def main()->int:
 a=argparse.ArgumentParser();a.add_argument("--protocol",type=Path,required=True);a.add_argument("--output",type=Path,required=True);x=a.parse_args();m.validate_protocol(m.load(x.protocol));r=run();x.output.write_bytes(m.cbytes(r));print(f"GATE2B3_SYNTHETIC_SELF_TEST=PASS;SCENARIOS={r['scenario_count']}");return 0
if __name__=="__main__":raise SystemExit(main())
