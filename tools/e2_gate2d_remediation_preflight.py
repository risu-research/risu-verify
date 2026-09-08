#!/usr/bin/env python3
from __future__ import annotations
import argparse,hashlib,json,os,platform,subprocess,sys,tempfile
from pathlib import Path
def cb(v):return (json.dumps(v,sort_keys=True,separators=(",",":"))+"\n").encode()
def sha(b):return hashlib.sha256(b).hexdigest()
def blob(b):return hashlib.sha1(b"blob "+str(len(b)).encode()+b"\0"+b).hexdigest()
def git(*a):return subprocess.check_output(["git",*a],text=True).strip()
def run(cmd,env=None):
 p=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env)
 return p.returncode,p.stdout,p.stderr
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--root",default=".");ap.add_argument("--out",required=True);a=ap.parse_args()
 r=Path(a.root).resolve();out=Path(a.out);out.parent.mkdir(parents=True,exist_ok=True);fail=[];checks={}
 contract_commit="e40eba526510835d1e988baf6f09397ff6023bc5"
 contract_path=r/"protocols/RISU_DIFF_E2_GATE2D_D2_REMEDIATION_CONTRACT_v0.1.json"
 contract_bytes=contract_path.read_bytes()
 checks["contract_sha256"]=sha(contract_bytes)
 if sha(contract_bytes)!="e8dc7b0e0625a0c95861c70060a7a7571da848f6555b0632cc8bd62576a301fd" or blob(contract_bytes)!="51d42de53ed5752bb9f201cc6fea072aa0eda619":fail.append("CONTRACT_IDENTITY")
 if git("rev-parse","HEAD^")!=contract_commit:fail.append("IMPLEMENTATION_PARENT_NOT_CONTRACT_FREEZE")
 allowed={
 ".github/workflows/e2-gate2d-d2-remediation-qualification.yml",
 "evaluation/gate2d/ABLATION_REGISTRY_v0.2.json",
 "evaluation/gate2d/D1_REMEDIATION_IDENTITY_MANIFEST_v0.1.json",
 "evaluation/gate2d/EVALUATOR_RUNTIME_CONFIG_v0.2.json",
 "tools/e2_gate2d_ablation_shadow_v2.py",
 "tools/e2_gate2d_remediation_execute.py",
 "tools/e2_gate2d_remediation_preflight.py"}
 got=set(x for x in git("diff","--name-only",contract_commit,"HEAD").splitlines() if x)
 checks["implementation_surface"]=sorted(got)
 if got!=allowed:fail.append("IMPLEMENTATION_SURFACE_MISMATCH")
 oldm=json.loads((r/"evaluation/gate2d/D1_IDENTITY_MANIFEST_v0.1.json").read_bytes())
 for p,x in sorted(oldm["files"].items()):
  b=(r/p).read_bytes()
  if sha(b)!=x["sha256"] or blob(b)!=x["git_blob"] or len(b)!=x["size"]:fail.append("HISTORICAL_D1_IDENTITY:"+p)
 pins={
  "protocols/RISU_DIFF_E2_GATE2D_EVALUATION_CONSTITUTION_v0.1.json":"75cead9960d74c221de19087901952f82d7c01c9",
  "protocols/RISU_DIFF_E2_GATE2D_D2_EXECUTION_PROTOCOL_v0.1.json":"7ad08bae645e010d0f369c4a8c20d226c07915ee",
  "tools/e2_gate2d_evaluate.py":"4a2319da29fcb636f0cf8d09722692902e33581c",
  "tools/e2_gate2d_check_evaluation.py":"56f7d9d33b9049213c415790d37adb5d6b3fdbcc",
  "tools/e2_gate2d_d2_generate_matrix.py":"e7854fafaf7f8c2b4e0594fe08d87b9b1a103fbf",
  "tools/e2_gate2d_d2_independent_oracle.py":"0f8769ce3766a50a7814c9eb52b7c9193c03f9f1",
  "tools/e2_gate2d_d2_execute.py":"e9bc78b6c257eac7ff4269e492e0f32077d2d999"}
 for p,w in sorted(pins.items()):
  if blob((r/p).read_bytes())!=w:fail.append("FROZEN_MACHINERY:"+p)
 d0=json.loads((r/"protocols/RISU_DIFF_E2_GATE2D_EVALUATION_CONSTITUTION_v0.1.json").read_bytes())
 for p,g in sorted(d0["authority_locks"]["semantic_snapshot"]["critical_blob_locks"].items()):
  if blob((r/p).read_bytes())!=g:fail.append("SEMANTIC_SNAPSHOT:"+p)
 f=json.loads((r/"experiments/risu-diff-e2/qualification/gate2d-evaluation-constitution/d2-adversarial-synthetic-first-complete/freeze_receipt.json").read_bytes())
 if f.get("status")!="GATE2D_D2_FIRST_COMPLETE_ADVERSARIAL_SYNTHETIC_NONPROMOTABLE_IMMUTABLY_FROZEN_BY_CONTAINING_COMMIT" or f.get("matrix",{}).get("predicate_pass_count")!=29 or f.get("d2_success") is not False:fail.append("FIRST_COMPLETE_FAILURE_NOT_EXACT")
 d=json.loads((r/"experiments/risu-diff-e2/qualification/gate2d-evaluation-constitution/d2-adversarial-synthetic-first-complete-diagnosis/diagnosis.json").read_bytes())
 if d.get("classification")!="FROZEN_D1_ABLATION_DRIVER_EXECUTABLE_RUNTIME_CONTRACT_DEFECT_EXPOSED_BY_D2_DIRECT_SCRIPT_LAUNCH":fail.append("DIAGNOSIS_NOT_EXACT")
 m=json.loads((r/"evaluation/gate2d/D1_REMEDIATION_IDENTITY_MANIFEST_v0.1.json").read_bytes())
 for p,x in sorted(m["files"].items()):
  b=(r/p).read_bytes()
  if sha(b)!=x["sha256"] or blob(b)!=x["git_blob"] or len(b)!=x["size"]:fail.append("REMEDIATION_IDENTITY:"+p)
 old=(r/"tools/e2_gate2d_ablation_shadow.py").read_text()
 new=(r/"tools/e2_gate2d_ablation_shadow_v2.py").read_text()
 imp="from risu_e2_c1.semantics import _independent_semantic_eval\n"
 expected=old.replace(imp,"",1).replace(' else:\n  x=copy.deepcopy(d.get("c1_semantic_slice",d))',' else:\n  '+imp+'  x=copy.deepcopy(d.get("c1_semantic_slice",d))',1)
 if new!=expected:fail.append("DRIVER_DELTA_NOT_EXACT")
 oldh=(r/"tools/e2_gate2d_d2_execute.py").read_text()
 newh=(r/"tools/e2_gate2d_remediation_execute.py").read_text()
 if newh!=oldh.replace("tools/e2_gate2d_ablation_shadow.py","tools/e2_gate2d_ablation_shadow_v2.py"):fail.append("HARNESS_DELTA_NOT_EXACT")
 v1=json.loads((r/"evaluation/gate2d/ABLATION_REGISTRY_v0.1.json").read_bytes());v2=json.loads((r/"evaluation/gate2d/ABLATION_REGISTRY_v0.2.json").read_bytes())
 if v2.get("ablations")!=v1.get("ablations") or v2.get("isolation")!=v1.get("isolation") or v2.get("semantic_snapshot_commit")!=v1.get("semantic_snapshot_commit") or v2.get("driver")!="tools/e2_gate2d_ablation_shadow_v2.py":fail.append("ABLATION_SEMANTICS_CHANGED")
 rt=json.loads((r/"evaluation/gate2d/EVALUATOR_RUNTIME_CONFIG_v0.2.json").read_bytes())
 want={"LC_ALL":"C.UTF-8","PYTHONHASHSEED":"0","TZ":"UTC","PYTHONPATH":"REPOSITORY_ROOT"}
 if rt.get("python")!="CPython 3.13.5" or rt.get("environment")!=want:fail.append("RUNTIME_CONFIG")
 if platform.python_version()!="3.13.5":fail.append("PYTHON_RUNTIME")
 for k,v in {"LC_ALL":"C.UTF-8","PYTHONHASHSEED":"0","TZ":"UTC"}.items():
  if os.environ.get(k)!=v:fail.append("ENV_"+k)
 if Path(os.environ.get("PYTHONPATH","")).resolve()!=r:fail.append("ENV_PYTHONPATH")
 smoke={}
 with tempfile.TemporaryDirectory() as td:
  t=Path(td)
  inputs={
   "A1_PRIMARY_ONLY_NO_C1_PROMOTION_GATE":{"tentative_kernel_prediction":"E2_PREDICTED_PRESERVATION_EVIDENCE"},
   "A2_C1_WITHOUT_AUTHORITY_SIDECARS":{"c1_semantic_slice":{}},
   "A3_C1_WITHOUT_CROSS_REPRESENTATION_EVIDENCE":{"c1_semantic_slice":{}}}
  env=dict(os.environ)
  for aid,doc in inputs.items():
   ip=t/(aid+".json");ip.write_bytes(cb(doc));ib=ip.read_bytes();oldouts=[];newouts=[]
   for tag,driver,store in (("old","tools/e2_gate2d_ablation_shadow.py",oldouts),("new","tools/e2_gate2d_ablation_shadow_v2.py",newouts)):
    for n in (1,2):
     op=t/f"{aid}.{tag}.{n}.json";rc,so,se=run([sys.executable,str(r/driver),"--ablation",aid,"--input",str(ip),"--output",str(op)],env=env)
     if rc:fail.append("SMOKE_EXEC:"+aid+":"+tag+":"+se.decode(errors="replace"));break
     store.append(op.read_bytes())
   if len(oldouts)==2 and len(newouts)==2:
    if oldouts[0]!=oldouts[1] or newouts[0]!=newouts[1]:fail.append("SMOKE_DUAL_REPLAY:"+aid)
    if oldouts[0]!=newouts[0]:fail.append("SMOKE_OLD_NEW_MISMATCH:"+aid)
    smoke[aid]={"sha256":sha(newouts[0]),"old_new_byte_identical":oldouts[0]==newouts[0],"new_dual_replay_byte_identical":newouts[0]==newouts[1]}
   if ip.read_bytes()!=ib:fail.append("SMOKE_INPUT_MUTATED:"+aid)
  aid="A1_PRIMARY_ONLY_NO_C1_PROMOTION_GATE";ip=t/(aid+".json");op=t/"a1_isolated.json";isol=dict(os.environ);isol.pop("PYTHONPATH",None)
  rc,so,se=run([sys.executable,"-I",str(r/"tools/e2_gate2d_ablation_shadow_v2.py"),"--ablation",aid,"--input",str(ip),"--output",str(op)],env=isol)
  checks["a1_isolated_no_pythonpath_success"]=rc==0
  if rc:fail.append("A1_NEGATIVE_IMPORT_PATH_SMOKE:"+se.decode(errors="replace"))
 report={"schema":"risu.e2-gate2d-d2-remediation-preflight/v0.1","status":"PASS" if not fail else "FAIL","failures":sorted(fail),"checks":checks,"smoke":smoke,"epistemic10_read":False,"truth_read":False,"fresh_target_read":False,"mutation_algebra_opened":False,"gate2e_authorized":False,"d3_closure_authorized":False}
 out.write_bytes(cb(report))
 if fail:raise SystemExit(2)
if __name__=="__main__":main()
