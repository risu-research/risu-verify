#!/usr/bin/env python3
from __future__ import annotations
import argparse,hashlib,json,os,platform,subprocess,sys,tempfile
from pathlib import Path
CONTRACT_COMMIT="5684cbdf163afbbf39922dccda32a3e0721bd8da"
CONTRACT_SHA256="25bd376b0ab6bc127c9e46cdd2b7bb9782e965e95772188118ebce712de279e6"
CONTRACT_BLOB="a8023a97ed255864396723f31f77b7430e723447"
def cb(v):return (json.dumps(v,sort_keys=True,separators=(",",":"))+"\n").encode()
def sha(b):return hashlib.sha256(b).hexdigest()
def blob(b):return hashlib.sha1(b"blob "+str(len(b)).encode()+b"\0"+b).hexdigest()
def git(*a):return subprocess.check_output(["git",*a],text=True).strip()
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--root",default=".");ap.add_argument("--out",required=True);a=ap.parse_args()
 r=Path(a.root).resolve();out=Path(a.out);out.parent.mkdir(parents=True,exist_ok=True);fail=[];checks={}
 c=(r/"protocols/RISU_DIFF_E2_GATE2D_D2P_30CASE_REQUALIFICATION_v0.1.json").read_bytes()
 if sha(c)!=CONTRACT_SHA256 or blob(c)!=CONTRACT_BLOB:fail.append("CONTRACT_IDENTITY")
 if git("rev-parse","HEAD^")!=CONTRACT_COMMIT:fail.append("IMPLEMENTATION_PARENT_NOT_D2P_CONTRACT")
 allowed={".github/workflows/e2-gate2d-d2prime-qualification.yml","evaluation/gate2d/BASELINE_REGISTRY_v0.2.json","tools/e2_gate2d_ablation_shadow_v2.py","tools/e2_gate2d_check_evaluation_v2.py","tools/e2_gate2d_d2prime_execute.py","tools/e2_gate2d_d2prime_preflight.py","tools/e2_gate2d_d2prime_transform_matrix.py","tools/e2_gate2d_evaluate_v2.py"}
 got=set(x for x in git("diff","--name-only",CONTRACT_COMMIT,"HEAD").splitlines() if x);checks["implementation_surface"]=sorted(got)
 if got!=allowed:fail.append("IMPLEMENTATION_SURFACE_MISMATCH")
 pins={
  "protocols/RISU_DIFF_E2_GATE2D_EVALUATION_CONSTITUTION_v0.1.json":"75cead9960d74c221de19087901952f82d7c01c9",
  "protocols/RISU_DIFF_E2_GATE2D_D2_EXECUTION_PROTOCOL_v0.1.json":"7ad08bae645e010d0f369c4a8c20d226c07915ee",
  "tools/e2_gate2d_d2_generate_matrix.py":"e7854fafaf7f8c2b4e0594fe08d87b9b1a103fbf",
  "tools/e2_gate2d_d2_independent_oracle.py":"0f8769ce3766a50a7814c9eb52b7c9193c03f9f1",
  "tools/e2_gate2d_d2_execute.py":"e9bc78b6c257eac7ff4269e492e0f32077d2d999",
  "tools/e2_gate2d_evaluate.py":"4a2319da29fcb636f0cf8d09722692902e33581c",
  "tools/e2_gate2d_check_evaluation.py":"56f7d9d33b9049213c415790d37adb5d6b3fdbcc",
  "evaluation/gate2d/BASELINE_REGISTRY_v0.2.json":"ea0d1525b784166e3626e3a46f636980729fb135",
  "tools/e2_gate2d_evaluate_v2.py":"082f65ec717d23a01e2c265af680a176ac6ace5a",
  "tools/e2_gate2d_check_evaluation_v2.py":"b90ca78d4632ea5a415451e1a62a36c19ec02bde",
  "tools/e2_gate2d_ablation_shadow_v2.py":"4bdaa15bc6f656517b19f6ca0dee15ff8113c7a7"}
 for p,w in pins.items():
  if blob((r/p).read_bytes())!=w:fail.append("PIN:"+p)
 old=(r/"tools/e2_gate2d_d2_execute.py").read_text()
 new=(r/"tools/e2_gate2d_d2prime_execute.py").read_text()
 expected=old.replace("tools/e2_gate2d_evaluate.py","tools/e2_gate2d_evaluate_v2.py").replace("tools/e2_gate2d_check_evaluation.py","tools/e2_gate2d_check_evaluation_v2.py").replace("tools/e2_gate2d_ablation_shadow.py","tools/e2_gate2d_ablation_shadow_v2.py")
 if new!=expected:fail.append("HARNESS_DELTA_NOT_EXACT")
 if platform.python_version()!="3.13.5":fail.append("PYTHON_RUNTIME")
 for k,v in {"LC_ALL":"C.UTF-8","PYTHONHASHSEED":"0","TZ":"UTC"}.items():
  if os.environ.get(k)!=v:fail.append("ENV_"+k)
 if Path(os.environ.get("PYTHONPATH","")).resolve()!=r:fail.append("ENV_PYTHONPATH")
 wf=(r/".github/workflows/e2-gate2d-d2prime-qualification.yml").read_text()
 forbidden=["COPILOT_"+"GITHUB_TOKEN","RISU_"+"COPILOT_PERSONAL_TOKEN","cop"+"ilot --prompt"]
 if any(x in wf for x in forbidden):fail.append("PROVIDER_SURFACE_PRESENT")
 with tempfile.TemporaryDirectory() as td:
  t=Path(td);raw=t/"raw";(raw/"cases").mkdir(parents=True)
  case={"schema":"x","baselines":{"B0_STRUCTURAL_SCHEMA_DIFF":{"unit_outputs":{}},"B3A_GPT56_SOL_FRONTIER":{"unit_outputs":{"U01":"INCOMPLETE"}},"B3B_CLAUDE_OPUS45_DATED":{"unit_outputs":{}}}}
  b=cb(case);(raw/"cases/T.json").write_bytes(b)
  man=cb({"schema":"x","case_count":1,"cases":[{"id":"T","sha256":sha(b),"size":len(b)}]})
  import py_compile
  for p in ["tools/e2_gate2d_d2prime_transform_matrix.py","tools/e2_gate2d_d2prime_execute.py","tools/e2_gate2d_evaluate_v2.py","tools/e2_gate2d_check_evaluation_v2.py","tools/e2_gate2d_ablation_shadow_v2.py"]:
   try:py_compile.compile(str(r/p),doraise=True)
   except Exception as e:fail.append("PYCOMPILE:"+p+":"+str(e))
 report={"schema":"risu.e2-gate2d-d2p-preflight/v0.1","status":"PASS" if not fail else "FAIL","failures":sorted(fail),"checks":checks,"epistemic10_read":False,"truth_read":False,"fresh_target_read":False,"mutation_algebra_opened":False,"copilot_semantic_request_count":0,"gate2e_authorized":False}
 out.write_bytes(cb(report))
 if fail:raise SystemExit(2)
if __name__=="__main__":main()
