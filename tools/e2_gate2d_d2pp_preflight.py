#!/usr/bin/env python3
from __future__ import annotations
import argparse,hashlib,json,os,platform,subprocess
from pathlib import Path

CONTRACT_COMMIT="f31dce68612e49728563a44b26e51296ea7dd284"
CONTRACT_PATH="protocols/RISU_DIFF_E2_GATE2D_D2PP_30CASE_REQUALIFICATION_v0.1.json"
CONTRACT_BLOB="4cc1853774aceb6ecbd9d0af6524ecf5fa4be68c"
D1PP_IMPL="75c81762fd7c9bc63db488f7c3e8aff155e41278"
D2P_IMPL="b0229133d94a3aa18bf02b662898e5b0ae4c5283"

def cb(v):return (json.dumps(v,sort_keys=True,separators=(",",":"))+"\n").encode()
def blob(b):return hashlib.sha1(b"blob "+str(len(b)).encode()+b"\0"+b).hexdigest()
def git(*a):return subprocess.check_output(["git",*a],text=True).strip()
def git_bytes(spec):return subprocess.check_output(["git","show",spec])

def main():
 ap=argparse.ArgumentParser();ap.add_argument("--root",default=".");ap.add_argument("--out",required=True);a=ap.parse_args()
 r=Path(a.root).resolve();out=Path(a.out);out.parent.mkdir(parents=True,exist_ok=True);fail=[];checks={}
 if git("rev-parse","HEAD^")!=CONTRACT_COMMIT:fail.append("IMPLEMENTATION_PARENT")
 if git("hash-object",CONTRACT_PATH)!=CONTRACT_BLOB:fail.append("CONTRACT_BLOB")
 allowed={
  ".github/workflows/e2-gate2d-d2pp-qualification.yml","evaluation/gate2d/BASELINE_REGISTRY_v0.3.json",
  "tools/e2_gate2d_ablation_shadow_v2.py","tools/e2_gate2d_check_evaluation_v3.py","tools/e2_gate2d_d2pp_execute.py",
  "tools/e2_gate2d_d2pp_preflight.py","tools/e2_gate2d_d2pp_transform_matrix.py","tools/e2_gate2d_evaluate_v3.py"}
 got=set(x for x in git("diff","--name-only",CONTRACT_COMMIT,"HEAD").splitlines() if x);checks["implementation_surface"]=sorted(got)
 if got!=allowed:fail.append("IMPLEMENTATION_SURFACE")
 pins={
  "protocols/RISU_DIFF_E2_GATE2D_EVALUATION_CONSTITUTION_v0.1.json":"75cead9960d74c221de19087901952f82d7c01c9",
  "protocols/RISU_DIFF_E2_GATE2D_D2_EXECUTION_PROTOCOL_v0.1.json":"7ad08bae645e010d0f369c4a8c20d226c07915ee",
  "tools/e2_gate2d_d2_generate_matrix.py":"e7854fafaf7f8c2b4e0594fe08d87b9b1a103fbf",
  "tools/e2_gate2d_d2_independent_oracle.py":"0f8769ce3766a50a7814c9eb52b7c9193c03f9f1",
  "tools/e2_gate2d_d2_execute.py":"e9bc78b6c257eac7ff4269e492e0f32077d2d999",
  "tools/e2_gate2d_evaluate.py":"4a2319da29fcb636f0cf8d09722692902e33581c",
  "tools/e2_gate2d_check_evaluation.py":"56f7d9d33b9049213c415790d37adb5d6b3fdbcc",
  "evaluation/gate2d/BASELINE_REGISTRY_v0.3.json":"6e90075c29b0ae497148cadca5ac83a1bf9c2186",
  "tools/e2_gate2d_evaluate_v3.py":"45829630d9128f5b0a12c445157d5bb0f946d01c",
  "tools/e2_gate2d_check_evaluation_v3.py":"c5cfd8997c8265905b57db3d61309888c066179e",
  "tools/e2_gate2d_ablation_shadow_v2.py":"4bdaa15bc6f656517b19f6ca0dee15ff8113c7a7"}
 for p,w in pins.items():
  if git("hash-object",p)!=w:fail.append("PIN:"+p)
 for p,w in {
  "evaluation/gate2d/BASELINE_REGISTRY_v0.3.json":"6e90075c29b0ae497148cadca5ac83a1bf9c2186",
  "tools/e2_gate2d_evaluate_v3.py":"45829630d9128f5b0a12c445157d5bb0f946d01c",
  "tools/e2_gate2d_check_evaluation_v3.py":"c5cfd8997c8265905b57db3d61309888c066179e"}.items():
  if blob(git_bytes(D1PP_IMPL+":"+p))!=w:fail.append("D1PP_HISTORICAL_PIN:"+p)
 oldt=git_bytes(D2P_IMPL+":tools/e2_gate2d_d2prime_transform_matrix.py").decode()
 newt=(r/"tools/e2_gate2d_d2pp_transform_matrix.py").read_text()
 recovered_t=newt.replace("B3A_GPT56_TERRA_COPILOT","B3A_GPT56_SOL_COPILOT").replace("B3B_CLAUDE_SONNET5_COPILOT","B3B_CLAUDE_OPUS5_COPILOT")
 if blob(recovered_t.encode())!="d0a8419d747970e6b1c2cad391faaa6d7b11669a" or recovered_t!=oldt:fail.append("TRANSFORM_DELTA")
 olde=git_bytes(D2P_IMPL+":tools/e2_gate2d_d2prime_execute.py").decode()
 newe=(r/"tools/e2_gate2d_d2pp_execute.py").read_text()
 recovered_e=newe.replace("tools/e2_gate2d_evaluate_v3.py","tools/e2_gate2d_evaluate_v2.py").replace("tools/e2_gate2d_check_evaluation_v3.py","tools/e2_gate2d_check_evaluation_v2.py")
 if blob(recovered_e.encode())!="98ceb998b150489616e32f130dc766e3bc1cfe12" or recovered_e!=olde:fail.append("EXECUTE_DELTA")
 if platform.python_version()!="3.13.5":fail.append("PYTHON_RUNTIME")
 for k,v in {"LC_ALL":"C.UTF-8","PYTHONHASHSEED":"0","TZ":"UTC"}.items():
  if os.environ.get(k)!=v:fail.append("ENV_"+k)
 if Path(os.environ.get("PYTHONPATH","")).resolve()!=r:fail.append("ENV_PYTHONPATH")
 wf=(r/".github/workflows/e2-gate2d-d2pp-qualification.yml").read_text()
 for forbidden in ("COPILOT_GITHUB_TOKEN","RISU_COPILOT_PERSONAL_TOKEN","copilot --prompt"):
  if forbidden in wf:fail.append("PROVIDER_SURFACE:"+forbidden)
 import py_compile
 for p in ["tools/e2_gate2d_d2pp_transform_matrix.py","tools/e2_gate2d_d2pp_execute.py","tools/e2_gate2d_evaluate_v3.py","tools/e2_gate2d_check_evaluation_v3.py","tools/e2_gate2d_ablation_shadow_v2.py"]:
  try:py_compile.compile(str(r/p),doraise=True)
  except Exception as e:fail.append("PYCOMPILE:"+p+":"+str(e))
 report={"schema":"risu.e2-gate2d-d2pp-preflight/v0.1","status":"PASS" if not fail else "FAIL","failures":sorted(fail),"checks":checks,"scientific_case_consumption_before_preflight":0,"epistemic10_read":False,"truth_read":False,"fresh_target_read":False,"mutation_algebra_opened":False,"copilot_semantic_request_count":0,"gate2e_authorized":False}
 out.write_bytes(cb(report));print(out.read_text(),end="")
 if fail:raise SystemExit(2)
if __name__=="__main__":main()
