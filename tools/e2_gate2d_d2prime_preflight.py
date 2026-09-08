#!/usr/bin/env python3
from __future__ import annotations
import argparse,hashlib,json,os,platform,subprocess,sys
from pathlib import Path

CONTRACT_COMMIT="860a5bbeb3a5693a586a0e05fd2fa52bd183308c"
CONTRACT_PATH="protocols/RISU_DIFF_E2_GATE2D_D2P_30CASE_REQUALIFICATION_v0.2.json"
CONTRACT_SHA256="b75cb5402332d34d0e4419ad52ce5d1b75318b7937fdf5d17bd857035f4924a4"
CONTRACT_BLOB="14760b4fd36f96d8ef8a13b339cce27d4d5feabe"
FIRST_IMPL="9c095699f29f4fc4d1af037513452bff4afd1079"

def cb(v): return (json.dumps(v,sort_keys=True,separators=(",",":"))+"\n").encode()
def sha(b): return hashlib.sha256(b).hexdigest()
def blob(b): return hashlib.sha1(b"blob "+str(len(b)).encode()+b"\0"+b).hexdigest()
def git(*a): return subprocess.check_output(["git",*a],text=True).strip()

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--root",default=".")
    ap.add_argument("--out",required=True)
    a=ap.parse_args()
    r=Path(a.root).resolve()
    out=Path(a.out); out.parent.mkdir(parents=True,exist_ok=True)
    fail=[]; checks={}

    c=(r/CONTRACT_PATH).read_bytes()
    checks["contract_sha256"]=sha(c)
    checks["contract_git_blob"]=blob(c)
    if sha(c)!=CONTRACT_SHA256 or blob(c)!=CONTRACT_BLOB:
        fail.append("CONTRACT_IDENTITY")
    if git("rev-parse","HEAD^")!=CONTRACT_COMMIT:
        fail.append("IMPLEMENTATION_PARENT_NOT_V02_CONTRACT")

    allowed={
      ".github/workflows/e2-gate2d-d2prime-qualification.yml",
      "evaluation/gate2d/BASELINE_REGISTRY_v0.2.json",
      "tools/e2_gate2d_ablation_shadow_v2.py",
      "tools/e2_gate2d_check_evaluation_v2.py",
      "tools/e2_gate2d_d2prime_execute.py",
      "tools/e2_gate2d_d2prime_preflight.py",
      "tools/e2_gate2d_d2prime_transform_matrix.py",
      "tools/e2_gate2d_evaluate_v2.py",
    }
    got=set(x for x in git("diff","--name-only",CONTRACT_COMMIT,"HEAD").splitlines() if x)
    checks["implementation_surface"]=sorted(got)
    if got!=allowed: fail.append("IMPLEMENTATION_SURFACE_MISMATCH")

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
      "tools/e2_gate2d_ablation_shadow_v2.py":"4bdaa15bc6f656517b19f6ca0dee15ff8113c7a7",
      "tools/e2_gate2d_d2prime_transform_matrix.py":"d0a8419d747970e6b1c2cad391faaa6d7b11669a",
      "tools/e2_gate2d_d2prime_execute.py":"98ceb998b150489616e32f130dc766e3bc1cfe12",
    }
    observed={}
    for p,w in pins.items():
        g=blob((r/p).read_bytes()); observed[p]=g
        if g!=w: fail.append("PIN:"+p)
    checks["blob_pins"]=observed

    for p in [
      "evaluation/gate2d/BASELINE_REGISTRY_v0.2.json",
      "tools/e2_gate2d_evaluate_v2.py",
      "tools/e2_gate2d_check_evaluation_v2.py",
      "tools/e2_gate2d_ablation_shadow_v2.py",
      "tools/e2_gate2d_d2prime_transform_matrix.py",
      "tools/e2_gate2d_d2prime_execute.py",
    ]:
        first=git("rev-parse",f"{FIRST_IMPL}:{p}")
        now=git("rev-parse",f"HEAD:{p}")
        if first!=now: fail.append("R2_SCIENTIFIC_BYTE_REUSE:"+p)

    old=(r/"tools/e2_gate2d_d2_execute.py").read_text()
    new=(r/"tools/e2_gate2d_d2prime_execute.py").read_text()
    expected=(old
      .replace("tools/e2_gate2d_evaluate.py","tools/e2_gate2d_evaluate_v2.py")
      .replace("tools/e2_gate2d_check_evaluation.py","tools/e2_gate2d_check_evaluation_v2.py")
      .replace("tools/e2_gate2d_ablation_shadow.py","tools/e2_gate2d_ablation_shadow_v2.py"))
    if new!=expected: fail.append("HARNESS_DELTA_NOT_EXACT")

    if platform.python_version()!="3.13.5": fail.append("PYTHON_RUNTIME")
    for k,v in {"LC_ALL":"C.UTF-8","PYTHONHASHSEED":"0","TZ":"UTC"}.items():
        if os.environ.get(k)!=v: fail.append("ENV_"+k)
    if Path(os.environ.get("PYTHONPATH","")).resolve()!=r: fail.append("ENV_PYTHONPATH")

    wf=(r/".github/workflows/e2-gate2d-d2prime-qualification.yml").read_text()
    first_wf=subprocess.check_output(["git","show",FIRST_IMPL+":.github/workflows/e2-gate2d-d2prime-qualification.yml"],text=True)
    expected_wf=first_wf.replace("- gate2d-d2prime-qualification\n","- gate2d-d2prime-qualification-r2\n",1)
    if wf!=expected_wf: fail.append("WORKFLOW_DELTA_NOT_BRANCH_ONLY")
    if "gate2d-d2prime-qualification-r2" not in wf:
        fail.append("WORKFLOW_BRANCH_NOT_R2")
    forbidden=["COPILOT_"+"GITHUB_TOKEN","RISU_"+"COPILOT_PERSONAL_TOKEN","cop"+"ilot --prompt"]
    if any(x in wf for x in forbidden): fail.append("PROVIDER_SURFACE_PRESENT")

    import py_compile
    for p in [
      "tools/e2_gate2d_d2prime_transform_matrix.py",
      "tools/e2_gate2d_d2prime_execute.py",
      "tools/e2_gate2d_evaluate_v2.py",
      "tools/e2_gate2d_check_evaluation_v2.py",
      "tools/e2_gate2d_ablation_shadow_v2.py",
    ]:
        try: py_compile.compile(str(r/p),doraise=True)
        except Exception as e: fail.append("PYCOMPILE:"+p+":"+str(e))

    report={
      "schema":"risu.e2-gate2d-d2p-preflight/v0.2",
      "status":"PASS" if not fail else "FAIL",
      "failures":sorted(fail),
      "checks":checks,
      "scientific_case_consumption_before_preflight":0,
      "epistemic10_read":False,
      "truth_read":False,
      "fresh_target_read":False,
      "mutation_algebra_opened":False,
      "copilot_semantic_request_count":0,
      "gate2e_authorized":False,
    }
    out.write_bytes(cb(report))
    print(out.read_text(),end="")
    if fail: raise SystemExit(2)

if __name__=="__main__":
    main()
