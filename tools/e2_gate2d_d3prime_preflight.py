#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json, os, platform, subprocess
from pathlib import Path

CONTRACT_COMMIT="8b5a8bd52946a7d52f3d29b450104b24f7b18686"
CONTRACT_PATH="protocols/RISU_DIFF_E2_GATE2D_D3P_COPILOT_SMOKE_v0.1.json"
CONTRACT_SHA256="2320c9c9a52d3a46cf21661d581e756df0a9670a2af8b84dc85ed01d4662bdcf"
CONTRACT_BLOB="f3073558dfb33eba46801cff34f4879e8a79054d"
EXPECTED_COPIED={
 "evaluation/gate2d/B3_COPILOT_CONFIG_v0.1.json":"429785e3f3a3430f5a0dc78a5796a70d859dad33",
 "evaluation/gate2d/B3_LLM_PROMPT_v0.1.txt":"d2aeec22e6a500a60b53dc36ef4238a7c734d060",
 "evaluation/gate2d/B3_LLM_RESPONSE_SCHEMA_v0.1.json":"ec2578ccfba33f70c7b0057a5fbfe9b994eaf48d",
 "evaluation/gate2d/COMMON_BLINDED_INPUT_CONTRACT_v0.1.json":"db7e6e53ea82ef7942557adaf31b7b781c71365d",
 "tools/e2_gate2d_copilot_baseline.py":"1383bb5fa0ea5c3ed3c391788c672b58e20fb0eb",
}
EXPECTED_CHANGED={
 ".github/workflows/e2-gate2d-d3prime-copilot-smoke.yml",
 "evaluation/gate2d/B3_COPILOT_CONFIG_v0.1.json",
 "tools/e2_gate2d_copilot_baseline.py",
 "tools/e2_gate2d_d3prime_preflight.py",
 "tools/e2_gate2d_d3prime_smoke.py",
}

def cb(v):
    return (json.dumps(v,sort_keys=True,separators=(",",":"))+"\n").encode()
def sha(b):
    return hashlib.sha256(b).hexdigest()
def blob(b):
    return hashlib.sha1(b"blob "+str(len(b)).encode()+b"\0"+b).hexdigest()
def git(*args):
    return subprocess.check_output(["git",*args],text=True).strip()

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--root",default="."); ap.add_argument("--out",required=True); a=ap.parse_args()
    r=Path(a.root).resolve(); out=Path(a.out); out.parent.mkdir(parents=True,exist_ok=True)
    fail=[]; checks={}
    b=(r/CONTRACT_PATH).read_bytes()
    checks["contract_sha256"]=sha(b); checks["contract_git_blob"]=blob(b)
    if sha(b)!=CONTRACT_SHA256 or blob(b)!=CONTRACT_BLOB: fail.append("D3P_CONTRACT_IDENTITY")
    if git("rev-parse","HEAD^")!=CONTRACT_COMMIT: fail.append("IMPLEMENTATION_PARENT_NOT_D3P_CONTRACT")
    changed={x for x in git("diff","--name-only",CONTRACT_COMMIT,"HEAD").splitlines() if x}
    checks["implementation_surface"]=sorted(changed)
    if changed!=EXPECTED_CHANGED: fail.append("IMPLEMENTATION_SURFACE")
    for rel,want in sorted(EXPECTED_COPIED.items()):
        p=r/rel
        if not p.is_file() or blob(p.read_bytes())!=want: fail.append("D1P_REUSED_BLOB:"+rel)

    d1p=json.loads((r/"experiments/risu-diff-e2/qualification/gate2d-evaluation-constitution/d1p-copilot-identity-r2/freeze_receipt.json").read_bytes())
    if d1p.get("status")!="GATE2D_D1PRIME_R2_COPILOT_IDENTITY_PASS_IMMUTABLY_FROZEN_BY_CONTAINING_COMMIT" or d1p.get("identity_result",{}).get("provider_semantic_request_count")!=0:
        fail.append("D1P_PASS_AUTHORITY")
    d2p=json.loads((r/"experiments/risu-diff-e2/qualification/gate2d-evaluation-constitution/d2p-r2-first-complete-pass/freeze_receipt.json").read_bytes())
    if d2p.get("status")!="GATE2D_D2PRIME_R2_FIRST_COMPLETE_PASS_30_OF_30_IMMUTABLY_FROZEN_BY_CONTAINING_COMMIT" or d2p.get("scientific_result",{}).get("predicate_pass_count")!=30 or d2p.get("d3prime_authorized") is not True:
        fail.append("D2P_PASS_AUTHORITY")
    olddiag=r/"experiments/risu-diff-e2/qualification/gate2d-evaluation-constitution/d3-r2-first-complete-diagnosis/diagnosis.json"
    if blob(olddiag.read_bytes())!="ce559be953bd8da695fe8c643af07c6e670b6a22":
        fail.append("HISTORICAL_D3_R2_DIAGNOSIS_IDENTITY")
    else:
        d=json.loads(olddiag.read_bytes())
        if d.get("classification")!="D3_R2_CREDENTIAL_PROVISIONING_GAP_PRE_PROVIDER" or d.get("evidence",{}).get("provider_request_count")!=0:
            fail.append("HISTORICAL_D3_R2_DIAGNOSIS_SEMANTICS")
    if git("hash-object","protocols/RISU_DIFF_E2_GATE2D_D3_CLOSURE_PROTOCOL_v0.1.json")!="e528f6022de092f492d01b1057db3b956398848d":
        fail.append("HISTORICAL_D3_PROTOCOL_IDENTITY")

    cfg=json.loads((r/"evaluation/gate2d/B3_COPILOT_CONFIG_v0.1.json").read_bytes())
    t=cfg.get("transport",{})
    if t.get("cli_package")!="@github/copilot" or t.get("cli_version")!="1.0.83" or t.get("repository_secret")!="RISU_COPILOT_PERSONAL_TOKEN":
        fail.append("COPILOT_TRANSPORT_IDENTITY")
    if t.get("authentication_env")!="COPILOT_GITHUB_TOKEN" or t.get("max_ai_credits_per_response")!=30 or t.get("semantic_retry_cap")!=0:
        fail.append("COPILOT_TRANSPORT_RULES")
    lanes=cfg.get("lanes",{})
    want={"B3A_GPT56_SOL_COPILOT":"gpt-5.6-sol","B3B_CLAUDE_OPUS5_COPILOT":"claude-opus-5"}
    if {k:v.get("model") for k,v in lanes.items()}!=want: fail.append("COPILOT_LANES")

    c=json.loads(b)
    fx=c["nonheldout_fixture"]
    fxb=fx["content"].encode()
    if len(fxb)!=314 or sha(fxb)!="8f89253ab4a2f1eae2baaf0364a3e5e7dc9946eda69780d38cfe29b3893819d6" or fx.get("expected_semantic_outcome") is not None:
        fail.append("NONHELDOUT_FIXTURE_IDENTITY")
    if fx.get("heldout_bytes_present") or fx.get("truth_label_present") or fx.get("fresh_target_bytes_present") or fx.get("mutation_operator_identity_present"):
        fail.append("NONHELDOUT_FIXTURE_FIREWALL")

    if platform.python_version()!="3.13.5": fail.append("PYTHON_RUNTIME")
    for k,v in {"LC_ALL":"C.UTF-8","PYTHONHASHSEED":"0","TZ":"UTC"}.items():
        if os.environ.get(k)!=v: fail.append("ENV_"+k)
    if Path(os.environ.get("PYTHONPATH","")).resolve()!=r: fail.append("ENV_PYTHONPATH")

    wf=(r/".github/workflows/e2-gate2d-d3prime-copilot-smoke.yml").read_text()
    if "secrets.RISU_COPILOT_PERSONAL_TOKEN" not in wf: fail.append("WORKFLOW_PERSONAL_SECRET_BINDING")
    if "secrets.GITHUB_TOKEN" in wf or "github.token" in wf: fail.append("WORKFLOW_ORG_TOKEN_SEMANTIC_ROUTE")
    if "gate2d-d3prime-copilot-smoke-run" not in wf: fail.append("WORKFLOW_RUN_BRANCH")

    report={
      "schema":"risu.e2-gate2d-d3p-preflight/v0.1",
      "status":"PASS" if not fail else "FAIL",
      "failures":sorted(fail),
      "checks":checks,
      "provider_semantic_request_count":0,
      "epistemic10_read":False,"truth_read":False,"fresh_target_read":False,"mutation_algebra_opened":False,
      "gate2e_authorized":False,
    }
    out.write_bytes(cb(report))
    if fail: raise SystemExit(2)
if __name__=="__main__": main()
