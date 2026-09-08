#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json, os, subprocess, sys
from pathlib import Path

LANES=[
 ("B3A_GPT56_SOL_COPILOT","gpt-5.6-sol"),
 ("B3B_CLAUDE_OPUS5_COPILOT","claude-opus-5"),
]
FIXTURE_SHA="8f89253ab4a2f1eae2baaf0364a3e5e7dc9946eda69780d38cfe29b3893819d6"

def cb(v):
    return (json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=False)+"\n").encode()
def sha(b):
    return hashlib.sha256(b).hexdigest()
def load(p):
    return json.loads(Path(p).read_bytes())

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--root",default="."); ap.add_argument("--out",required=True); a=ap.parse_args()
    r=Path(a.root).resolve(); out=Path(a.out); out.mkdir(parents=True,exist_ok=True)
    c=load(r/"protocols/RISU_DIFF_E2_GATE2D_D3P_COPILOT_SMOKE_v0.1.json")
    fx=c["nonheldout_fixture"]; b=fx["content"].encode()
    fixture_path=r/fx["path"]; fixture_path.parent.mkdir(parents=True,exist_ok=True); fixture_path.write_bytes(b)
    if len(b)!=314 or sha(b)!=FIXTURE_SHA: raise SystemExit("FIXTURE_IDENTITY")
    artifact_fixture=out/"fixture"/"blinded_document.txt"; artifact_fixture.parent.mkdir(parents=True,exist_ok=True); artifact_fixture.write_bytes(b)
    manifest=fx["manifest"]
    manifest_path=out/"D3P_MANIFEST.json"; manifest_path.write_bytes(cb(manifest))

    token=os.environ.get("COPILOT_GITHUB_TOKEN","")
    if not token:
        summary={"schema":"risu.e2-gate2d-d3p-smoke/v0.1","status":"PRE_PROVIDER_CREDENTIAL_MISSING","provider_semantic_request_count":0,
                 "lanes":[],"epistemic10_read":False,"truth_read":False,"fresh_target_read":False,"mutation_algebra_opened":False,"gate2e_authorized":False}
        (out/"D3P_SMOKE_SUMMARY.json").write_bytes(cb(summary))
        return

    rows=[]; invoked=0
    for baseline_id,model in LANES:
        lane_dir=out/baseline_id; lane_dir.mkdir(parents=True,exist_ok=True)
        output=lane_dir/"output.json"; raw=lane_dir/"raw.jsonl"; receipt=lane_dir/"receipt.json"
        cmd=[sys.executable,str(r/"tools/e2_gate2d_copilot_baseline.py"),
             "--baseline-id",baseline_id,"--root",str(r),"--manifest",str(manifest_path),
             "--output",str(output),"--raw-jsonl",str(raw),"--receipt",str(receipt)]
        invoked += 1
        cp=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        (lane_dir/"runner_stdout.sha256").write_text(sha(cp.stdout)+"\n")
        (lane_dir/"runner_stderr.sha256").write_text(sha(cp.stderr)+"\n")
        rec=load(receipt) if receipt.exists() else {}
        od=load(output) if output.exists() else {}
        normalized_valid=od.get("normalized_outcome")!="BASELINE_INVALID" and od.get("normalized_outcome") in {"DEFINITIVE_PRESERVATION","DEFINITIVE_REGRESSION","INCOMPLETE"}
        row={
          "baseline_id":baseline_id,"expected_model":model,"runner_returncode":cp.returncode,
          "receipt_present":bool(rec),"output_present":bool(od),
          "receipt_model_exact":rec.get("model")==model,
          "receipt_cli_exact":rec.get("cli_package")=="@github/copilot" and rec.get("cli_version")=="1.0.83",
          "request_sha256":rec.get("request_sha256"),
          "visible_input_bytes":rec.get("visible_input_bytes"),
          "raw_jsonl_sha256":rec.get("raw_jsonl_sha256"),
          "semantically_valid":rec.get("semantically_valid") is True,
          "normalized_schema_valid":normalized_valid,
          "provider_semantic_request_count":1,
        }
        rows.append(row)

    reqs=[x.get("request_sha256") for x in rows]
    passed=(len(rows)==2 and invoked==2 and all(x["runner_returncode"]==0 and x["receipt_model_exact"] and x["receipt_cli_exact"]
              and x["semantically_valid"] and x["normalized_schema_valid"] and x["visible_input_bytes"]==314 for x in rows)
            and None not in reqs and len(set(reqs))==1)
    summary={
      "schema":"risu.e2-gate2d-d3p-smoke/v0.1",
      "status":"PASS" if passed else "FAIL",
      "provider_semantic_request_count":invoked,
      "lane_count":len(rows),
      "both_lane_request_sha256_equal":None not in reqs and len(set(reqs))==1,
      "lanes":rows,
      "semantic_outcome_values_used_for_gate_decision":False,
      "epistemic10_read":False,"truth_read":False,"fresh_target_read":False,"mutation_algebra_opened":False,
      "gate2e_authorized":False,
    }
    (out/"D3P_SMOKE_SUMMARY.json").write_bytes(cb(summary))
if __name__=="__main__": main()
