#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json, os, subprocess, tempfile
from pathlib import Path
from typing import Any

CONFIG_REL = "evaluation/gate2d/B3_COPILOT_CONFIG_v0.2.json"

def cb(v: Any) -> bytes:
    return (json.dumps(v, sort_keys=True, separators=(",",":"), ensure_ascii=False) + "\n").encode()

def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def valid_result(x: Any) -> bool:
    if not isinstance(x, dict) or set(x) != {"outcome","confidence","evidence_paths","reason"}:
        return False
    if x["outcome"] not in {"DEFINITIVE_PRESERVATION","DEFINITIVE_REGRESSION","INCOMPLETE"}:
        return False
    if not isinstance(x["confidence"], (int,float)) or isinstance(x["confidence"], bool) or not 0 <= x["confidence"] <= 1:
        return False
    if not isinstance(x["evidence_paths"], list) or not all(isinstance(y,str) for y in x["evidence_paths"]):
        return False
    if len(set(x["evidence_paths"])) != len(x["evidence_paths"]):
        return False
    if not isinstance(x["reason"], str) or len(x["reason"]) > 2000:
        return False
    return True

def collect_candidates(v: Any, out: list[dict[str,Any]]) -> None:
    if valid_result(v):
        out.append(v)
    if isinstance(v, dict):
        for z in v.values():
            collect_candidates(z, out)
    elif isinstance(v, list):
        for z in v:
            collect_candidates(z, out)
    elif isinstance(v, str):
        s = v.strip()
        if s.startswith("{") and s.endswith("}"):
            try:
                z = json.loads(s)
            except Exception:
                return
            if valid_result(z):
                out.append(z)

def collect_docs(root: Path, manifest: dict[str,Any], limit: int) -> tuple[list[dict[str,str]],int]:
    paths = sorted(map(str, manifest.get("llm_visible_paths", []) or []))
    forbidden = set(map(str, manifest.get("truth_or_operator_paths", []) or []))
    if forbidden.intersection(paths):
        raise ValueError("TRUTH_PATH_VISIBLE")
    docs=[]; total=0
    for rel in paths:
        p = root / rel
        b = p.read_bytes()
        try:
            s = b.decode("utf-8")
        except UnicodeDecodeError:
            raise ValueError("NON_UTF8_LLM_INPUT:"+rel)
        total += len(b)
        if total > limit:
            raise ValueError("LLM_INPUT_OVER_LIMIT")
        docs.append({"path":rel,"content":s})
    return docs,total

def main() -> None:
    ap=argparse.ArgumentParser()
    ap.add_argument("--baseline-id", choices=["B3A_GPT56_TERRA_COPILOT","B3B_CLAUDE_SONNET5_COPILOT"], required=True)
    ap.add_argument("--root", required=True)
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--raw-jsonl", required=True)
    ap.add_argument("--receipt", required=True)
    a=ap.parse_args()
    root=Path(a.root).resolve()
    cfg=json.loads((root/CONFIG_REL).read_bytes())
    lane=cfg["lanes"][a.baseline_id]
    manifest=json.loads(Path(a.manifest).read_bytes())
    docs,total=collect_docs(root,manifest,int(cfg["input"]["max_visible_bytes"]))
    prompt=(root/cfg["input"]["prompt"]).read_text()
    schema=(root/cfg["input"]["response_schema"]).read_text()
    request = (
        prompt.rstrip()+"\n\n"
        "COPILOT_BASELINE_EXECUTION_RULES:\n"
        "- Do not use tools, files, shell, URLs, memory, repository context, or unstated information.\n"
        "- Decide only from BLINDED_DOCUMENTS_JSON below.\n"
        "- Return exactly one JSON object conforming to RESPONSE_SCHEMA_JSON, with no markdown fence or surrounding prose.\n\n"
        "RESPONSE_SCHEMA_JSON:\n"+schema.strip()+"\n\n"
        "BLINDED_DOCUMENTS_JSON:\n"+json.dumps(docs,sort_keys=True,separators=(",",":"),ensure_ascii=False)
    )
    token=os.environ.get("COPILOT_GITHUB_TOKEN","")
    if not token:
        raise SystemExit("COPILOT_GITHUB_TOKEN_MISSING")
    tcfg=cfg["transport"]
    command=[
        "copilot",
        "--prompt",request,
        "--model="+lane["model"],
        "--output-format="+tcfg["output_format"],
        "--max-ai-credits="+str(tcfg["max_ai_credits_per_response"]),
        "--no-ask-user","--no-auto-update","--no-bash-env","--no-color",
        "--no-custom-instructions","--no-experimental","--no-remote","--no-remote-export",
        "--deny-tool=shell,write,read,url,memory",
        "--secret-env-vars=COPILOT_GITHUB_TOKEN",
    ]
    with tempfile.TemporaryDirectory(prefix="risu-copilot-home-") as home, tempfile.TemporaryDirectory(prefix="risu-copilot-cwd-") as cwd:
        env=dict(os.environ)
        env["COPILOT_HOME"]=home
        env["COPILOT_GITHUB_TOKEN"]=token
        env.pop("GH_TOKEN",None); env.pop("GITHUB_TOKEN",None); env.pop("COPILOT_MODEL",None)
        cp=subprocess.run(command,cwd=cwd,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    raw=cp.stdout.encode()
    Path(a.raw_jsonl).write_bytes(raw)
    candidates=[]
    jsonl_ok=True
    for line in cp.stdout.splitlines():
        if not line.strip():
            continue
        try:
            obj=json.loads(line)
        except Exception:
            jsonl_ok=False
            continue
        collect_candidates(obj,candidates)
    unique={json.dumps(x,sort_keys=True,separators=(",",":"),ensure_ascii=False):x for x in candidates}
    if cp.returncode==0 and jsonl_ok and len(unique)==1:
        x=next(iter(unique.values()))
        native=x["outcome"]; normalized=x["outcome"]; detail=x
        valid=True
    else:
        native="COPILOT_OR_SCHEMA_ERROR"; normalized="BASELINE_INVALID"
        detail={"returncode":cp.returncode,"jsonl_ok":jsonl_ok,"candidate_count":len(unique)}
        valid=False
    out={
        "schema":"risu.e2-gate2d-baseline-output/v0.2",
        "baseline_id":a.baseline_id,
        "native_outcome":native,
        "normalized_outcome":normalized,
        "details":detail,
    }
    receipt={
        "schema":"risu.e2-gate2d-copilot-execution-receipt/v0.1",
        "baseline_id":a.baseline_id,
        "model":lane["model"],
        "cli_package":tcfg["cli_package"],
        "cli_version":tcfg["cli_version"],
        "request_sha256":sha256(request.encode()),
        "visible_input_bytes":total,
        "raw_jsonl_sha256":sha256(raw),
        "stderr_sha256":sha256(cp.stderr.encode()),
        "returncode":cp.returncode,
        "semantically_valid":valid,
        "tool_permissions_granted":[],
        "credential_value_persisted":False,
    }
    Path(a.output).write_bytes(cb(out))
    Path(a.receipt).write_bytes(cb(receipt))
    if not valid:
        raise SystemExit(2)

if __name__=="__main__":
    main()
