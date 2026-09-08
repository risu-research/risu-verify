#!/usr/bin/env python3
from __future__ import annotations
import argparse,ast,hashlib,json,subprocess
from pathlib import Path
from typing import Any
def cb(v:Any)->bytes:return (json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=False)+"\n").encode()
def gb(b:bytes)->str:return hashlib.sha1(b"blob "+str(len(b)).encode()+b"\0"+b).hexdigest()
def sha(b:bytes)->str:return hashlib.sha256(b).hexdigest()
def git(*args)->str:return subprocess.check_output(["git",*args],text=True).strip()
def imports(path:Path)->list[str]:
 t=ast.parse(path.read_text());out=[]
 for n in ast.walk(t):
  if isinstance(n,ast.Import):out += [a.name for a in n.names]
  elif isinstance(n,ast.ImportFrom):out.append(n.module or "")
 return out
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--manifest",required=True);ap.add_argument("--d0",required=True);ap.add_argument("--protocol",required=True);ap.add_argument("--output",required=True);a=ap.parse_args()
 m=json.loads(Path(a.manifest).read_bytes());d0=json.loads(Path(a.d0).read_bytes());p=json.loads(Path(a.protocol).read_bytes())
 failures=[]
 if p.get("schema")!="risu.e2-gate2d-d1-evaluator-baseline-ablation-identity-freeze/v0.2":failures.append("D1_PROTOCOL_SCHEMA")
 if git("rev-parse","HEAD^")!=p["lineage_parent_commit"]:failures.append("LINEAGE_PARENT")
 if [x for x in git("diff","--name-only",p["scientific_base_authority_commit"],"HEAD^").splitlines() if x]:failures.append("D0_RECOVERY_CONTENT_NOT_EXACT")
 for rel,x in sorted(m.get("files",{}).items()):
  q=Path(rel)
  if not q.is_file():failures.append("MISSING:"+rel);continue
  b=q.read_bytes()
  if sha(b)!=x["sha256"]:failures.append("SHA256:"+rel)
  if gb(b)!=x["git_blob"]:failures.append("GIT_BLOB:"+rel)
 # production semantic snapshot must remain byte-identical to D0 locks
 locks=d0["authority_locks"]["semantic_snapshot"]["critical_blob_locks"]
 for rel,want in sorted(locks.items()):
  q=Path(rel)
  if not q.is_file() or git("hash-object",rel)!=want:failures.append("SEMANTIC_SNAPSHOT:"+rel)
 # D1 diff surface
 changed=[x for x in git("diff","--name-only",p["scientific_base_authority_commit"],"HEAD").splitlines() if x]
 allowed=lambda x:(x.startswith("evaluation/gate2d/") or x.startswith("tools/e2_gate2d_") or x=="protocols/RISU_DIFF_E2_GATE2D_D1_EVALUATOR_BASELINE_ABLATION_IDENTITY_FREEZE_v0.2.json" or x==".github/workflows/e2-gate2d-d1-identity-qualification.yml")
 for x in changed:
  if not allowed(x):failures.append("FORBIDDEN_DIFF:"+x)
 # evaluator/checker import independence and stdlib-only
 std={"__future__","argparse","json","pathlib","typing"}
 ev=imports(Path("tools/e2_gate2d_evaluate.py"));ck=imports(Path("tools/e2_gate2d_check_evaluation.py"))
 if any("e2_gate2d_evaluate" in x for x in ck):failures.append("CHECKER_IMPORTS_EVALUATOR")
 if any((x.split(".")[0] not in std) for x in ev):failures.append("EVALUATOR_NON_STDLIB:"+",".join(ev))
 if any((x.split(".")[0] not in std) for x in ck):failures.append("CHECKER_NON_STDLIB:"+",".join(ck))
 br=json.loads(Path("evaluation/gate2d/BASELINE_REGISTRY_v0.1.json").read_bytes())
 ar=json.loads(Path("evaluation/gate2d/ABLATION_REGISTRY_v0.1.json").read_bytes())
 bids=sorted(x["id"] for x in br["baselines"]); aids=sorted(x["id"] for x in ar["ablations"])
 if bids!=sorted(p["baseline_panel"]["required_ids"]):failures.append("BASELINE_ID_SET")
 if aids!=sorted(p["ablation_panel"]["required_ids"]):failures.append("ABLATION_ID_SET")
 # exact external identities
 b2=next(x for x in br["baselines"] if x["id"]=="B2_STRONG_STATIC_DATAFLOW")
 if b2["release_tag"]!="v2.26.4" or b2["linux_bundle_sha256"]!="d372d54345e058fe6f7ff8074acd155522fff6770b8d72ee1371ea89deafa193" or b2["codeql_repo_commit"]!="1d123a2caa0e4e6256a49d963bfcbd51a01617e8":failures.append("CODEQL_IDENTITY")
 cfg=json.loads(Path("evaluation/gate2d/B3_LLM_CONFIG_v0.1.json").read_bytes())
 if cfg["providers"]["openai"]["model"]!="gpt-5.6-sol" or cfg["providers"]["openai"]["reasoning"]!={"effort":"max"}:failures.append("OPENAI_IDENTITY")
 if cfg["providers"]["anthropic"]["model"]!="claude-opus-4-5-20251101":failures.append("ANTHROPIC_IDENTITY")
 receipt={"schema":"risu.e2-gate2d-d1-hosted-identity-qualification/v0.1","status":"PASS" if not failures else "FAIL","d1_commit":git("rev-parse","HEAD"),"d0_scientific_base":p["scientific_base_authority_commit"],"lineage_parent":git("rev-parse","HEAD^"),"d0_recovery_content_exact":"D0_RECOVERY_CONTENT_NOT_EXACT" not in failures,"manifest_file_count":len(m.get("files",{})),"changed_files":changed,"semantic_snapshot_exact":not any(x.startswith("SEMANTIC_SNAPSHOT:") for x in failures),"checker_imports_evaluator":False if "CHECKER_IMPORTS_EVALUATOR" not in failures else True,"baseline_ids":bids,"ablation_ids":aids,"epistemic10_read":False,"truth_read":False,"fresh_target_read":False,"mutation_algebra_opened":False,"failures":sorted(failures)}
 Path(a.output).write_bytes(cb(receipt));print(json.dumps({"schema":receipt["schema"],"status":receipt["status"],"manifest_file_count":receipt["manifest_file_count"]},sort_keys=True,separators=(",",":")))
 if failures:raise SystemExit(2)
if __name__=="__main__":main()
