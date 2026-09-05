#!/usr/bin/env python3
from __future__ import annotations
import hashlib,json,subprocess,sys,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
U=ROOT/"corpus/0.1/units/002-octokit-pulls-merge"
BASE="b52bde0d0fdef0a2be7d5973e564daccd12296c9"
PREMERGE=set(['.github/workflows/unit002-r-closure.yml', '.github/workflows/unit002-r-preprimary-seal.yml', '.github/workflows/unit002-r-target-qualification.yml', 'corpus/0.1/ENROLLMENT.json', 'corpus/0.1/units/002-octokit-pulls-merge/PREMERGE_CLOSURE.json', 'corpus/0.1/units/002-octokit-pulls-merge/friction.json', 'corpus/0.1/units/002-octokit-pulls-merge/post-result/COVERAGE_DIAGNOSTIC.json', 'tools/unit002r_closure_verify.py'])
CLOSED=PREMERGE|{"corpus/0.1/units/002-octokit-pulls-merge/CLOSURE.json"}
def load(p): return json.loads(Path(p).read_text(encoding="utf-8"))
def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def git(*a): return subprocess.run(["git",*a],cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
def die(m): print("UNIT002-R CLOSURE VERIFY: FAIL:",m,file=sys.stderr); raise SystemExit(1)
def changed_surface():
    committed=set(git("diff","--name-only",f"{BASE}..HEAD").stdout.splitlines())
    working=set(git("diff","--name-only","HEAD","--").stdout.splitlines())
    untracked=set(git("ls-files","--others","--exclude-standard").stdout.splitlines())
    return {x for x in committed|working|untracked if x}
try:
  if git("cat-file","-e",BASE+"^{commit}").returncode!=0: die("result-freeze base missing")
  changed=changed_surface()
  final=U/"CLOSURE.json"
  expected=CLOSED if final.exists() else PREMERGE
  if changed!=expected: die(f"post-result surface mismatch: expected={sorted(expected)} actual={sorted(changed)}")
  rel=str((U/"primary-result").relative_to(ROOT))
  if git("diff","--quiet",BASE,"--",rel).returncode!=0: die("primary-result tracked bytes changed after freeze")
  untracked_primary=git("ls-files","--others","--exclude-standard","--",rel).stdout.splitlines()
  if untracked_primary: die(f"untracked primary-result additions: {untracked_primary}")
  expected_hashes={
    U/"primary-result/PRIMARY_RESULT.json":"0d7c940e5f5b1918a9b832644df779a1afb3355d8092cb151ee45d8abbe76351",
    U/"primary-result/PRIMARY_ARTIFACT_INDEX.json":"3586a6e6c1307376e0463c6c22a138fc45ab77db9f72d2c64c86d9152182b805",
    U/"primary-result/actions-artifact-33947031284.zip":"a622c27422d36a9d28302893e4ad9001114bd86e62815aa4f62f3e68918f8a9b",
    U/"primary-result/self-contained-primary.zip":"eb0dcf71ea5ae6b0f40c9899dc8fe3e0e6e54fab84bcc1ee927f44e627f8cf95",
    U/"primary-result/canonical/report.json":"a09e52ac538f8a43646703eeb81e6d5dee36b1e4ad282e54885bb6090169ddb2",
    U/"primary-result/canonical/certificate.json":"75cbdba31eb7717ea3b30f084b3b5f77a05cecbd3eeba26a20cb7f55bf38d418",
    U/"primary-result/canonical/primary-observation.json":"4b0d87ca6be5001ba3fcf552f475748b6ac7769573eb2f28b1325933d3479262",
  }
  for p,h in expected_hashes.items():
    if sha(p)!=h: die(f"hash mismatch {p}")
  primary=load(U/"primary-result/PRIMARY_RESULT.json"); report=load(U/"primary-result/canonical/report.json"); cert=load(U/"primary-result/canonical/certificate.json")
  if primary["status"]!="FROZEN_FIRST_VALID_PRIMARY": die("primary result no longer frozen")
  cp=primary["canonical_primary"]
  if cp["run_id"]!=33947031284 or cp["product_status"]!="PRESERVED_IN_DECLARED_SCOPE" or cp["semantic_exit_code"]!=0: die("canonical primary identity/outcome mismatch")
  if report["product_status"]!="PRESERVED_IN_DECLARED_SCOPE": die("report product status changed")
  if report["structural"]["coverage_complete"] is not False: die("coverage was upgraded")
  if report["exact_realization"]["status"]!="REALIZATION_ESTABLISHED": die("exact realization changed")
  if not all(w["matches"] for w in report["worlds"]): die("bounded world match changed")
  gap=cert["results"]["structural"]["coverage_gap"]
  want={"in_scope_only":["GUARDED_OCTOKIT_PULLS_MERGE_REVIEWED_HEAD_SHA"],"source_only":["GUARDED_MERGE_REVIEWED_HEAD_SHA"]}
  if cert["results"]["structural"]["coverage_complete"] is not False or gap!=want: die(f"coverage gap changed: {gap}")
  cov=load(U/"post-result/COVERAGE_DIAGNOSTIC.json")
  if cov["status"]!="RETAINED_UNRESOLVED_SCOPE_COVERAGE_IDENTIFIER_NON_EQUIVALENCE" or cov["certificate_coverage_gap"]!=want or cov["coverage_complete"] is not False or cov["primary_bytes_modified"] is not False: die("coverage diagnostic weakens primary")
  fr=load(U/"friction.json")
  if fr["candidate_id"]!="octokit/rest.js::github-version-bound-write" or fr["unit_id"]!="corpus01-unit-002" or fr["primary_result_frozen"] is not True: die("friction identity mismatch")
  rt=fr["phases"]["verification_runtime"]
  if rt["status"]!="COMPLETE" or rt["wall_clock_seconds"]!=0.647976 or rt["active_seconds"]!=0.647976: die("measured runtime changed")
  for n,p in fr["phases"].items():
    if n!="verification_runtime":
      if p["status"]!="BLOCKED": die(f"unmeasured phase promoted: {n}")
      if p["wall_clock_seconds"] is not None or p["active_seconds"] is not None: die(f"fabricated timing: {n}")
  enr=load(ROOT/"corpus/0.1/ENROLLMENT.json"); u2=next(x for x in enr["units"] if x["unit_id"]=="corpus01-unit-002")
  frozen={"enrollment_position":2,"candidate_id":"octokit/rest.js::github-version-bound-write","organization":"octokit","stratum":"NON_AGENT_SPECIFIC","mechanism_family":"COMMIT_OR_OBJECT_IDENTITY","target_revision":"cd9cb8cd4965d99c7dac8c87d249308956250be3","screened_operation":"octokit.rest.pulls.merge","verdict_observed_at_enrollment":False}
  for k,v in frozen.items():
    if u2.get(k)!=v: die(f"enrollment selection identity changed: {k}")
  if not u2["authoring_started"] or not u2["authoring_frozen"] or u2["friction_ledger"]!="corpus/0.1/units/002-octokit-pulls-merge/friction.json" or u2.get("authoring_acceptance_path")!="corpus/0.1/units/002-octokit-pulls-merge/AUTHOR_ACCEPTANCE.json": die("Unit002 operational enrollment state not closed")
  for wf in [ROOT/".github/workflows/unit002-r-preprimary-seal.yml",ROOT/".github/workflows/unit002-r-target-qualification.yml"]:
    t=wf.read_text(encoding="utf-8")
    if "pull_request:" in t or "workflow_dispatch:" not in t: die(f"automatic pre-result workflow not retired: {wf.name}")
  pre=load(U/"PREMERGE_CLOSURE.json")
  if pre["status"]!="READY_FOR_GUARDED_MERGE" or pre["retained_limitations"]["coverage_complete"] is not False or pre["closure_conditions"]["guarded_pr_merge_still_required"] is not True: die("premerge closure invalid")
  with zipfile.ZipFile(U/"primary-result/self-contained-primary.zip") as z:
    lines=z.read("MANIFEST.sha256").decode().strip().splitlines()
    if len(lines)!=24: die("self-contained manifest entry count changed")
    for line in lines:
      h,relp=line.split("  ",1)
      if hashlib.sha256(z.read(relp)).hexdigest()!=h: die(f"self-contained mismatch: {relp}")
  phase="READY_FOR_GUARDED_MERGE"
  if final.exists():
    c=load(final)
    if c["schema"]!="risu.corpus-authoritative-closure/v0.1alpha1" or c["status"]!="CLOSED": die("authoritative closure schema/status invalid")
    if c["unit_id"]!="corpus01-unit-002" or c["canonical_phrase"]!="Corpus 0.1 — Unit 002-R: CLOSED": die("authoritative closure identity invalid")
    if c["scientific_pr"]["number"]!=6 or not c["scientific_pr"]["merged"] or len(c["scientific_pr"]["merge_commit_sha"])!=40: die("scientific merge identity invalid")
    if c["canonical_primary"]["run_id"]!=33947031284 or c["canonical_primary"]["product_status"]!="PRESERVED_IN_DECLARED_SCOPE" or c["canonical_primary"]["semantic_exit_code"]!=0: die("closure primary identity mismatch")
    if c["retained_limitations"]["coverage_complete"] is not False or c["retained_limitations"]["unqualified_preserved_claim_prohibited"] is not True: die("closure limitations weakened")
    if c["immutability"]["primary_result_freeze_commit"]!=BASE or c["immutability"]["primary_result_sha256"]!="0d7c940e5f5b1918a9b832644df779a1afb3355d8092cb151ee45d8abbe76351": die("closure immutability binding invalid")
    phase="CLOSED"
  print(json.dumps({"status":"PASS","unit_id":"corpus01-unit-002","phase":phase,"primary_result":"PRESERVED_IN_DECLARED_SCOPE","coverage_complete":False,"primary_bytes_immutable":True,"changed_paths":sorted(changed)},indent=2,sort_keys=True))
except SystemExit: raise
except Exception as e: die(f"{type(e).__name__}: {e}")
