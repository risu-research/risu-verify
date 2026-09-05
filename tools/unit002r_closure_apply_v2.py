#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(os.environ.get("SCIENTIFIC_REPO", ".")).resolve()
BASE = "b52bde0d0fdef0a2be7d5973e564daccd12296c9"
BRANCH = "unit002-r-real-prospective"
U = ROOT / "corpus/0.1/units/002-octokit-pulls-merge"
ENR = ROOT / "corpus/0.1/ENROLLMENT.json"
FRICTION = U / "friction.json"
COVERAGE = U / "post-result/COVERAGE_DIAGNOSTIC.json"
PREMERGE = U / "PREMERGE_CLOSURE.json"
PREPRIMARY = ROOT / ".github/workflows/unit002-r-preprimary-seal.yml"
TARGETQUAL = ROOT / ".github/workflows/unit002-r-target-qualification.yml"
CLOSURE_TOOL = ROOT / "tools/unit002r_closure_verify.py"
CLOSURE_WF = ROOT / ".github/workflows/unit002-r-closure.yml"

EXPECTED_PREMERGE_PATHS = {
    ".github/workflows/unit002-r-preprimary-seal.yml",
    ".github/workflows/unit002-r-target-qualification.yml",
    ".github/workflows/unit002-r-closure.yml",
    "corpus/0.1/ENROLLMENT.json",
    "corpus/0.1/units/002-octokit-pulls-merge/friction.json",
    "corpus/0.1/units/002-octokit-pulls-merge/post-result/COVERAGE_DIAGNOSTIC.json",
    "corpus/0.1/units/002-octokit-pulls-merge/PREMERGE_CLOSURE.json",
    "tools/unit002r_closure_verify.py",
}


def run(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    p = subprocess.run(list(args), cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if check and p.returncode:
        raise RuntimeError(
            f"command failed {args}: rc={p.returncode}\nstdout={p.stdout}\nstderr={p.stderr}"
        )
    return p


def git(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return run("git", *args, check=check)


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def write(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def changed_surface() -> set[str]:
    committed = set(git("diff", "--name-only", f"{BASE}..HEAD").stdout.splitlines())
    working = set(git("diff", "--name-only", "HEAD", "--").stdout.splitlines())
    untracked = set(git("ls-files", "--others", "--exclude-standard").stdout.splitlines())
    return {x for x in committed | working | untracked if x}


def assert_primary_immutable() -> None:
    rel = str((U / "primary-result").relative_to(ROOT))
    if git("diff", "--quiet", BASE, "--", rel, check=False).returncode != 0:
        raise RuntimeError("primary-result tracked bytes changed after result freeze")
    untracked = git("ls-files", "--others", "--exclude-standard", "--", rel).stdout.splitlines()
    if untracked:
        raise RuntimeError(f"untracked primary-result additions after result freeze: {untracked}")
    expected = {
        U / "primary-result/PRIMARY_RESULT.json": "0d7c940e5f5b1918a9b832644df779a1afb3355d8092cb151ee45d8abbe76351",
        U / "primary-result/PRIMARY_ARTIFACT_INDEX.json": "3586a6e6c1307376e0463c6c22a138fc45ab77db9f72d2c64c86d9152182b805",
        U / "primary-result/actions-artifact-33947031284.zip": "a622c27422d36a9d28302893e4ad9001114bd86e62815aa4f62f3e68918f8a9b",
        U / "primary-result/self-contained-primary.zip": "eb0dcf71ea5ae6b0f40c9899dc8fe3e0e6e54fab84bcc1ee927f44e627f8cf95",
        U / "primary-result/canonical/report.json": "a09e52ac538f8a43646703eeb81e6d5dee36b1e4ad282e54885bb6090169ddb2",
        U / "primary-result/canonical/certificate.json": "75cbdba31eb7717ea3b30f084b3b5f77a05cecbd3eeba26a20cb7f55bf38d418",
        U / "primary-result/canonical/primary-observation.json": "4b0d87ca6be5001ba3fcf552f475748b6ac7769573eb2f28b1325933d3479262",
    }
    for path, digest in expected.items():
        if sha(path) != digest:
            raise RuntimeError(f"primary exact-byte mismatch: {path}")


def verify_inner_bundle() -> None:
    with zipfile.ZipFile(U / "primary-result/self-contained-primary.zip") as z:
        lines = z.read("MANIFEST.sha256").decode("utf-8").strip().splitlines()
        if len(lines) != 24:
            raise RuntimeError(f"inner bundle manifest expected 24 entries, got {len(lines)}")
        for line in lines:
            digest, rel = line.split("  ", 1)
            if hashlib.sha256(z.read(rel)).hexdigest() != digest:
                raise RuntimeError(f"inner bundle mismatch: {rel}")


def retire_pr_trigger(path: Path, fragment: str) -> None:
    text = path.read_text(encoding="utf-8")
    if fragment not in text:
        raise RuntimeError(f"expected automatic trigger fragment missing in {path}")
    path.write_text(text.replace(fragment, "on:\n  workflow_dispatch:\n", 1), encoding="utf-8")


def make_closure_verifier() -> str:
    premerge = sorted(EXPECTED_PREMERGE_PATHS)
    return f'''#!/usr/bin/env python3
from __future__ import annotations
import hashlib,json,subprocess,sys,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
U=ROOT/"corpus/0.1/units/002-octokit-pulls-merge"
BASE="{BASE}"
PREMERGE=set({premerge!r})
CLOSED=PREMERGE|{{"corpus/0.1/units/002-octokit-pulls-merge/CLOSURE.json"}}
def load(p): return json.loads(Path(p).read_text(encoding="utf-8"))
def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def git(*a): return subprocess.run(["git",*a],cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
def die(m): print("UNIT002-R CLOSURE VERIFY: FAIL:",m,file=sys.stderr); raise SystemExit(1)
def changed_surface():
    committed=set(git("diff","--name-only",f"{{BASE}}..HEAD").stdout.splitlines())
    working=set(git("diff","--name-only","HEAD","--").stdout.splitlines())
    untracked=set(git("ls-files","--others","--exclude-standard").stdout.splitlines())
    return {{x for x in committed|working|untracked if x}}
try:
  if git("cat-file","-e",f"{{BASE}}^{{commit}}").returncode!=0: die("result-freeze base missing")
  changed=changed_surface()
  final=U/"CLOSURE.json"
  expected=CLOSED if final.exists() else PREMERGE
  if changed!=expected: die(f"post-result surface mismatch: expected={{sorted(expected)}} actual={{sorted(changed)}}")
  rel=str((U/"primary-result").relative_to(ROOT))
  if git("diff","--quiet",BASE,"--",rel).returncode!=0: die("primary-result tracked bytes changed after freeze")
  untracked_primary=git("ls-files","--others","--exclude-standard","--",rel).stdout.splitlines()
  if untracked_primary: die(f"untracked primary-result additions: {{untracked_primary}}")
  expected_hashes={{
    U/"primary-result/PRIMARY_RESULT.json":"0d7c940e5f5b1918a9b832644df779a1afb3355d8092cb151ee45d8abbe76351",
    U/"primary-result/PRIMARY_ARTIFACT_INDEX.json":"3586a6e6c1307376e0463c6c22a138fc45ab77db9f72d2c64c86d9152182b805",
    U/"primary-result/actions-artifact-33947031284.zip":"a622c27422d36a9d28302893e4ad9001114bd86e62815aa4f62f3e68918f8a9b",
    U/"primary-result/self-contained-primary.zip":"eb0dcf71ea5ae6b0f40c9899dc8fe3e0e6e54fab84bcc1ee927f44e627f8cf95",
    U/"primary-result/canonical/report.json":"a09e52ac538f8a43646703eeb81e6d5dee36b1e4ad282e54885bb6090169ddb2",
    U/"primary-result/canonical/certificate.json":"75cbdba31eb7717ea3b30f084b3b5f77a05cecbd3eeba26a20cb7f55bf38d418",
    U/"primary-result/canonical/primary-observation.json":"4b0d87ca6be5001ba3fcf552f475748b6ac7769573eb2f28b1325933d3479262",
  }}
  for p,h in expected_hashes.items():
    if sha(p)!=h: die(f"hash mismatch {{p}}")
  primary=load(U/"primary-result/PRIMARY_RESULT.json"); report=load(U/"primary-result/canonical/report.json"); cert=load(U/"primary-result/canonical/certificate.json")
  if primary["status"]!="FROZEN_FIRST_VALID_PRIMARY": die("primary result no longer frozen")
  cp=primary["canonical_primary"]
  if cp["run_id"]!=33947031284 or cp["product_status"]!="PRESERVED_IN_DECLARED_SCOPE" or cp["semantic_exit_code"]!=0: die("canonical primary identity/outcome mismatch")
  if report["product_status"]!="PRESERVED_IN_DECLARED_SCOPE": die("report product status changed")
  if report["structural"]["coverage_complete"] is not False: die("coverage was upgraded")
  if report["exact_realization"]["status"]!="REALIZATION_ESTABLISHED": die("exact realization changed")
  if not all(w["matches"] for w in report["worlds"]): die("bounded world match changed")
  gap=cert["results"]["structural"]["coverage_gap"]
  want={{"in_scope_only":["GUARDED_OCTOKIT_PULLS_MERGE_REVIEWED_HEAD_SHA"],"source_only":["GUARDED_MERGE_REVIEWED_HEAD_SHA"]}}
  if cert["results"]["structural"]["coverage_complete"] is not False or gap!=want: die(f"coverage gap changed: {{gap}}")
  cov=load(U/"post-result/COVERAGE_DIAGNOSTIC.json")
  if cov["status"]!="RETAINED_UNRESOLVED_SCOPE_COVERAGE_IDENTIFIER_NON_EQUIVALENCE" or cov["certificate_coverage_gap"]!=want or cov["coverage_complete"] is not False or cov["primary_bytes_modified"] is not False: die("coverage diagnostic weakens primary")
  fr=load(U/"friction.json")
  if fr["candidate_id"]!="octokit/rest.js::github-version-bound-write" or fr["unit_id"]!="corpus01-unit-002" or fr["primary_result_frozen"] is not True: die("friction identity mismatch")
  rt=fr["phases"]["verification_runtime"]
  if rt["status"]!="COMPLETE" or rt["wall_clock_seconds"]!=0.647976 or rt["active_seconds"]!=0.647976: die("measured runtime changed")
  for n,p in fr["phases"].items():
    if n!="verification_runtime":
      if p["status"]!="BLOCKED": die(f"unmeasured phase promoted: {{n}}")
      if p["wall_clock_seconds"] is not None or p["active_seconds"] is not None: die(f"fabricated timing: {{n}}")
  enr=load(ROOT/"corpus/0.1/ENROLLMENT.json"); u2=next(x for x in enr["units"] if x["unit_id"]=="corpus01-unit-002")
  frozen={{"enrollment_position":2,"candidate_id":"octokit/rest.js::github-version-bound-write","organization":"octokit","stratum":"NON_AGENT_SPECIFIC","mechanism_family":"COMMIT_OR_OBJECT_IDENTITY","target_revision":"cd9cb8cd4965d99c7dac8c87d249308956250be3","screened_operation":"octokit.rest.pulls.merge","verdict_observed_at_enrollment":False}}
  for k,v in frozen.items():
    if u2.get(k)!=v: die(f"enrollment selection identity changed: {{k}}")
  if not u2["authoring_started"] or not u2["authoring_frozen"] or u2["friction_ledger"]!="corpus/0.1/units/002-octokit-pulls-merge/friction.json" or u2.get("authoring_acceptance_path")!="corpus/0.1/units/002-octokit-pulls-merge/AUTHOR_ACCEPTANCE.json": die("Unit002 operational enrollment state not closed")
  for wf in [ROOT/".github/workflows/unit002-r-preprimary-seal.yml",ROOT/".github/workflows/unit002-r-target-qualification.yml"]:
    t=wf.read_text(encoding="utf-8")
    if "pull_request:" in t or "workflow_dispatch:" not in t: die(f"automatic pre-result workflow not retired: {{wf.name}}")
  pre=load(U/"PREMERGE_CLOSURE.json")
  if pre["status"]!="READY_FOR_GUARDED_MERGE" or pre["retained_limitations"]["coverage_complete"] is not False or pre["closure_conditions"]["guarded_pr_merge_still_required"] is not True: die("premerge closure invalid")
  with zipfile.ZipFile(U/"primary-result/self-contained-primary.zip") as z:
    lines=z.read("MANIFEST.sha256").decode().strip().splitlines()
    if len(lines)!=24: die("self-contained manifest entry count changed")
    for line in lines:
      h,relp=line.split("  ",1)
      if hashlib.sha256(z.read(relp)).hexdigest()!=h: die(f"self-contained mismatch: {{relp}}")
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
'''


def make_closure_workflow() -> str:
    return '''name: RISU Unit 002-R closure

on:
  pull_request:
    paths:
      - "corpus/0.1/ENROLLMENT.json"
      - "corpus/0.1/units/002-octokit-pulls-merge/**"
      - "tools/unit002r_closure_verify.py"
      - ".github/workflows/unit002-r-closure.yml"
      - ".github/workflows/unit002-r-preprimary-seal.yml"
      - ".github/workflows/unit002-r-target-qualification.yml"
  push:
    branches: [main]
    paths:
      - "corpus/0.1/ENROLLMENT.json"
      - "corpus/0.1/units/002-octokit-pulls-merge/**"
      - "tools/unit002r_closure_verify.py"
      - ".github/workflows/unit002-r-closure.yml"
      - ".github/workflows/unit002-r-preprimary-seal.yml"
      - ".github/workflows/unit002-r-target-qualification.yml"

permissions:
  contents: read

jobs:
  closure:
    runs-on: ubuntu-latest
    env:
      PYTHONDONTWRITEBYTECODE: "1"
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - name: Validate Corpus protocol and friction ledger
        run: python tools/corpus01_validate.py --json
      - name: Verify Unit 002-R closure invariants
        run: python tools/unit002r_closure_verify.py
      - name: Run protocol-preserving Corpus regression tests
        run: |
          python -m unittest \
            tests.test_corpus01_bound_evidence \
            tests.test_corpus01_unit_harness \
            tests.test_corpus01_primary_v08
'''


def main() -> int:
    head = git("rev-parse", "HEAD").stdout.strip()
    if head != BASE:
        raise RuntimeError(f"scientific branch moved before closure apply: expected={BASE} actual={head}")
    if git("status", "--porcelain").stdout.strip():
        raise RuntimeError("scientific checkout not pristine at closure start")
    assert_primary_immutable()
    verify_inner_bundle()

    primary = load(U / "primary-result/PRIMARY_RESULT.json")
    report = load(U / "primary-result/canonical/report.json")
    cert = load(U / "primary-result/canonical/certificate.json")
    if primary["status"] != "FROZEN_FIRST_VALID_PRIMARY":
        raise RuntimeError("primary result not frozen")
    cp = primary["canonical_primary"]
    if cp["run_id"] != 33947031284 or cp["product_status"] != "PRESERVED_IN_DECLARED_SCOPE" or cp["semantic_exit_code"] != 0:
        raise RuntimeError("canonical primary mismatch")
    if report["product_status"] != "PRESERVED_IN_DECLARED_SCOPE" or report["structural"]["coverage_complete"] is not False:
        raise RuntimeError("primary status/coverage mismatch")
    if [w["matches"] for w in report["worlds"]] != [True, True] or report["exact_realization"]["status"] != "REALIZATION_ESTABLISHED":
        raise RuntimeError("bounded realization mismatch")
    gap = cert["results"]["structural"]["coverage_gap"]
    want = {
        "in_scope_only": ["GUARDED_OCTOKIT_PULLS_MERGE_REVIEWED_HEAD_SHA"],
        "source_only": ["GUARDED_MERGE_REVIEWED_HEAD_SHA"],
    }
    if cert["results"]["structural"]["coverage_complete"] is not False or gap != want:
        raise RuntimeError(f"certificate coverage mismatch: {gap}")

    write(COVERAGE, {
        "schema": "risu.corpus-post-result-coverage-diagnostic/v0.1alpha1",
        "status": "RETAINED_UNRESOLVED_SCOPE_COVERAGE_IDENTIFIER_NON_EQUIVALENCE",
        "unit_id": "corpus01-unit-002",
        "primary_result_freeze_commit": BASE,
        "primary_run_id": 33947031284,
        "primary_product_status": "PRESERVED_IN_DECLARED_SCOPE",
        "primary_semantic_exit_code": 0,
        "coverage_complete": False,
        "certificate_coverage_gap": gap,
        "source_family": ["GUARDED_MERGE_REVIEWED_HEAD_SHA"],
        "target_in_scope": ["GUARDED_OCTOKIT_PULLS_MERGE_REVIEWED_HEAD_SHA"],
        "bounded_world_realization": {"world_count": 2, "all_worlds_match": True, "exact_realization": "REALIZATION_ESTABLISHED", "failure_mode": "NONE"},
        "interpretation": "The bounded two-world guarded-call realization is exact, but the frozen core reports coverage incomplete because the SOURCE family identifier and TARGET in-scope identifier are distinct and no pre-result equivalence mapping was frozen. Closure retains that non-equivalence rather than post-hoc aliasing them.",
        "forbidden_post_result_upgrade": [
            "Do not declare the source-family and target-scope identifiers equivalent after observing the primary result.",
            "Do not rewrite the primary report, certificate, adapter, source contract, manifest, seal, or result freeze.",
            "Do not upgrade PRESERVED_IN_DECLARED_SCOPE to an unqualified PRESERVED claim.",
        ],
        "claim_limits": primary["scientific_result"]["claim_scope"],
        "live_github_service_conformance": "NOT_CLAIMED",
        "general_unguarded_calls": "OUT_OF_SCOPE",
        "primary_bytes_modified": False,
    })

    blocked = "Scientific work for this phase completed, but phase-level wall/active timing was not instrumented prospectively. Measurement completion is therefore marked BLOCKED rather than backfilled with fictitious precision."
    def phase(status, corrections=0, notes=None, wall=None, active=None, automation=None):
        return {"status": status, "wall_clock_seconds": wall, "active_seconds": active, "correction_count": corrections, "notes": notes or [], "automation_opportunities_observed": automation or []}
    write(FRICTION, {
        "ledger_schema": "risu.corpus-friction-ledger/v0.1alpha2",
        "candidate_id": "octokit/rest.js::github-version-bound-write",
        "unit_id": "corpus01-unit-002",
        "status": "CLOSED_MEASUREMENT_PARTIAL_NO_FABRICATED_TIMING",
        "primary_result_frozen": True,
        "measurement_boundary": "Authoring timing was not instrumented from the first Unit 002-R action and is not reconstructed. Only the primary harness runtime is retained as measured telemetry.",
        "phases": {
            "operation_identification": phase("BLOCKED", notes=[blocked]),
            "source_semantic_reconstruction": phase("BLOCKED", notes=[blocked]),
            "boundary_definition": phase("BLOCKED", notes=[blocked]),
            "evidence_acquisition": phase("BLOCKED", notes=[blocked], automation=["dependency-aware provenance traversal"]),
            "version_binding_discovery": phase("BLOCKED", notes=[blocked]),
            "adapter_or_envelope_authoring": phase("BLOCKED", corrections=3, notes=[blocked, "Corrections retained: checksum-pointer bookkeeping, outer adapter protocol label, inner blind-program protocol label."], automation=["separate harness/core protocol namespaces", "mechanically derive all protocol labels from frozen core contract"]),
            "human_correction": phase("BLOCKED", notes=[blocked]),
            "verification_runtime": phase("COMPLETE", wall=0.647976, active=0.647976, notes=["Measured by the canonical v0.8 primary harness only; verifier_seconds=0.471554."]),
        },
        "cross_phase": {
            "tool_calls": None,
            "tool_calls_measured": False,
            "files_authored": None,
            "files_authored_measured": False,
            "evidence_objects_pinned": 6,
            "human_acceptance_events": 1,
            "uncertainties_left_open": [
                "Live GitHub provider conformance is not claimed.",
                "General unguarded Octokit merge calls remain out of scope.",
                "Coverage remains incomplete because SOURCE-family and TARGET-scope identifiers are not predeclared equivalent.",
            ],
            "candidate_automation_not_adopted_yet": [
                "dependency-aware provenance traversal",
                "generated target-only carrier probes",
                "protocol namespace/type separation between harness and frozen scientific core",
                "artifact-role-aware post-result assertions that distinguish canonical files from bundle staging copies",
            ],
        },
        "observed_friction": [
            {"id": "U002R-F01", "class": "EVIDENCE_CHAIN", "observation": "Octokit semantics traverse separately versioned dependency packages.", "automation_candidate": "dependency-aware provenance traversal", "promote_to_infrastructure_now": False},
            {"id": "U002R-F02", "class": "STATIC_TO_OPERATIVE", "observation": "A target-only black-box qualification materially strengthened the carrier claim without live-provider contact or RISU execution.", "automation_candidate": "generated carrier qualification probes", "promote_to_infrastructure_now": False},
            {"id": "U002R-F03", "class": "CHECKSUM_BOOKKEEPING", "observation": "A hand-entered envelope checksum pointer was wrong and the read-only audit stopped execution before primary. Unit 001 had a related bookkeeping-hash failure.", "automation_candidate": "zero-hand-entered scientific-pointer hashes", "promote_to_infrastructure_now": True},
            {"id": "U002R-F04", "class": "PROTOCOL_NAMESPACE_COLLISION", "observation": "Harness v0.8 was mistakenly written into frozen-core adapter/program protocol labels, which actually require 0.7 and 0.5.", "automation_candidate": "typed and separately named harness/core protocol version fields", "promote_to_infrastructure_now": True},
            {"id": "U002R-F05", "class": "SEAL_BOOTSTRAP_CONTAMINATION", "observation": "Audit materialization, pycache, and repo-local tee output dirtied the seal tree until audit/seal runners were physically isolated.", "automation_candidate": "pristine seal runner as first process with temp-only logs", "promote_to_infrastructure_now": True},
            {"id": "U002R-F06", "class": "FILESYSTEM_MODE_TRANSPORT", "observation": "Connector-created Git contents did not preserve the executable bit for risu-verify; byte-identity was verified before mode normalization.", "automation_candidate": "content-hash-first executable-mode normalization helper", "promote_to_infrastructure_now": False},
            {"id": "U002R-F07", "class": "ARTIFACT_ALIAS", "observation": "Post-result glob matched the canonical primary observation and its byte-identical bundle staging copy, making the workflow red after a valid primary.", "automation_candidate": "artifact-role-aware canonical path assertions", "promote_to_infrastructure_now": True},
            {"id": "U002R-F08", "class": "ARCHIVAL_COMPLEXITY", "observation": "The self-contained v0.8 bundle enabled 24/24 internal-manifest verification and exact archive recovery after the wrapper failure.", "automation_candidate": "promote self-contained primary bundle as mandatory corpus primitive", "promote_to_infrastructure_now": True},
            {"id": "U002R-F09", "class": "CLOSURE_OBSERVABILITY", "observation": "The first closure verifier inspected BASE..HEAD only and therefore could not see its own uncommitted candidate surface; v2 unions committed, working-tree, and untracked paths and requires an exact surface.", "automation_candidate": "phase-aware closure verifier over committed+working+untracked state", "promote_to_infrastructure_now": True},
        ],
        "rule": "No missing authoring timing is reconstructed. Automation promotion should distinguish repeated friction from one-off carrier-specific friction.",
    })

    enrollment_before = load(ENR)
    u2_before = next(x for x in enrollment_before["units"] if x["unit_id"] == "corpus01-unit-002")
    frozen = {k: u2_before[k] for k in ["enrollment_position", "unit_id", "candidate_id", "organization", "stratum", "mechanism_family", "target_revision", "screened_operation", "verdict_observed_at_enrollment"]}
    expected_frozen = {
        "enrollment_position": 2,
        "unit_id": "corpus01-unit-002",
        "candidate_id": "octokit/rest.js::github-version-bound-write",
        "organization": "octokit",
        "stratum": "NON_AGENT_SPECIFIC",
        "mechanism_family": "COMMIT_OR_OBJECT_IDENTITY",
        "target_revision": "cd9cb8cd4965d99c7dac8c87d249308956250be3",
        "screened_operation": "octokit.rest.pulls.merge",
        "verdict_observed_at_enrollment": False,
    }
    if frozen != expected_frozen:
        raise RuntimeError(f"pre-update enrollment identity mismatch: {frozen}")
    old = ENR.read_text(encoding="utf-8")
    needle = '      "authoring_started": false,\n      "authoring_frozen": false,\n      "friction_ledger": null\n'
    repl = '      "authoring_started": true,\n      "authoring_frozen": true,\n      "friction_ledger": "corpus/0.1/units/002-octokit-pulls-merge/friction.json",\n      "authoring_acceptance_path": "corpus/0.1/units/002-octokit-pulls-merge/AUTHOR_ACCEPTANCE.json"\n'
    marker = '"candidate_id": "octokit/rest.js::github-version-bound-write"'
    pos = old.index(marker)
    tail = old[pos:]
    if needle not in tail:
        raise RuntimeError("Unit002 operational enrollment block not found")
    ENR.write_text(old[:pos] + tail.replace(needle, repl, 1), encoding="utf-8")
    enrollment_after = load(ENR)
    u2_after = next(x for x in enrollment_after["units"] if x["unit_id"] == "corpus01-unit-002")
    for k, v in expected_frozen.items():
        if u2_after.get(k) != v:
            raise RuntimeError(f"frozen enrollment field changed: {k}")
    for before in enrollment_before["units"]:
        if before["unit_id"] == "corpus01-unit-002":
            continue
        after = next(x for x in enrollment_after["units"] if x["unit_id"] == before["unit_id"])
        if after != before:
            raise RuntimeError(f"non-Unit002 enrollment row changed: {before['unit_id']}")

    retire_pr_trigger(PREPRIMARY, 'on:\n  pull_request:\n    paths:\n      - "corpus/0.1/units/002-octokit-pulls-merge/**"\n      - "tools/unit002r_acceptance_verify.py"\n      - ".github/workflows/unit002-r-preprimary-seal.yml"\n  workflow_dispatch:\n')
    retire_pr_trigger(TARGETQUAL, 'on:\n  pull_request:\n    paths:\n      - "corpus/0.1/units/002-octokit-pulls-merge/**"\n      - "tools/unit002r_octokit_probe.mjs"\n      - ".github/workflows/unit002-r-target-qualification.yml"\n  workflow_dispatch:\n')

    write(PREMERGE, {
        "schema": "risu.corpus-premerge-closure/v0.1alpha2",
        "status": "READY_FOR_GUARDED_MERGE",
        "unit_id": "corpus01-unit-002",
        "canonical_phrase": "Corpus 0.1 — Unit 002-R: READY FOR GUARDED MERGE",
        "primary_result_freeze_commit": BASE,
        "authoring_freeze_commit": "ce4c3a311bcf9f6b74b43af24e8732d1af8fd5ac",
        "sealed_scientific_head": "1f9fba3a270f05d06763a5c81216d2edddffad8b",
        "primary": {
            "run_id": 33947031284,
            "job_id": 101254891951,
            "artifact_id": 9963646702,
            "semantic_exit_code": 0,
            "product_status": "PRESERVED_IN_DECLARED_SCOPE",
            "C": "C1",
            "D": "D1",
            "O": "O1",
            "exact_realization": "REALIZATION_ESTABLISHED",
            "actions_artifact_sha256": "a622c27422d36a9d28302893e4ad9001114bd86e62815aa4f62f3e68918f8a9b",
            "self_contained_bundle_sha256": "eb0dcf71ea5ae6b0f40c9899dc8fe3e0e6e54fab84bcc1ee927f44e627f8cf95",
            "primary_result_sha256": "0d7c940e5f5b1918a9b832644df779a1afb3355d8092cb151ee45d8abbe76351",
            "artifact_index_sha256": "3586a6e6c1307376e0463c6c22a138fc45ab77db9f72d2c64c86d9152182b805",
        },
        "retained_limitations": {
            "coverage_complete": False,
            "coverage_diagnostic": "post-result/COVERAGE_DIAGNOSTIC.json",
            "general_unguarded_calls": "OUT_OF_SCOPE",
            "all_merge_failures": "OUT_OF_SCOPE",
            "live_github_service_conformance": "NOT_CLAIMED",
            "model_relative": True,
            "unqualified_preserved_claim_prohibited": True,
        },
        "history_retained": {
            "invalid_prevalid_toolchain_run": 33946439332,
            "presemantic_mode_gate_stop": 33947000387,
            "failed_closure_v1_run": 33947411380,
            "post_result_wrapper_failure_on_canonical_run": True,
            "canonical_primary_rerun_prohibited": True,
        },
        "closure_conditions": {
            "primary_bytes_immutable_since_result_freeze": True,
            "coverage_gap_retained_without_posthoc_alias": True,
            "friction_closed_without_fabricated_timing": True,
            "enrollment_selection_identity_unchanged": True,
            "preprimary_automatic_workflow_retired": True,
            "target_qualification_automatic_workflow_retired": True,
            "closure_candidate_surface_exactly_checked": True,
            "guarded_pr_merge_still_required": True,
            "authoritative_main_closure_pending_merge_identity": True,
        },
    })
    CLOSURE_TOOL.write_text(make_closure_verifier(), encoding="utf-8")
    CLOSURE_WF.write_text(make_closure_workflow(), encoding="utf-8")

    # Pass 1: uncommitted candidate must be exactly the approved eight-file surface.
    actual = changed_surface()
    if actual != EXPECTED_PREMERGE_PATHS:
        raise RuntimeError(f"candidate surface mismatch before commit: expected={sorted(EXPECTED_PREMERGE_PATHS)} actual={sorted(actual)}")
    assert_primary_immutable()
    run(sys.executable, "tools/corpus01_validate.py", "--json")
    run(sys.executable, "tools/unit002r_closure_verify.py")
    run(sys.executable, "-m", "unittest", "tests.test_corpus01_bound_evidence", "tests.test_corpus01_unit_harness", "tests.test_corpus01_primary_v08")

    # Commit only the approved surface.
    git("add", "--", *sorted(EXPECTED_PREMERGE_PATHS))
    staged = set(git("diff", "--cached", "--name-only").stdout.splitlines())
    if staged != EXPECTED_PREMERGE_PATHS:
        raise RuntimeError(f"staged surface mismatch: {sorted(staged)}")
    git("config", "user.name", "RISU Protocol Bot")
    git("config", "user.email", "protocol-bot@users.noreply.github.com")
    git("commit", "-m", "Close Unit 002-R for guarded merge without rewriting primary")
    closure_head = git("rev-parse", "HEAD").stdout.strip()
    if git("merge-base", BASE, closure_head).stdout.strip() != BASE:
        raise RuntimeError("closure commit is not a descendant of result freeze")

    # Pass 2: committed candidate, clean worktree, same exact surface.
    if git("status", "--porcelain").stdout.strip():
        raise RuntimeError("worktree not clean after closure commit")
    actual2 = changed_surface()
    if actual2 != EXPECTED_PREMERGE_PATHS:
        raise RuntimeError(f"committed surface mismatch: {sorted(actual2)}")
    assert_primary_immutable()
    run(sys.executable, "tools/corpus01_validate.py", "--json")
    run(sys.executable, "tools/unit002r_closure_verify.py")
    run(sys.executable, "-m", "unittest", "tests.test_corpus01_bound_evidence", "tests.test_corpus01_unit_harness", "tests.test_corpus01_primary_v08")

    remote_line = git("ls-remote", "origin", f"refs/heads/{BRANCH}").stdout.strip()
    remote = remote_line.split()[0] if remote_line else ""
    if remote != BASE:
        raise RuntimeError(f"remote scientific branch moved: expected={BASE} actual={remote}")
    git("push", "origin", f"HEAD:refs/heads/{BRANCH}")
    print(json.dumps({
        "status": "COMMITTED_PREMERGE_CLOSURE",
        "base": BASE,
        "closure_head": closure_head,
        "changed_paths": sorted(actual2),
        "primary_result_sha256": sha(U / "primary-result/PRIMARY_RESULT.json"),
        "coverage_complete": False,
        "canonical_primary": "PRESERVED_IN_DECLARED_SCOPE",
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
