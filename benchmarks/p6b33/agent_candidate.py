"""B33 read-only candidate: generate an exact resource change proposal.

This process is deliberately run WITHOUT GH_TOKEN, before a privileged
trusted broker handles the result. Attesting this program's digest is
only build/source provenance, not a separate owner's write permission.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys

SCHEMA="risu-b33-signed-readonly-candidate-execution-v1"

def sha256(data:bytes)->str:
    return hashlib.sha256(data).hexdigest()

def now()->str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00","Z")

def main()->int:
    parser=argparse.ArgumentParser()
    parser.add_argument("--intent",required=True)
    parser.add_argument("--out",required=True)
    a=parser.parse_args()
    if "GH_TOKEN" in os.environ or "GITHUB_TOKEN" in os.environ:
        raise RuntimeError("UNTRUSTED_CANDIDATE_MUST_NOT_RECEIVE_GITHUB_WRITE_TOKEN")
    expected_repo="risu-research/risu-verify"
    expected_path="benchmarks/p6b33/owner_resource.txt"
    started=now()
    source=Path(__file__).resolve()
    source_digest=sha256(source.read_bytes())
    intent_path=Path(a.intent)
    intent_bytes=intent_path.read_bytes()
    intent=json.loads(intent_bytes)
    if intent.get("owner_repository")!=expected_repo or intent.get("resource_path")!=expected_path:
        raise RuntimeError("CANDIDATE_OUT_OF_FIXED_SCOPE")
    desired=intent["desired_content"].encode("utf-8")
    if sha256(desired)!=intent.get("desired_content_sha256"):
        raise RuntimeError("CANDIDATE_DESIRED_CONTENT_NOT_HASH_BOUND")
    if intent.get("source_program")!="benchmarks/p6b33/agent_candidate.py":
        raise RuntimeError("CANDIDATE_PROGRAM_PATH_NOT_BOUND")
    repo=os.environ.get("GITHUB_REPOSITORY")
    run=os.environ.get("GITHUB_RUN_ID")
    sha=os.environ.get("GITHUB_SHA")
    actor=os.environ.get("GITHUB_ACTOR")
    attempt=os.environ.get("GITHUB_RUN_ATTEMPT","1")
    ref=os.environ.get("GITHUB_REF")
    if (repo!=expected_repo or not run or not run.isdecimal() or
        not sha or len(sha)!=40 or not actor or
        attempt!="1" or ref!=intent.get("execution_ref")):
        raise RuntimeError("CANDIDATE_NOT_ORIGINAL_RUN_CONTEXT")
    output=Path(a.out)
    if output.exists() or not output.parent.is_dir():
        raise RuntimeError("CANDIDATE_OUTPUT_ALREADY_EXISTS_OR_MISSING_PARENT")
    completed=now()
    receipt={
      "schema":SCHEMA,
      "repo":repo,"run_id":int(run),"attempt":int(attempt),"actor":actor,
      "head_sha":sha,"branch_ref":ref,
      "tool_program":"benchmarks/p6b33/agent_candidate.py",
      "tool_program_sha256":source_digest,
      "policy_sha256":sha256(intent_bytes),
      "resource_path":expected_path,
      "expected_prior_sha256":intent["expected_prior_sha256"],
      "desired_sha256":intent["desired_content_sha256"],
      "invoked_at":started,"returned_at":completed,
      "runtime_pid":os.getpid(),
      "tool_write_credential_available":False,
      "semantics":"candidate made a request; a separate fixed broker may refuse or write",
    }
    with output.open("x",encoding="utf-8") as f:
        json.dump(receipt,f,indent=2,sort_keys=True)
        f.write("\n")
    print("B33_UNPRIVILEGED_SIGNED_CANDIDATE_EXECUTED",source_digest,flush=True)
    return 0
if __name__=="__main__":
    raise SystemExit(main())
