"""B33 trusted GitHub Contents broker, exact one-file demonstrator.

The repo-scoped GitHub Actions write token is available ONLY to this fixed
broker step. In particular, the signed candidate process has NO token.
This is controlled platform authorization, NOT separate human owner consent.
"""
from __future__ import annotations
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from urllib.parse import quote
from urllib.request import Request, urlopen

REPO="risu-research/risu-verify"
PATH="benchmarks/p6b33/owner_resource.txt"
PROGRAM="benchmarks/p6b33/agent_candidate.py"
BROKER="benchmarks/p6b33/trusted_writer.py"
SOURCE_PATTERN=re.compile(r"^[0-9a-f]{40}$")
DIGEST_PATTERN=re.compile(r"^[0-9a-f]{64}$")

def now():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00","Z")

def sha256(data):
    return hashlib.sha256(data).hexdigest()

def git_blob(data):
    return hashlib.sha1(b"blob "+str(len(data)).encode()+b"\x00"+data).hexdigest()

def need(ok,message):
    if not ok:
        raise RuntimeError("B33_BROKER_REFUSED_"+message)

def strict_json(data):
    def pairs(items):
        out={}
        for key,val in items:
            need(key not in out,"DUPLICATE_JSON_KEY")
            out[key]=val
        return out
    return json.loads(data,object_pairs_hook=pairs)

def api(method,endpoint,token,body=None):
    headers={
        "Accept":"application/vnd.github+json",
        "Authorization":"Bearer "+token,
        "X-GitHub-Api-Version":"2022-11-28",
        "User-Agent":"RISU-Probe-B33-Trusted-Broker",
    }
    req=Request("https://api.github.com"+endpoint,
          data=json.dumps(body).encode("utf-8") if body is not None else None,
          headers=headers,method=method)
    with urlopen(req,timeout=35) as r:
        need(r.status in (200,201),"GITHUB_API_STATUS")
        return strict_json(r.read())

def decode_contents(obj):
    need(type(obj) is dict and obj.get("type")=="file" and
         obj.get("encoding")=="base64","REMOTE_CONTENTS_INVALID")
    raw=obj.get("content")
    need(type(raw) is str,"MISSING_REMOTE_FILE_BYTES")
    text=raw.replace("\n","").replace("\r","")
    need(re.fullmatch(r"[A-Za-z0-9+/]*={0,2}",text) is not None,
         "MALFORMED_GITHUB_BASE64")
    decoded=base64.b64decode(text,validate=True)
    need(base64.b64encode(decoded).decode("ascii")==text,
         "NONCANONICAL_GITHUB_BASE64")
    need(len(decoded)==obj.get("size") and git_blob(decoded)==obj.get("sha"),
         "REMOTE_BLOB_DIGEST_MISMATCH")
    return decoded

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--intent",required=True)
    ap.add_argument("--candidate",required=True)
    ap.add_argument("--out",required=True)
    args=ap.parse_args()
    token=os.environ.get("GH_TOKEN")
    need(type(token) is str and len(token)>12,
         "TRUSTED_BROKER_GITHUB_TOKEN_MISSING")
    start=now()
    policy_data=Path(args.intent).read_bytes()
    policy=strict_json(policy_data)
    candidate=strict_json(Path(args.candidate).read_bytes())
    repo=os.environ.get("GITHUB_REPOSITORY")
    head=os.environ.get("GITHUB_SHA")
    run=os.environ.get("GITHUB_RUN_ID")
    attempt=os.environ.get("GITHUB_RUN_ATTEMPT")
    actor=os.environ.get("GITHUB_ACTOR")
    branch=os.environ.get("GITHUB_REF")
    need(repo==REPO and head and SOURCE_PATTERN.fullmatch(head) is not None,
         "UNEXPECTED_EXECUTION_REPOSITORY_OR_SOURCE")
    need(run and run.isdecimal() and attempt=="1" and actor and
         branch and branch.startswith("refs/heads/"),
         "ORIGINAL_RUN_ID_OR_ACTOR_MISSING")
    need(policy.get("schema")=="risu-b33-local-platform-authorized-source-effect-intent-v1" and
         policy.get("owner_repository")==REPO and
         policy.get("execution_ref")==branch and
         policy.get("resource_path")==PATH and
         policy.get("source_program")==PROGRAM and
         policy.get("trusted_broker")==BROKER,
         "RESOURCE_OR_SOURCE_OUTSIDE_FIXED_SCOPE")
    need(policy.get("approval_tier")==
         "GITHUB_WORKFLOW_PLATFORM_REPOSITORY_WRITE_AUTHORITY_NO_INDEPENDENT_HUMAN_REVIEW",
         "FALSE_HUMAN_OWNER_ASSERTION")
    need(policy.get("exact_one_effect_commit") is True,"UNBOUNDED_EFFECT_INTENT")
    desired=policy.get("desired_content")
    need(type(desired) is str and
         sha256(desired.encode("utf-8"))==policy.get("desired_content_sha256"),
         "DESIRED_BYTES_NOT_PREAUTHORIZED")
    need(DIGEST_PATTERN.fullmatch(policy.get("expected_prior_sha256","")) is not None and
         re.fullmatch(r"[0-9a-f]{40}",policy.get("expected_prior_git_blob","")) is not None,
         "PRESTATE_HASHES_NOT_PINNED")

    program_bytes=Path(PROGRAM).read_bytes()
    broker_bytes=Path(BROKER).read_bytes()
    candidate_digest=sha256(program_bytes)
    broker_digest=sha256(broker_bytes)
    need(candidate.get("schema")=="risu-b33-signed-readonly-candidate-execution-v1" and
         candidate.get("repo")==REPO and
         candidate.get("head_sha")==head and
         candidate.get("run_id")==int(run) and
         candidate.get("attempt")==1 and
         candidate.get("actor")==actor and
         candidate.get("branch_ref")==branch and
         candidate.get("tool_program")==PROGRAM and
         candidate.get("tool_program_sha256")==candidate_digest and
         candidate.get("policy_sha256")==sha256(policy_data) and
         candidate.get("resource_path")==PATH and
         candidate.get("expected_prior_sha256")==policy["expected_prior_sha256"] and
         candidate.get("desired_sha256")==policy["desired_content_sha256"] and
         candidate.get("tool_write_credential_available") is False,
         "CANDIDATE_RUN_OR_SIGNED_DIGEST_NOT_BOUND")
    # Actual times are runner self-reported; independent audit separately
    # checks GitHub's native job and commit timestamps.
    for x in ("invoked_at","returned_at"):
        need(type(candidate.get(x)) is str and candidate[x].endswith("Z"),
             "EXECUTION_TIMESTAMPS_MISSING")
    need(candidate["invoked_at"]<=candidate["returned_at"]<=start,
         "RUNTIME_EXECUTION_TIME_REVERSED")

    out=Path(args.out)
    need(not out.exists() and out.parent.is_dir(),"EFFECT_RECEIPT_PATH_REFUSED")
    ref=branch[len("refs/heads/"):]
    remote_ref=api("GET",f"/repos/{REPO}/git/ref/heads/"+quote(ref,safe="/"),token)
    need(remote_ref.get("object",{}).get("sha")==head,
         "BRANCH_MOVED_SINCE_SIGNED_ORIGINAL_SOURCE")
    target_endpoint=f"/repos/{REPO}/contents/{PATH}"
    before=api("GET",target_endpoint+"?ref="+quote(ref,safe=""),token)
    old=decode_contents(before)
    need(sha256(old)==policy["expected_prior_sha256"] and
         before.get("sha")==policy["expected_prior_git_blob"],
         "RESOURCE_PRESTATE_NOT_PREAUTHORIZED")
    need(old!=desired.encode("utf-8"),"RESOURCE_EFFECT_ALREADY_APPLIED")

    payload={
        "message":"B33: signed candidate executed, trusted broker one-file Github effect",
        "content":base64.b64encode(desired.encode("utf-8")).decode("ascii"),
        "sha":before["sha"],
        "branch":ref,
    }
    written=api("PUT",target_endpoint,token,payload)
    commit=written.get("commit",{})
    need(type(commit.get("sha")) is str and
         SOURCE_PATTERN.fullmatch(commit["sha"]) is not None and
         written.get("content",{}).get("sha")==git_blob(desired.encode("utf-8")),
         "ACTUAL_REMOTE_PUT_RESULT_NOT_ORIGINAL_DESIRED_BLOB")
    # Independent read-only audit checks remote commit ancestry and target.
    receipt={
       "schema":"risu-b33-original-run-trusted-broker-effect-receipt-v1",
       "status":"BROKER_REPORTED_ACTUAL_GITHUB_CONTENTS_PUT_201",
       "approval_tier":policy["approval_tier"],
       "repo":REPO,"run_id":int(run),"attempt":1,"actor":actor,
       "source_sha":head,"branch_ref":branch,
       "source_program":PROGRAM,"signed_program_sha256":candidate_digest,
       "trusted_broker":BROKER,"signed_broker_sha256":broker_digest,
       "policy_sha256":sha256(policy_data),
       "candidate_receipt_sha256":sha256(Path(args.candidate).read_bytes()),
       "resource_path":PATH,
       "before_sha256":sha256(old),"before_git_blob":git_blob(old),
       "after_sha256":sha256(desired.encode("utf-8")),
       "after_git_blob":git_blob(desired.encode("utf-8")),
       "remote_effect_commit":commit["sha"],
       "tool_invoked_at":candidate["invoked_at"],
       "tool_returned_at":candidate["returned_at"],
       "broker_started_at":start,
       "broker_finished_at":now(),
       "github_effect_method":"PUT",
       "candidate_write_token_available":False,
       "trusted_broker_write_token_scope":"REPOSITORY_CONTENTS_WRITE_NOT_FILE_SCOPED",
       "signer_and_runner_assurance":"GITHUB_ACTIONS_SIGNED_SOURCE_AND_SIGNED_RUNNER_CLAIM_NO_TEE",
       "human_owner_approval_proven":False,
    }
    with out.open("x",encoding="utf-8") as f:
        json.dump(receipt,f,indent=2,sort_keys=True)
        f.write("\n")
    print("B33_ACTUAL_SINGLE_GITHUB_CONTENTS_PUT_EFFECT_COMMIT",commit["sha"],flush=True)
    return 0

if __name__=="__main__":
    raise SystemExit(main())
