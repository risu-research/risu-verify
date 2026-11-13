"""B33 independent read-only GitHub/Sigstore signed-execution-effect auditor.

Called in a DIFFERENT GitHub Actions job with only read permissions and an
original-source checkout, after the privileged writer job has succeeded.
This verifies GitHub-native commit/file evidence, three official Sigstore
signatures, signer run identities, and event ordering. It does NOT assert a
third-party human approval or hardware-attested runtime instruction trace.
"""
from __future__ import annotations
import base64
from datetime import datetime,timezone,timedelta
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from urllib.parse import quote
from urllib.request import Request,urlopen

REPO="risu-research/risu-verify"
WORKFLOW="p6b33-signed-execution-effect.yml"
REF="refs/heads/qualification/p6b33-signed-execution-effect-live-20261113"
SOURCE_URI=f"https://github.com/{REPO}/.github/workflows/{WORKFLOW}@{REF}"
RESOURCE="benchmarks/p6b33/owner_resource.txt"
STATEMENT="https://in-toto.io/Statement/v1"
PREDICATE="https://slsa.dev/provenance/v1"
ISSUER="https://token.actions.githubusercontent.com"
SHA40=re.compile(r"^[0-9a-f]{40}$")
SHA64=re.compile(r"^[0-9a-f]{64}$")

def need(x,reason):
    if not x:raise RuntimeError("B33_INDEPENDENT_AUDIT_REFUSED_"+reason)
def now(text):
    need(type(text) is str and text.endswith("Z"),"MISSING_UTC_TIMESTAMP")
    try:
        return datetime.fromisoformat(text.replace("Z","+00:00")).astimezone(timezone.utc)
    except ValueError:
        raise RuntimeError("B33_INDEPENDENT_AUDIT_REFUSED_MALFORMED_UTC_TIMESTAMP")
def sha256(data):return hashlib.sha256(data).hexdigest()
def git_blob(data):
    return hashlib.sha1(b"blob "+str(len(data)).encode()+b"\x00"+data).hexdigest()
def strict(data):
    def pairs(items):
        d={}
        for k,v in items:
            need(k not in d,"DUPLICATE_JSON_KEY")
            d[k]=v
        return d
    return json.loads(data,object_pairs_hook=pairs)
def api(endpoint):
    token=os.environ.get("GH_TOKEN")
    need(token and len(token)>12,"READONLY_API_TOKEN_MISSING")
    req=Request("https://api.github.com"+endpoint,headers={
        "Authorization":"Bearer "+token,
        "Accept":"application/vnd.github+json",
        "X-GitHub-Api-Version":"2022-11-28",
        "User-Agent":"RISU-B33-ReadOnly-Auditor"})
    with urlopen(req,timeout=35) as r:
        need(r.status==200,"REMOTE_API_RESULT_INVALID")
        return strict(r.read())
def decode(obj):
    need(type(obj) is dict and obj.get("type")=="file" and
         obj.get("encoding")=="base64","REMOTE_FILE_NOT_CONTENTS_OBJECT")
    text=obj.get("content","")
    need(type(text) is str,"REMOTE_CONTENT_NOT_BASE64")
    text=text.replace("\r","").replace("\n","")
    need(re.fullmatch(r"[A-Za-z0-9+/]*={0,2}",text) is not None,
         "INVALID_BASE64_ALPHABET")
    data=base64.b64decode(text,validate=True)
    need(base64.b64encode(data).decode("ascii")==text and
         len(data)==obj.get("size") and
         git_blob(data)==obj.get("sha"),
         "REMOTE_ORIGINAL_GIT_BLOB_INVALID")
    return data
def gh_native_verified(path,source_sha,run_id):
    cmd=["gh","attestation","verify",str(path),"--repo",REPO,
         "--cert-identity",SOURCE_URI,
         "--cert-oidc-issuer",ISSUER,
         "--source-ref",REF,
         "--predicate-type",PREDICATE,
         "--format","json"]
    last=""
    for attempt in range(5):
        p=subprocess.run(cmd,capture_output=True,text=True,timeout=60)
        if p.returncode==0:
            try:r=strict(p.stdout)
            except Exception:raise RuntimeError("B33_INDEPENDENT_AUDIT_REFUSED_GH_INVALID_SIGNED_RESULT")
            need(type(r) is list and 1<=len(r)<=10,
                 "NO_VERIFIED_SIGSTORE_ATTESTATION")
            matches=[]
            for e in r:
                v=e.get("verificationResult",{})
                cert=v.get("signature",{}).get("certificate",{})
                need(cert.get("issuer")==ISSUER and
                     cert.get("subjectAlternativeName")==SOURCE_URI and
                     cert.get("buildSignerURI")==SOURCE_URI and
                     cert.get("sourceRepositoryURI")==f"https://github.com/{REPO}" and
                     cert.get("sourceRepositoryRef")==REF and
                     cert.get("sourceRepositoryDigest")==source_sha and
                     cert.get("runInvocationURI")==
                      f"https://github.com/{REPO}/actions/runs/{run_id}/attempts/1",
                     "SIGNED_CERT_NOT_ORIGINAL_SOURCE_AND_SAME_RUN")
                st=v.get("statement",{})
                need(st.get("_type")==STATEMENT and st.get("predicateType")==PREDICATE,
                     "SIGNED_SLSA_OR_STATEMENT_INVALID")
                work=st.get("predicate",{}).get("buildDefinition",{}).get("externalParameters",{}).get("workflow",{})
                need(work.get("repository")==f"https://github.com/{REPO}" and
                     work.get("path")==f".github/workflows/{WORKFLOW}" and
                     work.get("ref")==REF,"SIGNED_BUILD_WORKFLOW_WRONG")
                ts=v.get("verifiedTimestamps")
                need(type(ts) is list and ts and
                     type(ts[0].get("timestamp")) is str,
                     "SIGNED_TIME_UNVERIFIED")
                for sub in st.get("subject",[]):
                    if type(sub) is dict and type(sub.get("name")) is str and
                       sub.get("digest",{}).get("sha256")==sha256(path.read_bytes()):
                        matches.append({
                            "attested_name":sub["name"],
                            "sha256":sha256(path.read_bytes()),
                            "signed_at":ts[0]["timestamp"],
                            "signer":SOURCE_URI,
                            "source_sha":source_sha,
                            "run_id":run_id,
                        })
            need(len(matches)==1,"SIGNED_SUBJECT_ABSENT_OR_AMBIGUOUS")
            return matches[0]
        last=(p.stderr or p.stdout)[-280:]
        time.sleep(2)
    raise RuntimeError("B33_INDEPENDENT_AUDIT_REFUSED_GH_SIGNATURE_FAILED "+last)
def main():
    run_text=os.environ.get("GITHUB_RUN_ID")
    source=os.environ.get("GITHUB_SHA")
    need(run_text and run_text.isdecimal() and
         source and SHA40.fullmatch(source) is not None and
         os.environ.get("GITHUB_REPOSITORY")==REPO and
         os.environ.get("GITHUB_REF")==REF,
         "AUDITOR_NOT_ORIGINAL_SOURCE_CONTEXT")
    run_id=int(run_text)
    original=api(f"/repos/{REPO}/actions/runs/{run_id}")
    need(original.get("head_sha")==source and
         original.get("run_attempt")==1 and
         original.get("event")=="push" and
         original.get("head_branch")==REF[len("refs/heads/"):] and
         original.get("status") in ("in_progress","completed") and
         original.get("actor",{}).get("login"),
         "NATIVE_WORKFLOW_RUN_PROVENANCE_MISMATCH")
    actor=original["actor"]["login"]
    jobs=api(f"/repos/{REPO}/actions/runs/{run_id}/jobs?per_page=100")
    writers=[x for x in jobs.get("jobs",[]) if
             x.get("name")=="signed-candidate-execute-one-effect" and
             x.get("conclusion")=="success"]
    need(len(writers)==1,"ORIGINAL_PRIVILEGED_JOB_NOT_COMPLETED_SUCCESSFULLY")
    writer=writers[0]
    jobs_started=now(writer["started_at"])
    jobs_completed=now(writer["completed_at"])
    need(jobs_started<=jobs_completed,"WRITER_JOB_TIME_ORDER_INVALID")
    p=Path(".b33-evidence")
    policy_bytes=Path("benchmarks/p6b33/INTENT.json").read_bytes()
    policy=strict(policy_bytes)
    candidate_path=p/"CANDIDATE_EXECUTION.json"
    receipt_path=p/"EXECUTION_RECEIPT.json"
    candidate=strict(candidate_path.read_bytes())
    receipt=strict(receipt_path.read_bytes())
    need(policy.get("owner_repository")==REPO and
         policy.get("resource_path")==RESOURCE and
         policy.get("execution_ref")==REF,
         "AUTHOR_INTENT_RESOURCE_SCOPE_MISMATCH")
    need(candidate.get("schema")=="risu-b33-signed-readonly-candidate-execution-v1" and
         receipt.get("schema")=="risu-b33-original-run-trusted-broker-effect-receipt-v1",
         "ORIGINAL_CANDIDATE_OR_BROKER_TYPE_MISMATCH")
    for k,val in (("repo",REPO),("run_id",run_id),("attempt",1),("actor",actor)):
        need(candidate.get(k)==val and receipt.get(k)==val,
             "RUNTIME_SIGNER_OR_ACTOR_IDENTITY_CROSS_RUN_MISMATCH")
    need(candidate.get("head_sha")==source and receipt.get("source_sha")==source and
         candidate.get("branch_ref")==REF and receipt.get("branch_ref")==REF,
         "RECEIPT_SOURCE_COMMIT_OR_BRANCH_MISMATCH")
    need(candidate.get("policy_sha256")==sha256(policy_bytes) and
         receipt.get("policy_sha256")==sha256(policy_bytes),
         "OWNER_INTENT_SHA256_NOT_SAME_SOURCE")
    need(receipt.get("candidate_receipt_sha256")==sha256(candidate_path.read_bytes()),
         "ACTUAL_TOOL_EXECUTION_RECEIPT_NOT_BOUND")
    program=Path("benchmarks/p6b33/agent_candidate.py")
    broker=Path("benchmarks/p6b33/trusted_writer.py")
    sigs={
       "candidate_program":gh_native_verified(program,source,run_id),
       "trusted_broker":gh_native_verified(broker,source,run_id),
       "original_execution_receipt":gh_native_verified(receipt_path,source,run_id),
    }
    need(candidate.get("tool_program_sha256")==sigs["candidate_program"]["sha256"] and
         receipt.get("signed_program_sha256")==sigs["candidate_program"]["sha256"] and
         receipt.get("signed_broker_sha256")==sigs["trusted_broker"]["sha256"],
         "SIGNED_PROGRAM_BYTES_NOT_CANDIDATE_AND_EXECUTED_BROKER")
    needs={
       "invoked_at":candidate.get("invoked_at"),
       "returned_at":candidate.get("returned_at"),
       "broker_started_at":receipt.get("broker_started_at"),
       "broker_finished_at":receipt.get("broker_finished_at"),
       "signed_source_at":sigs["candidate_program"]["signed_at"],
       "signed_broker_at":sigs["trusted_broker"]["signed_at"],
       "signed_receipt_at":sigs["original_execution_receipt"]["signed_at"],
    }
    t={key:now(val) for key,val in needs.items()}
    # Signed build precedes reported runtime execution, signed receipt
    # follows broker effect. GitHub native commit time is an external clock.
    need(jobs_started <= t["signed_source_at"]+timedelta(seconds=3) and
         jobs_started <= t["signed_broker_at"]+timedelta(seconds=3) and
         max(t["signed_source_at"],t["signed_broker_at"])
               <=t["invoked_at"]+timedelta(seconds=3) and
         t["invoked_at"]<=t["returned_at"]<=t["broker_started_at"]<=
         t["broker_finished_at"]<=t["signed_receipt_at"]+timedelta(seconds=3) and
         t["signed_receipt_at"] <= jobs_completed+timedelta(seconds=5),
         "SOURCE_EXECUTION_EFFECT_ATTESTATION_TIME_ORDER_INVALID")

    commit_sha=receipt.get("remote_effect_commit")
    need(type(commit_sha) is str and SHA40.fullmatch(commit_sha) is not None,
         "ACTUAL_EFFECT_COMMIT_UNKNOWN")
    effect=api(f"/repos/{REPO}/commits/{commit_sha}")
    parents=effect.get("parents",[])
    need(len(parents)==1 and parents[0].get("sha")==source,
         "ACTUAL_GIT_EFFECT_NOT_DIRECT_DESCENDANT_OF_SIGNED_SOURCE")
    files=effect.get("files",[])
    need(len(files)==1 and files[0].get("filename")==RESOURCE and
         files[0].get("status")=="modified",
         "ACTUAL_COMMIT_MODIFIED_WRONG_OR_ADDITIONAL_RESOURCE")
    expected_before=api(f"/repos/{REPO}/contents/{RESOURCE}?ref={source}")
    expected_after=api(f"/repos/{REPO}/contents/{RESOURCE}?ref={commit_sha}")
    before=decode(expected_before)
    after=decode(expected_after)
    expected=policy["desired_content"].encode("utf-8")
    need(before!=after and after==expected and
         sha256(before)==policy["expected_prior_sha256"] and
         git_blob(before)==policy["expected_prior_git_blob"] and
         sha256(after)==policy["desired_content_sha256"] and
         receipt.get("before_sha256")==sha256(before) and
         receipt.get("after_sha256")==sha256(after) and
         receipt.get("before_git_blob")==git_blob(before) and
         receipt.get("after_git_blob")==git_blob(after) and
         files[0].get("sha")==git_blob(after),
         "INDEPENDENT_REMOTE_ACTUAL_RESOURCE_BYTES_NOT_INTENT")
    commit_time=now(effect["commit"]["committer"]["date"])
    need(t["invoked_at"]-timedelta(minutes=2)<=commit_time<=
         t["broker_finished_at"]+timedelta(minutes=2) and
         jobs_started-timedelta(seconds=5)<=commit_time<=
         jobs_completed+timedelta(minutes=2),
         "REMOTE_GIT_COMMIT_TIME_OUTSIDE_ORIGINAL_EXECUTION")
    need(receipt.get("approval_tier")==
         "GITHUB_WORKFLOW_PLATFORM_REPOSITORY_WRITE_AUTHORITY_NO_INDEPENDENT_HUMAN_REVIEW" and
         receipt.get("human_owner_approval_proven") is False and
         receipt.get("candidate_write_token_available") is False and
         receipt.get("trusted_broker_write_token_scope")==
           "REPOSITORY_CONTENTS_WRITE_NOT_FILE_SCOPED",
         "BROKER_FALSE_OWNER_OR_EXCESSIVE_SCOPE_CLAIM")
    report={
      "schema":"risu-b33-live-source-execution-effect-readonly-audit-v1",
      "status":"SIGNED_SOURCE_RUN_BOUND_TO_PLATFORM_AUTHORIZED_ONE_FILE_GIT_EFFECT",
      "assurance":"GITHUB_RUNNER_REPORTED_EXECUTION_PLUS_NATIVE_SIGSTORE_AND_INDEPENDENT_GIT_EFFECT_NOT_TEE",
      "repository":REPO,"run_id":run_id,"attempt":1,
      "native_run_actor":actor,"native_writer_job_id":writer["id"],
      "source_commit":source,
      "native_effect_commit":commit_sha,
      "resource_path":RESOURCE,
      "exact_one_original_git_file_modified":True,
      "source_signatures":sigs,
      "original_times":{**needs,
                         "native_git_commit_time":effect["commit"]["committer"]["date"],
                         "native_writer_job_started":writer["started_at"],
                         "native_writer_job_completed":writer["completed_at"]},
      "original_before_sha256":sha256(before),
      "original_after_sha256":sha256(after),
      "candidate_receipt_sha256":sha256(candidate_path.read_bytes()),
      "signed_original_execution_receipt_sha256":sha256(receipt_path.read_bytes()),
      "platform_write_actor_authorized_by_workflow":True,
      "independently_authorized_human_owner":False,
      "repository_wide_token_not_file_scoped":True,
      "genuine_execute_by_signer_proven":False,
      "no_cross_run_or_cross_resource_evidence_accepted":True,
      "limits":[
        "GitHub Actions runner and its self-reported process invocation, timestamp and privileged broker steps are trusted; no TEE or independent hardware instruction trace",
        "GitHub Contents token is repository scoped; broker code imposes exact path and bytes",
        "Both the original signer and policy belong to the test organization's workflow; no independent human resource owner signed intent",
        "A signed execution receipt is a genuine attestation of a runner assertion, not independent proof the runtime action occurred; GitHub Git commit is checked separately",
      ],
    }
    out=Path(".b33-audit")
    out.mkdir(parents=True,exist_ok=True)
    with (out/"INDEPENDENT_ORIGINAL_SIGNED_EXECUTION_EFFECT_AUDIT.json").open("x",encoding="utf-8") as f:
        json.dump(report,f,sort_keys=True,indent=2)
        f.write("\n")
    print("B33_ORIGINAL_REAL_SIGSTORE_SOURCE_CANDIDATE_BROKER_RECEIPT_SIGNATURES_PASS",flush=True)
    print("B33_ACTUAL_READONLY_GITHUB_REMOTE_EXACT_ONE_FILE_BYTES_AND_PARENT_PASS",flush=True)
    print("B33_NATIVE_TIMES_AND_SIGNED_RUN_ACTOR_BINDING_PASS",flush=True)
    print("B33_ZERO_UNSUPPORTED_INDEPENDENT_HUMAN_OR_TEE_CLAIM_PASS",flush=True)
    return 0

if __name__=="__main__":
    raise SystemExit(main())
