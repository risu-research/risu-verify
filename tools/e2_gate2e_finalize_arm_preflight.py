#!/usr/bin/env python3
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

def canonical(v: Any) -> bytes:
    return (json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()

def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""): h.update(chunk)
    return h.hexdigest()

def load(path: Path) -> dict[str, Any]:
    x=json.loads(path.read_bytes())
    if not isinstance(x,dict): raise ValueError("EXPECTED_OBJECT")
    return x

def main() -> None:
    ap=argparse.ArgumentParser(); ap.add_argument("--artifact-dir",required=True); a=ap.parse_args(); root=Path(a.artifact_dir).resolve(); failures=[]
    required={"STATIC_PREFLIGHT.json","HOSTED_CONTEXT.json","CREDENTIAL_READINESS.json","COPILOT_CLI_READINESS.json","CODEQL_READINESS.json"}
    missing=sorted(x for x in required if not (root/x).is_file())
    if missing: failures.append("MISSING_REQUIRED_READINESS_ARTIFACT")
    docs={}
    for name in sorted(required-set(missing)):
        try: docs[name]=load(root/name)
        except Exception: failures.append("MALFORMED:"+name)
    static=docs.get("STATIC_PREFLIGHT.json",{}); cred=docs.get("CREDENTIAL_READINESS.json",{}); cli=docs.get("COPILOT_CLI_READINESS.json",{}); codeql=docs.get("CODEQL_READINESS.json",{})
    if static.get("status")!="PASS" or static.get("failures")!=[]: failures.append("STATIC_PREFLIGHT_NOT_PASS")
    sf=static.get("scientific_firewall",{})
    zero_firewall=sf.get("protected_locator_resolution_attempt_count")==0 and sf.get("epistemic10_read") is False and sf.get("truth_read") is False and sf.get("fresh_target_read") is False and sf.get("mutation_algebra_opened") is False and sf.get("full_system_semantic_execution_count_on_epistemic10")==0 and sf.get("baseline_semantic_execution_count_on_epistemic10")==0 and sf.get("ablation_semantic_execution_count_on_epistemic10")==0 and sf.get("raw_source_log_exposure_count")==0 and sf.get("copilot_semantic_request_count")==0 and sf.get("heldout_case_ids_human_read") is False and sf.get("heldout_raw_source_human_read") is False and sf.get("gate2e_scientific_execution_started") is False
    if not zero_firewall: failures.append("ZERO_EXPOSURE_FIREWALL_NOT_EXACT")
    if not (cred.get("credential_present_boolean") is True and cred.get("credential_value_injected_into_preflight_process") is False and cred.get("credential_value_logged") is False and cred.get("credential_value_artifacted") is False): failures.append("CREDENTIAL_READINESS_NOT_PASS")
    if not (cli.get("status")=="PASS" and cli.get("semantic_request_count")==0 and cli.get("version_exact") is True and cli.get("npm_integrity_exact") is True): failures.append("COPILOT_CLI_NOT_PASS")
    if not (codeql.get("status")=="PASS" and codeql.get("asset_sha256_exact") is True and codeql.get("version_exact") is True and codeql.get("queries_repo_commit_exact") is True and codeql.get("synthetic_database_create_pass") is True and codeql.get("synthetic_analysis_pass") is True and codeql.get("network_during_synthetic_analysis") is False): failures.append("CODEQL_READINESS_NOT_PASS")
    summary={"schema":"risu.e2-gate2e-preheldout-arm-preflight-summary/v0.1","status":"PASS" if not failures else "FAIL","failures":sorted(set(failures)),"authorization_effect":{"gate2e_armed_by_this_artifact_alone":False,"heldout_open_authorized_by_this_artifact_alone":False,"required_next_if_pass":"FREEZE_PREHELDOUT_ARM_RECEIPT_PASS_ON_E2_DEVELOPMENT_AUTHORITY"},"readiness":{"static_identity_and_firewall_pass":static.get("status")=="PASS" and static.get("failures")==[],"personal_copilot_credential_boolean_ready":cred.get("credential_present_boolean") is True,"copilot_cli_exact_and_no_semantic_request":cli.get("status")=="PASS" and cli.get("semantic_request_count")==0,"codeql_exact_bundle_queries_and_synthetic_offline_runtime_ready":codeql.get("status")=="PASS"},"scientific_firewall":{"protected_locator_resolution_attempt_count":0,"epistemic10_read":False,"truth_read":False,"fresh_target_read":False,"mutation_algebra_opened":False,"full_system_semantic_execution_count_on_epistemic10":0,"baseline_semantic_execution_count_on_epistemic10":0,"ablation_semantic_execution_count_on_epistemic10":0,"raw_source_log_exposure_count":0,"copilot_semantic_request_count":0,"heldout_case_ids_human_read":False,"heldout_raw_source_human_read":False,"gate2e_scientific_execution_started":False}}
    (root/"ARM_PREFLIGHT_SUMMARY.json").write_bytes(canonical(summary))
    entries=[]
    for p in sorted(x for x in root.rglob("*") if x.is_file() and x.name!="FILE_MANIFEST.json"):
        entries.append({"path":p.relative_to(root).as_posix(),"size":p.stat().st_size,"sha256":sha256_file(p)})
    fm={"schema":"risu.e2-gate2e-preheldout-arm-artifact-manifest/v0.1","file_count":len(entries),"files":entries,"credential_bytes_available_to_manifest_builder":False,"raw_heldout_source_artifacted":False,"semantic_output_artifacted":False}
    (root/"FILE_MANIFEST.json").write_bytes(canonical(fm)); raise SystemExit(0)
if __name__=="__main__": main()
