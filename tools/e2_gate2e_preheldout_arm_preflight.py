#!/usr/bin/env python3
from __future__ import annotations
import argparse
import json
import os
import subprocess
from pathlib import Path
from typing import Any

MANIFEST_REL = "evaluation/gate2e/PREHELDOUT_ARM_MANIFEST_v0.1.json"
WORKFLOW_REL = ".github/workflows/e2-gate2e-preheldout-arm-preflight.yml"

def canonical(v: Any) -> bytes:
    return (json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()

def git(root: Path, *args: str) -> str:
    cp = subprocess.run(["git", "-C", str(root), *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    if cp.returncode != 0:
        raise RuntimeError("GIT_COMMAND_FAILED:" + " ".join(args))
    return cp.stdout.strip()

def blob_at(root: Path, ref: str, rel: str) -> str:
    return git(root, "rev-parse", f"{ref}:{rel}")

def safe_rel(rel: str) -> bool:
    p = Path(rel)
    return bool(rel) and not p.is_absolute() and ".." not in p.parts

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    root = Path(a.root).resolve(); out = Path(a.out)
    failures: list[str] = []; checks: dict[str, Any] = {}
    def fail(name: str) -> None: failures.append(name)

    try: manifest = json.loads((root / MANIFEST_REL).read_bytes())
    except Exception: manifest = {}; fail("MANIFEST_PARSE")

    allowed_content_reads = {MANIFEST_REL, WORKFLOW_REL, manifest.get("authority", {}).get("protocol_path", ""), manifest.get("authority", {}).get("d0_constitution_path", "")}
    for x in manifest.get("gate2d_exit", {}).values(): allowed_content_reads.add(x.get("path", ""))
    for x in manifest.get("active_b3", {}).values():
        if isinstance(x, dict) and "path" in x: allowed_content_reads.add(x["path"])
    allowed_content_reads.discard("")
    def read_bytes(rel: str) -> bytes:
        if rel not in allowed_content_reads or not safe_rel(rel): raise RuntimeError("NON_ALLOWLISTED_CONTENT_READ")
        return (root / rel).read_bytes()
    def read_json(rel: str) -> dict[str, Any]:
        x=json.loads(read_bytes(rel))
        if not isinstance(x,dict): raise ValueError("EXPECTED_OBJECT")
        return x

    try:
        head=git(root,"rev-parse","HEAD"); parts=git(root,"rev-list","--parents","-n","1","HEAD").split(); parent=parts[1] if len(parts)==2 else None
        checks["head"]=head; checks["sole_parent"]=parent
        checks["implementation_has_exact_sole_parent"]=(len(parts)==2 and parent==manifest["authority"]["required_implementation_parent"])
        if not checks["implementation_has_exact_sole_parent"]: fail("IMPLEMENTATION_PARENT")
    except Exception: fail("IMPLEMENTATION_TOPOLOGY")

    ref_name=os.environ.get("GITHUB_REF_NAME"); checks["github_ref_name"]=ref_name
    checks["required_branch_exact"]=ref_name==manifest.get("authority",{}).get("required_branch")
    if not checks["required_branch_exact"]: fail("BRANCH_IDENTITY")

    expected_tree_files: dict[str,str]={}; auth=manifest.get("authority",{})
    expected_tree_files[auth.get("protocol_path","")]=auth.get("protocol_git_blob","")
    expected_tree_files[auth.get("d0_constitution_path","")]=auth.get("d0_constitution_git_blob","")
    for x in manifest.get("gate2d_exit",{}).values(): expected_tree_files[x["path"]]=x["git_blob"]
    for x in manifest.get("active_b3",{}).values():
        if isinstance(x,dict) and "path" in x and "git_blob" in x: expected_tree_files[x["path"]]=x["git_blob"]
    expected_tree_files.update(manifest.get("frozen_non_b3_files",{}))
    for x in manifest.get("qualified_runtime_adapters",{}).values():
        if isinstance(x,dict) and "path" in x and "git_blob" in x: expected_tree_files[x["path"]]=x["git_blob"]
    identity_mismatches=[]
    for rel,want in sorted(expected_tree_files.items()):
        if not safe_rel(rel) or not want: identity_mismatches.append(rel or "<empty>"); continue
        try: got=blob_at(root,"HEAD",rel)
        except Exception: got=None
        if got!=want: identity_mismatches.append(rel)
    checks["frozen_identity_file_count"]=len(expected_tree_files); checks["frozen_identity_mismatch_count"]=len(identity_mismatches); checks["frozen_identity_mismatches"]=identity_mismatches
    if identity_mismatches: fail("FROZEN_IDENTITY")

    semantic_mismatches=[]; snapshot=auth.get("semantic_snapshot_commit")
    for rel,want in sorted(manifest.get("semantic_snapshot_files",{}).items()):
        try: at_snapshot=blob_at(root,snapshot,rel); at_head=blob_at(root,"HEAD",rel)
        except Exception: at_snapshot=at_head=None
        if at_snapshot!=want or at_head!=want: semantic_mismatches.append(rel)
    checks["semantic_snapshot_file_count"]=len(manifest.get("semantic_snapshot_files",{})); checks["semantic_snapshot_mismatch_count"]=len(semantic_mismatches); checks["semantic_snapshot_mismatches"]=semantic_mismatches
    if semantic_mismatches: fail("SEMANTIC_SNAPSHOT")

    try:
        d1=read_json(manifest["gate2d_exit"]["d1pp"]["path"]); sf=d1.get("scientific_firewall",{})
        ok=d1.get("status")==manifest["gate2d_exit"]["d1pp"]["required_status"] and d1.get("provider_semantic_request_count")==0 and sf.get("epistemic10_read") is False and sf.get("truth_read") is False
        checks["d1pp_pass_exact"]=ok
        if not ok: fail("D1PP_PASS")
    except Exception: fail("D1PP_READ")
    try:
        d2=read_json(manifest["gate2d_exit"]["d2pp"]["path"])
        ok=d2.get("status")=="PASS" and d2.get("case_count")==30 and d2.get("predicate_pass_count")==30 and d2.get("copilot_semantic_request_count")==0 and d2.get("epistemic10_read") is False and d2.get("truth_read") is False and d2.get("fresh_target_read") is False and d2.get("mutation_algebra_opened") is False
        checks["d2pp_30_of_30_exact"]=ok
        if not ok: fail("D2PP_PASS")
    except Exception: fail("D2PP_READ")
    try:
        d3=read_json(manifest["gate2d_exit"]["d3pp"]["path"]); sf=d3.get("scientific_firewall",{}); fi=d3.get("frozen_assertion_implications",{})
        ok=d3.get("status")==manifest["gate2d_exit"]["d3pp"]["required_status"] and sf.get("epistemic10_read") is False and sf.get("truth_read") is False and sf.get("fresh_target_read") is False and sf.get("mutation_algebra_opened") is False and fi.get("both_lanes_exact_model_and_cli_receipts") is True and fi.get("both_lanes_schema_valid_non_BASELINE_INVALID") is True and fi.get("semantic_outcome_values_used_for_gate_decision") is False
        checks["d3pp_pass_exact"]=ok
        if not ok: fail("D3PP_PASS")
    except Exception: fail("D3PP_READ")

    try:
        cfg=read_json(manifest["active_b3"]["config"]["path"]); lanes={k:v.get("model") for k,v in cfg.get("lanes",{}).items()}; transport=cfg.get("transport",{}); isolation=cfg.get("isolation",{})
        ok=lanes==manifest["active_b3"]["lanes"] and transport.get("cli_package")=="@github/copilot" and transport.get("cli_version")=="1.0.83" and transport.get("repository_secret")=="RISU_COPILOT_PERSONAL_TOKEN" and transport.get("semantic_retry_cap")==0 and transport.get("transport_retry_cap")==1 and cfg.get("binding",{}).get("first_semantically_valid_response_is_binding") is True and cfg.get("binding",{}).get("self_consistency") is False and set(isolation.get("tools_denied",[]))=={"shell","write","read","url","memory"} and isolation.get("custom_instructions") is False and isolation.get("remote") is False and isolation.get("remote_export") is False
        checks["active_b3_config_exact"]=ok
        if not ok: fail("ACTIVE_B3_CONFIG")
    except Exception: fail("ACTIVE_B3_CONFIG_READ")
    try:
        reg=read_json(manifest["active_b3"]["registry"]["path"]); got={x.get("id"):x.get("model") for x in reg.get("baselines",[]) if x.get("id") in manifest["active_b3"]["lanes"]}; ok=got==manifest["active_b3"]["lanes"]
        checks["active_b3_registry_exact"]=ok
        if not ok: fail("ACTIVE_B3_REGISTRY")
    except Exception: fail("ACTIVE_B3_REGISTRY_READ")

    adapter_paths=[x["path"] for x in manifest.get("qualified_runtime_adapters",{}).values() if isinstance(x,dict) and "path" in x]
    python_paths=[rel for rel in list(manifest.get("frozen_non_b3_files",{}))+[manifest["active_b3"]["runner"]["path"]]+adapter_paths if rel.endswith(".py")]
    compile_failures=[]
    for rel in sorted(set(python_paths)):
        try: compile((root/rel).read_text(encoding="utf-8"),rel,"exec")
        except Exception: compile_failures.append(rel)
    checks["syntax_checked_python_file_count"]=len(set(python_paths)); checks["syntax_failure_count"]=len(compile_failures); checks["syntax_failures"]=compile_failures
    if compile_failures: fail("FROZEN_PYTHON_SYNTAX")

    try:
        w=read_bytes(WORKFLOW_REL).decode("utf-8"); secret_ref="secrets.RISU_COPILOT_PERSONAL_TOKEN"; secret_lines=[line.strip() for line in w.splitlines() if secret_ref in line]
        no_secret_value_injection=len(secret_lines)==1 and "!= ''" in secret_lines[0] and "COPILOT_GITHUB_TOKEN" not in w
        forbidden_exec_markers=["tools/e2_gate2d_copilot_baseline_v2.py --","tools/e2_gate2d_ablation_shadow.py --","tools/e2_gate2d_baseline_b0_structural.py --","tools/e2_gate2d_baseline_b1_python_ast.py --","tools/e2_gate2d_baseline_b4_execution_diff.py --","tools/e2_gate2d_evaluate.py --","tools/e2_gate2d_check_evaluation.py --","tools/e2_gate2d_evaluate_v3.py --","tools/e2_gate2d_check_evaluation_v3.py --","tools/e2_gate2d_ablation_shadow_v2.py --","--prompt"]
        scientific_execution_surface_absent=not any(x in w for x in forbidden_exec_markers)
        protected_data_enumeration_surface_absent=all(x not in w for x in ["find experiments","find corpus","grep -R","git grep","rglob(","glob("])
        checks["secret_value_injection_surface_absent"]=no_secret_value_injection; checks["scientific_execution_surface_absent"]=scientific_execution_surface_absent; checks["protected_data_enumeration_surface_absent"]=protected_data_enumeration_surface_absent
        if not no_secret_value_injection: fail("SECRET_SURFACE")
        if not scientific_execution_surface_absent: fail("SCIENTIFIC_EXECUTION_SURFACE")
        if not protected_data_enumeration_surface_absent: fail("PROTECTED_ENUMERATION_SURFACE")
    except Exception: fail("WORKFLOW_AUDIT")

    zero=manifest.get("zero_exposure_contract",{}); zero_ok=zero.get("protected_locator_resolution_attempt_count")==0 and zero.get("epistemic10_read") is False and zero.get("truth_read") is False and zero.get("fresh_target_read") is False and zero.get("mutation_algebra_opened") is False and zero.get("full_system_semantic_execution_count_on_epistemic10")==0 and zero.get("baseline_semantic_execution_count_on_epistemic10")==0 and zero.get("ablation_semantic_execution_count_on_epistemic10")==0 and zero.get("raw_source_log_exposure_count")==0 and zero.get("copilot_semantic_request_count")==0
    checks["prospective_zero_exposure_contract_exact"]=zero_ok
    if not zero_ok: fail("ZERO_EXPOSURE_CONTRACT")

    doc={"schema":"risu.e2-gate2e-preheldout-static-preflight/v0.1","status":"PASS" if not failures else "FAIL","failures":sorted(set(failures)),"checks":checks,"scientific_firewall":{"protected_locator_resolution_attempt_count":0,"epistemic10_read":False,"truth_read":False,"fresh_target_read":False,"mutation_algebra_opened":False,"full_system_semantic_execution_count_on_epistemic10":0,"baseline_semantic_execution_count_on_epistemic10":0,"ablation_semantic_execution_count_on_epistemic10":0,"raw_source_log_exposure_count":0,"copilot_semantic_request_count":0,"heldout_case_ids_human_read":False,"heldout_raw_source_human_read":False,"gate2e_scientific_execution_started":False}}
    out.parent.mkdir(parents=True,exist_ok=True); out.write_bytes(canonical(doc)); raise SystemExit(0 if not failures else 2)
if __name__=="__main__": main()
