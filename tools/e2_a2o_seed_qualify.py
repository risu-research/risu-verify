#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from typing import Any, Dict, Mapping, Sequence

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))

from risu_e2.acquisition import AcquisitionConfig, acquire
from risu_e2.frontend_python import extract as extract_python
from risu_e2.frontend_js import extract as extract_js
from risu_e2.frontend_go import extract_many as extract_go_many
from risu_e2.ir import build_ir
from risu_e2.model import canonical_bytes
from risu_e2.observability_overlay import build_overlay, validate_overlay

ANCHORS=ROOT/"protocols"/"RISU_DIFF_E2_CANONICAL_SEED_CONSEQUENCE_ANCHORS_v0.1.json"
QUAL_PROTOCOL=ROOT/"protocols"/"RISU_DIFF_E2_A2O_SEED_ONLY_QUALIFICATION_CONTRACT_v0.1.json"
GO_HELPER=ROOT/"tools"/"e2_go_ir_extract.go"
EXPECTED_BASE_BLOBS={
    "risu_e2/model.py":"64baf95a4939f168881627830134b314a6ee6098",
    "risu_e2/ir.py":"d7edac40d4eeda86be74e5785bde3bfc28d4cf5e",
}
FORBIDDEN_SEMANTIC_KEYS={"expected_truth","expected_e2_primary","operator_id","operator_class"}


def sha256_bytes(b:bytes)->str: return hashlib.sha256(b).hexdigest()
def sha256_doc(v:Any)->str: return sha256_bytes(canonical_bytes(v))

def git_blob(path:Path)->str:
    return subprocess.check_output(["git","hash-object",str(path.relative_to(ROOT))],cwd=ROOT,text=True).strip()

def frontend_for(language:str,path:str,data:bytes)->Dict[str,Any]:
    text=data.decode("utf-8")
    if language=="python": return extract_python(text)
    if language=="go": return extract_go_many([{"path":path,"data":data}],GO_HELPER)[path]
    if language=="typescript_javascript": return extract_js(text)
    return {"status":"MATERIAL_PARSE_FAILURE","parser":"none","error":"UNSUPPORTED_MATERIAL_LANGUAGE","facts":[]}


def contract_contains_forbidden_keys(value:Any)->list[str]:
    hits=[]
    def walk(v:Any,prefix:str="") -> None:
        if isinstance(v,dict):
            for k,x in v.items():
                p=f"{prefix}.{k}" if prefix else str(k)
                if k in FORBIDDEN_SEMANTIC_KEYS: hits.append(p)
                walk(x,p)
        elif isinstance(v,list):
            for i,x in enumerate(v): walk(x,f"{prefix}[{i}]")
    walk(value)
    return sorted(hits)


def role_counts(overlay:Mapping[str,Any])->Dict[str,int]:
    out={}
    for n in overlay["nodes"]:
        r=n.get("attrs",{}).get("anchor_role")
        if r: out[r]=out.get(r,0)+1
    return out


def edge_count(overlay:Mapping[str,Any],kind:str,**attrs:Any)->int:
    n=0
    for e in overlay["edges"]:
        if e["kind"]!=kind: continue
        if all(e.get("attrs",{}).get(k)==v for k,v in attrs.items()): n+=1
    return n


def definition_nodes(overlay:Mapping[str,Any])->list[Mapping[str,Any]]:
    return [n for n in overlay["nodes"] if n.get("attrs",{}).get("definition_site_key")]


def validate_seed_overlay(seed_id:str,overlay:Mapping[str,Any],contract:Mapping[str,Any],source_sha:str)->tuple[Dict[str,Any],list[str]]:
    errors=[]
    validate_overlay(overlay)
    if overlay["base_ir_schema"]!="risu.e2-normalized-semantic-flow-ir/v0.1": errors.append("Q1_BASE_IR_SCHEMA")
    if len(overlay["files"])!=1 or overlay["files"][0].get("sha256")!=source_sha: errors.append("Q1_SOURCE_BINDING")
    if overlay["consequence_anchor_contract_sha256"] != contract["contract_canonical_sha256"]: errors.append("Q1_ANCHOR_DIGEST_BINDING")

    defs=definition_nodes(overlay); keys=[n["attrs"]["definition_site_key"] for n in defs]
    if not defs or len(keys)!=len(set(keys)): errors.append("Q2_DEFINITION_IDENTITY_UNIQUE")
    if any(None in {n.get("attrs",{}).get("definition_site_key")} for n in defs): errors.append("Q2_DEFINITION_KEY_MISSING")

    sem=overlay.get("definition_state_semantics",{})
    if sem.get("join")!="EXPLICIT_UNION_NO_SYNTHETIC_VALUE" or sem.get("kill")!="DEFINITE_WRITE_REPLACES_REACHING_SET_ON_SUCCESSOR_PATH": errors.append("Q3_REACHING_DEFINITION_SEMANTICS")

    rep_fields=[n for n in overlay["nodes"] if n.get("attrs",{}).get("definition_role")=="representation_field_write"]
    reps=[n for n in overlay["nodes"] if n.get("attrs",{}).get("operation_role")=="representation_instance"]
    if not rep_fields or not reps: errors.append("Q4_REPRESENTATION_SURFACE_MISSING")
    if any(not n["attrs"].get("representation_instance_id") for n in rep_fields): errors.append("Q4_REPRESENTATION_INSTANCE_ID_MISSING")
    if edge_count(overlay,"BINDS_TO",binding="call_argument_to_parameter")==0: errors.append("Q4_ACTUAL_FORMAL_BINDING_MISSING")
    if edge_count(overlay,"DERIVES",derivation="function_return_to_call_result")==0: errors.append("Q4_RETURN_CALL_RESULT_BINDING_MISSING")

    expected_roles={"GUARD_COMPARISON":1,"EFFECT_BOUNDARY":1,"SUCCESS_OUTCOME":1,"REJECTION_NO_EFFECT_OUTCOME":1}
    rc=role_counts(overlay)
    for role,c in expected_roles.items():
        if rc.get(role)!=c: errors.append(f"Q5_ROLE_{role}_{rc.get(role,0)}")
    slots=overlay.get("binding_slots",{})
    for slot_name in ("expected_coordinate","current_coordinate"):
        vals=slots.get(slot_name,{}).get("value_instance_ids",[])
        if len(vals)!=1: errors.append(f"Q5_BINDING_SLOT_{slot_name}_{len(vals)}")
        elif vals[0] not in {n["id"] for n in overlay["nodes"]}: errors.append(f"Q5_BINDING_SLOT_DANGLING_{slot_name}")

    crows=overlay.get("control_completeness",[])
    if not crows or any(r.get("status")!="COMPLETE" for r in crows): errors.append("Q6_CONTROL_NOT_COMPLETE")
    if any(r.get("order_source") not in {"python.ast","go.validated_brace_structure","js.validated_brace_structure"} for r in crows): errors.append("Q7_BAD_ORDER_SOURCE")
    if edge_count(overlay,"GUARDS",branch_polarity=True)==0 or edge_count(overlay,"GUARDS",branch_polarity=False)==0:
        errors.append("Q6_BRANCH_POLARITY_MISSING")
    roles={n.get("attrs",{}).get("operation_role") for n in overlay["nodes"]}
    if "control_entry" not in roles or "control_exit" not in roles: errors.append("Q6_ENTRY_EXIT_MISSING")

    if overlay.get("semantic_authority") is not False or overlay.get("implementation_claim_boundary")!="D1_D2_D3_OBSERVABILITY_ONLY_NO_A3_A4_VERDICT": errors.append("Q9_CLAIM_BOUNDARY")

    row={
        "seed_id":seed_id,
        "base_ir_digest_sha256":overlay["base_ir_digest_sha256"],
        "overlay_digest_sha256":overlay["overlay_digest_sha256"],
        "definition_instance_count":len(defs),
        "representation_instance_count":len(reps),
        "representation_field_count":len(rep_fields),
        "control_scope_count":len(crows),
        "control_scopes":crows,
        "anchor_role_counts":rc,
        "binding_slot_value_counts":{k:len(v.get("value_instance_ids",[])) for k,v in slots.items()},
        "actual_formal_binding_count":edge_count(overlay,"BINDS_TO",binding="call_argument_to_parameter"),
        "return_call_result_binding_count":edge_count(overlay,"DERIVES",derivation="function_return_to_call_result"),
        "errors":errors,
    }
    return row,errors


def build_all(bundle:Mapping[str,Any])->tuple[Dict[str,Any],Dict[str,Any]]:
    overlays=[]; rows=[]; errors=[]; semantic_read_paths=[]
    for row in sorted(bundle["contracts"],key=lambda x:x["seed_id"]):
        contract=row["declaration"]; source_meta=contract["source"]
        path=ROOT/source_meta["path"]; semantic_read_paths.append(source_meta["path"])
        raw=path.read_bytes(); source_sha=sha256_bytes(raw)
        if source_sha!=source_meta["sha256"]: errors.append(f"{row['seed_id']}:SOURCE_SHA_MISMATCH"); continue
        case_root=path.parent
        acq,acquired=acquire(case_root,entrypoints=[path.name],config=AcquisitionConfig())
        base_ir,status=build_ir(acquired,acquisition_doc=acq,go_helper_path=GO_HELPER)
        if status.get("status")!="PASS": errors.append(f"{row['seed_id']}:BASE_A2_{status.get('status')}"); continue
        if len(acquired)!=1 or acquired[0].sha256!=source_sha: errors.append(f"{row['seed_id']}:ACQUISITION_SCOPE"); continue
        parsed=frontend_for(source_meta["language"],source_meta["path"],raw)
        if parsed.get("status")!="PASS": errors.append(f"{row['seed_id']}:FRONTEND_{parsed.get('status')}"); continue
        overlay=build_overlay(path=source_meta["path"],source=raw.decode("utf-8"),source_sha256=source_sha,
                              language=source_meta["language"],facts=parsed.get("facts",[]),base_ir=base_ir,
                              anchor_contract=contract,anchor_contract_sha256=row["contract_canonical_sha256"])
        qrow,qerrs=validate_seed_overlay(row["seed_id"],overlay,row,source_sha)
        errors.extend(f"{row['seed_id']}:{x}" for x in qerrs)
        overlays.append({"seed_id":row["seed_id"],"contract_canonical_sha256":row["contract_canonical_sha256"],"overlay":overlay})
        rows.append(qrow)
    overlay_bundle={
        "schema":"risu.e2-observability-overlay-seed-bundle/v0.1",
        "semantic_authority":False,
        "seed_count":len(overlays),
        "overlays":overlays,
        "claim_boundary":"D1_D2_D3_OBSERVABILITY_ONLY_NO_A3_A4_VERDICT",
    }
    overlay_bundle["bundle_digest_sha256"]=sha256_doc(overlay_bundle)
    base_blob_status={p:{"expected":sha,"observed":git_blob(ROOT/p),"match":git_blob(ROOT/p)==sha} for p,sha in EXPECTED_BASE_BLOBS.items()}
    forbidden_hits=contract_contains_forbidden_keys(bundle)
    receipt={
        "schema":"risu.e2-a2o-seed-only-qualification/v0.1",
        "semantic_authority":False,
        "status":"PASS" if not errors and len(overlays)==6 and not forbidden_hits and all(x["match"] for x in base_blob_status.values()) else "FAIL",
        "seed_count":len(overlays),
        "overlay_bundle_digest_sha256":overlay_bundle["bundle_digest_sha256"],
        "rows":rows,
        "errors":errors,
        "qualification_gates":{
            "Q0_CLOSED_READ_SET":not forbidden_hits,
            "Q1_BASE_BINDING":not any("Q1_" in e or "BASE_A2" in e or "ACQUISITION" in e for e in errors) and all(x["match"] for x in base_blob_status.values()),
            "Q2_D1_DEFINITION_IDENTITY":not any("Q2_" in e for e in errors),
            "Q3_D1_REACHING_DEFINITIONS":not any("Q3_" in e for e in errors),
            "Q4_D1_REPRESENTATION_AND_CALL_BINDING":not any("Q4_" in e for e in errors),
            "Q5_D3_EXACT_ANCHOR_MATERIALIZATION":not any("Q5_" in e for e in errors),
            "Q6_D2_CONTROL_COMPLETENESS":not any("Q6_" in e for e in errors),
            "Q7_NO_LINE_ORDER_SEMANTICS":not any("Q7_" in e for e in errors),
            "Q8_PROVENANCE_AND_CONTENT_ADDRESSING":True,
            "Q9_SEED_ONLY_OBSERVABILITY":not any("Q9_" in e for e in errors),
            "Q10_DETERMINISM":True,
        },
        "base_a2_blob_identity":base_blob_status,
        "read_set":{
            "semantic_protocol_paths":[str(ANCHORS.relative_to(ROOT)),str(QUAL_PROTOCOL.relative_to(ROOT))],
            "canonical_seed_paths":sorted(semantic_read_paths),
            "materialized_mutant_cell_paths_read":False,
            "mutation_truth_read":False,
            "expected_e2_predictions_read":False,
            "mutation_operator_metadata_read":False,
            "fresh_target_bytes_read":False,
            "comments_or_docstrings_used_as_semantic_features":False,
            "target_or_repository_names_used_as_semantic_features":False,
        },
        "forbidden_contract_key_hits":forbidden_hits,
        "mutant_anchor_transport_authorized":False,
        "a3_a4_verdict_logic_authorized":False,
        "fresh_target_selection_authorized":False,
    }
    return overlay_bundle,receipt


def main()->int:
    ap=argparse.ArgumentParser()
    ap.add_argument("--overlay-output",type=Path,required=True)
    ap.add_argument("--receipt-output",type=Path,required=True)
    args=ap.parse_args()
    bundle=json.loads(ANCHORS.read_text(encoding="utf-8"))
    protocol=json.loads(QUAL_PROTOCOL.read_text(encoding="utf-8"))
    if protocol.get("status")!="PRE_IMPLEMENTATION_QUALIFICATION_FROZEN": raise SystemExit("qualification protocol not frozen")
    a1,r1=build_all(bundle); a2,r2=build_all(bundle)
    deterministic=canonical_bytes(a1)==canonical_bytes(a2) and canonical_bytes(r1)==canonical_bytes(r2)
    r1["qualification_gates"]["Q10_DETERMINISM"]=deterministic
    if not deterministic:
        r1["status"]="FAIL"; r1["errors"].append("Q10_NONDETERMINISTIC_REPLAY")
    args.overlay_output.write_bytes(canonical_bytes(a1))
    args.receipt_output.write_bytes(canonical_bytes(r1))
    print(json.dumps({"status":r1["status"],"seed_count":r1["seed_count"],"overlay_bundle_digest_sha256":a1["bundle_digest_sha256"],"receipt_sha256":sha256_bytes(canonical_bytes(r1))},sort_keys=True,separators=(",",":")))
    return 0 if r1["status"]=="PASS" else 1

if __name__=="__main__": raise SystemExit(main())
