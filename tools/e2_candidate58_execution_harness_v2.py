#!/usr/bin/env python3
from __future__ import annotations

"""Machine-only Candidate-58 driver with hard upstream-incomplete precedence.

Mechanical only: no A3/A4/CTV predicates are implemented here. Transport or
primary-preparation incompleteness is terminal for the first-complete case and
never enters the primary adapter or C1 lane. Truth/operator/expected labels are
not accepted as inputs.
"""

import argparse, hashlib, json
from pathlib import Path
from typing import Any, Mapping, Sequence

from risu_e2_semantic.adapter_support import _execution_signature
from risu_e2_semantic.candidate58_harness import (
    CASE_OUTPUT_SCHEMA, EXECUTION_RECEIPT_SCHEMA, INCOMPLETE, assemble_outputs,
    execute_prepared_case, identities_from_implementation_freeze,
    make_case_read_receipt, protocol_digests_from_execution_protocol,
    runtime_from_execution_protocol, validate_plan,
)
from risu_e2_semantic.certificate import produce_certificate
from risu_e2_semantic.closed_read_set import ClosedReadSet, load_bootstrap_policy
from risu_e2_semantic.kernel import SLICE_SCHEMA, canonical_bytes, evaluate, sha256_json

EXECUTION_PROTOCOL_SCHEMA="risu.e2-candidate58-first-semantic-execution-protocol/v0.1"
ADMISSION_SCHEMA="risu.e2-sanitized-opaque-58-admission-manifest/v0.1"
BLIND_SCHEMA="risu.e2-blind-58-anchor-transport-bundle/v0.1"
PREP_SCHEMA="risu.e2-candidate58-preparation-receipt/v0.1"
PLACEHOLDER_SCHEMA="risu.e2-candidate58-upstream-incomplete-placeholder/v0.1"
C1_SCHEMA="risu.e2-c1-recheck/v0.1"
UNSUPPORTED="UNSUPPORTED_CERTIFICATE"


def parse(raw: bytes) -> Any: return json.loads(raw.decode("utf-8"))
def sha(raw: bytes) -> str: return hashlib.sha256(raw).hexdigest()
def write(path: Path, value: Any) -> str:
    raw=canonical_bytes(value); path.parent.mkdir(parents=True,exist_ok=True); path.write_bytes(raw); return sha(raw)

def select(rows: Sequence[Mapping[str,Any]], key: str, value: str) -> Mapping[str,Any]:
    found=[r for r in rows if str(r.get(key))==value]
    if len(found)!=1: raise ValueError(f"selection cardinality:{key}:{value}:{len(found)}")
    return found[0]

def admission_map(doc: Mapping[str,Any]) -> dict[str,Mapping[str,Any]]:
    rows=doc.get("cases")
    if doc.get("schema")!=ADMISSION_SCHEMA or doc.get("semantic_authority") is not False or doc.get("case_count")!=58 or not isinstance(rows,list) or len(rows)!=58: raise ValueError("admission mismatch")
    out={str(r.get("transport_case_id")):r for r in rows}
    if len(out)!=58: raise ValueError("admission duplicate")
    return out

def transport_map(doc: Mapping[str,Any]) -> dict[str,Mapping[str,Any]]:
    rows=doc.get("receipts")
    if doc.get("schema")!=BLIND_SCHEMA or doc.get("semantic_authority") is not False or doc.get("case_count")!=58 or not isinstance(rows,list) or len(rows)!=58: raise ValueError("transport mismatch")
    out={str(r.get("transport_case_id")):r for r in rows}
    if len(out)!=58: raise ValueError("transport duplicate")
    return out

def prep_map(doc: Mapping[str,Any]) -> dict[str,Mapping[str,Any]]:
    rows=doc.get("cases")
    if doc.get("schema")!=PREP_SCHEMA or doc.get("status")!="PREPARED_NO_SEMANTIC_VERDICT" or doc.get("case_count")!=58 or not isinstance(rows,list) or len(rows)!=58: raise ValueError("preparation receipt mismatch")
    out={str(r.get("case_id")):r for r in rows}
    if len(out)!=58: raise ValueError("preparation duplicate")
    return out


def upstream_incomplete(*, reason: str, case_id: str, seed_id: str, language: str,
                        source_path: str, source: bytes, signature: Mapping[str,Any],
                        profile: Mapping[str,Any], world: Mapping[str,Any],
                        read_receipt: Mapping[str,Any], protocol_digests: Mapping[str,str],
                        identities: Mapping[str,str]) -> dict[str,Any]:
    ex=_execution_signature(signature,profile,world)
    flags={k:False for k in ("aliases_complete","call_targets_complete","reaching_definitions_complete","branches_complete","representations_complete","effects_complete","exceptions_exits_complete","resources_complete","helper_polarity_complete","all_entry_paths_enumerated")}
    semantic_slice={"schema":SLICE_SCHEMA,"case_id":case_id,"canonical_signature_digest":sha256_json(ex),"language":language,"source_contract":{"path":source_path,"anchors":{}},"source_evidence":[],"bindings":[],"guard":{"form":"UNPROVEN","effective_guard_id":"","effective_guard_count":0,"net_polarity":"UNPROVEN","helper_chain":[],"effect_polarity":ex["guard"]["effect_polarity"],"rejection_polarity":ex["guard"]["rejection_polarity"],"operator":None},"control_paths":[],"effect":{"surfaces":[],"equivalence_proof_id":None,"success_outcome_id":"","rejection_outcome_id":"","effect_before_success_structural":False},"scope":{"scope_id":f"upstream:{case_id}","complete":False,"unresolved":[reason],**flags},"worlds":[]}
    kernel=evaluate(semantic_slice)
    cert=produce_certificate(case_id=case_id,semantic_slice=semantic_slice,source_files={source_path:source},identities=identities,protocol_digests=protocol_digests,canonical_signature_digest=sha256_json(ex),read_set_receipt=read_receipt)
    c1={"schema":C1_SCHEMA,"checker_output":UNSUPPORTED,"machine_prediction":INCOMPLETE,"reasons":[reason],"assurance_level":"NONE","c1_executed":False}
    adapter={"schema":"risu.e2-primary-semantic-slice-adapter-receipt/v0.1","case_id":case_id,"execution_signature":ex,"unresolved":[reason],"semantic_authority":False,"primary_adapter_executed":False}
    record={"schema":CASE_OUTPUT_SCHEMA,"case_id":case_id,"seed_id":seed_id,"language":language,"candidate_source_sha256":sha(source),"machine_prediction":INCOMPLETE,"tentative_kernel_prediction":kernel["prediction"],"c1_checker_output":UNSUPPORTED,"assurance_level":"NONE","promotion_reasons":[reason],"semantic_slice_sha256":sha256_json(semantic_slice),"adapter_receipt_sha256":sha256_json(adapter),"kernel_result_sha256":sha256_json(kernel),"certificate_sha256":sha256_json(cert),"c1_report_sha256":sha256_json(c1),"read_receipt_sha256":sha256_json(read_receipt)}
    return {"record":record,"semantic_slice":semantic_slice,"adapter_receipt":adapter,"kernel_result":kernel,"certificate":cert,"c1_report":c1,"machine_prediction":INCOMPLETE,"promotion_reasons":[reason]}


def main() -> int:
    ap=argparse.ArgumentParser()
    for name in ("capsule-root","read-policy","read-policy-sha256","plan-path","preparation-receipt-path","execution-protocol-path","implementation-freeze-path","admission-manifest-path","blind-transport-path","signature-bundle-path","profile-bundle-path","world-bundle-path","output-dir"): ap.add_argument("--"+name,required=True)
    a=ap.parse_args(); root=Path(a.capsule_root).resolve(strict=True); policy,_=load_bootstrap_policy(Path(a.read_policy),a.read_policy_sha256); guard=ClosedReadSet(root,policy); guard.install_audit_guard()
    protocol=parse(guard.read_bytes(a.execution_protocol_path,purpose="candidate58_execution_protocol")); impl=parse(guard.read_bytes(a.implementation_freeze_path,purpose="gate1b1c_implementation_freeze")); admission=parse(guard.read_bytes(a.admission_manifest_path,purpose="sanitized_candidate58_admission")); transport=parse(guard.read_bytes(a.blind_transport_path,purpose="frozen_blind58_transport")); plan=parse(guard.read_bytes(a.plan_path,purpose="candidate58_prepared_execution_plan")); prep=parse(guard.read_bytes(a.preparation_receipt_path,purpose="candidate58_preparation_receipt")); sigs=parse(guard.read_bytes(a.signature_bundle_path,purpose="frozen_canonical_signature")); profiles=parse(guard.read_bytes(a.profile_bundle_path,purpose="canonical_execution_profile")); worlds=parse(guard.read_bytes(a.world_bundle_path,purpose="declared_finite_worlds"))
    if protocol.get("schema")!=EXECUTION_PROTOCOL_SCHEMA or protocol.get("status")!="PROSPECTIVE_SEALED_NOT_EXECUTED": raise ValueError("protocol mismatch")
    rows=validate_plan(plan); amap=admission_map(admission); tmap=transport_map(transport); pmap=prep_map(prep)
    expected=[r["case_id"] for r in rows]
    if sorted(amap)!=expected or sorted(tmap)!=expected or sorted(pmap)!=expected: raise ValueError("opaque identity-set mismatch")
    if prep.get("plan_sha256")!=sha256_json(plan): raise ValueError("preparation/plan digest mismatch")
    protocol_digests=protocol_digests_from_execution_protocol(protocol); identities=identities_from_implementation_freeze(impl); runtime=runtime_from_execution_protocol(protocol); global_reads=list(guard.reads); out=Path(a.output_dir); outputs=[]
    for row in rows:
        cid=row["case_id"]; admitted=amap[cid]; transport_row=tmap[cid]; prep_row=pmap[cid]
        if str(admitted.get("seed_id"))!=row["seed_id"] or str(admitted.get("language"))!=row["language"] or str(admitted.get("candidate_source_sha256"))!=row["candidate_source_sha256"]: raise ValueError("plan/admission mismatch")
        start=len(guard.reads); source=guard.read_bytes(row["candidate_source_path"],purpose="candidate_source")
        if sha(source)!=row["candidate_source_sha256"]: raise ValueError("candidate source digest mismatch")
        signature=select(sigs.get("signatures",[]),"seed_id",row["seed_id"]); profile=select(profiles.get("profiles",[]),"seed_id",row["seed_id"]); world=select(worlds.get("world_documents",[]),"seed_id",row["seed_id"])
        reason=None
        if transport_row.get("case_transport_status")!="COMPLETE": reason="FROZEN_TRANSPORT_INCOMPLETE_PRECEDENCE"
        elif prep_row.get("preparation_status")!="PREPARED": reason=str(prep_row.get("incomplete_reason") or "PRIMARY_EVIDENCE_INCOMPLETE")
        if reason is not None:
            receipt=make_case_read_receipt(policy_digest_sha256=guard.policy_digest,reads=global_reads+list(guard.reads[start:]),source_path=row["candidate_source_path"])
            item=upstream_incomplete(reason=reason,case_id=cid,seed_id=row["seed_id"],language=row["language"],source_path=row["candidate_source_path"],source=source,signature=signature,profile=profile,world=world,read_receipt=receipt,protocol_digests=protocol_digests,identities=identities)
        else:
            overlay_raw=guard.read_bytes(row["overlay_path"],purpose="primary_overlay"); path_raw=guard.read_bytes(row["path_observability_path"],purpose="primary_path_observability")
            if sha(overlay_raw)!=row["overlay_sha256"] or sha(path_raw)!=row["path_observability_sha256"]: raise ValueError("prepared evidence digest mismatch")
            overlay=parse(overlay_raw); pathdoc=parse(path_raw)
            if overlay.get("schema")==PLACEHOLDER_SCHEMA or pathdoc.get("schema")==PLACEHOLDER_SCHEMA: raise ValueError("prepared status/placeholder disagreement")
            receipt=make_case_read_receipt(policy_digest_sha256=guard.policy_digest,reads=global_reads+list(guard.reads[start:]),source_path=row["candidate_source_path"])
            item=execute_prepared_case(case_id=cid,seed_id=row["seed_id"],language=row["language"],source_path=row["candidate_source_path"],source_bytes=source,overlay=overlay,path_observability=pathdoc,canonical_signature=signature,canonical_profile=profile,worlds_document=world,read_receipt=receipt,protocol_digests=protocol_digests,identities=identities,expected_runtime=runtime)
        case_dir=out/"cases"/cid
        for filename,key in (("semantic_slice.json","semantic_slice"),("adapter_receipt.json","adapter_receipt"),("kernel_result.json","kernel_result"),("certificate.json","certificate"),("c1_report.json","c1_report"),("machine_record.json","record")): write(case_dir/filename,item[key])
        write(case_dir/"read_receipt.json",receipt); outputs.append(item)
    assembled=assemble_outputs(outputs,expected_case_ids=expected); matrix_sha=write(out/"E2_CANDIDATE58_MACHINE_PREDICTION_MATRIX.json",assembled["matrix"]); cert_sha=write(out/"E2_CANDIDATE58_CERTIFICATE_INDEX.json",assembled["certificate_index"]); c1_sha=write(out/"E2_CANDIDATE58_C1_INDEX.json",assembled["c1_index"]); final_guard=guard.receipt(source_paths=[])
    if final_guard.get("forbidden_reads"): raise PermissionError("closed read firewall violation")
    receipt={"schema":EXECUTION_RECEIPT_SCHEMA,"status":"MACHINE_ONLY_COMPLETE_NOT_GOLD_JOINED","case_count":58,"machine_prediction_matrix_sha256":matrix_sha,"certificate_index_sha256":cert_sha,"c1_index_sha256":c1_sha,"runtime_read_policy_digest_sha256":guard.policy_digest,"global_read_receipt_sha256":sha256_json(final_guard),"prepared_plan_sha256":sha256_json(plan),"preparation_receipt_sha256":sha256_json(prep),"scientific_firewall":{"candidate_source_bytes_read":True,"candidate_truth_or_gold_read":False,"expected_e2_prediction_read":False,"mutation_operator_metadata_read":False,"epistemic10_read":False,"fresh_heldout_read":False,"truth_join_executed":False},"upstream_incomplete_never_entered_primary_adapter":True,"first_complete_freeze_performed":False,"next_required_action":"DETERMINISTIC_SECOND_REPLAY_AND_BYTE_IDENTITY_CHECK_THEN_IMMUTABLE_FIRST_COMPLETE_FREEZE_BEFORE_ANY_TRUTH_JOIN"}; receipt["execution_receipt_digest_sha256"]=sha256_json(receipt); write(out/"E2_CANDIDATE58_EXECUTION_RECEIPT.json",receipt)
    print(json.dumps({"status":receipt["status"],"case_count":58,"matrix_sha256":matrix_sha},sort_keys=True,separators=(",",":"))); return 0

if __name__=="__main__": raise SystemExit(main())
