#!/usr/bin/env python3
from __future__ import annotations

"""Machine-only Candidate-58 driver for the prospectively sealed Gate 1D lane.

DO NOT run this during harness qualification.  The qualification workflow uses
synthetic fixtures only.  Production invocation requires a separately frozen
closed read policy and prepared evidence plan.
"""

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from risu_e2_semantic.candidate58_harness import (
    EXECUTION_RECEIPT_SCHEMA,
    INCOMPLETE,
    assemble_outputs,
    execute_prepared_case,
    identities_from_implementation_freeze,
    make_case_read_receipt,
    protocol_digests_from_execution_protocol,
    runtime_from_execution_protocol,
    validate_plan,
)
from risu_e2_semantic.closed_read_set import ClosedReadSet, load_bootstrap_policy
from risu_e2_semantic.kernel import canonical_bytes, sha256_json

EXECUTION_PROTOCOL_SCHEMA = "risu.e2-candidate58-first-semantic-execution-protocol/v0.1"
ADMISSION_SCHEMA = "risu.e2-sanitized-opaque-58-admission/v0.1"
BLIND_SCHEMA = "risu.e2-blind-58-anchor-transport-bundle/v0.1"


def _json(raw: bytes) -> Any:
    return json.loads(raw.decode("utf-8"))


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _write(path: Path, value: Any) -> str:
    raw = canonical_bytes(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    return _sha(raw)


def _select(rows: list[Mapping[str, Any]], key: str, value: str) -> Mapping[str, Any]:
    found = [x for x in rows if str(x.get(key)) == value]
    if len(found) != 1:
        raise ValueError(f"selection cardinality:{key}:{value}:{len(found)}")
    return found[0]


def _admission_map(doc: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    if doc.get("schema") != ADMISSION_SCHEMA or doc.get("case_count") != 58 or doc.get("semantic_authority") is not False:
        raise ValueError("sanitized admission authority mismatch")
    rows = doc.get("cases")
    if not isinstance(rows, list) or len(rows) != 58:
        raise ValueError("sanitized admission cardinality mismatch")
    out = {str(x.get("transport_case_id")):x for x in rows}
    if len(out) != 58:
        raise ValueError("sanitized admission duplicate identity")
    return out


def _transport_map(doc: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    if doc.get("schema") != BLIND_SCHEMA or doc.get("case_count") != 58 or doc.get("semantic_authority") is not False:
        raise ValueError("blind transport authority mismatch")
    rows = doc.get("receipts")
    if not isinstance(rows, list) or len(rows) != 58:
        raise ValueError("blind transport cardinality mismatch")
    out = {str(x.get("transport_case_id")):x for x in rows}
    if len(out) != 58:
        raise ValueError("blind transport duplicate identity")
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo-root", required=True)
    ap.add_argument("--read-policy", required=True)
    ap.add_argument("--read-policy-sha256", required=True)
    ap.add_argument("--plan-path", required=True)
    ap.add_argument("--execution-protocol-path", required=True)
    ap.add_argument("--implementation-freeze-path", required=True)
    ap.add_argument("--admission-manifest-path", required=True)
    ap.add_argument("--blind-transport-path", required=True)
    ap.add_argument("--signature-bundle-path", required=True)
    ap.add_argument("--profile-bundle-path", required=True)
    ap.add_argument("--world-bundle-path", required=True)
    ap.add_argument("--output-dir", required=True)
    a = ap.parse_args()

    root = Path(a.repo_root).resolve(strict=True)
    policy, _ = load_bootstrap_policy(Path(a.read_policy), a.read_policy_sha256)
    guard = ClosedReadSet(root, policy)
    guard.install_audit_guard()

    protocol = _json(guard.read_bytes(a.execution_protocol_path, purpose="candidate58_execution_protocol"))
    impl_freeze = _json(guard.read_bytes(a.implementation_freeze_path, purpose="gate1b1c_implementation_freeze"))
    admission = _json(guard.read_bytes(a.admission_manifest_path, purpose="sanitized_candidate58_admission"))
    transport = _json(guard.read_bytes(a.blind_transport_path, purpose="frozen_blind58_transport"))
    plan = _json(guard.read_bytes(a.plan_path, purpose="candidate58_prepared_execution_plan"))
    sigbundle = _json(guard.read_bytes(a.signature_bundle_path, purpose="frozen_canonical_signature"))
    profiles = _json(guard.read_bytes(a.profile_bundle_path, purpose="canonical_execution_profile"))
    worlds = _json(guard.read_bytes(a.world_bundle_path, purpose="declared_finite_worlds"))

    if protocol.get("schema") != EXECUTION_PROTOCOL_SCHEMA or protocol.get("status") != "PROSPECTIVE_SEALED_NOT_EXECUTED":
        raise ValueError("Gate1D execution protocol authority mismatch")
    rows = validate_plan(plan)
    amap = _admission_map(admission)
    tmap = _transport_map(transport)
    if sorted(amap) != [x["case_id"] for x in rows] or sorted(tmap) != [x["case_id"] for x in rows]:
        raise ValueError("plan/admission/transport opaque identity set mismatch")

    protocol_digests = protocol_digests_from_execution_protocol(protocol)
    identities = identities_from_implementation_freeze(impl_freeze)
    expected_runtime = runtime_from_execution_protocol(protocol)
    global_reads = list(guard.reads)
    outroot = Path(a.output_dir)
    case_outputs=[]

    for row in rows:
        case_id=row["case_id"]
        admitted=amap[case_id]
        if str(admitted.get("seed_id")) != row["seed_id"] or str(admitted.get("language")) != row["language"] or str(admitted.get("candidate_source_sha256")) != row["candidate_source_sha256"]:
            raise ValueError("prepared plan differs from frozen sanitized admission")
        tr=tmap[case_id]
        if str(tr.get("candidate_source_sha256")) != row["candidate_source_sha256"]:
            raise ValueError("blind transport/source identity mismatch")
        if tr.get("case_transport_status") not in {"COMPLETE","TRANSPORT_INCOMPLETE"}:
            raise ValueError("unknown frozen transport state")

        start=len(guard.reads)
        source=guard.read_bytes(row["candidate_source_path"],purpose="candidate_source")
        overlay_raw=guard.read_bytes(row["overlay_path"],purpose="primary_overlay")
        path_raw=guard.read_bytes(row["path_observability_path"],purpose="primary_path_observability")
        if _sha(source) != row["candidate_source_sha256"] or _sha(overlay_raw) != row["overlay_sha256"] or _sha(path_raw) != row["path_observability_sha256"]:
            raise ValueError("prepared case digest mismatch")
        receipt=make_case_read_receipt(
            policy_digest_sha256=guard.policy_digest,
            reads=global_reads + list(guard.reads[start:]),
            source_path=row["candidate_source_path"],
        )
        sig=_select(list(sigbundle.get("signatures",[])),"seed_id",row["seed_id"])
        profile=_select(list(profiles.get("profiles",[])),"seed_id",row["seed_id"])
        world=_select(list(worlds.get("world_documents",[])),"seed_id",row["seed_id"])
        item=execute_prepared_case(
            case_id=case_id, seed_id=row["seed_id"], language=row["language"],
            source_path=row["candidate_source_path"], source_bytes=source,
            overlay=_json(overlay_raw), path_observability=_json(path_raw),
            canonical_signature=sig, canonical_profile=profile, worlds_document=world,
            read_receipt=receipt, protocol_digests=protocol_digests,
            identities=identities, expected_runtime=expected_runtime,
        )
        if tr.get("case_transport_status") != "COMPLETE":
            item["machine_prediction"] = INCOMPLETE
            item["record"]["machine_prediction"] = INCOMPLETE
            item["record"]["promotion_reasons"] = sorted(set(item["record"].get("promotion_reasons",[])+["FROZEN_TRANSPORT_INCOMPLETE_PRECEDENCE"]))
        case_dir=outroot/"cases"/case_id
        _write(case_dir/"semantic_slice.json",item["semantic_slice"])
        _write(case_dir/"adapter_receipt.json",item["adapter_receipt"])
        _write(case_dir/"kernel_result.json",item["kernel_result"])
        _write(case_dir/"certificate.json",item["certificate"])
        _write(case_dir/"c1_report.json",item["c1_report"])
        _write(case_dir/"read_receipt.json",receipt)
        _write(case_dir/"machine_record.json",item["record"])
        case_outputs.append(item)

    assembled=assemble_outputs(case_outputs,expected_case_ids=[x["case_id"] for x in rows])
    matrix_sha=_write(outroot/"E2_CANDIDATE58_MACHINE_PREDICTION_MATRIX.json",assembled["matrix"])
    cert_index_sha=_write(outroot/"E2_CANDIDATE58_CERTIFICATE_INDEX.json",assembled["certificate_index"])
    c1_index_sha=_write(outroot/"E2_CANDIDATE58_C1_INDEX.json",assembled["c1_index"])
    final_guard_receipt=guard.receipt(source_paths=[])
    if final_guard_receipt.get("forbidden_reads"):
        raise PermissionError("closed runtime read firewall recorded forbidden reads")
    receipt={
        "schema":EXECUTION_RECEIPT_SCHEMA,
        "status":"MACHINE_ONLY_COMPLETE_NOT_GOLD_JOINED",
        "case_count":58,
        "machine_prediction_matrix_sha256":matrix_sha,
        "certificate_index_sha256":cert_index_sha,
        "c1_index_sha256":c1_index_sha,
        "runtime_read_policy_digest_sha256":guard.policy_digest,
        "global_read_receipt_sha256":sha256_json(final_guard_receipt),
        "opaque_identity_set_sha256":hashlib.sha256(canonical_bytes(sorted(amap))).hexdigest(),
        "scientific_firewall":{
            "candidate_source_bytes_read":True,
            "candidate_truth_or_gold_read":False,
            "expected_e2_prediction_read":False,
            "mutation_operator_metadata_read":False,
            "epistemic10_read":False,
            "fresh_heldout_read":False,
            "truth_join_executed":False,
        },
        "first_complete_freeze_performed":False,
        "next_required_action":"DETERMINISTIC_SECOND_REPLAY_AND_BYTE_IDENTITY_CHECK_THEN_IMMUTABLE_FIRST_COMPLETE_FREEZE_BEFORE_ANY_TRUTH_JOIN",
    }
    _write(outroot/"E2_CANDIDATE58_EXECUTION_RECEIPT.json",receipt)
    print(json.dumps({"status":receipt["status"],"case_count":58,"matrix_sha256":matrix_sha},sort_keys=True,separators=(",",":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
