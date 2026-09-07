from __future__ import annotations

"""Mechanical Candidate-58 execution harness for the frozen Gate 1D seal.

This module deliberately contains no A3/A4 semantic predicates.  It only:
  * validates a truth-free opaque execution plan,
  * invokes the already-frozen primary adapter -> kernel -> certificate -> C1 chain,
  * applies the already-frozen VALID_C1 promotion floor, and
  * assembles deterministic machine-only outputs.

Candidate-58 truth/operator/expected-prediction and Epistemic-10 material are
outside this module's input schema by construction.
"""

import hashlib
import json
import re
from typing import Any, Mapping, Sequence

from risu_e2_c1.rechecker import recheck as c1_recheck
from risu_e2_semantic.certificate import produce_certificate
from risu_e2_semantic.kernel import (
    INFRA_INVALID,
    INCOMPLETE,
    PRESERVATION,
    REGRESSION,
    canonical_bytes,
    evaluate,
    sha256_json,
)
from risu_e2_semantic.primary_adapter import adapt_primary

PLAN_SCHEMA = "risu.e2-candidate58-prepared-execution-plan/v0.1"
CASE_OUTPUT_SCHEMA = "risu.e2-candidate58-case-machine-output/v0.1"
MATRIX_SCHEMA = "risu.e2-candidate58-machine-prediction-matrix/v0.1"
CERT_INDEX_SCHEMA = "risu.e2-candidate58-certificate-index/v0.1"
C1_INDEX_SCHEMA = "risu.e2-candidate58-c1-index/v0.1"
EXECUTION_RECEIPT_SCHEMA = "risu.e2-candidate58-first-semantic-execution-receipt/v0.1"
READ_RECEIPT_SCHEMA = "risu.e2-closed-runtime-read-receipt/v0.1"

ALLOWED_LANGUAGES = frozenset({"python", "go", "typescript_javascript"})
ALLOWED_MACHINE_LABELS = frozenset({REGRESSION, PRESERVATION, INCOMPLETE, INFRA_INVALID})
DEFINITIVE = frozenset({REGRESSION, PRESERVATION})
VALID_C1 = "VALID_C1"
OPAQUE_ID = re.compile(r"^[0-9a-f]{64}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")

# Keys are rejected recursively.  This is intentionally broader than the public
# plan schema so nested accidental metadata cannot silently widen the read set.
FORBIDDEN_KEYS = frozenset({
    "expected_truth", "gold", "gold_class", "expected_e2_prediction",
    "operator", "operator_id", "operator_name", "operator_class",
    "mutation_class", "repair", "verdict", "m_plus", "m_zero", "m_question",
    "cell_id", "original_cell_id", "original_path", "epistemic10",
})
PLAN_FIELDS = frozenset({
    "case_id", "seed_id", "language", "candidate_source_path",
    "candidate_source_sha256", "overlay_path", "overlay_sha256",
    "path_observability_path", "path_observability_sha256",
})


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _walk_forbidden(value: Any, where: str = "root") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            k = str(key).lower()
            if k in FORBIDDEN_KEYS:
                raise ValueError(f"forbidden semantic metadata key:{where}.{key}")
            _walk_forbidden(child, f"{where}.{key}")
    elif isinstance(value, list):
        for idx, child in enumerate(value):
            _walk_forbidden(child, f"{where}[{idx}]")


def _safe_relpath(value: Any, field: str) -> str:
    text = str(value)
    if not text or text.startswith("/") or "\\" in text:
        raise ValueError(f"unsafe {field}")
    parts = text.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ValueError(f"unsafe {field}")
    return text


def validate_plan(plan: Mapping[str, Any], *, expected_count: int = 58) -> list[dict[str, Any]]:
    _walk_forbidden(plan)
    if plan.get("schema") != PLAN_SCHEMA:
        raise ValueError("execution plan schema mismatch")
    if plan.get("semantic_authority") is not False:
        raise ValueError("execution plan must be non-semantic")
    if plan.get("case_count") != expected_count:
        raise ValueError("execution plan count mismatch")
    rows = plan.get("cases")
    if not isinstance(rows, list) or len(rows) != expected_count:
        raise ValueError("execution plan row count mismatch")
    seen: set[str] = set()
    normalized: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, Mapping) or set(row) != PLAN_FIELDS:
            raise ValueError("execution plan row field allowlist mismatch")
        case_id = str(row["case_id"])
        if not OPAQUE_ID.fullmatch(case_id) or case_id in seen:
            raise ValueError("execution plan opaque case identity mismatch")
        seen.add(case_id)
        language = str(row["language"])
        if language not in ALLOWED_LANGUAGES:
            raise ValueError("execution plan language mismatch")
        for field in ("candidate_source_sha256", "overlay_sha256", "path_observability_sha256"):
            if not SHA256.fullmatch(str(row[field])):
                raise ValueError(f"execution plan digest malformed:{field}")
        normalized.append({
            "case_id": case_id,
            "seed_id": str(row["seed_id"]),
            "language": language,
            "candidate_source_path": _safe_relpath(row["candidate_source_path"], "candidate_source_path"),
            "candidate_source_sha256": str(row["candidate_source_sha256"]),
            "overlay_path": _safe_relpath(row["overlay_path"], "overlay_path"),
            "overlay_sha256": str(row["overlay_sha256"]),
            "path_observability_path": _safe_relpath(row["path_observability_path"], "path_observability_path"),
            "path_observability_sha256": str(row["path_observability_sha256"]),
        })
    if [r["case_id"] for r in normalized] != sorted(seen):
        raise ValueError("execution plan must be canonical opaque-id order")
    return normalized


def protocol_digests_from_execution_protocol(protocol: Mapping[str, Any]) -> dict[str, str]:
    lock = protocol.get("normative_protocol_lock", {}) or {}
    required = {
        "verdict_protocol": "E2_CANDIDATE58_SEMANTIC_VERDICT_PROTOCOL_v0.1",
        "minimal_fragment": "E2_GATE1B1C_MINIMAL_SEMANTIC_FRAGMENT_v0.1",
        "trust_boundary": "E2_CERTIFICATE_TRUST_BOUNDARY_v0.1",
    }
    out: dict[str, str] = {}
    for key, name in required.items():
        value = str(lock.get(name, ""))
        if not value.startswith("gitblob:"):
            raise ValueError(f"execution protocol missing normative identity:{name}")
        out[key] = value.removeprefix("gitblob:")
    return out


def identities_from_implementation_freeze(freeze: Mapping[str, Any]) -> dict[str, str]:
    ids = freeze.get("content_addressed_identities", {}) or {}
    mapping = {
        "semantic_engine": "semantic_engine_identity",
        "certificate_producer": "certificate_producer_identity",
        "source_evidence_checker": "source_evidence_checker_identity",
        "semantic_checker": "semantic_checker_identity",
        "minimal_semantic_fragment": "minimal_semantic_fragment_identity",
    }
    out = {k: str(ids.get(v, "")) for k, v in mapping.items()}
    if any(not value for value in out.values()):
        raise ValueError("implementation freeze identity set incomplete")
    return out


def runtime_from_execution_protocol(protocol: Mapping[str, Any]) -> dict[str, Any]:
    lock = protocol.get("runtime_lock", {}) or {}
    expected = {
        "implementation": str(lock.get("implementation", "")),
        "python_major": int(lock.get("python_major", -1)),
        "python_minor": int(lock.get("python_minor", -1)),
        "python_micro": int(lock.get("python_micro", -1)),
        "parser": str(lock.get("parser", "")),
    }
    if expected != {"implementation":"CPython","python_major":3,"python_minor":13,"python_micro":5,"parser":"python_stdlib_ast"}:
        raise ValueError("execution runtime lock mismatch")
    return expected


def make_case_read_receipt(*, policy_digest_sha256: str, reads: Sequence[Mapping[str, Any]], source_path: str) -> dict[str, Any]:
    if not SHA256.fullmatch(policy_digest_sha256):
        raise ValueError("read policy digest malformed")
    unique: dict[str, dict[str, Any]] = {}
    for raw in reads:
        path = _safe_relpath(raw.get("path"), "receipt path")
        digest = str(raw.get("sha256", ""))
        if not SHA256.fullmatch(digest):
            raise ValueError("receipt read digest malformed")
        row = {"path":path,"sha256":digest,"purpose":str(raw.get("purpose","")),"role":str(raw.get("role",""))}
        if path in unique and unique[path] != row:
            raise ValueError("conflicting duplicate read receipt")
        unique[path] = row
    if source_path not in unique:
        raise ValueError("candidate source absent from case read receipt")
    out = {
        "schema": READ_RECEIPT_SCHEMA,
        "closed": True,
        "policy_digest_sha256": policy_digest_sha256,
        "reads": [unique[k] for k in sorted(unique)],
        "read_paths": [source_path],
        "forbidden_reads": [],
    }
    out["receipt_digest_sha256"] = sha256_json(out)
    return out


def _promote(*, tentative: str, c1_report: Mapping[str, Any]) -> tuple[str, list[str]]:
    if tentative not in ALLOWED_MACHINE_LABELS:
        return INFRA_INVALID, ["UNKNOWN_TENTATIVE_MACHINE_LABEL"]
    if tentative == INFRA_INVALID:
        return INFRA_INVALID, ["KERNEL_INFRASTRUCTURE_INVALID"]
    if tentative not in DEFINITIVE:
        return INCOMPLETE, []
    if c1_report.get("checker_output") != VALID_C1:
        return INCOMPLETE, ["DEFINITIVE_BLOCKED_WITHOUT_VALID_C1"]
    if c1_report.get("machine_prediction") != tentative:
        return INCOMPLETE, ["DEFINITIVE_BLOCKED_BY_PRIMARY_C1_DISAGREEMENT"]
    return tentative, []


def certify_semantic_slice(*, case_id: str, semantic_slice: Mapping[str, Any], source_path: str,
                           source_bytes: bytes, execution_signature: Mapping[str, Any],
                           read_receipt: Mapping[str, Any], protocol_digests: Mapping[str, str],
                           identities: Mapping[str, str], expected_runtime: Mapping[str, Any]) -> dict[str, Any]:
    tentative = evaluate(semantic_slice)
    signature_digest = sha256_json(execution_signature)
    if semantic_slice.get("canonical_signature_digest") != signature_digest:
        raise ValueError("semantic slice/execution signature digest mismatch")
    cert = produce_certificate(
        case_id=case_id,
        semantic_slice=semantic_slice,
        source_files={source_path: source_bytes},
        identities=identities,
        protocol_digests=protocol_digests,
        canonical_signature_digest=signature_digest,
        read_set_receipt=read_receipt,
    )
    if canonical_bytes(cert.get("producer_kernel_result")) != canonical_bytes(tentative):
        raise ValueError("certificate producer/kernel replay mismatch")
    c1 = c1_recheck(
        certificate=cert,
        source_files={source_path: source_bytes},
        canonical_signature=execution_signature,
        expected_protocol_digests=protocol_digests,
        expected_identities=identities,
        expected_runtime=expected_runtime,
    )
    final_prediction, promotion_reasons = _promote(tentative=str(tentative.get("prediction")), c1_report=c1)
    return {
        "kernel_result": tentative,
        "certificate": cert,
        "c1_report": c1,
        "machine_prediction": final_prediction,
        "promotion_reasons": promotion_reasons,
    }


def execute_prepared_case(*, case_id: str, seed_id: str, language: str, source_path: str,
                          source_bytes: bytes, overlay: Mapping[str, Any],
                          path_observability: Mapping[str, Any], canonical_signature: Mapping[str, Any],
                          canonical_profile: Mapping[str, Any], worlds_document: Mapping[str, Any],
                          read_receipt: Mapping[str, Any], protocol_digests: Mapping[str, str],
                          identities: Mapping[str, str], expected_runtime: Mapping[str, Any]) -> dict[str, Any]:
    if not OPAQUE_ID.fullmatch(case_id):
        raise ValueError("case id is not frozen opaque identity")
    if language not in ALLOWED_LANGUAGES:
        raise ValueError("unsupported plan language")
    if str(canonical_signature.get("seed_id")) != seed_id:
        raise ValueError("case/canonical seed mismatch")
    semantic_slice, adapter_receipt = adapt_primary(
        case_id=case_id,
        language=language,
        source_path=source_path,
        overlay=overlay,
        path_observability=path_observability,
        canonical_signature=canonical_signature,
        canonical_profile=canonical_profile,
        worlds_document=worlds_document,
    )
    certified = certify_semantic_slice(
        case_id=case_id,
        semantic_slice=semantic_slice,
        source_path=source_path,
        source_bytes=source_bytes,
        execution_signature=adapter_receipt["execution_signature"],
        read_receipt=read_receipt,
        protocol_digests=protocol_digests,
        identities=identities,
        expected_runtime=expected_runtime,
    )
    record = {
        "schema": CASE_OUTPUT_SCHEMA,
        "case_id": case_id,
        "seed_id": seed_id,
        "language": language,
        "candidate_source_sha256": _sha(source_bytes),
        "machine_prediction": certified["machine_prediction"],
        "tentative_kernel_prediction": certified["kernel_result"]["prediction"],
        "c1_checker_output": certified["c1_report"].get("checker_output"),
        "assurance_level": certified["c1_report"].get("assurance_level", "NONE"),
        "promotion_reasons": certified["promotion_reasons"],
        "semantic_slice_sha256": sha256_json(semantic_slice),
        "adapter_receipt_sha256": sha256_json(adapter_receipt),
        "kernel_result_sha256": sha256_json(certified["kernel_result"]),
        "certificate_sha256": sha256_json(certified["certificate"]),
        "c1_report_sha256": sha256_json(certified["c1_report"]),
        "read_receipt_sha256": sha256_json(read_receipt),
    }
    return {"record":record,"semantic_slice":semantic_slice,"adapter_receipt":adapter_receipt,**certified}


def assemble_outputs(case_outputs: Sequence[Mapping[str, Any]], *, expected_case_ids: Sequence[str]) -> dict[str, Any]:
    expected = sorted(str(x) for x in expected_case_ids)
    if len(expected) != 58 or len(set(expected)) != 58 or any(not OPAQUE_ID.fullmatch(x) for x in expected):
        raise ValueError("expected identity set is not exact opaque 58")
    records = [dict(x["record"]) for x in case_outputs]
    if len(records) != 58 or sorted(str(x.get("case_id")) for x in records) != expected:
        raise ValueError("machine output does not cover exact frozen 58")
    if any(str(x.get("machine_prediction")) not in ALLOWED_MACHINE_LABELS for x in records):
        raise ValueError("machine output contains unknown label")
    records.sort(key=lambda x: str(x["case_id"]))
    cert_index=[]; c1_index=[]
    by_id={str(x["record"]["case_id"]):x for x in case_outputs}
    for row in records:
        case_id=str(row["case_id"]); item=by_id[case_id]
        cert_index.append({"case_id":case_id,"certificate_sha256":sha256_json(item["certificate"])})
        c1_index.append({"case_id":case_id,"c1_report_sha256":sha256_json(item["c1_report"]),"checker_output":item["c1_report"].get("checker_output")})
    matrix={"schema":MATRIX_SCHEMA,"case_count":58,"machine_only":True,"cases":records}
    certs={"schema":CERT_INDEX_SCHEMA,"case_count":58,"certificates":cert_index}
    c1s={"schema":C1_INDEX_SCHEMA,"case_count":58,"reports":c1_index}
    return {"matrix":matrix,"certificate_index":certs,"c1_index":c1s}
