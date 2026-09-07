from __future__ import annotations

"""Independent C1 certificate orchestrator.

Trust-boundary rule: this package does not import ``risu_e2`` or
``risu_e2_semantic``. Raw Python bytes are reconstructed by a separate local
parser lane and semantics are recomputed independently.
"""

import ast
import platform
import sys
from typing import Any, Mapping

from .common import (CERT_SCHEMA, SLICE_SCHEMA, C1_SCHEMA, REGRESSION,
                     INCOMPLETE, VALID, INVALID, UNSUPPORTED,
                     _digest_json, _digest_bytes)
from .source_extract import _extract_direct
from .semantics import _independent_semantic_eval

def recheck(
    *, certificate: Mapping[str, Any], source_files: Mapping[str, bytes],
    canonical_signature: Mapping[str, Any], expected_protocol_digests: Mapping[str, str],
    expected_identities: Mapping[str, str], expected_runtime: Mapping[str, Any],
) -> dict[str, Any]:
    invalid: list[str] = []
    unsupported: list[str] = []
    if certificate.get("schema") != CERT_SCHEMA: invalid.append("CERTIFICATE_SCHEMA_MISMATCH")
    cert_body = dict(certificate); claimed_cert_digest = cert_body.pop("certificate_digest_sha256", None)
    if claimed_cert_digest != _digest_json(cert_body): invalid.append("CERTIFICATE_DIGEST_MISMATCH")
    if certificate.get("semantic_slice", {}).get("schema") != SLICE_SCHEMA: invalid.append("SEMANTIC_SLICE_SCHEMA_MISMATCH")
    if certificate.get("semantic_slice_digest_sha256") != _digest_json(certificate.get("semantic_slice")): invalid.append("SEMANTIC_SLICE_DIGEST_MISMATCH")
    if certificate.get("producer_kernel_result_digest_sha256") != _digest_json(certificate.get("producer_kernel_result")): invalid.append("PRODUCER_KERNEL_RESULT_DIGEST_MISMATCH")
    if certificate.get("canonical_signature_digest") != _digest_json(canonical_signature): invalid.append("CANONICAL_SIGNATURE_DIGEST_MISMATCH")
    if certificate.get("semantic_slice", {}).get("canonical_signature_digest") != _digest_json(canonical_signature): invalid.append("SLICE_CANONICAL_SIGNATURE_DIGEST_MISMATCH")
    if dict(certificate.get("protocol_digests", {})) != dict(expected_protocol_digests): invalid.append("PROTOCOL_DIGEST_SET_MISMATCH")
    identity_fields = {
        "semantic_engine":"semantic_engine_identity",
        "certificate_producer":"certificate_producer_identity",
        "source_evidence_checker":"source_evidence_checker_identity",
        "semantic_checker":"semantic_checker_identity",
        "minimal_semantic_fragment":"minimal_semantic_fragment_identity",
    }
    for key, field in identity_fields.items():
        if certificate.get(field) != expected_identities.get(key): invalid.append(f"IMPLEMENTATION_IDENTITY_MISMATCH:{key}")
    runtime_actual={"implementation":platform.python_implementation(),"python_major":sys.version_info.major,"python_minor":sys.version_info.minor,"python_micro":sys.version_info.micro,"parser":"python_stdlib_ast"}
    if dict(expected_runtime) != runtime_actual: invalid.append("C1_RUNTIME_IDENTITY_MISMATCH")
    read_receipt = certificate.get("closed_read_set_receipt", {}) or {}
    if certificate.get("closed_read_set_receipt_digest") != _digest_json(read_receipt): invalid.append("READ_SET_RECEIPT_DIGEST_MISMATCH")
    if read_receipt.get("closed") is not True: invalid.append("READ_SET_NOT_CLOSED")
    if read_receipt.get("forbidden_reads", []) not in ([], None): invalid.append("FORBIDDEN_READ_RECORDED")
    if sorted(read_receipt.get("read_paths", []) or []) != sorted(source_files): invalid.append("READ_SET_SOURCE_PATH_MISMATCH")
    for path, claimed in sorted((certificate.get("source_hashes", {}) or {}).items()):
        if path not in source_files or _digest_bytes(source_files[path]) != claimed: invalid.append(f"SOURCE_HASH_MISMATCH:{path}")
    if set(certificate.get("source_hashes", {})) != set(source_files): invalid.append("SOURCE_FILE_SET_MISMATCH")
    if invalid:
        return {"schema":C1_SCHEMA,"checker_output":INVALID,"machine_prediction":INCOMPLETE,"reasons":sorted(set(invalid)),"assurance_level":"NONE"}

    proposal = certificate["semantic_slice"]
    if proposal.get("language") != "python":
        unsupported.append("C1_V0_1_LANGUAGE_NOT_SUPPORTED")
    contract = proposal.get("source_contract", {}) or {}
    path = contract.get("path")
    if path not in source_files: invalid.append("SOURCE_CONTRACT_PATH_NOT_BOUND")
    if (canonical_signature.get("guard", {}) or {}).get("form") != "DIRECT_CONTROL": unsupported.append("C1_V0_1_HELPER_CONTROL_NOT_SUPPORTED")
    if unsupported:
        return {"schema":C1_SCHEMA,"checker_output":UNSUPPORTED,"machine_prediction":INCOMPLETE,"reasons":sorted(set(unsupported)),"assurance_level":"NONE"}
    if invalid:
        return {"schema":C1_SCHEMA,"checker_output":INVALID,"machine_prediction":INCOMPLETE,"reasons":sorted(set(invalid)),"assurance_level":"NONE"}

    raw = source_files[path]
    try:
        text = raw.decode("utf-8"); tree = ast.parse(text)
    except (UnicodeDecodeError, SyntaxError) as exc:
        return {"schema":C1_SCHEMA,"checker_output":UNSUPPORTED,"machine_prediction":INCOMPLETE,"reasons":[f"PYTHON_PARSE_UNSUPPORTED:{type(exc).__name__}"],"assurance_level":"NONE"}
    reconstructed, bad = _extract_direct(source=raw, tree=tree, signature=canonical_signature, contract=contract, case_id=str(certificate.get("case_id")))
    if reconstructed is None:
        return {"schema":C1_SCHEMA,"checker_output":UNSUPPORTED,"machine_prediction":INCOMPLETE,"reasons":sorted(set(bad)),"assurance_level":"NONE"}

    independent = _independent_semantic_eval(reconstructed)
    producer = certificate.get("producer_kernel_result", {}) or {}
    # The checker does not require byte-identical internal data structures, but
    # the claimed prediction and every claim-critical source receipt must agree.
    disagreements: list[str] = []
    if producer.get("prediction") != independent["prediction"]:
        disagreements.append("PRIMARY_C1_PREDICTION_DISAGREEMENT")
    producer_wids = sorted({str(x.get("witness_id")) for x in producer.get("witnesses", []) or []})
    if producer.get("prediction") == REGRESSION and producer_wids != independent["witness_ids"]:
        disagreements.append("PRIMARY_C1_WITNESS_SET_DISAGREEMENT")
    # Compare source-evidence receipts by evidence id/path/span/hash. Producer
    # may carry extra diagnostic evidence, but every C1-required receipt must match.
    p_receipts = {(x.get("evidence_id"),x.get("path"),tuple(x.get("span",[]))):x.get("slice_sha256") for x in certificate.get("source_evidence_receipts", []) or []}
    for x in reconstructed.get("source_evidence", []):
        key=(x.get("evidence_id"),x.get("path"),tuple(x.get("span",[])))
        if p_receipts.get(key) != x.get("slice_sha256"): disagreements.append(f"SOURCE_EVIDENCE_RECEIPT_DISAGREEMENT:{x.get('evidence_id')}")
    if disagreements:
        return {
            "schema":C1_SCHEMA,"checker_output":INVALID,"machine_prediction":INCOMPLETE,"reasons":sorted(set(disagreements)),"assurance_level":"NONE",
            "producer_prediction":producer.get("prediction"),"c1_recomputed_prediction":independent["prediction"],
            "c1_reconstructed_slice_digest_sha256":_digest_json(reconstructed),
        }

    out = {
        "schema": C1_SCHEMA, "checker_output": VALID,
        "machine_prediction": independent["prediction"], "assurance_level": "C1_INDEPENDENT_SOURCE_EVIDENCE",
        "reasons": [], "c1_semantic_result": independent,
        "c1_reconstructed_slice_digest_sha256": _digest_json(reconstructed),
        "c1_source_hashes": {p:_digest_bytes(b) for p,b in sorted(source_files.items())},
        "trusted_import_boundary": {"imports_primary_e2": False, "imports_producer_kernel": False, "parser": "python_stdlib_ast"},
        "runtime_identity": runtime_actual,
    }
    out["c1_result_digest_sha256"] = _digest_json(out)
    return out
