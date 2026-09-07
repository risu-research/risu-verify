from __future__ import annotations

"""Untrusted certificate producer for Gate 1B/1C.

The producer may use primary E2 outputs to propose a semantic slice.  Nothing
produced here is C1-authoritative until the independent raw-source rechecker
reconstructs and recomputes the claim.
"""

import hashlib
import json
from typing import Any, Mapping

from .kernel import SLICE_SCHEMA, canonical_bytes, evaluate, sha256_json

CERT_SCHEMA = "risu.e2-semantic-certificate/v0.1"


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _span_bytes(source: bytes, span: list[int] | tuple[int, int, int, int]) -> bytes:
    """Slice UTF-8 source by Python/AST byte columns (1-based lines, byte cols)."""
    sl, sc, el, ec = map(int, span)
    lines = source.splitlines(keepends=True)
    if sl < 1 or el < sl or el > len(lines):
        raise ValueError("invalid evidence span")
    if sl == el:
        return lines[sl - 1][sc:ec]
    return b"".join([lines[sl - 1][sc:]] + lines[sl:el - 1] + [lines[el - 1][:ec]])


def produce_certificate(
    *,
    case_id: str,
    semantic_slice: Mapping[str, Any],
    source_files: Mapping[str, bytes],
    identities: Mapping[str, str],
    protocol_digests: Mapping[str, str],
    canonical_signature_digest: str,
    read_set_receipt: Mapping[str, Any],
) -> dict[str, Any]:
    if semantic_slice.get("schema") != SLICE_SCHEMA:
        raise ValueError("semantic slice schema mismatch")
    if semantic_slice.get("case_id") != case_id:
        raise ValueError("case id mismatch")
    if semantic_slice.get("canonical_signature_digest") != canonical_signature_digest:
        raise ValueError("canonical signature digest mismatch")

    source_hashes = {path: sha256_bytes(raw) for path, raw in sorted(source_files.items())}
    span_receipts = []
    for row in semantic_slice.get("source_evidence", []) or []:
        path = str(row.get("path", ""))
        if path not in source_files:
            raise ValueError(f"evidence path not supplied: {path}")
        span = list(row.get("span", []))
        if len(span) != 4:
            raise ValueError("evidence span must have four coordinates")
        raw = _span_bytes(source_files[path], span)
        span_receipts.append({
            "evidence_id": row.get("evidence_id"),
            "path": path,
            "span": span,
            "slice_sha256": sha256_bytes(raw),
        })

    kernel_result = evaluate(semantic_slice)
    envelope = {
        "schema": CERT_SCHEMA,
        "assurance_claimed": "C0_SHARED_FRONTEND_CONDITIONAL",
        "case_id": case_id,
        "source_hashes": source_hashes,
        "protocol_digests": dict(sorted(protocol_digests.items())),
        "canonical_signature_digest": canonical_signature_digest,
        "semantic_engine_identity": identities.get("semantic_engine"),
        "certificate_producer_identity": identities.get("certificate_producer"),
        "source_evidence_checker_identity": identities.get("source_evidence_checker"),
        "semantic_checker_identity": identities.get("semantic_checker"),
        "minimal_semantic_fragment_identity": identities.get("minimal_semantic_fragment"),
        "closed_read_set_receipt": dict(read_set_receipt),
        "closed_read_set_receipt_digest": sha256_json(read_set_receipt),
        "source_evidence_receipts": span_receipts,
        "semantic_slice": semantic_slice,
        "semantic_slice_digest_sha256": sha256_json(semantic_slice),
        "producer_kernel_result": kernel_result,
        "producer_kernel_result_digest_sha256": sha256_json(kernel_result),
        "trust_boundary": "PRODUCER_UNTRUSTED_UNTIL_C1_RECHECK",
    }
    # Certificate id excludes itself.
    envelope["certificate_digest_sha256"] = sha256_json(envelope)
    return envelope


def dumps_certificate(cert: Mapping[str, Any]) -> bytes:
    return canonical_bytes(cert)
