#!/usr/bin/env python3
from __future__ import annotations

"""Gate 2B.0: truth-free claim-eligibility frontier diagnostic.

Reads exactly two logical inputs: the frozen Gate2B0 protocol and the already-
immutable Candidate-58 machine matrix.  It imports no RISU semantic/C1 code,
reruns no scientific component, and never reads truth, operator metadata,
source bytes, semantic slices, certificates, or C1 reports.  The classifier is
fed only the six fields frozen by the Gate2B0 protocol.
"""

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any, Mapping

PROTOCOL_SCHEMA = "risu.e2-candidate58-gate2b0-claim-eligibility-frontier-protocol/v0.1"
PROTOCOL_STATUS = "POSTRESULT_DIAGNOSTIC_TAXONOMY_FROZEN_BEFORE_GATE2B0_EXECUTION"
MATRIX_SCHEMA = "risu.e2-candidate58-machine-prediction-matrix/v0.1"
LEDGER_SCHEMA = "risu.e2-candidate58-gate2b0-frontier-ledger/v0.1"
SUMMARY_SCHEMA = "risu.e2-candidate58-gate2b0-frontier-summary/v0.1"
RECEIPT_SCHEMA = "risu.e2-candidate58-gate2b0-diagnostic-receipt/v0.1"
EXPECTED_CASES = 58
EXPECTED_MATRIX_SHA256 = "7273ce4034d06e67989a33540f5b22fef3190cf311a8981474413b538e43472d"

REGRESSION = "E2_PREDICTED_REGRESSION_WITNESS"
PRESERVATION = "E2_PREDICTED_PRESERVATION_EVIDENCE"
INCOMPLETE = "E2_PREDICTED_ASSURANCE_INCOMPLETE"
INFRA = "INFRASTRUCTURE_INVALID_BEFORE_PREDICTION"
VALID_C1 = "VALID_C1"
UNSUPPORTED = "UNSUPPORTED_CERTIFICATE"
DEFINITIVE = frozenset({REGRESSION, PRESERVATION})
ALLOWED_MACHINE = frozenset({REGRESSION, PRESERVATION, INCOMPLETE, INFRA})
VIEW_FIELDS = (
    "case_id",
    "machine_prediction",
    "tentative_kernel_prediction",
    "c1_checker_output",
    "assurance_level",
    "promotion_reasons",
)
FRONTIERS = (
    "UPSTREAM_TRANSPORT_PRECEDENCE",
    "UPSTREAM_PRIMARY_PREPARATION_INCOMPLETE",
    "KERNEL_NONDEFINITIVE",
    "KERNEL_INFRASTRUCTURE_INVALID",
    "POST_KERNEL_PROMOTION_BLOCK",
    "DEFINITIVE_CLAIM_REACHED",
)


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def read_json(path: Path) -> tuple[Mapping[str, Any], bytes]:
    raw = path.read_bytes()
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, Mapping):
        raise ValueError(f"top-level JSON object required:{path}")
    return value, raw


def write_json(path: Path, value: Any) -> str:
    raw = canonical_bytes(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    return sha256_bytes(raw)


def validate_protocol(protocol: Mapping[str, Any]) -> None:
    if protocol.get("schema") != PROTOCOL_SCHEMA or protocol.get("status") != PROTOCOL_STATUS:
        raise ValueError("Gate2B0 protocol identity mismatch")
    authority = protocol.get("authority") or {}
    if authority.get("machine_matrix_sha256") != EXPECTED_MATRIX_SHA256:
        raise ValueError("Gate2B0 protocol matrix digest mismatch")
    if authority.get("gate2a_first_complete_freeze_commit") != "afcf9ce67d93be612f1004c6a2031e819f0ea12d":
        raise ValueError("Gate2B0 protocol Gate2A authority mismatch")
    if tuple(protocol.get("classifier_view_allowlist") or ()) != VIEW_FIELDS:
        raise ValueError("Gate2B0 classifier-view allowlist mismatch")
    if (protocol.get("determinism_and_freeze") or {}).get("stdlib_only_analyzer") is not True:
        raise ValueError("Gate2B0 stdlib-only requirement missing")


def validate_matrix(matrix: Mapping[str, Any], raw: bytes) -> list[Mapping[str, Any]]:
    if sha256_bytes(raw) != EXPECTED_MATRIX_SHA256:
        raise ValueError("frozen machine matrix SHA-256 mismatch")
    rows = matrix.get("cases")
    if matrix.get("schema") != MATRIX_SCHEMA or matrix.get("case_count") != EXPECTED_CASES:
        raise ValueError("frozen machine matrix schema/count mismatch")
    if not isinstance(rows, list) or len(rows) != EXPECTED_CASES:
        raise ValueError("frozen machine matrix row count mismatch")
    ids = [str(row.get("case_id", "")) for row in rows if isinstance(row, Mapping)]
    if len(ids) != EXPECTED_CASES or len(set(ids)) != EXPECTED_CASES or ids != sorted(ids):
        raise ValueError("frozen machine matrix opaque identity/order mismatch")
    return rows


def project_classifier_view(row: Mapping[str, Any]) -> dict[str, Any]:
    missing = [key for key in VIEW_FIELDS if key not in row]
    if missing:
        raise ValueError(f"machine row missing classifier field:{missing}")
    reasons = row.get("promotion_reasons")
    if not isinstance(reasons, list) or any(not isinstance(x, str) for x in reasons):
        raise ValueError("promotion_reasons must be a string list")
    return {
        "case_id": str(row["case_id"]),
        "machine_prediction": str(row["machine_prediction"]),
        "tentative_kernel_prediction": str(row["tentative_kernel_prediction"]),
        "c1_checker_output": str(row["c1_checker_output"]),
        "assurance_level": str(row["assurance_level"]),
        "promotion_reasons": list(reasons),
    }


def classify(view: Mapping[str, Any]) -> str:
    final = str(view["machine_prediction"])
    tentative = str(view["tentative_kernel_prediction"])
    c1 = str(view["c1_checker_output"])
    assurance = str(view["assurance_level"])
    reasons = list(view["promotion_reasons"])

    if final not in ALLOWED_MACHINE or tentative not in ALLOWED_MACHINE:
        raise ValueError("unknown machine label in Gate2B0 view")

    if reasons == ["FROZEN_TRANSPORT_INCOMPLETE_PRECEDENCE"]:
        if final != INCOMPLETE or tentative != INCOMPLETE or c1 != UNSUPPORTED or assurance != "NONE":
            raise ValueError("transport-precedence record is internally contradictory")
        return "UPSTREAM_TRANSPORT_PRECEDENCE"

    if len(reasons) == 1 and reasons[0].startswith("PRIMARY_EVIDENCE_INCOMPLETE:") and reasons[0].split(":", 1)[1]:
        if final != INCOMPLETE or tentative != INCOMPLETE or c1 != UNSUPPORTED or assurance != "NONE":
            raise ValueError("preparation-incomplete record is internally contradictory")
        return "UPSTREAM_PRIMARY_PREPARATION_INCOMPLETE"

    if not reasons and tentative == INCOMPLETE:
        if final != INCOMPLETE:
            raise ValueError("kernel-incomplete record was unexpectedly promoted")
        return "KERNEL_NONDEFINITIVE"

    if reasons == ["KERNEL_INFRASTRUCTURE_INVALID"] and tentative == INFRA:
        if final != INFRA:
            raise ValueError("kernel-infrastructure-invalid record changed label")
        return "KERNEL_INFRASTRUCTURE_INVALID"

    if tentative in DEFINITIVE and final == INCOMPLETE and reasons in (
        ["DEFINITIVE_BLOCKED_WITHOUT_VALID_C1"],
        ["DEFINITIVE_BLOCKED_BY_PRIMARY_C1_DISAGREEMENT"],
    ):
        return "POST_KERNEL_PROMOTION_BLOCK"

    if tentative in DEFINITIVE and final == tentative and not reasons and c1 == VALID_C1 and assurance == VALID_C1:
        return "DEFINITIVE_CLAIM_REACHED"

    raise ValueError(
        "Gate2B0 frontier taxonomy matched no authorized state:"
        + canonical_bytes(dict(view)).decode("utf-8").strip()
    )


def self_test() -> None:
    base = {
        "case_id": "0" * 64,
        "machine_prediction": INCOMPLETE,
        "tentative_kernel_prediction": INCOMPLETE,
        "c1_checker_output": UNSUPPORTED,
        "assurance_level": "NONE",
        "promotion_reasons": [],
    }
    cases = [
        ({**base, "promotion_reasons": ["FROZEN_TRANSPORT_INCOMPLETE_PRECEDENCE"]}, "UPSTREAM_TRANSPORT_PRECEDENCE"),
        ({**base, "promotion_reasons": ["PRIMARY_EVIDENCE_INCOMPLETE:ValueError"]}, "UPSTREAM_PRIMARY_PREPARATION_INCOMPLETE"),
        (base, "KERNEL_NONDEFINITIVE"),
        ({**base, "machine_prediction": INFRA, "tentative_kernel_prediction": INFRA, "promotion_reasons": ["KERNEL_INFRASTRUCTURE_INVALID"]}, "KERNEL_INFRASTRUCTURE_INVALID"),
        ({**base, "tentative_kernel_prediction": REGRESSION, "promotion_reasons": ["DEFINITIVE_BLOCKED_WITHOUT_VALID_C1"]}, "POST_KERNEL_PROMOTION_BLOCK"),
        ({**base, "machine_prediction": PRESERVATION, "tentative_kernel_prediction": PRESERVATION, "c1_checker_output": VALID_C1, "assurance_level": VALID_C1}, "DEFINITIVE_CLAIM_REACHED"),
    ]
    for view, expected in cases:
        actual = classify(view)
        if actual != expected:
            raise AssertionError((actual, expected))
    try:
        classify({**base, "promotion_reasons": ["UNKNOWN_POSTHOC_REASON"]})
    except ValueError:
        pass
    else:
        raise AssertionError("unknown frontier reason did not fail closed")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--protocol")
    ap.add_argument("--matrix")
    ap.add_argument("--output-dir")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    if args.self_test:
        self_test()
        print(json.dumps({"status": "PASS", "test": "GATE2B0_FRONTIER_CLASSIFIER_SELF_TEST"}, sort_keys=True, separators=(",", ":")))
        return 0
    if not args.protocol or not args.matrix or not args.output_dir:
        raise SystemExit("--protocol, --matrix, and --output-dir are required")

    protocol, protocol_raw = read_json(Path(args.protocol))
    matrix, matrix_raw = read_json(Path(args.matrix))
    validate_protocol(protocol)
    rows = validate_matrix(matrix, matrix_raw)

    ledger_rows: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()
    for raw_row in rows:
        view = project_classifier_view(raw_row)
        frontier = classify(view)
        counts[frontier] += 1
        ledger_rows.append({
            "case_id": view["case_id"],
            "frontier": frontier,
            "promotion_reasons": view["promotion_reasons"],
            "tentative_kernel_prediction": view["tentative_kernel_prediction"],
            "machine_prediction": view["machine_prediction"],
            "c1_checker_output": view["c1_checker_output"],
            "assurance_level": view["assurance_level"],
        })

    if len(ledger_rows) != EXPECTED_CASES or sum(counts.values()) != EXPECTED_CASES:
        raise ValueError("Gate2B0 frontier partition is not exact 58")
    unknown = set(counts) - set(FRONTIERS)
    if unknown:
        raise ValueError(f"unknown frontier output:{sorted(unknown)}")

    frontier_counts = {name: counts.get(name, 0) for name in FRONTIERS}
    upstream = frontier_counts["UPSTREAM_TRANSPORT_PRECEDENCE"] + frontier_counts["UPSTREAM_PRIMARY_PREPARATION_INCOMPLETE"]
    semantic_chain_entered = EXPECTED_CASES - upstream

    ledger = {
        "schema": LEDGER_SCHEMA,
        "status": "GATE2B0_FRONTIER_PARTITION_COMPLETE",
        "case_count": EXPECTED_CASES,
        "rows": ledger_rows,
    }
    summary = {
        "schema": SUMMARY_SCHEMA,
        "status": "GATE2B0_DESCRIPTIVE_FRONTIER_SUMMARY_NOT_ROOT_CAUSE",
        "case_count": EXPECTED_CASES,
        "frontier_counts": frontier_counts,
        "upstream_terminal_total": upstream,
        "semantic_chain_entered_total": semantic_chain_entered,
        "post_kernel_promotion_block_total": frontier_counts["POST_KERNEL_PROMOTION_BLOCK"],
        "definitive_claim_reached_total": frontier_counts["DEFINITIVE_CLAIM_REACHED"],
        "partition_complete": True,
        "interpretation_boundary": {
            "frontier_is_not_semantic_root_cause": True,
            "remediation_effect_not_inferred": True,
            "gate2a_metrics_recomputed": False,
            "truth_or_operator_strata_used": False,
        },
    }

    out = Path(args.output_dir)
    ledger_sha = write_json(out / "E2_CANDIDATE58_GATE2B0_FRONTIER_LEDGER.json", ledger)
    summary_sha = write_json(out / "E2_CANDIDATE58_GATE2B0_FRONTIER_SUMMARY.json", summary)
    receipt = {
        "schema": RECEIPT_SCHEMA,
        "status": "FIRST_COMPLETE_GATE2B0_LOGICAL_OUTPUT",
        "inputs": {
            "protocol_sha256": sha256_bytes(protocol_raw),
            "machine_matrix_sha256": sha256_bytes(matrix_raw),
            "machine_matrix_git_blob": "60b27d641682693cb3df654d8aa4f064cc48455d",
            "gate2a_first_complete_freeze_commit": "afcf9ce67d93be612f1004c6a2031e819f0ea12d",
        },
        "outputs": {
            "frontier_ledger_sha256": ledger_sha,
            "frontier_summary_sha256": summary_sha,
        },
        "integrity": {
            "case_count": EXPECTED_CASES,
            "partition_total": sum(counts.values()),
            "unique_case_count": len({row["case_id"] for row in ledger_rows}),
            "classifier_view_fields": list(VIEW_FIELDS),
            "classifier_view_only": True,
        },
        "scientific_firewall": {
            "semantic_engine_rerun": False,
            "c1_checker_rerun": False,
            "gate2a_joined_ledger_read": False,
            "gate2a_metrics_read": False,
            "truth_or_operator_read": False,
            "candidate_source_read": False,
            "semantic_slice_content_read": False,
            "certificate_content_read": False,
            "c1_report_content_read": False,
            "fresh_heldout_read": False,
            "remediation": False,
            "semantic_rule_change": False,
        },
    }
    receipt_sha = write_json(out / "E2_CANDIDATE58_GATE2B0_DIAGNOSTIC_RECEIPT.json", receipt)
    print(json.dumps({
        "status": receipt["status"],
        "case_count": EXPECTED_CASES,
        "frontier_counts": frontier_counts,
        "ledger_sha256": ledger_sha,
        "summary_sha256": summary_sha,
        "receipt_sha256": receipt_sha,
    }, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
