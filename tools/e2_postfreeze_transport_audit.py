#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

SCHEMA = "risu.e2-post-freeze-transport-qualification-independent-audit/v0.1"
ANCHOR_KEYS = ("guard_comparison", "rejection_no_effect", "effect_applied")
SLOT_KEYS = ("expected_coordinate", "current_coordinate")
PRESENT = {"TRANSPORT_PRESENT_EXACT", "TRANSPORT_PRESENT_EDIT_DESCENDANT"}
AMBIG_OR_UNRESOLVED = {
    "TRANSPORT_UNRESOLVED",
    "TRANSPORT_AMBIGUOUS_MULTIPLE_CANDIDATES",
    "TRANSPORT_AMBIGUOUS_WITNESS_DISAGREEMENT",
}


def canon(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_json(path: Path) -> tuple[Any, bytes]:
    raw = path.read_bytes()
    return json.loads(raw.decode("utf-8")), raw


def load_jsonl(path: Path) -> tuple[list[dict[str, Any]], bytes]:
    raw = path.read_bytes()
    rows = [json.loads(line) for line in raw.decode("utf-8").splitlines() if line.strip()]
    return rows, raw


def frac(a: int, b: int) -> dict[str, int]:
    return {"numerator": a, "denominator": b}


def counts(vals: Iterable[str]) -> dict[str, int]:
    c = Counter(vals)
    return {k: c[k] for k in sorted(c)}


def metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    n = len(rows)
    cc = counts(r["case_transport_status"] for r in rows)
    pc = counts(r["parser_status"] for r in rows)
    aa: dict[str, Any] = {}
    for key in ANCHOR_KEYS:
        lin = [r["anchors"][key]["lineage_status"] for r in rows]
        rea = [r["anchors"][key]["realization_status"] for r in rows]
        aa[key] = {
            "lineage_status_counts": counts(lin),
            "realization_status_counts": counts(rea),
            "present_fraction": frac(sum(x in PRESENT for x in lin), n),
            "conclusive_absence_count": sum(x == "TRANSPORT_ABSENT_BY_EDIT_LINEAGE" for x in lin),
            "ambiguous_or_unresolved_count": sum(x in AMBIG_OR_UNRESOLVED for x in lin),
        }
    bb: dict[str, Any] = {}
    for key in SLOT_KEYS:
        vals = [r["binding_slots"][key] for r in rows]
        bb[key] = {
            "status_counts": counts(vals),
            "available_fraction": frac(sum(x == "AVAILABLE" for x in vals), n),
        }
    return {
        "n": n,
        "case_transport_status_counts": cc,
        "complete_fraction": frac(cc.get("COMPLETE", 0), n),
        "transport_incomplete_fraction": frac(cc.get("TRANSPORT_INCOMPLETE", 0), n),
        "parser_status_counts": pc,
        "parse_ok_fraction": frac(pc.get("PARSE_OK", 0), n),
        "anchors": aa,
        "binding_slots": bb,
    }


def grouped(rows: list[dict[str, Any]], fields: tuple[str, ...]) -> dict[str, Any]:
    buckets: dict[tuple[str, ...], list[dict[str, Any]]] = defaultdict(list)
    for r in rows:
        buckets[tuple(str(r[f]) for f in fields)].append(r)
    out: dict[str, Any] = {}
    for key in sorted(buckets):
        label = "|".join(key)
        out[label] = {"group": {f: v for f, v in zip(fields, key)}, "metrics": metrics(buckets[key])}
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--protocol", required=True)
    ap.add_argument("--transport-bundle", required=True)
    ap.add_argument("--matrix", required=True)
    ap.add_argument("--cells", required=True)
    ap.add_argument("--qualification", required=True)
    ap.add_argument("--output", required=True)
    args = ap.parse_args()

    errors: list[str] = []
    try:
        protocol, _ = load_json(Path(args.protocol))
        bundle, bundle_raw = load_json(Path(args.transport_bundle))
        matrix, matrix_raw = load_jsonl(Path(args.matrix))
        qualification, qualification_raw = load_json(Path(args.qualification))
        cells = Path(args.cells).resolve()

        if sha(bundle_raw) != protocol["frozen_authorities"]["blind_transport_bundle_sha256"]:
            errors.append("transport_bundle_sha256")
        if sha(matrix_raw) != protocol["frozen_authorities"]["expanded_truth_matrix_sha256"]:
            errors.append("matrix_sha256")
        if qualification.get("status") != "PASS":
            errors.append("qualification_status")
        qcopy = dict(qualification)
        qdigest = qcopy.pop("result_digest_sha256", None)
        if qdigest != sha(canon(qcopy)):
            errors.append("qualification_internal_digest")

        matrix_by_id = {str(r["cell_id"]): r for r in matrix}
        if len(matrix_by_id) != 58 or len(matrix) != 58:
            errors.append("matrix_cardinality")
        if counts(str(r["operator_class"]) for r in matrix) != protocol["truth_contract"]["required_class_counts"]:
            errors.append("class_cardinality")

        primary = protocol["primary_source_contract"]
        transport_by_key: dict[tuple[str, str, str], dict[str, Any]] = {}
        for receipt in bundle.get("receipts", []):
            key = (str(receipt["seed_id"]), str(receipt["language"]), str(receipt["candidate_source_sha256"]))
            if key in transport_by_key:
                errors.append("duplicate_transport_join_key")
            transport_by_key[key] = receipt
        if len(transport_by_key) != 58:
            errors.append("transport_cardinality")

        independent_rows: list[dict[str, Any]] = []
        consumed: set[str] = set()
        dirs = sorted(p for p in cells.iterdir() if p.is_dir() and re.fullmatch(r"Q\d{3}", p.name))
        if len(dirs) != 58:
            errors.append("cell_dir_cardinality")
        for d in dirs:
            cell, _ = load_json(d / "CELL.json")
            row = matrix_by_id.get(d.name)
            if row is None:
                errors.append("missing_matrix_row:" + d.name)
                continue
            for f in protocol["truth_contract"]["expanded_matrix_required_fields"]:
                if cell.get(f) != row.get(f):
                    errors.append("cell_matrix_mismatch:" + d.name + ":" + f)
            if cell.get("truth_source") != protocol["truth_contract"]["required_truth_source"]:
                errors.append("truth_source:" + d.name)
            seed = str(cell["seed_id"])
            spec = primary.get(seed)
            if not spec:
                errors.append("seed_contract:" + d.name)
                continue
            source = d / str(spec["filename"])
            if not source.is_file():
                errors.append("missing_primary_source:" + d.name)
                continue
            sh = sha(source.read_bytes())
            key = (seed, str(spec["language"]), sh)
            receipt = transport_by_key.get(key)
            if receipt is None:
                errors.append("join_missing:" + d.name)
                continue
            tid = str(receipt["transport_case_id"])
            if tid in consumed:
                errors.append("transport_reused:" + tid)
            consumed.add(tid)
            amap = {a["anchor_key"]: a for a in receipt["anchors"]}
            if set(amap) != set(ANCHOR_KEYS):
                errors.append("anchor_keys:" + d.name)
                continue
            binding = receipt["binding_slots"]
            if set(binding) != set(SLOT_KEYS):
                errors.append("slot_keys:" + d.name)
                continue
            independent_rows.append({
                "cell_id": d.name,
                "seed_id": seed,
                "language": str(spec["language"]),
                "operator_class": str(cell["operator_class"]),
                "operator_id": str(cell["operator_id"]),
                "expected_truth": str(cell["expected_truth"]),
                "expected_e2_primary": str(cell["expected_e2_primary"]),
                "truth_source": str(cell["truth_source"]),
                "candidate_source_sha256": sh,
                "transport_case_id": tid,
                "transport_receipt_digest_sha256": str(receipt["receipt_digest_sha256"]),
                "case_transport_status": str(receipt["case_transport_status"]),
                "parser_status": str(receipt["parser_status"]),
                "anchors": {
                    k: {"lineage_status": str(amap[k]["lineage_status"]), "realization_status": str(amap[k]["realization_status"])}
                    for k in ANCHOR_KEYS
                },
                "binding_slots": {k: str(binding[k]["status"]) for k in SLOT_KEYS},
            })

        independent_rows.sort(key=lambda x: x["cell_id"])
        if len(independent_rows) != 58 or len(consumed) != 58:
            errors.append("bijective_join_count")
        if independent_rows != qualification.get("joined_records"):
            errors.append("joined_records_mismatch")

        recomputed = {
            "overall": {"ALL": {"group": {}, "metrics": metrics(independent_rows)}},
            "operator_class": grouped(independent_rows, ("operator_class",)),
            "expected_truth": grouped(independent_rows, ("expected_truth",)),
            "operator_id": grouped(independent_rows, ("operator_id",)),
            "language": grouped(independent_rows, ("language",)),
            "seed_id": grouped(independent_rows, ("seed_id",)),
            "operator_class_x_language": grouped(independent_rows, ("operator_class", "language")),
        }
        if recomputed != qualification.get("aggregates"):
            errors.append("aggregate_mismatch")

        interpretation = qualification.get("interpretation_boundary", {})
        if any(interpretation.get(k) is not False for k in (
            "transport_is_regression_classifier",
            "tp_fp_fn_tn_labels_emitted",
            "accuracy_sensitivity_specificity_emitted",
            "expected_e2_primary_used_to_score_transport",
            "transport_incomplete_interpreted_as_semantic_loss_or_preservation",
            "m_question_incompleteness_auto_counted_as_success",
        )):
            errors.append("interpretation_boundary")
        claim = qualification.get("claim_boundary", {})
        if any(claim.get(k) is not False for k in (
            "transport_outputs_modified",
            "a3_a4_verdict_logic_executed",
            "fresh_target_selection_or_evaluation_executed",
            "post_unblinding_cell_exclusion_performed",
            "post_unblinding_metric_redefinition_performed",
        )):
            errors.append("claim_boundary")
    except Exception as exc:
        errors.append("auditor_exception:" + type(exc).__name__)
        qualification_raw = b""
        independent_rows = []
        recomputed = {}

    result = {
        "schema": SCHEMA,
        "status": "PASS" if not errors else "FAIL",
        "errors": sorted(set(errors)),
        "case_count": len(independent_rows),
        "qualification_sha256": sha(qualification_raw),
        "joined_records_digest_sha256": sha(canon(independent_rows)),
        "aggregates_digest_sha256": sha(canon(recomputed)),
        "bijective_join_recomputed_independently": not errors,
        "all_predeclared_aggregates_recomputed_independently": not errors,
        "qualifier_aggregation_code_imported": False,
        "transport_outputs_modified": False,
        "a3_a4_verdict_logic_executed": False,
        "fresh_target_selection_or_evaluation_executed": False,
    }
    result["audit_digest_sha256"] = sha(canon(result))
    raw = canon(result)
    Path(args.output).write_bytes(raw)
    print(json.dumps({"status": result["status"], "error_count": len(result["errors"]), "case_count": result["case_count"], "audit_sha256": sha(raw)}, sort_keys=True, separators=(",", ":")))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
