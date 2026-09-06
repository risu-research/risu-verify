#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

SCHEMA = "risu.e2-post-freeze-transport-qualification-result/v0.1"
PROTOCOL_SCHEMA = "risu.diff-e2-post-freeze-transport-qualification/v0.1"
EXPECTED_PROTOCOL_STATUS = "PREREGISTERED_BEFORE_TRUTH_OPERATOR_UNBLINDING"
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


def read_json(path: Path) -> tuple[Any, bytes]:
    raw = path.read_bytes()
    return json.loads(raw.decode("utf-8")), raw


def read_jsonl(path: Path) -> tuple[list[dict[str, Any]], bytes]:
    raw = path.read_bytes()
    rows = [json.loads(line) for line in raw.decode("utf-8").splitlines() if line.strip()]
    return rows, raw


def fraction(num: int, den: int) -> dict[str, int]:
    return {"numerator": num, "denominator": den}


def counter_dict(values: Iterable[str]) -> dict[str, int]:
    c = Counter(values)
    return {k: c[k] for k in sorted(c)}


def aggregate_group(rows: list[dict[str, Any]]) -> dict[str, Any]:
    n = len(rows)
    case_counts = counter_dict(r["case_transport_status"] for r in rows)
    parser_counts = counter_dict(r["parser_status"] for r in rows)
    anchors: dict[str, Any] = {}
    for key in ANCHOR_KEYS:
        lineage = [r["anchors"][key]["lineage_status"] for r in rows]
        realization = [r["anchors"][key]["realization_status"] for r in rows]
        anchors[key] = {
            "lineage_status_counts": counter_dict(lineage),
            "realization_status_counts": counter_dict(realization),
            "present_fraction": fraction(sum(x in PRESENT for x in lineage), n),
            "conclusive_absence_count": sum(x == "TRANSPORT_ABSENT_BY_EDIT_LINEAGE" for x in lineage),
            "ambiguous_or_unresolved_count": sum(x in AMBIG_OR_UNRESOLVED for x in lineage),
        }
    slots: dict[str, Any] = {}
    for key in SLOT_KEYS:
        vals = [r["binding_slots"][key] for r in rows]
        slots[key] = {
            "status_counts": counter_dict(vals),
            "available_fraction": fraction(sum(x == "AVAILABLE" for x in vals), n),
        }
    return {
        "n": n,
        "case_transport_status_counts": case_counts,
        "complete_fraction": fraction(case_counts.get("COMPLETE", 0), n),
        "transport_incomplete_fraction": fraction(case_counts.get("TRANSPORT_INCOMPLETE", 0), n),
        "parser_status_counts": parser_counts,
        "parse_ok_fraction": fraction(parser_counts.get("PARSE_OK", 0), n),
        "anchors": anchors,
        "binding_slots": slots,
    }


def group_records(rows: list[dict[str, Any]], fields: tuple[str, ...]) -> dict[str, Any]:
    groups: dict[tuple[str, ...], list[dict[str, Any]]] = defaultdict(list)
    for r in rows:
        groups[tuple(str(r[f]) for f in fields)].append(r)
    out: dict[str, Any] = {}
    for key in sorted(groups):
        label = "|".join(key)
        out[label] = {
            "group": {field: value for field, value in zip(fields, key)},
            "metrics": aggregate_group(groups[key]),
        }
    return out


def receipt_anchor_map(receipt: dict[str, Any]) -> dict[str, dict[str, Any]]:
    anchors = receipt.get("anchors", [])
    amap = {a.get("anchor_key"): a for a in anchors if isinstance(a, dict)}
    if set(amap) != set(ANCHOR_KEYS) or len(anchors) != 3:
        raise AssertionError("transport receipt anchor key set mismatch")
    return amap


def source_spec(protocol: dict[str, Any], seed_id: str) -> dict[str, str]:
    spec = protocol["primary_source_contract"].get(seed_id)
    if not isinstance(spec, dict):
        raise AssertionError("unknown seed_id in primary source contract")
    return {"language": str(spec["language"]), "filename": str(spec["filename"])}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True)
    ap.add_argument("--protocol", required=True)
    ap.add_argument("--transport-bundle", required=True)
    ap.add_argument("--matrix", required=True)
    ap.add_argument("--cells", required=True)
    ap.add_argument("--output", required=True)
    args = ap.parse_args()

    root = Path(args.root).resolve()
    protocol, protocol_raw = read_json(Path(args.protocol))
    bundle, bundle_raw = read_json(Path(args.transport_bundle))
    matrix, matrix_raw = read_jsonl(Path(args.matrix))
    cells = Path(args.cells).resolve()
    assert root.is_dir()

    assert protocol["schema"] == PROTOCOL_SCHEMA
    assert protocol["status"] == EXPECTED_PROTOCOL_STATUS
    assert protocol["scientific_boundary"]["truth_or_operator_metadata_read_before_this_protocol_freeze"] is False
    auth = protocol["frozen_authorities"]
    assert sha(bundle_raw) == auth["blind_transport_bundle_sha256"]
    assert sha(matrix_raw) == auth["expanded_truth_matrix_sha256"]
    assert bundle["case_count"] == 58 and len(bundle["receipts"]) == 58
    assert bundle["claim_boundary"]["a3_a4_verdict_logic_executed"] is False
    assert bundle["claim_boundary"]["truth_or_operator_unblinded"] is False
    assert bundle["forbidden_input_attestation"]["mutation_truth_read"] is False
    assert bundle["forbidden_input_attestation"]["mutation_operator_metadata_read"] is False

    required_count = int(protocol["truth_contract"]["required_cell_count"])
    required_fields = tuple(protocol["truth_contract"]["required_cell_fields"])
    matrix_fields = tuple(protocol["truth_contract"]["expanded_matrix_required_fields"])
    expected_truth_source = protocol["truth_contract"]["required_truth_source"]

    assert len(matrix) == required_count
    matrix_by_id: dict[str, dict[str, Any]] = {}
    for row in matrix:
        cell_id = str(row["cell_id"])
        assert re.fullmatch(r"Q\d{3}", cell_id)
        assert cell_id not in matrix_by_id
        for f in matrix_fields:
            assert f in row
        matrix_by_id[cell_id] = row

    class_counts = counter_dict(str(r["operator_class"]) for r in matrix)
    assert class_counts == protocol["truth_contract"]["required_class_counts"]
    allowed = {k: set(v) for k, v in protocol["truth_contract"]["allowed_operator_ids"].items()}
    for row in matrix:
        assert str(row["operator_class"]) in allowed
        assert str(row["operator_id"]) in allowed[str(row["operator_class"])]

    dirs = sorted(p for p in cells.iterdir() if p.is_dir() and re.fullmatch(r"Q\d{3}", p.name))
    assert len(dirs) == required_count
    assert {p.name for p in dirs} == set(matrix_by_id)

    transport_by_key: dict[tuple[str, str, str], dict[str, Any]] = {}
    transport_ids: set[str] = set()
    for receipt in bundle["receipts"]:
        key = (str(receipt["seed_id"]), str(receipt["language"]), str(receipt["candidate_source_sha256"]))
        assert key not in transport_by_key
        transport_by_key[key] = receipt
        tid = str(receipt["transport_case_id"])
        assert tid not in transport_ids
        transport_ids.add(tid)
    assert len(transport_by_key) == required_count

    joined: list[dict[str, Any]] = []
    consumed_transport_ids: set[str] = set()
    cell_join_keys: set[tuple[str, str, str]] = set()

    # First truth/operator consumption occurs here, after all preregistered authority checks.
    for cell_dir in dirs:
        cell, _ = read_json(cell_dir / "CELL.json")
        row = matrix_by_id[cell_dir.name]
        for f in required_fields:
            assert f in cell
        assert str(cell["cell_id"]) == cell_dir.name
        assert cell["truth_source"] == expected_truth_source
        for f in matrix_fields:
            assert cell[f] == row[f]
        spec = source_spec(protocol, str(cell["seed_id"]))
        source_path = cell_dir / spec["filename"]
        assert source_path.is_file()
        source_hash = sha(source_path.read_bytes())
        key = (str(cell["seed_id"]), spec["language"], source_hash)
        assert key not in cell_join_keys
        cell_join_keys.add(key)
        assert key in transport_by_key
        receipt = transport_by_key[key]
        tid = str(receipt["transport_case_id"])
        assert tid not in consumed_transport_ids
        consumed_transport_ids.add(tid)
        assert receipt["candidate_source_sha256"] == source_hash
        assert receipt["seed_id"] == cell["seed_id"]
        assert receipt["language"] == spec["language"]
        amap = receipt_anchor_map(receipt)
        binding = receipt["binding_slots"]
        assert set(binding) == set(SLOT_KEYS)
        joined.append({
            "cell_id": cell_dir.name,
            "seed_id": str(cell["seed_id"]),
            "language": spec["language"],
            "operator_class": str(cell["operator_class"]),
            "operator_id": str(cell["operator_id"]),
            "expected_truth": str(cell["expected_truth"]),
            "expected_e2_primary": str(cell["expected_e2_primary"]),
            "truth_source": str(cell["truth_source"]),
            "candidate_source_sha256": source_hash,
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

    assert len(joined) == required_count
    assert consumed_transport_ids == transport_ids
    assert len(cell_join_keys) == required_count
    joined.sort(key=lambda r: r["cell_id"])

    aggregates = {
        "overall": {"ALL": {"group": {}, "metrics": aggregate_group(joined)}},
        "operator_class": group_records(joined, ("operator_class",)),
        "expected_truth": group_records(joined, ("expected_truth",)),
        "operator_id": group_records(joined, ("operator_id",)),
        "language": group_records(joined, ("language",)),
        "seed_id": group_records(joined, ("seed_id",)),
        "operator_class_x_language": group_records(joined, ("operator_class", "language")),
    }
    assert list(aggregates) == protocol["predeclared_strata"]

    result = {
        "schema": SCHEMA,
        "status": "PASS",
        "qualification_pass_meaning": "PROVENANCE_AND_AGGREGATION_INTEGRITY_ONLY",
        "execution_head_sha": os.environ.get("GITHUB_SHA"),
        "authorities": {
            "protocol_git_blob": "8d1860312d259e628e86070416a4757c570ba05f",
            "protocol_sha256": sha(protocol_raw),
            "transport_bundle_sha256": sha(bundle_raw),
            "expanded_truth_matrix_sha256": sha(matrix_raw),
            "materialized_cells_tree_git_sha": auth["materialized_cells_tree_git_sha"],
            "truth_freeze_commit": auth["truth_freeze_commit"],
        },
        "integrity": {
            "cell_count": len(joined),
            "transport_receipt_count": len(bundle["receipts"]),
            "matrix_row_count": len(matrix),
            "class_counts": class_counts,
            "cell_matrix_exact_required_field_agreement_count": len(joined),
            "bijective_join_count": len(joined),
            "duplicate_cell_join_keys": 0,
            "duplicate_transport_join_keys": 0,
            "unconsumed_transport_receipts": 0,
            "excluded_cells": 0,
        },
        "joined_records": joined,
        "aggregates": aggregates,
        "interpretation_boundary": {
            "transport_is_regression_classifier": False,
            "tp_fp_fn_tn_labels_emitted": False,
            "accuracy_sensitivity_specificity_emitted": False,
            "expected_e2_primary_used_to_score_transport": False,
            "transport_incomplete_interpreted_as_semantic_loss_or_preservation": False,
            "m_question_incompleteness_auto_counted_as_success": False,
        },
        "claim_boundary": {
            "transport_outputs_modified": False,
            "a3_a4_verdict_logic_executed": False,
            "fresh_target_selection_or_evaluation_executed": False,
            "post_unblinding_cell_exclusion_performed": False,
            "post_unblinding_metric_redefinition_performed": False,
        },
    }
    result["result_digest_sha256"] = sha(canon(result))
    raw = canon(result)
    Path(args.output).write_bytes(raw)
    print(json.dumps({"status": "PASS", "case_count": len(joined), "result_sha256": sha(raw), "result_digest_sha256": result["result_digest_sha256"]}, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
