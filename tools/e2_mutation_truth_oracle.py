#!/usr/bin/env python3
"""Frozen E2 synthetic mutation truth oracle.

This oracle derives qualification truth only from the frozen seed catalog and
mutation-matrix contract. It deliberately has no input for E2 predictions.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CATALOG = ROOT / "experiments/risu-diff-e2/qualification/CANONICAL_SYNTHETIC_SEEDS.json"
DEFAULT_MATRIX = ROOT / "experiments/risu-diff-e2/qualification/MUTATION_QUALIFICATION_MATRIX.json"
DEFAULT_EXPANDED = ROOT / "experiments/risu-diff-e2/qualification/MUTATION_QUALIFICATION_MATRIX_EXPANDED.jsonl"

CLASS_ORDER = [
    "M_PLUS_SEMANTIC_LOSS",
    "M_ZERO_SEMANTIC_PRESERVING",
    "M_QUESTION_EPISTEMIC_ADVERSARIAL",
]


def canonical_row(row: dict[str, Any]) -> bytes:
    return (json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n").encode()


def expected_for(matrix: dict[str, Any], cls: str, operator_id: str) -> tuple[str, str]:
    rules = matrix["truth_rules"][cls]
    if cls == "M_QUESTION_EPISTEMIC_ADVERSARIAL":
        rule = rules.get("exceptions", {}).get(operator_id)
        if rule is not None:
            return rule["expected_truth"], rule["expected_e2_primary"]
        return rules["default_expected_truth"], rules["default_expected_e2_primary"]
    return rules["expected_truth"], rules["expected_e2_primary"]


def expand(matrix: dict[str, Any]) -> list[dict[str, Any]]:
    contract = matrix["expansion_contract"]
    rows: list[dict[str, Any]] = []
    index = 1
    for seed_id in contract["seed_order"]:
        for cls in contract["class_order"]:
            for operator_id in matrix["assignments"][seed_id][cls]:
                truth, expected_e2 = expected_for(matrix, cls, operator_id)
                rows.append(
                    {
                        "cell_id": f"Q{index:03d}",
                        "seed_id": seed_id,
                        "operator_class": cls,
                        "operator_id": operator_id,
                        "expected_truth": truth,
                        "expected_e2_primary": expected_e2,
                    }
                )
                index += 1
    return rows


def verify_seed_catalog(catalog: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if len(catalog["seeds"]) != 6:
        errors.append("seed_count_not_6")
    languages = Counter(seed["language"] for seed in catalog["seeds"])
    if languages != Counter({"python": 2, "go": 2, "typescript_javascript": 2}):
        errors.append(f"language_balance_mismatch:{dict(languages)}")
    for seed in catalog["seeds"]:
        if seed["baseline_truth"] != "CONSEQUENCE_STABLE_IN_DECLARED_SCOPE":
            errors.append(f"baseline_truth_mismatch:{seed['seed_id']}")
        if not seed["purity_attestation"]["pure_synthetic"]:
            errors.append(f"not_pure_synthetic:{seed['seed_id']}")
        if seed["purity_attestation"]["derived_from_real_target_bytes"]:
            errors.append(f"real_target_ancestry:{seed['seed_id']}")
        path = ROOT / seed["program_path"]
        if not path.is_file():
            errors.append(f"missing_program:{seed['seed_id']}")
            continue
        data = path.read_bytes()
        if len(data) != seed["program_bytes"]:
            errors.append(f"program_size_mismatch:{seed['seed_id']}")
        if hashlib.sha256(data).hexdigest() != seed["program_sha256"]:
            errors.append(f"program_sha256_mismatch:{seed['seed_id']}")
    return errors


def verify_matrix(matrix: dict[str, Any], expanded_path: Path) -> tuple[list[str], list[dict[str, Any]]]:
    errors: list[str] = []
    rows = expand(matrix)
    contract = matrix["expansion_contract"]
    if contract["class_order"] != CLASS_ORDER:
        errors.append("class_order_mismatch")
    if len(rows) != contract["expanded_row_count"]:
        errors.append("expanded_row_count_mismatch")
    generated = b"".join(canonical_row(row) for row in rows)
    digest = hashlib.sha256(generated).hexdigest()
    if digest != contract["expanded_jsonl_sha256"]:
        errors.append("expanded_digest_contract_mismatch")
    if not expanded_path.is_file():
        errors.append("expanded_matrix_missing")
    else:
        frozen = expanded_path.read_bytes()
        if frozen != generated:
            errors.append("expanded_matrix_bytes_mismatch")
        if hashlib.sha256(frozen).hexdigest() != contract["expanded_jsonl_sha256"]:
            errors.append("expanded_matrix_sha256_mismatch")

    counts = Counter(row["operator_class"] for row in rows)
    required = {
        "M_PLUS_SEMANTIC_LOSS": 24,
        "M_ZERO_SEMANTIC_PRESERVING": 24,
        "M_QUESTION_EPISTEMIC_ADVERSARIAL": 10,
    }
    if counts != Counter(required):
        errors.append(f"class_count_mismatch:{dict(counts)}")

    languages = {}
    for seed_id in contract["seed_order"]:
        if seed_id.startswith("SYN-PY"):
            languages[seed_id] = "python"
        elif seed_id.startswith("SYN-GO"):
            languages[seed_id] = "go"
        elif seed_id.startswith("SYN-TS"):
            languages[seed_id] = "typescript_javascript"
        else:
            errors.append(f"unknown_seed_language:{seed_id}")
    for lang in ("python", "go", "typescript_javascript"):
        positive = sum(
            row["operator_class"] == "M_PLUS_SEMANTIC_LOSS" and languages[row["seed_id"]] == lang
            for row in rows
        )
        negative = sum(
            row["operator_class"] == "M_ZERO_SEMANTIC_PRESERVING" and languages[row["seed_id"]] == lang
            for row in rows
        )
        if positive < 8:
            errors.append(f"positive_language_minimum_failed:{lang}:{positive}")
        if negative < 8:
            errors.append(f"negative_language_minimum_failed:{lang}:{negative}")
    return errors, rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
    parser.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX)
    parser.add_argument("--expanded", type=Path, default=DEFAULT_EXPANDED)
    parser.add_argument("--query")
    args = parser.parse_args()

    catalog = json.loads(args.catalog.read_text())
    matrix = json.loads(args.matrix.read_text())
    errors = verify_seed_catalog(catalog)
    matrix_errors, rows = verify_matrix(matrix, args.expanded)
    errors.extend(matrix_errors)

    if args.query:
        matches = [row for row in rows if row["cell_id"] == args.query]
        if len(matches) != 1:
            print(json.dumps({"status": "FAIL", "errors": errors + ["unknown_cell"]}, sort_keys=True))
            return 2
        print(json.dumps({"status": "PASS" if not errors else "FAIL", "errors": errors, "truth": matches[0]}, sort_keys=True))
        return 0 if not errors else 1

    summary = {
        "status": "PASS" if not errors else "FAIL",
        "errors": errors,
        "seed_count": len(catalog["seeds"]),
        "cell_count": len(rows),
        "matrix_sha256": matrix["expansion_contract"]["expanded_jsonl_sha256"],
        "e2_prediction_consumed": False,
    }
    print(json.dumps(summary, sort_keys=True))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
