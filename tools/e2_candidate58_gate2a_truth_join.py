#!/usr/bin/env python3
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]

PROTOCOL = ROOT / "protocols/RISU_DIFF_E2_CANDIDATE58_GATE2A_TRUTH_JOIN_PROTOCOL_v0.1.json"
MACHINE = ROOT / "experiments/risu-diff-e2/qualification/candidate58/first-complete-machine/E2_CANDIDATE58_FIRST_COMPLETE_MACHINE_PREDICTION_MATRIX.json"
MACHINE_FREEZE = ROOT / "experiments/risu-diff-e2/qualification/candidate58/first-complete-machine/E2_CANDIDATE58_FIRST_COMPLETE_MACHINE_IMMUTABLE_FREEZE_RECEIPT.json"
TRUTH_CONTRACT = ROOT / "experiments/risu-diff-e2/qualification/TRUTH_ORACLE_CONTRACT.json"
CATALOG = ROOT / "experiments/risu-diff-e2/qualification/CANONICAL_SYNTHETIC_SEEDS.json"
MATRIX = ROOT / "experiments/risu-diff-e2/qualification/MUTATION_QUALIFICATION_MATRIX.json"
EXPANDED = ROOT / "experiments/risu-diff-e2/qualification/MUTATION_QUALIFICATION_MATRIX_EXPANDED.jsonl"
ADMISSION = ROOT / "experiments/risu-diff-e2/qualification/anchor-transport/admission/E2_SANITIZED_OPAQUE_58_ADMISSION_MANIFEST.json"
CELLS = ROOT / "experiments/risu-diff-e2/qualification/materialized/cells"
POSTFREEZE_TRANSPORT = ROOT / "experiments/risu-diff-e2/qualification/anchor-transport/postfreeze/E2_POSTFREEZE_TRANSPORT_QUALIFICATION.json"

EXPECTED = {
    "machine_sha256": "7273ce4034d06e67989a33540f5b22fef3190cf311a8981474413b538e43472d",
    "expanded_sha256": "afd681d308a6f4ec8c183edd9b139c6b914fe501936cf84e5845a6a1c0d6b7cb",
    "admission_sha256": "847d85c2274cd6b94a83eefe0f6153a8fb183dbad758efa75118a4fd368623e4",
    "postfreeze_transport_sha256": "bbc7d72fded307b23f6e0d20609b85662e63013cc06cd05b0c3c30269ba71749",
    "class_counts": {
        "M_PLUS_SEMANTIC_LOSS": 24,
        "M_ZERO_SEMANTIC_PRESERVING": 24,
        "M_QUESTION_EPISTEMIC_ADVERSARIAL": 10,
    },
}

REG = "E2_PREDICTED_REGRESSION_WITNESS"
PRES = "E2_PREDICTED_PRESERVATION_EVIDENCE"
INC = "E2_PREDICTED_ASSURANCE_INCOMPLETE"
INFRA = "INFRASTRUCTURE_INVALID_BEFORE_PREDICTION"
DEFINITIVE = {REG, PRES}
ALLOWED_MACHINE = {REG, PRES, INC, INFRA}


def raw_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def write_canonical(path: Path, value: Any) -> str:
    raw = canonical_bytes(value)
    path.write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


def rate(n: int, d: int) -> dict[str, Any]:
    return {
        "numerator": n,
        "denominator": d,
        "rate_decimal": None if d == 0 else f"{n / d:.6f}",
    }


def expected_for(matrix: dict[str, Any], cls: str, operator_id: str) -> tuple[str, str]:
    rule = matrix["truth_rules"][cls]
    if cls == "M_QUESTION_EPISTEMIC_ADVERSARIAL":
        exc = rule.get("exceptions", {}).get(operator_id)
        if exc is not None:
            return exc["expected_truth"], exc["expected_e2_primary"]
        return rule["default_expected_truth"], rule["default_expected_e2_primary"]
    return rule["expected_truth"], rule["expected_e2_primary"]


def independently_expand(matrix: dict[str, Any]) -> list[dict[str, Any]]:
    contract = matrix["expansion_contract"]
    rows: list[dict[str, Any]] = []
    i = 1
    for seed_id in contract["seed_order"]:
        for cls in contract["class_order"]:
            for operator_id in matrix["assignments"][seed_id][cls]:
                truth, expected_e2 = expected_for(matrix, cls, operator_id)
                rows.append({
                    "cell_id": f"Q{i:03d}",
                    "seed_id": seed_id,
                    "operator_class": cls,
                    "operator_id": operator_id,
                    "expected_truth": truth,
                    "expected_e2_primary": expected_e2,
                })
                i += 1
    return rows


def source_language(seed_id: str) -> str:
    if seed_id.startswith("SYN-PY-"):
        return "python"
    if seed_id.startswith("SYN-GO-"):
        return "go"
    if seed_id.startswith("SYN-TS-"):
        return "typescript_javascript"
    raise ValueError(f"unknown seed language:{seed_id}")


def classify(row: dict[str, Any]) -> str:
    cls = row["operator_class"]
    pred = row["machine_prediction"]
    if cls == "M_PLUS_SEMANTIC_LOSS":
        return {
            REG: "CORRECT_REGRESSION_WITNESS",
            PRES: "UNSAFE_FALSE_STABILITY",
            INC: "ABSTAINED_ON_REGRESSION",
            INFRA: "INFRASTRUCTURE_LABEL_ON_REGRESSION",
        }[pred]
    if cls == "M_ZERO_SEMANTIC_PRESERVING":
        return {
            REG: "FALSE_REGRESSION_ON_STABLE",
            PRES: "CORRECT_STABLE_RESOLUTION",
            INC: "ABSTAINED_ON_STABLE",
            INFRA: "INFRASTRUCTURE_LABEL_ON_STABLE",
        }[pred]
    return "EPISTEMIC_EXACT" if pred == row["expected_e2_primary"] else "EPISTEMIC_MISMATCH"


def c1_bad(case: dict[str, Any]) -> bool:
    values = [str(case.get("c1_checker_output", ""))]
    values.extend(str(x) for x in case.get("promotion_reasons", []) or [])
    text = "|".join(values).upper()
    if "UNSUPPORTED" in text and "INVALID" not in text and "DISAGREEMENT" not in text:
        return False
    return "INVALID" in text or "DISAGREEMENT" in text


def stratum(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "n": len(rows),
        "exact_expected_primary_match": rate(sum(r["exact_primary_match"] for r in rows), len(rows)),
        "machine_prediction_counts": dict(sorted(Counter(r["machine_prediction"] for r in rows).items())),
        "operator_class_counts": dict(sorted(Counter(r["operator_class"] for r in rows).items())),
        "assurance_level_counts": dict(sorted(Counter(r["assurance_level"] for r in rows).items())),
        "c1_checker_output_counts": dict(sorted(Counter(r["c1_checker_output"] for r in rows).items())),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--output-dir", required=True, type=Path)
    args = ap.parse_args()
    out = args.output_dir
    if out.exists() and any(out.iterdir()):
        raise SystemExit("output directory must be empty")
    out.mkdir(parents=True, exist_ok=True)

    # Bind immutable machine and truth-side inputs before any scoring.
    if raw_sha256(MACHINE) != EXPECTED["machine_sha256"]:
        raise SystemExit("machine matrix digest mismatch")
    if raw_sha256(EXPANDED) != EXPECTED["expanded_sha256"]:
        raise SystemExit("expanded truth digest mismatch")
    if raw_sha256(ADMISSION) != EXPECTED["admission_sha256"]:
        raise SystemExit("admission digest mismatch")
    if raw_sha256(POSTFREEZE_TRANSPORT) != EXPECTED["postfreeze_transport_sha256"]:
        raise SystemExit("postfreeze transport digest mismatch")

    protocol = json.loads(PROTOCOL.read_text())
    if protocol.get("status") != "PROSPECTIVE_FROZEN_BEFORE_GATE2A_JOIN_EXECUTION":
        raise SystemExit("Gate2A protocol status mismatch")
    truth_contract = json.loads(TRUTH_CONTRACT.read_text())
    if truth_contract.get("status") != "SEALED_BEFORE_E2_IMPLEMENTATION_AND_BEFORE_MUTANT_MATERIALIZATION":
        raise SystemExit("truth contract status mismatch")
    catalog = json.loads(CATALOG.read_text())
    matrix = json.loads(MATRIX.read_text())
    admission = json.loads(ADMISSION.read_text())
    machine = json.loads(MACHINE.read_text())
    machine_freeze = json.loads(MACHINE_FREEZE.read_text())

    if machine_freeze.get("status") != "FIRST_COMPLETE_MACHINE_ONLY_IMMUTABLY_FROZEN_NOT_GOLD_JOINED":
        raise SystemExit("first-complete machine freeze status mismatch")
    if machine_freeze["first_complete_identity"]["machine_matrix_sha256"] != EXPECTED["machine_sha256"]:
        raise SystemExit("machine freeze does not bind expected matrix")
    if machine.get("schema") != "risu.e2-candidate58-machine-prediction-matrix/v0.1" or machine.get("machine_only") is not True:
        raise SystemExit("machine matrix schema/machine_only mismatch")
    if machine.get("case_count") != 58 or len(machine.get("cases", [])) != 58:
        raise SystemExit("machine matrix not exactly 58")
    if admission.get("case_count") != 58 or len(admission.get("cases", [])) != 58:
        raise SystemExit("admission not exactly 58")

    # Independent truth expansion; byte equality with the pre-E2 frozen JSONL is mandatory.
    rows = independently_expand(matrix)
    generated = b"".join(canonical_bytes(r) for r in rows)
    if generated != EXPANDED.read_bytes():
        raise SystemExit("independent truth expansion != frozen expanded bytes")
    if hashlib.sha256(generated).hexdigest() != EXPECTED["expanded_sha256"]:
        raise SystemExit("independent truth expansion digest mismatch")
    if len(rows) != 58:
        raise SystemExit("independent truth expansion not 58")
    if Counter(r["operator_class"] for r in rows) != Counter(EXPECTED["class_counts"]):
        raise SystemExit("truth class counts mismatch")

    # Seed catalog is checked here independently of the frozen truth-oracle executable.
    seeds = {s["seed_id"]: s for s in catalog.get("seeds", [])}
    if len(seeds) != 6:
        raise SystemExit("seed catalog not exactly six")
    if Counter(source_language(s) for s in seeds) != Counter({"python": 2, "go": 2, "typescript_javascript": 2}):
        raise SystemExit("seed language balance mismatch")

    admission_by_sha: dict[str, dict[str, Any]] = {}
    admission_by_case: dict[str, dict[str, Any]] = {}
    for a in admission["cases"]:
        sha = a["candidate_source_sha256"]
        cid = a["transport_case_id"]
        if sha in admission_by_sha or cid in admission_by_case:
            raise SystemExit("admission duplicate source hash or case id")
        admission_by_sha[sha] = a
        admission_by_case[cid] = a

    machine_by_case: dict[str, dict[str, Any]] = {}
    for c in machine["cases"]:
        cid = c["case_id"]
        if cid in machine_by_case:
            raise SystemExit("machine duplicate case id")
        if c["machine_prediction"] not in ALLOWED_MACHINE or c["tentative_kernel_prediction"] not in ALLOWED_MACHINE:
            raise SystemExit("unexpected machine label")
        machine_by_case[cid] = c
    if set(machine_by_case) != set(admission_by_case):
        raise SystemExit("machine/admission case-id set mismatch")

    truth_by_cell = {r["cell_id"]: r for r in rows}
    cell_to_case: dict[str, str] = {}
    consumed_source_hashes: set[str] = set()
    for i in range(1, 59):
        q = f"Q{i:03d}"
        d = CELLS / q
        if not d.is_dir():
            raise SystemExit(f"missing materialized cell:{q}")
        sources = sorted(p for p in d.iterdir() if p.is_file() and p.name != "CELL.json" and p.suffix in {".py", ".go", ".mjs", ".js", ".ts"})
        if len(sources) != 1:
            raise SystemExit(f"materialized cell must have exactly one source:{q}:{len(sources)}")
        sha = raw_sha256(sources[0])
        if sha not in admission_by_sha:
            raise SystemExit(f"materialized source absent from admission:{q}")
        if sha in consumed_source_hashes:
            raise SystemExit(f"duplicate materialized source hash:{q}")
        consumed_source_hashes.add(sha)
        a = admission_by_sha[sha]
        t = truth_by_cell[q]
        if a["seed_id"] != t["seed_id"] or a["language"] != source_language(t["seed_id"]):
            raise SystemExit(f"materialized/admission/truth seed-language mismatch:{q}")
        cell_to_case[q] = a["transport_case_id"]
    if consumed_source_hashes != set(admission_by_sha):
        raise SystemExit("materialized/admission source-hash bijection failed")
    if len(set(cell_to_case.values())) != 58:
        raise SystemExit("cell/case bridge not bijective")

    ledger: list[dict[str, Any]] = []
    for i in range(1, 59):
        q = f"Q{i:03d}"
        t = truth_by_cell[q]
        cid = cell_to_case[q]
        a = admission_by_case[cid]
        c = machine_by_case[cid]
        if c["candidate_source_sha256"] != a["candidate_source_sha256"] or c["seed_id"] != a["seed_id"] or c["language"] != a["language"]:
            raise SystemExit(f"machine/admission identity mismatch:{q}")
        r = {
            "cell_id": q,
            "case_id": cid,
            "candidate_source_sha256": a["candidate_source_sha256"],
            "seed_id": t["seed_id"],
            "language": a["language"],
            "operator_class": t["operator_class"],
            "operator_id": t["operator_id"],
            "expected_truth": t["expected_truth"],
            "expected_e2_primary": t["expected_e2_primary"],
            "machine_prediction": c["machine_prediction"],
            "tentative_kernel_prediction": c["tentative_kernel_prediction"],
            "assurance_level": c["assurance_level"],
            "c1_checker_output": c["c1_checker_output"],
            "promotion_reasons": c.get("promotion_reasons", []),
            "exact_primary_match": c["machine_prediction"] == t["expected_e2_primary"],
            "c1_disagreement_or_invalid": c1_bad(c),
        }
        r["classification"] = classify(r)
        ledger.append(r)

    plus = [r for r in ledger if r["operator_class"] == "M_PLUS_SEMANTIC_LOSS"]
    zero = [r for r in ledger if r["operator_class"] == "M_ZERO_SEMANTIC_PRESERVING"]
    epi = [r for r in ledger if r["operator_class"] == "M_QUESTION_EPISTEMIC_ADVERSARIAL"]
    semantic = plus + zero
    definitive_semantic = [r for r in semantic if r["machine_prediction"] in DEFINITIVE]
    supported_definitive_all = [r for r in ledger if r["machine_prediction"] in DEFINITIVE and r["assurance_level"] == "VALID_C1"]
    supported_definitive_semantic = [r for r in semantic if r["machine_prediction"] in DEFINITIVE and r["assurance_level"] == "VALID_C1"]
    expected_infra = [r for r in ledger if r["expected_e2_primary"] == INFRA]
    nonexpected_infra = [r for r in ledger if r["expected_e2_primary"] != INFRA]

    primary = {
        "unsafe_false_stability": rate(sum(r["machine_prediction"] == PRES for r in plus), 24),
        "regression_recall": rate(sum(r["machine_prediction"] == REG for r in plus), 24),
        "selective_coverage": rate(len(definitive_semantic), 48),
        "conditional_correctness_among_definitive_claims": rate(sum(r["exact_primary_match"] for r in definitive_semantic), len(definitive_semantic)),
        "stable_resolution": rate(sum(r["machine_prediction"] == PRES for r in zero), 24),
        "epistemic_calibration": rate(sum(r["exact_primary_match"] for r in epi), 10),
        "c1_disagreement_or_invalid_certificate_rate": rate(sum(r["c1_disagreement_or_invalid"] for r in ledger), 58),
        "supported_fragment_coverage_all58": rate(len(supported_definitive_all), 58),
        "supported_fragment_coverage_semantic48": rate(len(supported_definitive_semantic), 48),
    }

    by_language: dict[str, list[dict[str, Any]]] = defaultdict(list)
    by_class: dict[str, list[dict[str, Any]]] = defaultdict(list)
    by_operator: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in ledger:
        by_language[r["language"]].append(r)
        by_class[r["operator_class"]].append(r)
        by_operator[r["operator_id"]].append(r)

    metrics = {
        "schema": "risu.e2-candidate58-gate2a-truth-join-metrics/v0.1",
        "status": "GATE2A_DESCRIPTIVE_SCORING_COMPLETE_NOT_FRESH_GENERALIZATION",
        "population": {"all": 58, "semantic": 48, "M_PLUS": 24, "M_ZERO": 24, "M_QUESTION": 10},
        "primary_preregistered": primary,
        "mandatory_secondary": {
            "overall_exact_expected_primary_match": rate(sum(r["exact_primary_match"] for r in ledger), 58),
            "final_machine_prediction_counts": dict(sorted(Counter(r["machine_prediction"] for r in ledger).items())),
            "tentative_kernel_prediction_counts": dict(sorted(Counter(r["tentative_kernel_prediction"] for r in ledger).items())),
            "final_vs_tentative_transition_counts": dict(sorted(Counter(f"{r['tentative_kernel_prediction']}->{r['machine_prediction']}" for r in ledger).items())),
            "assurance_level_counts": dict(sorted(Counter(r["assurance_level"] for r in ledger).items())),
            "c1_checker_output_counts": dict(sorted(Counter(r["c1_checker_output"] for r in ledger).items())),
            "semantic_assurance_incomplete": rate(sum(r["machine_prediction"] == INC for r in semantic), 48),
            "semantic_infrastructure_invalid": rate(sum(r["machine_prediction"] == INFRA for r in semantic), 48),
            "false_regression_on_M_ZERO": rate(sum(r["machine_prediction"] == REG for r in zero), 24),
            "expected_infrastructure_exact_resolution": rate(sum(r["machine_prediction"] == INFRA for r in expected_infra), len(expected_infra)),
            "false_infrastructure_on_noninfrastructure": rate(sum(r["machine_prediction"] == INFRA for r in nonexpected_infra), len(nonexpected_infra)),
            "expected_infrastructure_count": len(expected_infra),
        },
        "strata": {
            "language": {k: stratum(v) for k, v in sorted(by_language.items())},
            "operator_class": {k: stratum(v) for k, v in sorted(by_class.items())},
            "operator_id": {k: stratum(v) for k, v in sorted(by_operator.items())},
        },
        "interpretation_boundary": {
            "development_qualification_only": True,
            "fresh_generalization_claim_authorized": False,
            "abstention_counts_as_correct_on_semantic_classes": False,
            "zero_definitive_denominator_yields_null_conditional_correctness": True,
        },
    }

    ledger_doc = {
        "schema": "risu.e2-candidate58-gate2a-truth-joined-ledger/v0.1",
        "case_count": 58,
        "rows": ledger,
    }
    ledger_sha = write_canonical(out / "E2_CANDIDATE58_GATE2A_JOINED_LEDGER.json", ledger_doc)
    metrics_sha = write_canonical(out / "E2_CANDIDATE58_GATE2A_METRICS.json", metrics)

    receipt = {
        "schema": "risu.e2-candidate58-gate2a-truth-join-receipt/v0.1",
        "status": "FIRST_COMPLETE_GATE2A_TRUTH_JOIN_LOGICAL_OUTPUT",
        "inputs": {
            "protocol_sha256": raw_sha256(PROTOCOL),
            "machine_matrix_sha256": raw_sha256(MACHINE),
            "machine_freeze_receipt_sha256": raw_sha256(MACHINE_FREEZE),
            "truth_oracle_contract_sha256": raw_sha256(TRUTH_CONTRACT),
            "seed_catalog_sha256": raw_sha256(CATALOG),
            "mutation_matrix_sha256": raw_sha256(MATRIX),
            "expanded_truth_sha256": raw_sha256(EXPANDED),
            "admission_sha256": raw_sha256(ADMISSION),
            "postfreeze_transport_qualification_sha256": raw_sha256(POSTFREEZE_TRANSPORT),
        },
        "integrity": {
            "independent_truth_expansion_byte_identity": True,
            "materialized_source_to_admission_bijection_count": 58,
            "admission_to_machine_case_bijection_count": 58,
            "all_cases_reported": True,
            "case_exclusions": 0,
        },
        "outputs": {
            "joined_ledger_sha256": ledger_sha,
            "metrics_sha256": metrics_sha,
        },
        "scientific_firewall": {
            "semantic_engine_rerun": False,
            "c1_checker_rerun": False,
            "machine_matrix_modified": False,
            "truth_modified": False,
            "fresh_heldout_read": False,
            "outcome_driven_case_exclusion": False,
            "outcome_driven_metric_or_denominator_change": False,
        },
    }
    receipt_sha = write_canonical(out / "E2_CANDIDATE58_GATE2A_JOIN_RECEIPT.json", receipt)
    print(json.dumps({
        "status": receipt["status"],
        "case_count": 58,
        "ledger_sha256": ledger_sha,
        "metrics_sha256": metrics_sha,
        "receipt_sha256": receipt_sha,
    }, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
