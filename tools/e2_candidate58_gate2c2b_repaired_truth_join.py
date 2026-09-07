#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
from typing import Any

import e2_candidate58_gate2a_truth_join as base
import e2_candidate58_gate2a_truth_join_v2 as v2

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL = ROOT / "protocols/RISU_DIFF_E2_GATE2C2B_REPAIRED_DEVELOPMENT_TRUTH_JOIN_PROTOCOL_v0.1.json"
REPAIRED_MACHINE = ROOT / "experiments/risu-diff-e2/qualification/candidate58/gate2c2a-repaired-machine-requalification/first-complete/E2_GATE2C2A_REPAIRED_MACHINE_PREDICTION_MATRIX.json"
REPAIRED_FREEZE = ROOT / "experiments/risu-diff-e2/qualification/candidate58/gate2c2a-repaired-machine-requalification/first-complete/E2_GATE2C2A_FIRST_COMPLETE_IMMUTABLE_FREEZE_RECEIPT.json"
ORIGINAL_METRICS = ROOT / "experiments/risu-diff-e2/qualification/candidate58/gate2a-first-complete-truth-join/E2_CANDIDATE58_GATE2A_METRICS.json"
EXPECTED_MACHINE_SHA256 = "da8cb707a5cc71b36881eafc01a377ba040bb5148ae3d3997ecd95f7572138d3"
EXPECTED_ORIGINAL_METRICS_SHA256 = "8014c1aa8ed252a5187be51b574348bdb3a744ba3070ace208a98156e7eed8a5"
EXPECTED_EXPANDED_SHA256 = "afd681d308a6f4ec8c183edd9b139c6b914fe501936cf84e5845a6a1c0d6b7cb"

PRIMARY_FIELDS = (
    "unsafe_false_stability",
    "regression_recall",
    "stable_resolution",
    "selective_coverage",
    "conditional_correctness_among_definitive_claims",
    "c1_disagreement_or_invalid_certificate_rate",
    "supported_fragment_coverage_all58",
    "supported_fragment_coverage_semantic48",
    "epistemic_calibration",
)
SECONDARY_FIELDS = (
    "final_machine_prediction_counts",
    "tentative_kernel_prediction_counts",
    "assurance_level_counts",
    "c1_checker_output_counts",
    "semantic_assurance_incomplete",
    "false_regression_on_M_ZERO",
    "expected_infrastructure_exact_resolution",
    "false_infrastructure_on_noninfrastructure",
    "overall_exact_expected_primary_match",
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canon(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def write(path: Path, value: Any) -> str:
    raw = canon(value)
    path.write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


def output_dir_from_argv() -> Path:
    import sys
    try:
        idx = sys.argv.index("--output-dir")
        return Path(sys.argv[idx + 1])
    except (ValueError, IndexError) as exc:
        raise SystemExit("--output-dir required") from exc


def preflight() -> tuple[dict[str, Any], dict[str, Any]]:
    protocol = json.loads(PROTOCOL.read_text())
    if protocol.get("status") != "PROSPECTIVE_FROZEN_BEFORE_GATE2C2B_JOIN_EXECUTION":
        raise SystemExit("Gate2C2b protocol status mismatch")
    if sha256(REPAIRED_MACHINE) != EXPECTED_MACHINE_SHA256:
        raise SystemExit("repaired machine matrix digest mismatch")
    freeze = json.loads(REPAIRED_FREEZE.read_text())
    if freeze.get("status") != "FIRST_COMPLETE_REPAIRED_CANDIDATE58_MACHINE_ONLY_IMMUTABLY_FROZEN_BY_CONTAINING_COMMIT":
        raise SystemExit("Gate2C2a freeze status mismatch")
    if freeze.get("frozen_files_sha256", {}).get("E2_GATE2C2A_REPAIRED_MACHINE_PREDICTION_MATRIX.json") != EXPECTED_MACHINE_SHA256:
        raise SystemExit("Gate2C2a freeze does not bind repaired matrix")
    if freeze.get("machine_only_before_truth_join") is not True or freeze.get("truth_or_gold_read") is not False:
        raise SystemExit("Gate2C2a scientific boundary mismatch")
    if sha256(ORIGINAL_METRICS) != EXPECTED_ORIGINAL_METRICS_SHA256:
        raise SystemExit("original Gate2A metrics digest mismatch")
    if sha256(base.EXPANDED) != EXPECTED_EXPANDED_SHA256:
        raise SystemExit("frozen expanded truth digest mismatch")
    return protocol, freeze


def side_by_side(out: Path, protocol: dict[str, Any], freeze: dict[str, Any]) -> None:
    repaired_metrics_path = out / "E2_CANDIDATE58_GATE2A_METRICS.json"
    repaired = json.loads(repaired_metrics_path.read_text())
    original = json.loads(ORIGINAL_METRICS.read_text())
    primary = {
        key: {"original": original["primary_preregistered"][key], "repaired": repaired["primary_preregistered"][key]}
        for key in PRIMARY_FIELDS
    }
    secondary = {
        key: {"original": original["mandatory_secondary"][key], "repaired": repaired["mandatory_secondary"][key]}
        for key in SECONDARY_FIELDS
    }
    unsafe = repaired["primary_preregistered"]["unsafe_false_stability"]["numerator"]
    c1bad = repaired["primary_preregistered"]["c1_disagreement_or_invalid_certificate_rate"]["numerator"]
    coverage = repaired["primary_preregistered"]["selective_coverage"]["numerator"]
    if unsafe > 0 or c1bad > 0:
        decision = "HARD_STOP_NO_HELDOUT"
    elif coverage == 0:
        decision = "NO_EPISTEMIC10_REASSESS_SUBSTRATE"
    else:
        decision = "EPISTEMIC10_ELIGIBLE_REASSESS_BEST_NEXT_STEP_FIRST"
    comparison = {
        "schema": "risu.e2-gate2c2b-original-vs-repaired-development-metrics/v0.1",
        "status": "DEVELOPMENT_REQUALIFICATION_SIDE_BY_SIDE_NOT_FRESH_GENERALIZATION",
        "population": repaired["population"],
        "original_machine_freeze_commit": "2ece1023252a8e9100a34d74079493040441e1e2",
        "original_truth_join_freeze_commit": "afcf9ce67d93be612f1004c6a2031e819f0ea12d",
        "repaired_machine_freeze_commit": "cad7072ed88abf3df6d0ecf263e3ba2de4d8172b",
        "metric_semantics": "EXACT_FROZEN_GATE2A_V1_V2_SEMANTICS_REUSED",
        "primary_preregistered": primary,
        "mandatory_secondary": secondary,
        "post_gate_decision": decision,
        "interpretation_boundary": {
            "development_population_only": True,
            "fresh_generalization_claim": False,
            "epistemic10_read": False,
            "new_scoring_rule_introduced": False,
        },
    }
    comparison_sha = write(out / "E2_GATE2C2B_ORIGINAL_VS_REPAIRED_DEVELOPMENT_METRICS.json", comparison)
    receipt = {
        "schema": "risu.e2-gate2c2b-compatibility-wrapper-receipt/v0.1",
        "status": "GATE2C2B_FROZEN_SCORING_REUSED_WITH_REPAIRED_MACHINE_INPUT",
        "protocol_sha256": sha256(PROTOCOL),
        "repaired_machine_sha256": sha256(REPAIRED_MACHINE),
        "repaired_machine_freeze_sha256": sha256(REPAIRED_FREEZE),
        "original_metrics_sha256": sha256(ORIGINAL_METRICS),
        "expanded_truth_sha256": sha256(base.EXPANDED),
        "gate2a_v1_joiner_git_blob": "f6645926d60a7029388b0f78a03115b7a4649c09",
        "gate2a_v2_wrapper_git_blob": "9eed33c52db0cd4af4def5ed61edd3ca05bd0ba0",
        "compatibility_view_semantic_authority": False,
        "compatibility_mutations": ["base.MACHINE", "base.EXPECTED.machine_sha256", "base.MACHINE_FREEZE"],
        "truth_or_metric_semantics_modified": False,
        "semantic_engine_rerun": False,
        "c1_checker_rerun": False,
        "epistemic10_read": False,
        "comparison_sha256": comparison_sha,
    }
    write(out / "E2_GATE2C2B_COMPATIBILITY_WRAPPER_RECEIPT.json", receipt)


def main() -> int:
    protocol, freeze = preflight()
    out = output_dir_from_argv()
    with tempfile.TemporaryDirectory(prefix="risu-gate2c2b-compat-") as td:
        compat = Path(td) / "machine-freeze-compat.json"
        compat.write_bytes(canon({
            "status": "FIRST_COMPLETE_MACHINE_ONLY_IMMUTABLY_FROZEN_NOT_GOLD_JOINED",
            "first_complete_identity": {"machine_matrix_sha256": EXPECTED_MACHINE_SHA256},
            "semantic_authority": False,
            "derived_from_gate2c2a_freeze_sha256": sha256(REPAIRED_FREEZE),
        }))
        base.MACHINE = REPAIRED_MACHINE
        base.MACHINE_FREEZE = compat
        base.EXPECTED["machine_sha256"] = EXPECTED_MACHINE_SHA256
        rc = v2.main()
    if rc != 0:
        return rc
    side_by_side(out, protocol, freeze)
    print(json.dumps({"status": "GATE2C2B_COMPLETE", "output_file_count": len(list(out.iterdir()))}, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
