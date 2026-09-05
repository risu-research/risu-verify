#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
EXP = ROOT / "experiments" / "unit002-m"
CANONICAL = EXP / "CANONICAL_RESULT.json"
PLAN = EXP / "PLAN.json"
FREEZE = EXP / "FREEZE.json"
CORRECTION = EXP / "IMPLEMENTATION_CORRECTION_001.json"
BASE_EXECUTOR = ROOT / "tools" / "unit002_mutation_control.py"
CORRECTION_WRAPPER = ROOT / "tools" / "unit002_mutation_control_correction001.py"


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fail(errors: list[str], message: str) -> None:
    errors.append(message)


def replay_ledger(result: dict) -> list[dict]:
    ledger: list[dict] = []
    for baseline in result.get("baselines") or []:
        runs = baseline.get("runs") or []
        if len(runs) != 2:
            raise ValueError(f"baseline repeat count != 2: {baseline.get('seed_id')}")
        r = runs[0]
        view = r["semantic_view"]
        artifacts = r["artifacts"]
        ledger.append({
            "seed_id": baseline["seed_id"],
            "operator_id": "BASELINE",
            "class": "BASELINE",
            "outcome": view["product_status"],
            "D": view["structural"]["D"],
            "exact_status": view["exact_realization"]["status"],
            "minimal_witness_world": None,
            "certificate_sha256": artifacts["certificate_sha256"],
            "proof_digest": artifacts["proof_view"]["proof_digest"],
            "repeat_identity": runs[0]["artifacts"] == runs[1]["artifacts"],
        })
    for cell in result.get("cells") or []:
        runs = cell.get("runs") or []
        if len(runs) != 2:
            raise ValueError(f"mutant repeat count != 2: {cell.get('seed_id')}:{cell.get('operator_id')}")
        r = runs[0]
        view = r["semantic_view"]
        artifacts = r["artifacts"]
        ledger.append({
            "seed_id": cell["seed_id"],
            "operator_id": cell["operator_id"],
            "class": cell["class"],
            "outcome": view["product_status"],
            "D": view["structural"]["D"],
            "exact_status": view["exact_realization"]["status"],
            "minimal_witness_world": r.get("minimal_witness_world"),
            "certificate_sha256": artifacts["certificate_sha256"],
            "proof_digest": artifacts["proof_view"]["proof_digest"],
            "repeat_identity": runs[0]["artifacts"] == runs[1]["artifacts"],
        })
    return sorted(ledger, key=lambda x: (x["seed_id"], x["operator_id"]))


def canonical_ledger(canonical: dict) -> list[dict]:
    return sorted(canonical.get("proof_identity_ledger") or [], key=lambda x: (x["seed_id"], x["operator_id"]))


def main() -> int:
    ap = argparse.ArgumentParser(description="Verify durable Unit 002-M canonical record and optional deterministic replay")
    ap.add_argument("--replay-result", help="Path to a newly generated MATRIX_RESULT.json")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    errors: list[str] = []
    try:
        c = read_json(CANONICAL)
        plan = read_json(PLAN)
        freeze = read_json(FREEZE)
        correction = read_json(CORRECTION)
    except Exception as exc:
        print(f"UNIT002-M CANONICAL VERIFY: FAIL: cannot load records: {exc}", file=sys.stderr)
        return 1

    if c.get("schema") != "risu.unit002-m-canonical-result/v0.1alpha1":
        fail(errors, "unsupported canonical schema")
    if c.get("status") != "PROMOTED_CANONICAL_CONTROL_RESULT":
        fail(errors, "canonical status is not PROMOTED_CANONICAL_CONTROL_RESULT")
    if c.get("promotion_rule_satisfied") is not True:
        fail(errors, "canonical promotion rule is not satisfied")
    if c.get("scientific_role") != "DETECTOR_CONTROL_NOT_REAL_TARGET_RESULT":
        fail(errors, "canonical scientific role widened unexpectedly")

    prospective = c.get("prospective_integrity") or {}
    if sha256_file(PLAN) != prospective.get("plan_sha256"):
        fail(errors, "PLAN SHA-256 differs from canonical pin")
    if sha256_file(FREEZE) != prospective.get("freeze_sha256"):
        fail(errors, "FREEZE SHA-256 differs from canonical pin")
    if prospective.get("plan_git_blob_sha1") != (freeze.get("plan") or {}).get("git_blob_sha1"):
        fail(errors, "PLAN Git blob identity mismatch between canonical and freeze")
    if prospective.get("plan_freeze_commit") != (freeze.get("plan") or {}).get("freeze_commit"):
        fail(errors, "PLAN freeze commit mismatch")
    if prospective.get("unit002_r_target_selection_from_result") != "PROHIBITED":
        fail(errors, "Unit002-R independence boundary weakened")

    impl = c.get("implementation_correction") or {}
    if correction.get("correction_id") != impl.get("id"):
        fail(errors, "implementation correction identity mismatch")
    if sha256_file(CORRECTION) != impl.get("record_sha256"):
        fail(errors, "implementation correction record SHA-256 mismatch")
    if sha256_file(BASE_EXECUTOR) != impl.get("base_executor_sha256"):
        fail(errors, "base executor bytes differ from canonical execution")
    if sha256_file(CORRECTION_WRAPPER) != impl.get("correction_wrapper_sha256"):
        fail(errors, "correction wrapper bytes differ from canonical execution")
    for field in ("frozen_plan_changed", "mutation_bytes_changed", "semantic_scoring_predicates_changed"):
        if impl.get(field) is not False:
            fail(errors, f"canonical correction boundary widened: {field}")

    expected_metrics = {
        "baseline_validity": (2, 2),
        "positive_sensitivity": (6, 6),
        "negative_specificity": (6, 6),
        "regression_witness_localization": (4, 4),
        "discriminator_detection": (2, 2),
        "deterministic_repeatability": (12, 12),
        "mutation_locality": (12, 12),
        "source_contract_invariance": (12, 12),
    }
    metrics = c.get("metrics") or {}
    for name, (passed, total) in expected_metrics.items():
        m = metrics.get(name) or {}
        if (m.get("passed"), m.get("total")) != (passed, total):
            fail(errors, f"canonical metric mismatch: {name}")
    if (metrics.get("false_semantic_alarm_count") or {}).get("value") != 0:
        fail(errors, "canonical false semantic alarms are not zero")

    ledger = canonical_ledger(c)
    if len(ledger) != 14:
        fail(errors, f"canonical proof ledger expected 14 cells, got {len(ledger)}")
    keys = [(x.get("seed_id"), x.get("operator_id")) for x in ledger]
    if len(set(keys)) != len(keys):
        fail(errors, "canonical proof ledger has duplicate seed/operator keys")
    if not all(x.get("repeat_identity") is True for x in ledger):
        fail(errors, "canonical proof ledger contains a non-repeat-identical cell")

    boundaries = c.get("boundaries") or {}
    for field in ("real_target_result", "live_runtime_claim", "prevalence_claim", "universal_detector_accuracy_claim"):
        if boundaries.get(field) is not False:
            fail(errors, f"canonical claim boundary widened: {field}")

    replay = None
    if args.replay_result:
        try:
            replay_path = Path(args.replay_result).resolve()
            result = read_json(replay_path)
            replay = {
                "path": str(replay_path),
                "status": result.get("status"),
                "metrics_match": result.get("metrics") == metrics,
                "proof_ledger_match": replay_ledger(result) == ledger,
                "promotion_rule_satisfied": result.get("promotion_rule_satisfied") is True,
            }
            if replay["status"] != "PROMOTED":
                fail(errors, f"replay status is not PROMOTED: {replay['status']}")
            if not replay["metrics_match"]:
                fail(errors, "replay metrics differ from canonical")
            if not replay["proof_ledger_match"]:
                fail(errors, "replay certificate/proof/witness ledger differs from canonical")
            if not replay["promotion_rule_satisfied"]:
                fail(errors, "replay promotion rule did not pass")
        except Exception as exc:
            fail(errors, f"cannot verify replay result: {exc}")

    result = {
        "schema": "risu.unit002-m-canonical-verification/v0.1alpha1",
        "status": "PASS" if not errors else "FAIL",
        "canonical_run_id": (c.get("canonical_execution") or {}).get("github_actions_run_id"),
        "canonical_checkout_head_sha": (c.get("canonical_execution") or {}).get("checkout_head_sha"),
        "proof_ledger_cells": len(ledger),
        "replay": replay,
        "errors": errors,
    }
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"UNIT002-M CANONICAL VERIFY: {result['status']}")
        if replay:
            print(f"  replay proof ledger match: {replay['proof_ledger_match']}")
        for error in errors:
            print(f"  ERROR: {error}", file=sys.stderr)
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
