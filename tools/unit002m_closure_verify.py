#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXP = ROOT / "experiments" / "unit002-m"
CLOSURE = EXP / "CLOSURE.json"
CANONICAL = EXP / "CANONICAL_RESULT.json"
CORRECTION = EXP / "IMPLEMENTATION_CORRECTION_001.json"
PLAN = EXP / "PLAN.json"

EXPECTED_MAIN_MERGE = "f3f1db0ad806e0abd051ecfe23ffbcbf039ad117"
EXPECTED_PLAN_COMMIT = "cecaf792cb131f022a1c7bcdd3ab12c0968a409f"
EXPECTED_CANONICAL_RUN = 33943444386
EXPECTED_CANONICAL_ARTIFACT = 9962563353
EXPECTED_MAIN_REPLAY_RUN = 33944438933
EXPECTED_MAIN_REPLAY_ARTIFACT = 9962868402


def read(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def fail(msg: str) -> None:
    raise SystemExit(f"UNIT002-M CLOSURE VERIFY: FAIL: {msg}")


def git_is_ancestor(ancestor: str) -> bool:
    p = subprocess.run(
        ["git", "merge-base", "--is-ancestor", ancestor, "HEAD"],
        cwd=str(ROOT), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    return p.returncode == 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    for path in (CLOSURE, CANONICAL, CORRECTION, PLAN):
        if not path.is_file():
            fail(f"missing required record: {path.relative_to(ROOT)}")

    closure = read(CLOSURE)
    canonical = read(CANONICAL)
    correction = read(CORRECTION)
    plan = read(PLAN)

    if closure.get("schema") != "risu.unit002-m-closure/v0.1alpha1":
        fail("closure schema mismatch")
    if closure.get("experiment_id") != "UNIT002_M_PAIRED_MUTATION_CONTROL":
        fail("closure experiment id mismatch")
    if closure.get("status") != "CLOSED_WHEN_PRESENT_ON_MAIN_AND_FINAL_MAIN_GATES_PASS":
        fail("closure status contract mismatch")

    if canonical.get("status") != "PROMOTED_CANONICAL_CONTROL_RESULT":
        fail("canonical result is not promoted")
    if canonical.get("experiment_id") != closure.get("experiment_id"):
        fail("canonical/closure experiment mismatch")
    if not canonical.get("promotion_rule_satisfied"):
        fail("canonical promotion rule is false")

    ce = canonical.get("canonical_execution") or {}
    cc = closure.get("canonical_control") or {}
    if ce.get("github_actions_run_id") != EXPECTED_CANONICAL_RUN or cc.get("github_actions_run_id") != EXPECTED_CANONICAL_RUN:
        fail("canonical run identity mismatch")
    if ce.get("artifact_id") != EXPECTED_CANONICAL_ARTIFACT or cc.get("artifact_id") != EXPECTED_CANONICAL_ARTIFACT:
        fail("canonical artifact identity mismatch")
    if ce.get("checkout_head_sha") != cc.get("checkout_head_sha"):
        fail("canonical checkout head mismatch")
    if ce.get("actions_artifact_zip_sha256") != cc.get("artifact_zip_sha256"):
        fail("canonical artifact digest mismatch")

    prospective = canonical.get("prospective_integrity") or {}
    if prospective.get("plan_freeze_commit") != EXPECTED_PLAN_COMMIT:
        fail("canonical prospective freeze commit mismatch")
    if cc.get("plan_freeze_commit") != EXPECTED_PLAN_COMMIT:
        fail("closure prospective freeze commit mismatch")
    if prospective.get("plan_git_blob_sha1") != cc.get("plan_git_blob_sha1"):
        fail("plan blob identity mismatch")
    if prospective.get("plan_sha256") != cc.get("plan_sha256"):
        fail("plan SHA-256 mismatch")
    if plan.get("status") != "PREDECLARED_BEFORE_MUTATION_EXECUTION":
        fail("PLAN is no longer predeclared")

    corr = canonical.get("implementation_correction") or {}
    ca = closure.get("implementation_audit") or {}
    if corr.get("id") != ca.get("correction_id"):
        fail("correction id mismatch")
    if corr.get("scope") != ca.get("correction_scope"):
        fail("correction scope mismatch")
    if corr.get("record_sha256") != ca.get("correction_record_sha256"):
        fail("correction record digest mismatch")
    if any((
        corr.get("frozen_plan_changed") is not False,
        corr.get("mutation_bytes_changed") is not False,
        corr.get("semantic_scoring_predicates_changed") is not False,
        ca.get("frozen_plan_changed") is not False,
        ca.get("mutation_bytes_changed") is not False,
        ca.get("semantic_scoring_predicates_changed") is not False,
    )):
        fail("bounded correction invariants violated")
    if correction.get("correction_id") != ca.get("correction_id"):
        fail("correction source record id mismatch")

    metrics = canonical.get("metrics") or {}
    expected = {
        "baseline_validity": (2, 2),
        "positive_sensitivity": (6, 6),
        "negative_specificity": (6, 6),
        "regression_witness_localization": (4, 4),
        "discriminator_detection": (2, 2),
        "deterministic_repeatability": (12, 12),
        "source_contract_invariance": (12, 12),
        "mutation_locality": (12, 12),
    }
    for key, (passed, total) in expected.items():
        row = metrics.get(key) or {}
        if row.get("passed") != passed or row.get("total") != total:
            fail(f"canonical metric changed: {key}")
    alarm = metrics.get("false_semantic_alarm_count") or {}
    if alarm.get("value") != 0 or alarm.get("required") != 0:
        fail("false semantic alarm count changed")

    ledger = canonical.get("proof_identity_ledger") or []
    if len(ledger) != 14:
        fail(f"expected 14 durable baseline/mutant proof identities, got {len(ledger)}")
    keys = {(x.get("seed_id"), x.get("operator_id"), x.get("class")) for x in ledger}
    if len(keys) != 14:
        fail("proof identity ledger contains duplicate logical cells")
    if not all(x.get("repeat_identity") is True for x in ledger):
        fail("a canonical ledger row lost deterministic repeat identity")

    merge = closure.get("merge") or {}
    if merge.get("pull_request") != 4:
        fail("merge PR identity mismatch")
    if merge.get("merge_commit_sha") != EXPECTED_MAIN_MERGE:
        fail("merge commit mismatch")
    if merge.get("expected_head_protection_used") is not True:
        fail("expected-head merge protection not recorded")
    if not git_is_ancestor(EXPECTED_MAIN_MERGE):
        fail("recorded Unit 002-M merge commit is not an ancestor of HEAD")

    main_replay = closure.get("merged_main_replay") or {}
    if main_replay.get("head_sha") != EXPECTED_MAIN_MERGE:
        fail("merged-main replay head mismatch")
    if main_replay.get("unit002_m_run") != EXPECTED_MAIN_REPLAY_RUN:
        fail("merged-main Unit 002-M run mismatch")
    if main_replay.get("unit002_m_artifact_id") != EXPECTED_MAIN_REPLAY_ARTIFACT:
        fail("merged-main replay artifact mismatch")
    if main_replay.get("canonical_static_record") != "PASS" or main_replay.get("matrix_replay") != "PASS" or main_replay.get("canonical_proof_identity_equality") != "PASS":
        fail("merged-main replay equality is not fully PASS")
    if main_replay.get("all_four_workflows_success") is not True:
        fail("merged-main supporting workflows not recorded as all-success")

    criteria = closure.get("closure_criteria") or {}
    if not criteria or not all(v is True for v in criteria.values()):
        fail("one or more closure criteria are not true")

    next_gate = closure.get("next_gate") or {}
    if next_gate.get("id") != "UNIT002_R_REAL_PROSPECTIVE_FALSIFICATION":
        fail("next gate drifted")
    if "independently" not in str(next_gate.get("selection_independence", "")).lower():
        fail("Unit 002-R independence rule missing")

    on_main = os.environ.get("GITHUB_REF") == "refs/heads/main"
    result = {
        "status": "PASS",
        "experiment_id": closure["experiment_id"],
        "canonical_run": EXPECTED_CANONICAL_RUN,
        "canonical_ledger_rows": len(ledger),
        "merge_commit": EXPECTED_MAIN_MERGE,
        "merged_main_replay_run": EXPECTED_MAIN_REPLAY_RUN,
        "all_closure_criteria": True,
        "record_present_on_main_runtime": on_main,
        "effective_closed": on_main,
        "next_gate": next_gate["id"],
    }
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print("UNIT002-M CLOSURE VERIFY: PASS")
        print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
