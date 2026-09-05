#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "corpus" / "0.1"
PROTOCOL = ROOT / "PROSPECTIVE_CORPUS_0.1_PROTOCOL.json"
TIMESTAMP = ROOT / "protocols" / "EXTERNAL_TIMESTAMP_RECORD_001.json"
POOL = CORPUS / "CANDIDATE_POOL.json"
PROCEDURE = CORPUS / "SCREENING_PROCEDURE.json"
OP_RULE = CORPUS / "OPERATION_SELECTION_RULE.json"
AUTHORING_PROTOCOL = CORPUS / "AUTHORING_PROTOCOL.json"
SCREENING_LOG = CORPUS / "SCREENING_LOG.jsonl"
ENROLLMENT = CORPUS / "ENROLLMENT.json"

EXPECTED_PROTOCOL_SHA256 = "9fbf3fcdf48e5554840c4f2418803779ad82757e1a5df71411212421c225ad70"
TARGET_ENROLLMENT = 8
FRICTION_FIELDS = [
    "operation_identification",
    "source_semantic_reconstruction",
    "boundary_definition",
    "evidence_acquisition",
    "version_binding_discovery",
    "adapter_or_envelope_authoring",
    "human_correction",
    "verification_runtime",
]
PHASE_STATUS_VALUES = {"NOT_STARTED", "IN_PROGRESS", "COMPLETE", "BLOCKED"}
REJECTION_CODES = {
    "NOT_INDEPENDENT_EXTERNAL_SYSTEM",
    "NO_CONSEQUENTIAL_WRITE_OR_STATE_TRANSITION",
    "NO_PLAUSIBLE_VERSION_BOUND_EFFECT",
    "SOURCE_OR_TARGET_NOT_REPRODUCIBLY_PINNABLE",
    "BOUNDED_VBE_WORLDS_NOT_DECLARABLE_WITHOUT_VERDICT",
    "CARRIER_EVIDENCE_NOT_SEPARABLE_FROM_SEMANTIC_INTERPRETATION",
    "KNOWN_RISU_DETECTABLE_BUG_USED_FOR_SELECTION",
    "RISU_AUTHORED_TARGET_OR_TOY",
    "REQUIRES_FROZEN_CORE_EXPANSION",
    "ORGANIZATION_CAP_REACHED",
    "DUPLICATE_OPERATIONAL_UNIT",
}
FORBIDDEN_PREVERDICT_KEYS = {
    "risu_verdict",
    "product_status",
    "structural",
    "exact_realization",
    "counterexample",
    "minimal_counterexample",
    "repair_obligations",
    "c",
    "d",
    "o",
}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def fail(errors: list[str], message: str) -> None:
    errors.append(message)


def walk_keys(value, path=""):
    if isinstance(value, dict):
        for key, item in value.items():
            p = f"{path}.{key}" if path else key
            yield key.lower(), p
            yield from walk_keys(item, p)
    elif isinstance(value, list):
        for i, item in enumerate(value):
            yield from walk_keys(item, f"{path}[{i}]")


def load_jsonl(path: Path, errors: list[str]) -> list[dict]:
    if not path.exists():
        return []
    rows = []
    for line_no, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not raw.strip():
            continue
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError as exc:
            fail(errors, f"screening log line {line_no} is invalid JSON: {exc}")
            continue
        if not isinstance(obj, dict):
            fail(errors, f"screening log line {line_no} must be an object")
            continue
        rows.append(obj)
    return rows


def validate_static(errors: list[str]) -> tuple[dict, dict, dict]:
    actual_protocol_sha = sha256_bytes(PROTOCOL.read_bytes())
    if actual_protocol_sha != EXPECTED_PROTOCOL_SHA256:
        fail(errors, f"sealed protocol hash changed: {actual_protocol_sha}")

    timestamp = read_json(TIMESTAMP)
    if timestamp.get("protocol_sha256") != EXPECTED_PROTOCOL_SHA256:
        fail(errors, "external timestamp record points to a different protocol hash")
    if timestamp.get("external_timestamp_requirement") != "SATISFIED_BY_PUBLIC_GIT_COMMIT":
        fail(errors, "external timestamp requirement is not satisfied")
    if timestamp.get("screening_state_when_recorded") != "NOT_STARTED":
        fail(errors, "external timestamp does not establish pre-screening publication")
    if not timestamp.get("commit_sha"):
        fail(errors, "external timestamp record has no commit identity")

    procedure = read_json(PROCEDURE)
    if procedure.get("status_at_commit") != "PRECOMMITTED_BEFORE_CANDIDATE_DISCOVERY":
        fail(errors, "screening procedure lacks pre-discovery status")
    if procedure.get("protocol", {}).get("sha256") != EXPECTED_PROTOCOL_SHA256:
        fail(errors, "screening procedure protocol pin mismatch")

    operation_rule = read_json(OP_RULE)
    if operation_rule.get("status_at_commit") != "PRECOMMITTED_BEFORE_DETAILED_ELIGIBILITY_SCREENING":
        fail(errors, "operation selection rule lacks pre-screening status")

    if AUTHORING_PROTOCOL.exists():
        authoring = read_json(AUTHORING_PROTOCOL)
        if authoring.get("status_at_commit") != "PRECOMMITTED_AFTER_ENROLLMENT_FREEZE_BEFORE_PRIMARY_VERDICTS":
            fail(errors, "authoring protocol has unexpected timing status")
        if authoring.get("parent_protocol_sha256") != EXPECTED_PROTOCOL_SHA256:
            fail(errors, "authoring protocol parent protocol pin mismatch")

    pool = read_json(POOL)
    candidates = pool.get("candidates") or []
    if pool.get("status") != "FROZEN_BEFORE_DETAILED_ELIGIBILITY_SCREENING":
        fail(errors, "candidate pool is not marked frozen before detailed screening")
    if pool.get("protocol_sha256") != EXPECTED_PROTOCOL_SHA256:
        fail(errors, "candidate pool protocol pin mismatch")
    if pool.get("candidate_count") != len(candidates):
        fail(errors, "candidate_count does not match candidates array")
    if len(candidates) < 16:
        fail(errors, "candidate pool violates minimum pre-screening pool target")

    ids = [c.get("candidate_id") for c in candidates]
    if None in ids or len(ids) != len(set(ids)):
        fail(errors, "candidate IDs must be present and unique")

    expected = []
    for c in candidates:
        cid = c.get("candidate_id")
        key = hashlib.sha256(f"{EXPECTED_PROTOCOL_SHA256}:{cid}".lower().encode()).hexdigest()
        if c.get("order_key") != key:
            fail(errors, f"candidate order key mismatch: {cid}")
        expected.append((key, cid))
    sorted_expected = sorted(expected)
    actual_order = [(c.get("order_key"), c.get("candidate_id")) for c in candidates]
    if actual_order != sorted_expected:
        fail(errors, "candidate array is not in deterministic hash order")
    for i, c in enumerate(candidates, 1):
        if c.get("order") != i:
            fail(errors, f"candidate order field mismatch at position {i}")

    return pool, procedure, operation_rule


def validate_screening(pool: dict, errors: list[str]) -> list[dict]:
    rows = load_jsonl(SCREENING_LOG, errors)
    candidates = pool.get("candidates") or []
    by_id = {c["candidate_id"]: c for c in candidates}

    if len(rows) > len(candidates):
        fail(errors, "screening log has more rows than the frozen pool")

    for i, row in enumerate(rows, 1):
        expected = candidates[i - 1]
        if row.get("sequence") != i:
            fail(errors, f"screening row {i} sequence must equal {i}")
        if row.get("candidate_id") != expected.get("candidate_id"):
            fail(errors, f"screening row {i} skips or reorders the frozen candidate pool")
        if row.get("candidate_order") != expected.get("order"):
            fail(errors, f"screening row {i} candidate_order mismatch")
        if row.get("order_key") != expected.get("order_key"):
            fail(errors, f"screening row {i} order_key mismatch")
        decision = row.get("eligibility")
        if decision not in {"ELIGIBLE", "REJECTED"}:
            fail(errors, f"screening row {i} eligibility must be ELIGIBLE or REJECTED")

        for required in ["target_revision", "screened_operation", "target_evidence", "source_operation", "source_evidence"]:
            if required not in row:
                fail(errors, f"screening row {i} missing {required}")

        if row.get("stratum") != expected.get("stratum"):
            fail(errors, f"screening row {i} stratum differs from frozen pool")
        if row.get("organization") != expected.get("organization"):
            fail(errors, f"screening row {i} organization differs from frozen pool")
        if row.get("mechanism_family") != expected.get("coarse_mechanism_family"):
            fail(errors, f"screening row {i} mechanism family differs from frozen pool")

        if decision == "REJECTED":
            reasons = row.get("rejection_reasons") or []
            if not reasons:
                fail(errors, f"screening row {i} rejection has no reason")
            unknown = set(reasons) - REJECTION_CODES
            if unknown:
                fail(errors, f"screening row {i} has unknown rejection codes: {sorted(unknown)}")
        elif row.get("rejection_reasons"):
            fail(errors, f"screening row {i} is eligible but carries rejection reasons")

        for key, key_path in walk_keys(row):
            if key in FORBIDDEN_PREVERDICT_KEYS:
                fail(errors, f"pre-verdict screening row {i} contains forbidden key {key_path}")

        if row.get("issue_tracker_consulted_before_enrollment") is not False:
            fail(errors, f"screening row {i} must explicitly record no pre-enrollment issue-tracker consultation")
        if row.get("risu_executed_before_enrollment") is not False:
            fail(errors, f"screening row {i} must explicitly record no pre-enrollment RISU execution")
        if row.get("candidate_id") not in by_id:
            fail(errors, f"screening row {i} references unknown candidate")

    return rows


def validate_enrollment(pool: dict, rows: list[dict], errors: list[str]) -> dict | None:
    if not ENROLLMENT.exists():
        return None
    enrollment = read_json(ENROLLMENT)
    units = enrollment.get("units") or []
    if len(units) > TARGET_ENROLLMENT:
        fail(errors, "enrollment exceeds frozen target of 8")

    row_by_id = {r.get("candidate_id"): r for r in rows}
    seen = set()
    for pos, unit in enumerate(units, 1):
        cid = unit.get("candidate_id")
        if cid in seen:
            fail(errors, f"candidate enrolled more than once: {cid}")
        seen.add(cid)
        screened = row_by_id.get(cid)
        if not screened or screened.get("eligibility") != "ELIGIBLE":
            fail(errors, f"enrolled unit {cid} lacks prior committed ELIGIBLE screening row")
        if unit.get("enrollment_position") != pos:
            fail(errors, f"enrollment position mismatch for {cid}")
        for field in ["organization", "stratum", "mechanism_family", "target_revision", "screened_operation"]:
            if unit.get(field) != screened.get(field):
                fail(errors, f"enrollment field {field} does not match screening record for {cid}")
        if unit.get("verdict_observed_at_enrollment") is not False:
            fail(errors, f"unit {cid} must record verdict_observed_at_enrollment=false")

    orgs = Counter(u.get("organization") for u in units)
    for org, count in orgs.items():
        if count > 2:
            fail(errors, f"organization cap exceeded: {org} has {count} units")

    eligible_rows = [r for r in rows if r.get("eligibility") == "ELIGIBLE"]
    rejected_rows = [r for r in rows if r.get("eligibility") == "REJECTED"]

    if len(units) == TARGET_ENROLLMENT:
        if len(orgs) < 4:
            fail(errors, "completed enrollment has fewer than 4 organizations")
        mechanisms = {u.get("mechanism_family") for u in units}
        if len(mechanisms) < 3:
            fail(errors, "completed enrollment has fewer than 3 mechanism families")
        strata = {u.get("stratum") for u in units}
        if not {"AGENT_FACING", "NON_AGENT_SPECIFIC"}.issubset(strata):
            fail(errors, "completed enrollment lacks one required stratum")

        if enrollment.get("status") != "COMPLETE_VERDICT_BLIND_ENROLLMENT_FROZEN":
            fail(errors, "completed eight-unit enrollment is not marked frozen")
        if enrollment.get("verdicts_observed_before_enrollment_freeze") != 0:
            fail(errors, "completed enrollment does not record zero pre-freeze verdicts")
        if enrollment.get("screened_candidates") != len(rows):
            fail(errors, "enrollment screened_candidates metadata mismatch")
        if enrollment.get("eligible_candidates") != len(eligible_rows):
            fail(errors, "enrollment eligible_candidates metadata mismatch")
        if enrollment.get("rejected_candidates") != len(rejected_rows):
            fail(errors, "enrollment rejected_candidates metadata mismatch")

        eligible_count = 0
        eighth_eligible_sequence = None
        for row in rows:
            if row.get("eligibility") == "ELIGIBLE":
                eligible_count += 1
                if eligible_count == TARGET_ENROLLMENT:
                    eighth_eligible_sequence = row.get("sequence")
                    break
        if eighth_eligible_sequence is None:
            fail(errors, "eight enrolled units exist without eight eligible screening rows")
        elif len(rows) != eighth_eligible_sequence:
            fail(errors, "screening continued after the eighth eligible unit instead of stopping immediately")
        if enrollment.get("reserve_pool_starts_at_candidate_order") != len(rows) + 1:
            fail(errors, "reserve pool start does not follow the final screened candidate")

    # Enrolled units must be the eligible stream in pool order, except hard org-cap skips.
    simulated = []
    counts = Counter()
    for row in rows:
        if row.get("eligibility") != "ELIGIBLE":
            continue
        org = row.get("organization")
        if counts[org] >= 2:
            continue
        if len(simulated) < TARGET_ENROLLMENT:
            simulated.append(row.get("candidate_id"))
            counts[org] += 1
    actual = [u.get("candidate_id") for u in units]
    if actual != simulated[: len(actual)]:
        fail(errors, "enrollment is not the deterministic eligible stream under the organization cap")

    return enrollment


def _nonnegative_number(value) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0


def validate_friction(enrollment: dict | None, errors: list[str]) -> None:
    if not enrollment:
        return
    for unit in enrollment.get("units") or []:
        cid = unit.get("candidate_id")
        if not unit.get("authoring_started"):
            if unit.get("friction_ledger") is not None:
                fail(errors, f"unit {cid} has a friction ledger before authoring_started")
            continue
        ledger_rel = unit.get("friction_ledger")
        if not ledger_rel:
            fail(errors, f"authoring-started unit {cid} has no friction ledger path")
            continue
        ledger_path = ROOT / ledger_rel
        if not ledger_path.is_file():
            fail(errors, f"friction ledger missing for {cid}: {ledger_rel}")
            continue
        ledger = read_json(ledger_path)
        if ledger.get("candidate_id") != cid:
            fail(errors, f"friction ledger candidate mismatch for {cid}")
        if ledger.get("unit_id") != unit.get("unit_id"):
            fail(errors, f"friction ledger unit mismatch for {cid}")
        phases = ledger.get("phases") or {}
        for field in FRICTION_FIELDS:
            phase = phases.get(field)
            if not isinstance(phase, dict):
                fail(errors, f"friction ledger for {cid} missing phase {field}")
                continue
            status = phase.get("status")
            if status not in PHASE_STATUS_VALUES:
                fail(errors, f"friction ledger {cid}/{field} has invalid status {status!r}")
            corrections = phase.get("correction_count")
            if not isinstance(corrections, int) or isinstance(corrections, bool) or corrections < 0:
                fail(errors, f"friction ledger {cid}/{field} has invalid correction_count")
            wall = phase.get("wall_clock_seconds")
            active = phase.get("active_seconds")
            if status == "COMPLETE":
                if not _nonnegative_number(wall) or not _nonnegative_number(active):
                    fail(errors, f"COMPLETE friction phase {cid}/{field} requires numeric nonnegative timing")
                elif active > wall:
                    fail(errors, f"friction ledger {cid}/{field} active time exceeds wall-clock time")
            elif status in {"NOT_STARTED", "IN_PROGRESS"}:
                for name, value in [("wall_clock_seconds", wall), ("active_seconds", active)]:
                    if value is not None and not _nonnegative_number(value):
                        fail(errors, f"friction ledger {cid}/{field} has invalid partial {name}")
            elif status == "BLOCKED":
                if not phase.get("notes"):
                    fail(errors, f"BLOCKED friction phase {cid}/{field} requires explanatory notes")
                for name, value in [("wall_clock_seconds", wall), ("active_seconds", active)]:
                    if value is not None and not _nonnegative_number(value):
                        fail(errors, f"friction ledger {cid}/{field} has invalid blocked {name}")

        if ledger.get("primary_result_frozen") is True:
            runtime = phases.get("verification_runtime") or {}
            if runtime.get("status") != "COMPLETE":
                fail(errors, f"primary-result-frozen ledger {cid} lacks COMPLETE verification_runtime")


def build_status(pool: dict, rows: list[dict], enrollment: dict | None, errors: list[str]) -> dict:
    units = (enrollment or {}).get("units") or []
    eligible = sum(1 for r in rows if r.get("eligibility") == "ELIGIBLE")
    rejected = sum(1 for r in rows if r.get("eligibility") == "REJECTED")
    complete = len(units) == TARGET_ENROLLMENT
    return {
        "status": "PASS" if not errors else "FAIL",
        "protocol_sha256": EXPECTED_PROTOCOL_SHA256,
        "candidate_pool": len(pool.get("candidates") or []),
        "screened": len(rows),
        "eligible": eligible,
        "rejected": rejected,
        "enrolled": len(units),
        "target_enrollment": TARGET_ENROLLMENT,
        "enrollment_complete": complete,
        "next_candidate_order": None if complete else (len(rows) + 1 if len(rows) < len(pool.get("candidates") or []) else None),
        "reserve_pool_start": (enrollment or {}).get("reserve_pool_starts_at_candidate_order") if complete else None,
        "errors": errors,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate RISU Prospective Corpus 0.1 procedural integrity")
    parser.add_argument("--json", action="store_true", help="print machine-readable status")
    args = parser.parse_args()

    errors: list[str] = []
    try:
        pool, _, _ = validate_static(errors)
        rows = validate_screening(pool, errors)
        enrollment = validate_enrollment(pool, rows, errors)
        validate_friction(enrollment, errors)
    except Exception as exc:
        errors.append(f"validator exception: {type(exc).__name__}: {exc}")
        pool = {"candidates": []}
        rows = []
        enrollment = None

    result = build_status(pool, rows, enrollment, errors)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"Corpus 0.1 integrity: {result['status']}")
        print(f"  pool={result['candidate_pool']} screened={result['screened']} eligible={result['eligible']} rejected={result['rejected']} enrolled={result['enrolled']}/{TARGET_ENROLLMENT}")
        if result["enrollment_complete"]:
            print(f"  enrollment_complete=true reserve_pool_start={result['reserve_pool_start']}")
        elif result["next_candidate_order"] is not None:
            print(f"  next_candidate_order={result['next_candidate_order']}")
        for error in errors:
            print(f"  ERROR: {error}", file=sys.stderr)
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
