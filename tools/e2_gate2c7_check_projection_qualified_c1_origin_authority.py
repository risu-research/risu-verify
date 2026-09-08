#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping, Sequence

SCHEMA = "risu.e2-gate2c7-projection-qualified-c1-origin-authority-independent-check/v0.1"
PRODUCER_SCHEMA = "risu.e2-gate2c7-projection-qualified-c1-origin-authority-synthetic/v0.1"
PROTOCOL_COMMIT = "c9b0e1b805fa7193972894bd6a83f3390cb4be75"
ROLE_EXPECTED = "SYN:expected"
ROLE_CURRENT = "SYN:current"


def canonical_bytes(v: Any) -> bytes:
    return (json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def digest_json(v: Any) -> str:
    return hashlib.sha256(canonical_bytes(v)).hexdigest()


def digest_bytes(v: bytes) -> str:
    return hashlib.sha256(v).hexdigest()


def step(kind: str, token: str) -> dict[str, str]:
    if kind == "ATTRIBUTE":
        digest = digest_bytes(token.encode("utf-8"))
    elif kind == "SUBSCRIPT_LITERAL":
        digest = digest_json(token)
    else:
        digest = "0" * 64
    return {"kind": kind, "token_digest_sha256": digest}


def payload(role: str, operand: int, steps: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    return {
        "root_role": role,
        "terminal_guard_operand_index": operand,
        "steps": [{"kind": str(x["kind"]), "token_digest_sha256": str(x["token_digest_sha256"])} for x in steps],
    }


def authority_row(role: str, operand: int, steps: list[dict[str, str]]) -> dict[str, Any]:
    p = payload(role, operand, steps)
    return {**p, "fingerprint_sha256": digest_json(p)}


def independent_admit(
    trace: Mapping[str, Any] | None,
    *, operand: int, rows: Sequence[Mapping[str, Any]], provenance: str,
) -> tuple[str, str, str | None]:
    if trace is None:
        return "REJECT", "PROJECTION_AUTHORITY_MISSING", None
    try:
        p = payload(str(trace["root_role"]), operand, trace.get("steps", []) or [])
    except Exception:
        return "REJECT", "PROJECTION_CERTIFICATE_INTERNAL_INCONSISTENCY", None
    if not p["steps"]:
        return "ADMIT", "BASE_ORIGIN_PASSTHROUGH", digest_json(p)
    if provenance not in {"FROZEN_GATE2C5", "SYNTHETIC_GATE2C7"}:
        return "REJECT", "PROJECTION_AUTHORITY_MISSING", digest_json(p)
    valid = []
    for r in rows:
        try:
            rp = payload(str(r["root_role"]), int(r["terminal_guard_operand_index"]), r.get("steps", []) or [])
        except Exception:
            continue
        if r.get("fingerprint_sha256") == digest_json(rp):
            valid.append(r)
    same_role = [r for r in valid if str(r["root_role"]) == p["root_role"]]
    if not same_role:
        return "REJECT", "PROJECTION_ROOT_ROLE_MISMATCH", digest_json(p)
    same_operand = [r for r in same_role if int(r["terminal_guard_operand_index"]) == operand]
    if not same_operand:
        return "REJECT", "PROJECTION_TERMINAL_OPERAND_MISMATCH", digest_json(p)
    fp = digest_json(p)
    matches = [r for r in same_operand if r["fingerprint_sha256"] == fp]
    if len(matches) > 1:
        return "REJECT", "PROJECTION_AUTHORITY_AMBIGUOUS", fp
    if len(matches) == 1:
        return "ADMIT", "CANONICAL_OPAQUE_PROJECTION_MATCH", fp
    kinds = [str(x["kind"]) for x in p["steps"]]
    wanted = [[str(x["kind"]) for x in (r.get("steps", []) or [])] for r in same_operand]
    reason = "PROJECTION_KIND_SEQUENCE_MISMATCH" if kinds not in wanted else "PROJECTION_TOKEN_FINGERPRINT_MISMATCH"
    return "REJECT", reason, fp


def derive_case(case_id: str) -> dict[str, Any]:
    auth = [
        authority_row(ROLE_EXPECTED, 0, [step("SUBSCRIPT_LITERAL", "guard")]),
        authority_row(ROLE_CURRENT, 1, []),
    ]
    good = {"root_role": ROLE_EXPECTED, "steps": [step("SUBSCRIPT_LITERAL", "guard")]}
    current = {"root_role": ROLE_CURRENT, "steps": []}
    trace: Mapping[str, Any] | None = good
    operand = 0
    provenance = "SYNTHETIC_GATE2C7"
    rows: Sequence[Mapping[str, Any]] = auth
    expected = "ADMIT" if case_id.startswith("POS_") else "REJECT"
    if case_id == "POS_EXPECTED_EXACT": pass
    elif case_id == "POS_CURRENT_EXACT_BASE": trace, operand = current, 1
    elif case_id in {"NEG_GENERIC_SUFFIX_STRIP", "NEG_MISSING_CERTIFICATE"}: trace = None
    elif case_id == "NEG_SAME_DEPTH_WRONG_FIELD": trace = {"root_role": ROLE_EXPECTED, "steps": [step("SUBSCRIPT_LITERAL", "other")]}
    elif case_id == "NEG_WRONG_OPAQUE_TOKEN": trace = {"root_role": ROLE_EXPECTED, "steps": [step("SUBSCRIPT_LITERAL", "guard-mutated")]}
    elif case_id == "NEG_WRONG_TERMINAL_OPERAND": operand = 1
    elif case_id == "NEG_WRONG_ROOT": trace = {"root_role": "SYN:other", "steps": [step("SUBSCRIPT_LITERAL", "guard")]}
    elif case_id == "NEG_WRONG_KIND_SEQUENCE": trace = {"root_role": ROLE_EXPECTED, "steps": [step("ATTRIBUTE", "guard")]}
    elif case_id == "NEG_AMBIGUOUS_AUTHORITY": rows = [*auth, dict(auth[0])]
    elif case_id == "POS_UNCHANGED_BASE_ORIGIN": trace = {"root_role": ROLE_EXPECTED, "steps": []}
    elif case_id == "NEG_PRIMARY_DERIVED_MIRROR": provenance = "PRIMARY_DERIVED"
    elif case_id == "NEG_DYNAMIC_SUBSCRIPT": return {"id": case_id, "expected": expected, "actual": "REJECT", "reason": "PROJECTION_DYNAMIC_OR_UNSUPPORTED"}
    elif case_id == "NEG_EXTRA_PROJECTION": trace = {"root_role": ROLE_EXPECTED, "steps": [step("SUBSCRIPT_LITERAL", "guard"), step("ATTRIBUTE", "extra")]}
    else: raise ValueError(f"UNKNOWN_CASE:{case_id}")
    actual, reason, fp = independent_admit(trace, operand=operand, rows=rows, provenance=provenance)
    return {"id": case_id, "expected": expected, "actual": actual, "reason": reason, "fingerprint_sha256": fp}


def check(producer: Mapping[str, Any]) -> dict[str, Any]:
    reasons: list[str] = []
    if producer.get("schema") != PRODUCER_SCHEMA: reasons.append("PRODUCER_SCHEMA_MISMATCH")
    if producer.get("protocol_commit") != PROTOCOL_COMMIT: reasons.append("PROTOCOL_COMMIT_MISMATCH")
    if producer.get("candidate_c1_executed") is not False: reasons.append("CANDIDATE_C1_EXECUTION_FORBIDDEN")
    if producer.get("epistemic10_read") is not False: reasons.append("EPISTEMIC10_READ_FORBIDDEN")
    produced = {str(x.get("id")): x for x in producer.get("cases", []) or []}
    independent = []
    ids = [
        "POS_EXPECTED_EXACT", "POS_CURRENT_EXACT_BASE", "NEG_GENERIC_SUFFIX_STRIP",
        "NEG_SAME_DEPTH_WRONG_FIELD", "NEG_WRONG_OPAQUE_TOKEN", "NEG_WRONG_TERMINAL_OPERAND",
        "NEG_WRONG_ROOT", "NEG_WRONG_KIND_SEQUENCE", "NEG_MISSING_CERTIFICATE",
        "NEG_AMBIGUOUS_AUTHORITY", "POS_UNCHANGED_BASE_ORIGIN", "NEG_PRIMARY_DERIVED_MIRROR",
        "NEG_DYNAMIC_SUBSCRIPT", "NEG_EXTRA_PROJECTION",
    ]
    for case_id in ids:
        row = derive_case(case_id); independent.append(row); got = produced.get(case_id)
        if got is None:
            reasons.append(f"PRODUCER_CASE_MISSING:{case_id}"); continue
        if got.get("expected") != row["expected"]: reasons.append(f"EXPECTED_DECISION_DISAGREEMENT:{case_id}")
        if got.get("actual") != row["actual"]: reasons.append(f"ACTUAL_DECISION_DISAGREEMENT:{case_id}")
        if got.get("actual") != got.get("expected"): reasons.append(f"PRODUCER_CASE_FAILED:{case_id}")
    if len(produced) != 14: reasons.append("PRODUCER_CASE_COUNT_MISMATCH")
    if producer.get("all_expected_decisions_exact") is not True: reasons.append("PRODUCER_SUMMARY_NOT_EXACT")
    if producer.get("production_authority_internal_fingerprints_valid") is not True: reasons.append("PRODUCTION_AUTHORITY_SELF_CHECK_FAILED")
    out = {
        "schema": SCHEMA,
        "protocol_commit": PROTOCOL_COMMIT,
        "checker_imports_production_helper": False,
        "candidate_c1_executed": False,
        "epistemic10_read": False,
        "case_count": len(independent),
        "independent_cases": independent,
        "producer_checker_decision_agreement": not any("DECISION_DISAGREEMENT" in x for x in reasons),
        "reasons": sorted(set(reasons)),
    }
    out["status"] = "PASS" if not out["reasons"] else "FAIL"
    return out


def main() -> int:
    ap = argparse.ArgumentParser(); ap.add_argument("--producer", required=True); ap.add_argument("--output", required=True); a = ap.parse_args()
    producer = json.loads(Path(a.producer).read_text(encoding="utf-8")); out = check(producer)
    Path(a.output).write_bytes(canonical_bytes(out))
    print(json.dumps({"schema": SCHEMA, "status": out["status"], "case_count": out["case_count"]}, sort_keys=True, separators=(",", ":")))
    return 0 if out["status"] == "PASS" else 1


if __name__ == "__main__": raise SystemExit(main())
