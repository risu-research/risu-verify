#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path
from typing import Any, Mapping

from risu_e2_c1.common import _canonical_bytes, _digest_bytes, _digest_json
from risu_e2_c1.projection_authority import (
    FROZEN_PRODUCTION_AUTHORITY,
    GATE2C5_AUTHORITY_DIGEST_SHA256,
    GATE2C5_AUTHORITY_FILE_SHA256,
    GATE2C7_PROTOCOL_COMMIT,
    _trace_expr,
    admit_projection_trace,
)

SCHEMA = "risu.e2-gate2c7-projection-qualified-c1-origin-authority-synthetic/v0.1"
ROLE_EXPECTED = "SYN:expected"
ROLE_CURRENT = "SYN:current"


def step(kind: str, token: str) -> dict[str, str]:
    if kind == "ATTRIBUTE":
        digest = _digest_bytes(token.encode("utf-8"))
    elif kind == "SUBSCRIPT_LITERAL":
        digest = _digest_json(token)
    else:
        digest = "0" * 64
    return {"kind": kind, "token_digest_sha256": digest}


def authority_row(role: str, operand: int, steps: list[dict[str, str]]) -> dict[str, Any]:
    payload = {"root_role": role, "terminal_guard_operand_index": operand, "steps": steps}
    return {**payload, "fingerprint_sha256": _digest_json(payload)}


def run_case(case_id: str, authority: list[Mapping[str, Any]]) -> dict[str, Any]:
    expected = "ADMIT" if case_id.startswith("POS_") else "REJECT"
    good = {"root_role": ROLE_EXPECTED, "steps": [step("SUBSCRIPT_LITERAL", "guard")]}
    current = {"root_role": ROLE_CURRENT, "steps": []}
    provenance = "SYNTHETIC_GATE2C7"
    rows: list[Mapping[str, Any]] = list(authority)
    trace: Mapping[str, Any] | None = good
    operand = 0

    if case_id == "POS_EXPECTED_EXACT":
        pass
    elif case_id == "POS_CURRENT_EXACT_BASE":
        trace, operand = current, 1
    elif case_id == "NEG_GENERIC_SUFFIX_STRIP":
        trace = None
    elif case_id == "NEG_SAME_DEPTH_WRONG_FIELD":
        trace = {"root_role": ROLE_EXPECTED, "steps": [step("SUBSCRIPT_LITERAL", "other")]}
    elif case_id == "NEG_WRONG_OPAQUE_TOKEN":
        trace = {"root_role": ROLE_EXPECTED, "steps": [step("SUBSCRIPT_LITERAL", "guard-mutated")]}
    elif case_id == "NEG_WRONG_TERMINAL_OPERAND":
        operand = 1
    elif case_id == "NEG_WRONG_ROOT":
        trace = {"root_role": "SYN:other", "steps": [step("SUBSCRIPT_LITERAL", "guard")]}
    elif case_id == "NEG_WRONG_KIND_SEQUENCE":
        trace = {"root_role": ROLE_EXPECTED, "steps": [step("ATTRIBUTE", "guard")]}
    elif case_id == "NEG_MISSING_CERTIFICATE":
        trace = None
    elif case_id == "NEG_AMBIGUOUS_AUTHORITY":
        rows = [*rows, dict(rows[0])]
    elif case_id == "POS_UNCHANGED_BASE_ORIGIN":
        trace = {"root_role": ROLE_EXPECTED, "steps": []}
    elif case_id == "NEG_PRIMARY_DERIVED_MIRROR":
        provenance = "PRIMARY_DERIVED"
    elif case_id == "NEG_DYNAMIC_SUBSCRIPT":
        tree = ast.parse("expected[key]", mode="eval")
        try:
            _trace_expr(tree.body, {}, {"expected": {"root_role": ROLE_EXPECTED, "steps": []}})
        except ValueError as exc:
            return {
                "id": case_id, "expected": expected, "actual": "REJECT",
                "reason": str(exc), "pass": str(exc) == "PROJECTION_DYNAMIC_OR_UNSUPPORTED",
            }
        return {"id": case_id, "expected": expected, "actual": "ADMIT", "reason": "UNEXPECTED_TRACE", "pass": False}
    elif case_id == "NEG_EXTRA_PROJECTION":
        trace = {
            "root_role": ROLE_EXPECTED,
            "steps": [step("SUBSCRIPT_LITERAL", "guard"), step("ATTRIBUTE", "extra")],
        }
    else:
        raise ValueError(f"UNKNOWN_CASE:{case_id}")

    receipt = admit_projection_trace(
        trace, operand_index=operand, authority_rows=rows, authority_provenance=provenance
    )
    return {
        "id": case_id,
        "expected": expected,
        "actual": receipt["decision"],
        "reason": receipt["reason"],
        "pass": receipt["decision"] == expected,
        "fingerprint_sha256": receipt.get("fingerprint_sha256"),
    }


def run() -> dict[str, Any]:
    synthetic_authority = [
        authority_row(ROLE_EXPECTED, 0, [step("SUBSCRIPT_LITERAL", "guard")]),
        authority_row(ROLE_CURRENT, 1, []),
    ]
    ids = [
        "POS_EXPECTED_EXACT",
        "POS_CURRENT_EXACT_BASE",
        "NEG_GENERIC_SUFFIX_STRIP",
        "NEG_SAME_DEPTH_WRONG_FIELD",
        "NEG_WRONG_OPAQUE_TOKEN",
        "NEG_WRONG_TERMINAL_OPERAND",
        "NEG_WRONG_ROOT",
        "NEG_WRONG_KIND_SEQUENCE",
        "NEG_MISSING_CERTIFICATE",
        "NEG_AMBIGUOUS_AUTHORITY",
        "POS_UNCHANGED_BASE_ORIGIN",
        "NEG_PRIMARY_DERIVED_MIRROR",
        "NEG_DYNAMIC_SUBSCRIPT",
        "NEG_EXTRA_PROJECTION",
    ]
    cases = [run_case(x, synthetic_authority) for x in ids]

    production_self_check = []
    for row in FROZEN_PRODUCTION_AUTHORITY:
        payload = {
            "root_role": row["root_role"],
            "terminal_guard_operand_index": row["terminal_guard_operand_index"],
            "steps": [dict(x) for x in row["steps"]],
        }
        production_self_check.append(row["fingerprint_sha256"] == _digest_json(payload))

    out = {
        "schema": SCHEMA,
        "protocol_commit": GATE2C7_PROTOCOL_COMMIT,
        "candidate_c1_executed": False,
        "epistemic10_read": False,
        "primary_adapter_imported": False,
        "gate2c5_builder_imported": False,
        "gate2c6_tracer_imported": False,
        "gate2c5_authority_digest_sha256": GATE2C5_AUTHORITY_DIGEST_SHA256,
        "gate2c5_authority_file_sha256": GATE2C5_AUTHORITY_FILE_SHA256,
        "case_count": len(cases),
        "cases": cases,
        "all_expected_decisions_exact": all(x["pass"] for x in cases),
        "production_authority_internal_fingerprints_valid": all(production_self_check),
    }
    out["status"] = "PASS" if (
        out["all_expected_decisions_exact"]
        and out["production_authority_internal_fingerprints_valid"]
        and out["candidate_c1_executed"] is False
        and out["epistemic10_read"] is False
    ) else "FAIL"
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", required=True)
    a = ap.parse_args()
    out = run()
    Path(a.output).write_bytes(_canonical_bytes(out))
    print(json.dumps({"schema": SCHEMA, "status": out["status"], "case_count": out["case_count"]}, sort_keys=True, separators=(",", ":")))
    return 0 if out["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
