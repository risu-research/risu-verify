#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
import copy
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

SCHEMA = "risu.e2-gate2c8-projection-qualified-a3-binding-authority-independent-check/v0.1"
PRODUCER_SCHEMA = "risu.e2-gate2c8-projection-qualified-a3-binding-authority-synthetic/v0.1"
PROTOCOL_COMMIT = "11433abadf2f2b322d9e4209ed5e721ebe059d80"

ROLE_EXPECTED = "SYN:expected"
ROLE_CURRENT = "SYN:current"
ROLE_OTHER = "SYN:other"

EXACT_BASE_MATCH = "EXACT_BASE_MATCH"
CERTIFIED_PROJECTION_MATCH = "CERTIFIED_PROJECTION_MATCH"
CERTIFIED_NONMATCH = "CERTIFIED_NONMATCH"
UNRESOLVED_AUTHORITY = "UNRESOLVED_AUTHORITY"
INCOMPLETE = "E2_PREDICTED_ASSURANCE_INCOMPLETE"


def canonical_bytes(v: Any) -> bytes:
    return (
        json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")


def digest_json(v: Any) -> str:
    return hashlib.sha256(canonical_bytes(v)).hexdigest()


def digest_bytes(v: bytes) -> str:
    return hashlib.sha256(v).hexdigest()


def token_step(kind: str, token: str) -> dict[str, str]:
    return {
        "kind": kind,
        "token_digest_sha256": (
            digest_json(token)
            if kind == "SUBSCRIPT_LITERAL"
            else digest_bytes(token.encode("utf-8"))
        ),
    }


def auth_row(role: str, operand: int, steps: list[dict[str, str]]) -> dict[str, Any]:
    p = {
        "root_role": role,
        "terminal_guard_operand_index": operand,
        "steps": steps,
    }
    return {**p, "fingerprint_sha256": digest_json(p)}


def authority() -> list[dict[str, Any]]:
    return [
        auth_row(ROLE_EXPECTED, 0, [token_step("SUBSCRIPT_LITERAL", "guard")]),
        auth_row(ROLE_CURRENT, 1, []),
        auth_row(ROLE_OTHER, 0, [token_step("SUBSCRIPT_LITERAL", "guard")]),
    ]


def source_for(left: str = 'expected["guard"]') -> str:
    return (
        "def target(expected,current,other=None,key=None):\n"
        f"    projected = {left}\n"
        "    if projected != current:\n"
        "        return current\n"
        "    return expected\n"
    )


def trace_expression(
    expr: ast.AST,
    symbols: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    if isinstance(expr, ast.Name):
        if expr.id not in symbols:
            raise ValueError("UNRESOLVED")
        row = symbols[expr.id]
        return {
            "role": str(row["role"]),
            "steps": [dict(x) for x in row.get("steps", [])],
            "raw": str(row["raw"]),
        }
    if isinstance(expr, ast.Attribute):
        base = trace_expression(expr.value, symbols)
        return {
            "role": base["role"],
            "steps": [*base["steps"], token_step("ATTRIBUTE", expr.attr)],
            "raw": f"{base['raw']}.slot:{expr.attr}",
        }
    if isinstance(expr, ast.Subscript):
        if not isinstance(expr.slice, ast.Constant) or expr.slice.value is None:
            raise ValueError("UNRESOLVED")
        base = trace_expression(expr.value, symbols)
        key = expr.slice.value
        return {
            "role": base["role"],
            "steps": [*base["steps"], token_step("SUBSCRIPT_LITERAL", str(key))],
            "raw": f"{base['raw']}.slot:{key}",
        }
    raise ValueError("UNRESOLVED")


def independently_trace_guard_left(source: str) -> dict[str, Any]:
    tree = ast.parse(source)
    fn = tree.body[0]
    assert isinstance(fn, ast.FunctionDef)
    symbols: dict[str, dict[str, Any]] = {
        "expected": {"role": ROLE_EXPECTED, "steps": [], "raw": ROLE_EXPECTED},
        "current": {"role": ROLE_CURRENT, "steps": [], "raw": ROLE_CURRENT},
        "other": {"role": ROLE_OTHER, "steps": [], "raw": ROLE_OTHER},
    }
    guard_if = None
    for stmt in fn.body:
        if isinstance(stmt, ast.If):
            guard_if = stmt
            break
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
            symbols[stmt.targets[0].id] = trace_expression(stmt.value, symbols)
    if guard_if is None or not isinstance(guard_if.test, ast.Compare):
        raise ValueError("UNRESOLVED")
    return trace_expression(guard_if.test.left, symbols)


def issue_receipt(
    source: str,
    *,
    raw_origin: str,
    case_id: str = "SYNTHETIC_CASE",
    binding_id: str = "guard-expected",
    slot: Mapping[str, Any] | None = None,
    rows: list[Mapping[str, Any]] | None = None,
    provenance: str = "SYNTHETIC_GATE2C8",
    derivation_source: str = "C1_RAW_BINDING_AST",
) -> dict[str, Any]:
    if derivation_source != "C1_RAW_BINDING_AST":
        return {"decision": "REJECT"}
    slot = dict(slot or {"operand_index": 0})
    operand = slot.get("operand_index")
    if not isinstance(operand, int):
        return {"decision": "REJECT"}
    try:
        tr = independently_trace_guard_left(source)
    except Exception:
        return {"decision": "REJECT"}
    if tr["raw"] != raw_origin:
        return {"decision": "REJECT"}

    projection = {
        "root_role": tr["role"],
        "terminal_guard_operand_index": operand,
        "steps": tr["steps"],
    }
    fp = digest_json(projection)
    if projection["steps"]:
        if provenance != "SYNTHETIC_GATE2C8":
            return {"decision": "REJECT"}
        rows = authority() if rows is None else rows
        valid = []
        for r in rows:
            p = {
                "root_role": str(r["root_role"]),
                "terminal_guard_operand_index": int(r["terminal_guard_operand_index"]),
                "steps": [
                    {
                        "kind": str(x["kind"]),
                        "token_digest_sha256": str(x["token_digest_sha256"]),
                    }
                    for x in r.get("steps", [])
                ],
            }
            if r.get("fingerprint_sha256") == digest_json(p):
                valid.append(r)
        matches = [
            r
            for r in valid
            if str(r["root_role"]) == projection["root_role"]
            and int(r["terminal_guard_operand_index"]) == operand
            and r["fingerprint_sha256"] == fp
        ]
        if len(matches) != 1:
            return {"decision": "REJECT"}
        auth_prov = provenance
    else:
        if projection["root_role"] != raw_origin:
            return {"decision": "REJECT"}
        auth_prov = "DIRECT_SOURCE_ROLE"

    cert_digest = digest_json(
        {"projection_certificate": projection, "authority_provenance": auth_prov}
    )
    wrapper = {
        "case_id": case_id,
        "binding_id": binding_id,
        "source_sha256": digest_bytes(source.encode("utf-8")),
        "raw_origin": raw_origin,
        "binding_slot_identity": slot,
        "certified_role": projection["root_role"],
        "projection_fingerprint_sha256": fp,
        "projection_certificate_digest_sha256": cert_digest,
    }
    return {
        "decision": "ADMIT",
        "binding_wrapper": wrapper,
        "binding_wrapper_digest_sha256": digest_json(wrapper),
        "projection_certificate": projection,
        "authority_provenance": auth_prov,
        "derivation_source": "C1_RAW_BINDING_AST",
        "world_evaluation_receipt_reused": False,
        "primary_derived": False,
    }


def classify(
    source: str,
    *,
    raw: str,
    allowed: list[str],
    receipt: Mapping[str, Any] | None,
    case_id: str = "SYNTHETIC_CASE",
    binding_id: str = "guard-expected",
    slot: Mapping[str, Any] | None = None,
) -> str:
    if raw in set(allowed):
        return EXACT_BASE_MATCH
    slot = dict(slot or {"operand_index": 0})
    if not receipt or receipt.get("decision") != "ADMIT":
        return UNRESOLVED_AUTHORITY
    if receipt.get("derivation_source") != "C1_RAW_BINDING_AST":
        return UNRESOLVED_AUTHORITY
    if receipt.get("primary_derived") is not False:
        return UNRESOLVED_AUTHORITY
    if receipt.get("world_evaluation_receipt_reused") is not False:
        return UNRESOLVED_AUTHORITY
    w = receipt.get("binding_wrapper", {}) or {}
    if (
        w.get("case_id") != case_id
        or w.get("binding_id") != binding_id
        or w.get("source_sha256") != digest_bytes(source.encode("utf-8"))
        or w.get("raw_origin") != raw
        or w.get("binding_slot_identity") != slot
    ):
        return UNRESOLVED_AUTHORITY
    if receipt.get("binding_wrapper_digest_sha256") != digest_json(w):
        return UNRESOLVED_AUTHORITY
    p = receipt.get("projection_certificate", {}) or {}
    fp = digest_json(p)
    if w.get("projection_fingerprint_sha256") != fp:
        return UNRESOLVED_AUTHORITY
    if w.get("certified_role") != p.get("root_role"):
        return UNRESOLVED_AUTHORITY
    if w.get("projection_certificate_digest_sha256") != digest_json(
        {
            "projection_certificate": p,
            "authority_provenance": receipt.get("authority_provenance"),
        }
    ):
        return UNRESOLVED_AUTHORITY
    return CERTIFIED_PROJECTION_MATCH if w["certified_role"] in set(allowed) else CERTIFIED_NONMATCH


def origin_for(left: str) -> str:
    return {
        'expected["guard"]': ROLE_EXPECTED + ".slot:guard",
        'expected["other"]': ROLE_EXPECTED + ".slot:other",
        "expected.guard": ROLE_EXPECTED + ".slot:guard",
        'expected["guard"].extra': ROLE_EXPECTED + ".slot:guard.slot:extra",
        "expected[key]": ROLE_EXPECTED + ".slot:dynamic",
        'other["guard"]': ROLE_OTHER + ".slot:guard",
        "expected": ROLE_EXPECTED,
        "current": ROLE_CURRENT,
    }[left]


RELATION_IDS = [
    "POS_EXACT_BASE_EXPECTED",
    "POS_CERTIFIED_EXPECTED_PROJECTION",
    "POS_EXACT_BASE_CURRENT",
    "POS_RAW_ORIGIN_AND_LINEAGE_RETAINED",
    "NEG_GENERIC_SUFFIX_WITHOUT_AUTHORITY",
    "NEG_WRONG_OPAQUE_TOKEN",
    "NEG_WRONG_TERMINAL_OPERAND",
    "NEG_WRONG_PROJECTION_KIND_SEQUENCE",
    "NEG_EXTRA_PROJECTION_HOP",
    "NEG_DYNAMIC_SUBSCRIPT",
    "NEG_AMBIGUOUS_PROJECTION_AUTHORITY",
    "NEG_MISSING_BINDING_WRAPPER",
    "NEG_BINDING_ID_REPLAY",
    "NEG_CASE_ID_REPLAY",
    "NEG_SOURCE_HASH_REPLAY",
    "NEG_RAW_ORIGIN_TAMPER",
    "NEG_CERTIFIED_ROLE_TAMPER",
    "NEG_SLOT_IDENTITY_TAMPER",
    "NEG_WORLD_RECEIPT_REUSE",
    "NEG_PRIMARY_DERIVED_MIRROR",
    "NEG_CERTIFIED_OTHER_ROLE_CAN_SUPPORT_MISMATCH",
]


def independent_relation(case_id: str) -> str:
    source = source_for()
    raw = origin_for('expected["guard"]')
    allowed = [ROLE_EXPECTED]
    slot = {"operand_index": 0}
    receipt = issue_receipt(source, raw_origin=raw)

    if case_id == "POS_EXACT_BASE_EXPECTED":
        source, raw, receipt = source_for("expected"), ROLE_EXPECTED, None
    elif case_id in {"POS_CERTIFIED_EXPECTED_PROJECTION", "POS_RAW_ORIGIN_AND_LINEAGE_RETAINED"}:
        pass
    elif case_id == "POS_EXACT_BASE_CURRENT":
        source, raw, allowed, receipt = source_for("current"), ROLE_CURRENT, [ROLE_CURRENT], None
    elif case_id in {"NEG_GENERIC_SUFFIX_WITHOUT_AUTHORITY", "NEG_MISSING_BINDING_WRAPPER"}:
        receipt = None
    elif case_id == "NEG_WRONG_OPAQUE_TOKEN":
        source = source_for('expected["other"]')
        raw = origin_for('expected["other"]')
        receipt = issue_receipt(source, raw_origin=raw)
    elif case_id == "NEG_WRONG_TERMINAL_OPERAND":
        slot = {"operand_index": 1}
        receipt = issue_receipt(source, raw_origin=raw, slot=slot)
    elif case_id == "NEG_WRONG_PROJECTION_KIND_SEQUENCE":
        source = source_for("expected.guard")
        raw = origin_for("expected.guard")
        receipt = issue_receipt(source, raw_origin=raw)
    elif case_id == "NEG_EXTRA_PROJECTION_HOP":
        source = source_for('expected["guard"].extra')
        raw = origin_for('expected["guard"].extra')
        receipt = issue_receipt(source, raw_origin=raw)
    elif case_id == "NEG_DYNAMIC_SUBSCRIPT":
        source = source_for("expected[key]")
        raw = origin_for("expected[key]")
        receipt = issue_receipt(source, raw_origin=raw)
    elif case_id == "NEG_AMBIGUOUS_PROJECTION_AUTHORITY":
        rows = authority()
        rows.append(copy.deepcopy(rows[0]))
        receipt = issue_receipt(source, raw_origin=raw, rows=rows)
    elif case_id == "NEG_BINDING_ID_REPLAY":
        receipt = copy.deepcopy(receipt)
        receipt["binding_wrapper"]["binding_id"] = "other-binding"
        receipt["binding_wrapper_digest_sha256"] = digest_json(receipt["binding_wrapper"])
    elif case_id == "NEG_CASE_ID_REPLAY":
        receipt = copy.deepcopy(receipt)
        receipt["binding_wrapper"]["case_id"] = "OTHER_CASE"
        receipt["binding_wrapper_digest_sha256"] = digest_json(receipt["binding_wrapper"])
    elif case_id == "NEG_SOURCE_HASH_REPLAY":
        receipt = copy.deepcopy(receipt)
        receipt["binding_wrapper"]["source_sha256"] = "0" * 64
        receipt["binding_wrapper_digest_sha256"] = digest_json(receipt["binding_wrapper"])
    elif case_id == "NEG_RAW_ORIGIN_TAMPER":
        raw = ROLE_EXPECTED + ".slot:tampered"
        receipt = issue_receipt(source, raw_origin=raw)
    elif case_id == "NEG_CERTIFIED_ROLE_TAMPER":
        receipt = copy.deepcopy(receipt)
        receipt["binding_wrapper"]["certified_role"] = ROLE_OTHER
        receipt["binding_wrapper_digest_sha256"] = digest_json(receipt["binding_wrapper"])
    elif case_id == "NEG_SLOT_IDENTITY_TAMPER":
        receipt = copy.deepcopy(receipt)
        receipt["binding_wrapper"]["binding_slot_identity"] = {"operand_index": 9}
        receipt["binding_wrapper_digest_sha256"] = digest_json(receipt["binding_wrapper"])
    elif case_id == "NEG_WORLD_RECEIPT_REUSE":
        receipt = copy.deepcopy(receipt)
        receipt["world_evaluation_receipt_reused"] = True
    elif case_id == "NEG_PRIMARY_DERIVED_MIRROR":
        receipt = issue_receipt(source, raw_origin=raw, derivation_source="PRIMARY_ADAPTER")
    elif case_id == "NEG_CERTIFIED_OTHER_ROLE_CAN_SUPPORT_MISMATCH":
        source = source_for('other["guard"]')
        raw = origin_for('other["guard"]')
        receipt = issue_receipt(source, raw_origin=raw)
    else:
        raise ValueError(case_id)

    return classify(
        source,
        raw=raw,
        allowed=allowed,
        receipt=receipt,
        slot=slot,
    )


def check(producer: Mapping[str, Any]) -> dict[str, Any]:
    reasons: list[str] = []
    if producer.get("schema") != PRODUCER_SCHEMA:
        reasons.append("PRODUCER_SCHEMA_MISMATCH")
    if producer.get("protocol_commit") != PROTOCOL_COMMIT:
        reasons.append("PROTOCOL_COMMIT_MISMATCH")
    if producer.get("candidate_c1_executed") is not False:
        reasons.append("CANDIDATE_C1_EXECUTION_FORBIDDEN")
    if producer.get("candidate_source_bytes_read_by_qualification") != 0:
        reasons.append("CANDIDATE_SOURCE_READ_FORBIDDEN")
    if producer.get("epistemic10_read") is not False:
        reasons.append("EPISTEMIC10_READ_FORBIDDEN")

    produced = {str(x.get("id")): x for x in producer.get("cases", []) or []}
    independent: list[dict[str, Any]] = []
    for case_id in RELATION_IDS:
        rel = independent_relation(case_id)
        independent.append({"id": case_id, "relation": rel})
        got = produced.get(case_id)
        if got is None:
            reasons.append(f"PRODUCER_CASE_MISSING:{case_id}")
        elif got.get("actual_relation") != rel:
            reasons.append(f"RELATION_DISAGREEMENT:{case_id}")

    property_expectations = {
        "NEG_ALLOWED_SET_MUST_NOT_INFLUENCE_CERTIFIED_ROLE": "PASS",
        "NEG_UNRESOLVED_MUST_NOT_CREATE_REGRESSION": INCOMPLETE,
        "POS_NON_ROLE_A3_OBLIGATIONS_UNCHANGED": "PASS",
        "POS_ALL_A4_SEMANTICS_UNCHANGED": "PASS",
    }
    for case_id, expected in property_expectations.items():
        got = produced.get(case_id)
        if got is None:
            reasons.append(f"PRODUCER_CASE_MISSING:{case_id}")
            continue
        if case_id == "NEG_UNRESOLVED_MUST_NOT_CREATE_REGRESSION":
            if got.get("actual_prediction") != INCOMPLETE:
                reasons.append(f"PROPERTY_DISAGREEMENT:{case_id}")
            if got.get("projection_derived_regression_witnesses") not in ([], None):
                reasons.append(f"UNRESOLVED_PROMOTED_TO_REGRESSION:{case_id}")
        elif got.get("actual") != "PASS":
            reasons.append(f"PROPERTY_DISAGREEMENT:{case_id}")

    src = source_for()
    raw = origin_for('expected["guard"]')
    rec = issue_receipt(src, raw_origin=raw)
    if rec.get("binding_wrapper", {}).get("certified_role") != ROLE_EXPECTED:
        reasons.append("CERTIFIED_ROLE_NOT_RAW_DERIVED")
    if classify(src, raw=raw, allowed=[ROLE_EXPECTED], receipt=rec) != CERTIFIED_PROJECTION_MATCH:
        reasons.append("MATCH_RELATION_FAILED")
    if classify(src, raw=raw, allowed=[ROLE_OTHER], receipt=rec) != CERTIFIED_NONMATCH:
        reasons.append("NONMATCH_RELATION_FAILED")

    if len(produced) != 25 or producer.get("case_count") != 25:
        reasons.append("PRODUCER_CASE_COUNT_MISMATCH")
    if producer.get("all_expected_decisions_exact") is not True:
        reasons.append("PRODUCER_SUMMARY_NOT_EXACT")
    if producer.get("raw_origin_bytes_identical_before_after_authorization") is not True:
        reasons.append("RAW_EVIDENCE_RETENTION_FAILED")
    if producer.get("lineage_bytes_identical_before_after_authorization") is not True:
        reasons.append("LINEAGE_RETENTION_FAILED")

    out = {
        "schema": SCHEMA,
        "protocol_commit": PROTOCOL_COMMIT,
        "checker_imports_gate2c7_projection_helper": False,
        "checker_imports_production_binding_consumer": False,
        "candidate_c1_executed": False,
        "candidate_source_bytes_read_by_qualification": 0,
        "epistemic10_read": False,
        "case_count": 25,
        "independent_relation_cases": independent,
        "producer_checker_relation_agreement": not any(
            x.startswith("RELATION_DISAGREEMENT") for x in reasons
        ),
        "unresolved_authority_never_creates_projection_derived_regression": not any(
            x.startswith("UNRESOLVED_PROMOTED") for x in reasons
        ),
        "reasons": sorted(set(reasons)),
    }
    out["status"] = "PASS" if not out["reasons"] else "FAIL"
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--producer", required=True)
    ap.add_argument("--output", required=True)
    a = ap.parse_args()
    producer = json.loads(Path(a.producer).read_text(encoding="utf-8"))
    out = check(producer)
    Path(a.output).write_bytes(canonical_bytes(out))
    print(
        json.dumps(
            {"schema": SCHEMA, "status": out["status"], "case_count": out["case_count"]},
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0 if out["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
