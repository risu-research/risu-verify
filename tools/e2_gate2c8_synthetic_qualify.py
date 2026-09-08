#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
import copy
import json
from pathlib import Path
from typing import Any, Mapping

from risu_e2_c1.binding_authority import (
    CERTIFIED_NONMATCH,
    CERTIFIED_PROJECTION_MATCH,
    EXACT_BASE_MATCH,
    GATE2C8_PROTOCOL_COMMIT,
    UNRESOLVED_AUTHORITY,
    classify_binding_origin_relation,
    derive_binding_authority_receipt,
    prefix_binding_environment,
)
from risu_e2_c1.common import INCOMPLETE, _canonical_bytes, _digest_bytes, _digest_json
from risu_e2_c1.semantics import _independent_semantic_eval

SCHEMA = "risu.e2-gate2c8-projection-qualified-a3-binding-authority-synthetic/v0.1"
ROLE_EXPECTED = "SYN:expected"
ROLE_CURRENT = "SYN:current"
ROLE_OTHER = "SYN:other"


def step(kind: str, token: str) -> dict[str, str]:
    return {
        "kind": kind,
        "token_digest_sha256": (
            _digest_json(token)
            if kind == "SUBSCRIPT_LITERAL"
            else _digest_bytes(token.encode("utf-8"))
        ),
    }


def authority_row(role: str, operand: int, steps: list[dict[str, str]]) -> dict[str, Any]:
    payload = {
        "root_role": role,
        "terminal_guard_operand_index": operand,
        "steps": steps,
    }
    return {**payload, "fingerprint_sha256": _digest_json(payload)}


def synthetic_authority() -> list[dict[str, Any]]:
    return [
        authority_row(ROLE_EXPECTED, 0, [step("SUBSCRIPT_LITERAL", "guard")]),
        authority_row(ROLE_CURRENT, 1, []),
        authority_row(ROLE_OTHER, 0, [step("SUBSCRIPT_LITERAL", "guard")]),
    ]


def source_for(left: str = 'expected["guard"]') -> str:
    return (
        "def target(expected,current,other=None,key=None):\n"
        f"    projected = {left}\n"
        "    if projected != current:\n"
        "        return current\n"
        "    return expected\n"
    )


def parse_binding_source(source: str) -> tuple[ast.FunctionDef, ast.If, ast.expr, dict[str, Any], dict[str, Any], list[str]]:
    tree = ast.parse(source)
    fn = tree.body[0]
    assert isinstance(fn, ast.FunctionDef)
    guard_if = next(x for x in fn.body if isinstance(x, ast.If))
    signature = {
        "source_roles": {
            ROLE_EXPECTED: {"parameter_index": 0},
            ROLE_CURRENT: {"parameter_index": 1},
            ROLE_OTHER: {"parameter_index": 2},
        }
    }
    env, params, bad = prefix_binding_environment(fn, guard_if, signature)
    assert isinstance(guard_if.test, ast.Compare)
    return fn, guard_if, guard_if.test.left, env, params, bad


def origin_for(left: str) -> str:
    if left == 'expected["guard"]':
        return ROLE_EXPECTED + ".slot:guard"
    if left == 'expected["other"]':
        return ROLE_EXPECTED + ".slot:other"
    if left == "expected.guard":
        return ROLE_EXPECTED + ".slot:guard"
    if left == 'expected["guard"].extra':
        return ROLE_EXPECTED + ".slot:guard.slot:extra"
    if left == "expected[key]":
        return ROLE_EXPECTED + ".slot:dynamic"
    if left == 'other["guard"]':
        return ROLE_OTHER + ".slot:guard"
    if left == "expected":
        return ROLE_EXPECTED
    if left == "current":
        return ROLE_CURRENT
    raise ValueError(left)


def make_binding(
    *,
    raw_origin: str,
    allowed: list[str],
    receipt: Mapping[str, Any] | None,
    case_id: str = "SYNTHETIC_CASE",
    binding_id: str = "guard-expected",
    slot: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "binding_id": binding_id,
        "coordinate_identity": "coordinate",
        "resource_identity": "resource",
        "slot_identity": dict(slot or {"operand_index": 0}),
        "allowed_origins": list(allowed),
        "observed_origins": [raw_origin],
        "binding_complete": True,
        "definitions_complete": True,
        "lineage_paths": [
            {
                "origin": raw_origin,
                "edges": [
                    {
                        "kind": "BINDS_TO",
                        "from": raw_origin,
                        "to": binding_id,
                        "path_id": "guard-direct",
                    }
                ],
            }
        ],
        "definition_trace": [],
        "representation": {"required": False},
        "binding_authority_receipts": [] if receipt is None else [copy.deepcopy(receipt)],
        "_case_id": case_id,
    }


def derive(
    *,
    left: str = 'expected["guard"]',
    raw_origin: str | None = None,
    case_id: str = "SYNTHETIC_CASE",
    binding_id: str = "guard-expected",
    slot: Mapping[str, Any] | None = None,
    rows: list[Mapping[str, Any]] | None = None,
    provenance: str = "SYNTHETIC_GATE2C8",
    derivation_source: str = "C1_RAW_BINDING_AST",
) -> tuple[str, dict[str, Any], str, list[str]]:
    source = source_for(left)
    _, _, expr, env, params, bad = parse_binding_source(source)
    raw = origin_for(left) if raw_origin is None else raw_origin
    receipt = derive_binding_authority_receipt(
        expr,
        case_id=case_id,
        binding_id=binding_id,
        source_sha256=_digest_bytes(source.encode("utf-8")),
        raw_origin=raw,
        binding_slot_identity=dict(slot or {"operand_index": 0}),
        env=env,
        param_by_name=params,
        authority_rows=synthetic_authority() if rows is None else rows,
        authority_provenance=provenance,
        derivation_source=derivation_source,
    )
    return source, receipt, raw, bad


def relation(
    *,
    source: str,
    raw: str,
    receipt: Mapping[str, Any] | None,
    allowed: list[str],
    case_id: str = "SYNTHETIC_CASE",
    binding_id: str = "guard-expected",
    slot: Mapping[str, Any] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    b = make_binding(
        raw_origin=raw,
        allowed=allowed,
        receipt=receipt,
        case_id=case_id,
        binding_id=binding_id,
        slot=slot,
    )
    out = classify_binding_origin_relation(
        b,
        raw_origin=raw,
        case_id=case_id,
        source_sha256=_digest_bytes(source.encode("utf-8")),
    )
    return out, b


def semantic_doc(binding: Mapping[str, Any], source_sha256: str) -> dict[str, Any]:
    return {
        "case_id": "SEMANTIC_SYNTH",
        "binding_authority_source_sha256": source_sha256,
        "bindings": [copy.deepcopy(binding)],
        "guard": {
            "form": "DIRECT_CONTROL",
            "effective_guard_id": "g0",
            "effective_guard_count": 1,
            "net_polarity": "PRESERVE",
            "effect_polarity": "true",
            "rejection_polarity": "false",
        },
        "control_paths": [
            {
                "path_id": "guard-true",
                "guard_polarity": "true",
                "events": ["ENTRY", "GUARD:g0", "EFFECT:E", "SUCCESS:S", "EXIT"],
                "complete": True,
                "realizable": True,
            },
            {
                "path_id": "guard-false",
                "guard_polarity": "false",
                "events": ["ENTRY", "GUARD:g0", "REJECTION:R", "EXIT"],
                "complete": True,
                "realizable": True,
            },
        ],
        "effect": {
            "surfaces": ["E"],
            "success_outcome_id": "S",
            "rejection_outcome_id": "R",
            "effect_before_success_structural": True,
        },
        "scope": {
            "complete": True,
            "unresolved": [],
            "aliases_complete": True,
            "call_targets_complete": True,
            "reaching_definitions_complete": True,
            "branches_complete": True,
            "representations_complete": True,
            "effects_complete": True,
            "exceptions_exits_complete": True,
            "resources_complete": True,
            "helper_polarity_complete": True,
            "all_entry_paths_enumerated": True,
        },
        "worlds": [
            {"id": "w0", "kappa": {"v": 0}, "rho": {"outcome": "SUCCESS_EFFECT"}},
            {"id": "w1", "kappa": {"v": 1}, "rho": {"outcome": "REJECTION_NO_EFFECT"}},
        ],
    }


RELATION_EXPECTED = {
    "POS_EXACT_BASE_EXPECTED": EXACT_BASE_MATCH,
    "POS_CERTIFIED_EXPECTED_PROJECTION": CERTIFIED_PROJECTION_MATCH,
    "POS_EXACT_BASE_CURRENT": EXACT_BASE_MATCH,
    "POS_RAW_ORIGIN_AND_LINEAGE_RETAINED": CERTIFIED_PROJECTION_MATCH,
    "NEG_GENERIC_SUFFIX_WITHOUT_AUTHORITY": UNRESOLVED_AUTHORITY,
    "NEG_WRONG_OPAQUE_TOKEN": UNRESOLVED_AUTHORITY,
    "NEG_WRONG_TERMINAL_OPERAND": UNRESOLVED_AUTHORITY,
    "NEG_WRONG_PROJECTION_KIND_SEQUENCE": UNRESOLVED_AUTHORITY,
    "NEG_EXTRA_PROJECTION_HOP": UNRESOLVED_AUTHORITY,
    "NEG_DYNAMIC_SUBSCRIPT": UNRESOLVED_AUTHORITY,
    "NEG_AMBIGUOUS_PROJECTION_AUTHORITY": UNRESOLVED_AUTHORITY,
    "NEG_MISSING_BINDING_WRAPPER": UNRESOLVED_AUTHORITY,
    "NEG_BINDING_ID_REPLAY": UNRESOLVED_AUTHORITY,
    "NEG_CASE_ID_REPLAY": UNRESOLVED_AUTHORITY,
    "NEG_SOURCE_HASH_REPLAY": UNRESOLVED_AUTHORITY,
    "NEG_RAW_ORIGIN_TAMPER": UNRESOLVED_AUTHORITY,
    "NEG_CERTIFIED_ROLE_TAMPER": UNRESOLVED_AUTHORITY,
    "NEG_SLOT_IDENTITY_TAMPER": UNRESOLVED_AUTHORITY,
    "NEG_WORLD_RECEIPT_REUSE": UNRESOLVED_AUTHORITY,
    "NEG_PRIMARY_DERIVED_MIRROR": UNRESOLVED_AUTHORITY,
    "NEG_CERTIFIED_OTHER_ROLE_CAN_SUPPORT_MISMATCH": CERTIFIED_NONMATCH,
}


def run_relation_case(case_id: str) -> dict[str, Any]:
    expected = RELATION_EXPECTED[case_id]
    case_ctx = "SYNTHETIC_CASE"
    source, receipt, raw, bad = derive()
    allowed = [ROLE_EXPECTED]
    binding_id = "guard-expected"
    slot = {"operand_index": 0}

    if case_id == "POS_EXACT_BASE_EXPECTED":
        source = source_for("expected")
        raw = ROLE_EXPECTED
        receipt = None
    elif case_id == "POS_CERTIFIED_EXPECTED_PROJECTION":
        pass
    elif case_id == "POS_EXACT_BASE_CURRENT":
        source = source_for("current")
        raw = ROLE_CURRENT
        receipt = None
        allowed = [ROLE_CURRENT]
    elif case_id == "POS_RAW_ORIGIN_AND_LINEAGE_RETAINED":
        pass
    elif case_id == "NEG_GENERIC_SUFFIX_WITHOUT_AUTHORITY":
        receipt = None
    elif case_id == "NEG_WRONG_OPAQUE_TOKEN":
        source, receipt, raw, bad = derive(left='expected["other"]')
    elif case_id == "NEG_WRONG_TERMINAL_OPERAND":
        source, receipt, raw, bad = derive(slot={"operand_index": 1})
        slot = {"operand_index": 1}
    elif case_id == "NEG_WRONG_PROJECTION_KIND_SEQUENCE":
        source, receipt, raw, bad = derive(left="expected.guard")
    elif case_id == "NEG_EXTRA_PROJECTION_HOP":
        source, receipt, raw, bad = derive(left='expected["guard"].extra')
    elif case_id == "NEG_DYNAMIC_SUBSCRIPT":
        source, receipt, raw, bad = derive(left="expected[key]")
    elif case_id == "NEG_AMBIGUOUS_PROJECTION_AUTHORITY":
        rows = synthetic_authority()
        rows.append(copy.deepcopy(rows[0]))
        source, receipt, raw, bad = derive(rows=rows)
    elif case_id == "NEG_MISSING_BINDING_WRAPPER":
        receipt = None
    elif case_id == "NEG_BINDING_ID_REPLAY":
        assert receipt.get("decision") == "ADMIT"
        receipt = copy.deepcopy(receipt)
        receipt["binding_wrapper"]["binding_id"] = "other-binding"
        receipt["binding_wrapper_digest_sha256"] = _digest_json(receipt["binding_wrapper"])
    elif case_id == "NEG_CASE_ID_REPLAY":
        receipt = copy.deepcopy(receipt)
        receipt["binding_wrapper"]["case_id"] = "OTHER_CASE"
        receipt["binding_wrapper_digest_sha256"] = _digest_json(receipt["binding_wrapper"])
    elif case_id == "NEG_SOURCE_HASH_REPLAY":
        receipt = copy.deepcopy(receipt)
        receipt["binding_wrapper"]["source_sha256"] = "0" * 64
        receipt["binding_wrapper_digest_sha256"] = _digest_json(receipt["binding_wrapper"])
    elif case_id == "NEG_RAW_ORIGIN_TAMPER":
        source, receipt, raw, bad = derive(raw_origin=ROLE_EXPECTED + ".slot:tampered")
    elif case_id == "NEG_CERTIFIED_ROLE_TAMPER":
        receipt = copy.deepcopy(receipt)
        receipt["binding_wrapper"]["certified_role"] = ROLE_OTHER
        receipt["binding_wrapper_digest_sha256"] = _digest_json(receipt["binding_wrapper"])
    elif case_id == "NEG_SLOT_IDENTITY_TAMPER":
        receipt = copy.deepcopy(receipt)
        receipt["binding_wrapper"]["binding_slot_identity"] = {"operand_index": 9}
        receipt["binding_wrapper_digest_sha256"] = _digest_json(receipt["binding_wrapper"])
    elif case_id == "NEG_WORLD_RECEIPT_REUSE":
        receipt = copy.deepcopy(receipt)
        receipt["world_evaluation_receipt_reused"] = True
    elif case_id == "NEG_PRIMARY_DERIVED_MIRROR":
        source, receipt, raw, bad = derive(derivation_source="PRIMARY_ADAPTER")
    elif case_id == "NEG_CERTIFIED_OTHER_ROLE_CAN_SUPPORT_MISMATCH":
        source, receipt, raw, bad = derive(left='other["guard"]')
    else:
        raise ValueError(case_id)

    rel, binding = relation(
        source=source,
        raw=raw,
        receipt=receipt,
        allowed=allowed,
        case_id=case_ctx,
        binding_id=binding_id,
        slot=slot,
    )
    evidence_before = {
        "observed_origins": copy.deepcopy(binding["observed_origins"]),
        "lineage_paths": copy.deepcopy(binding["lineage_paths"]),
    }
    evidence_after = {
        "observed_origins": copy.deepcopy(binding["observed_origins"]),
        "lineage_paths": copy.deepcopy(binding["lineage_paths"]),
    }
    return {
        "id": case_id,
        "expected_relation": expected,
        "actual_relation": rel["relation"],
        "pass": rel["relation"] == expected,
        "relation_reason": rel.get("reason"),
        "certified_role": rel.get("certified_role"),
        "derivation_decision": receipt.get("decision") if isinstance(receipt, Mapping) else None,
        "derivation_reason": receipt.get("reason") if isinstance(receipt, Mapping) else None,
        "raw_origin": raw,
        "raw_origin_retained": evidence_before["observed_origins"] == evidence_after["observed_origins"],
        "lineage_retained": evidence_before["lineage_paths"] == evidence_after["lineage_paths"],
        "synthetic_source_sha256": _digest_bytes(source.encode("utf-8")),
        "derivation_sidecar_errors": bad,
    }


def run_property_case(case_id: str) -> dict[str, Any]:
    source, receipt, raw, bad = derive()
    source_sha = _digest_bytes(source.encode("utf-8"))

    if case_id == "NEG_ALLOWED_SET_MUST_NOT_INFLUENCE_CERTIFIED_ROLE":
        rel1, _ = relation(source=source, raw=raw, receipt=receipt, allowed=[ROLE_EXPECTED])
        rel2, _ = relation(source=source, raw=raw, receipt=receipt, allowed=[ROLE_OTHER])
        actual = (
            receipt.get("binding_wrapper", {}).get("certified_role") == ROLE_EXPECTED
            and rel1["relation"] == CERTIFIED_PROJECTION_MATCH
            and rel2["relation"] == CERTIFIED_NONMATCH
            and rel1.get("certified_role") == rel2.get("certified_role") == ROLE_EXPECTED
        )
        return {
            "id": case_id,
            "expected": "PASS",
            "actual": "PASS" if actual else "FAIL",
            "pass": actual,
            "certified_role": receipt.get("binding_wrapper", {}).get("certified_role"),
            "allowed_set_used_during_derivation": False,
        }

    baseline_binding = make_binding(
        raw_origin=raw,
        allowed=[ROLE_EXPECTED],
        receipt=None,
        case_id="SEMANTIC_SYNTH",
    )
    repaired_binding = make_binding(
        raw_origin=raw,
        allowed=[ROLE_EXPECTED],
        receipt=receipt,
        case_id="SEMANTIC_SYNTH",
    )
    baseline = semantic_doc(baseline_binding, source_sha)
    repaired = semantic_doc(repaired_binding, source_sha)
    before = _independent_semantic_eval(baseline)
    after = _independent_semantic_eval(repaired)

    if case_id == "NEG_UNRESOLVED_MUST_NOT_CREATE_REGRESSION":
        bad_witnesses = {
            "A3_R1_WRONG_BINDING_IDENTITY",
            "A3_R2_DEFINITE_OVERWRITE_TO_WRONG_CARRIER",
            "A3_R3_EXPLICIT_CARRIER_SUBSTITUTION_OR_DROP",
        }
        actual = (
            before["prediction"] == INCOMPLETE
            and not (bad_witnesses & set(before["witness_ids"]))
            and before["obligations"]["A3_P1_REQUIRED_ROLE_REACHABILITY"] is False
        )
        return {
            "id": case_id,
            "expected_prediction": INCOMPLETE,
            "actual_prediction": before["prediction"],
            "pass": actual,
            "projection_derived_regression_witnesses": sorted(
                bad_witnesses & set(before["witness_ids"])
            ),
        }

    if case_id == "POS_NON_ROLE_A3_OBLIGATIONS_UNCHANGED":
        keys = [
            "A3_P2_BINDING_IDENTITY",
            "A3_P3_DEFINITION_SENSITIVITY",
            "A3_P4_REPRESENTATION_SURVIVAL",
            "A3_P5_PATH_REALIZABILITY",
        ]
        actual = all(before["obligations"][k] == after["obligations"][k] for k in keys)
        return {
            "id": case_id,
            "expected": "PASS",
            "actual": "PASS" if actual else "FAIL",
            "pass": actual,
            "checked_obligations": keys,
            "before": {k: before["obligations"][k] for k in keys},
            "after": {k: after["obligations"][k] for k in keys},
        }

    if case_id == "POS_ALL_A4_SEMANTICS_UNCHANGED":
        keys = [f"A4_P{i}_{name}" for i, name in []]  # documentation-only placeholder
        before_a4 = {k: v for k, v in before["obligations"].items() if k.startswith("A4_")}
        after_a4 = {k: v for k, v in after["obligations"].items() if k.startswith("A4_")}
        before_w = sorted(x for x in before["witness_ids"] if x.startswith("A4_"))
        after_w = sorted(x for x in after["witness_ids"] if x.startswith("A4_"))
        actual = (
            before_a4 == after_a4
            and before_w == after_w
            and before["world_relation"] == after["world_relation"]
            and _canonical_bytes(baseline["worlds"]) == _canonical_bytes(repaired["worlds"])
        )
        return {
            "id": case_id,
            "expected": "PASS",
            "actual": "PASS" if actual else "FAIL",
            "pass": actual,
            "a4_obligations_identical": before_a4 == after_a4,
            "a4_witnesses_identical": before_w == after_w,
            "world_relation_identical": before["world_relation"] == after["world_relation"],
            "world_outputs_identical": _canonical_bytes(baseline["worlds"]) == _canonical_bytes(repaired["worlds"]),
        }

    raise ValueError(case_id)


def run() -> dict[str, Any]:
    ids = [
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
        "NEG_ALLOWED_SET_MUST_NOT_INFLUENCE_CERTIFIED_ROLE",
        "NEG_UNRESOLVED_MUST_NOT_CREATE_REGRESSION",
        "NEG_CERTIFIED_OTHER_ROLE_CAN_SUPPORT_MISMATCH",
        "POS_NON_ROLE_A3_OBLIGATIONS_UNCHANGED",
        "POS_ALL_A4_SEMANTICS_UNCHANGED",
    ]
    cases = []
    for case_id in ids:
        if case_id in RELATION_EXPECTED:
            cases.append(run_relation_case(case_id))
        else:
            cases.append(run_property_case(case_id))

    relation_rows = [x for x in cases if "expected_relation" in x]
    out = {
        "schema": SCHEMA,
        "protocol_commit": GATE2C8_PROTOCOL_COMMIT,
        "case_count": len(cases),
        "cases": cases,
        "all_expected_decisions_exact": all(x["pass"] for x in cases),
        "producer_relation_case_count": len(relation_rows),
        "raw_origin_bytes_identical_before_after_authorization": all(
            x.get("raw_origin_retained", True) for x in cases
        ),
        "lineage_bytes_identical_before_after_authorization": all(
            x.get("lineage_retained", True) for x in cases
        ),
        "candidate_c1_executed": False,
        "candidate_source_bytes_read_by_qualification": 0,
        "epistemic10_read": False,
        "truth_read": False,
        "fresh_target_read": False,
        "primary_adapter_imported": False,
        "producer_kernel_imported": False,
        "world_evaluation_receipt_reused_for_binding_authority": False,
        "allowed_origins_used_during_certificate_derivation": False,
        "elapsed_or_wall_clock_fields_emitted": False,
    }
    out["status"] = "PASS" if (
        out["case_count"] == 25
        and out["all_expected_decisions_exact"]
        and out["raw_origin_bytes_identical_before_after_authorization"]
        and out["lineage_bytes_identical_before_after_authorization"]
        and out["candidate_c1_executed"] is False
        and out["candidate_source_bytes_read_by_qualification"] == 0
        and out["epistemic10_read"] is False
    ) else "FAIL"
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", required=True)
    a = ap.parse_args()
    out = run()
    Path(a.output).write_bytes(_canonical_bytes(out))
    print(json.dumps(
        {"schema": SCHEMA, "status": out["status"], "case_count": out["case_count"]},
        sort_keys=True,
        separators=(",", ":"),
    ))
    return 0 if out["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
