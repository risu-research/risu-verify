from __future__ import annotations

import ast
import copy
import inspect
import unittest

from risu_e2_c1.binding_authority import (
    CERTIFIED_NONMATCH,
    CERTIFIED_PROJECTION_MATCH,
    EXACT_BASE_MATCH,
    FROZEN_BINDING_PROJECTION_AUTHORITY,
    GATE2C8_PROTOCOL_COMMIT,
    UNRESOLVED_AUTHORITY,
    classify_binding_origin_relation,
    derive_binding_authority_receipt,
    prefix_binding_environment,
)
from risu_e2_c1.common import INCOMPLETE, _digest_bytes, _digest_json
from risu_e2_c1.semantics import _independent_semantic_eval

EXPECTED = "SYN:expected"
CURRENT = "SYN:current"
OTHER = "SYN:other"


def step(kind: str, token: str):
    return {
        "kind": kind,
        "token_digest_sha256": (
            _digest_json(token)
            if kind == "SUBSCRIPT_LITERAL"
            else _digest_bytes(token.encode())
        ),
    }


def row(role: str, operand: int, steps):
    p = {
        "root_role": role,
        "terminal_guard_operand_index": operand,
        "steps": list(steps),
    }
    return {**p, "fingerprint_sha256": _digest_json(p)}


AUTH = [
    row(EXPECTED, 0, [step("SUBSCRIPT_LITERAL", "guard")]),
    row(CURRENT, 1, []),
    row(OTHER, 0, [step("SUBSCRIPT_LITERAL", "guard")]),
]


def source(left='expected["guard"]'):
    return (
        "def target(expected,current,other=None,key=None):\n"
        f"    projected = {left}\n"
        "    if projected != current:\n"
        "        return current\n"
        "    return expected\n"
    )


def context(left='expected["guard"]'):
    s = source(left)
    tree = ast.parse(s)
    fn = tree.body[0]
    guard_if = next(x for x in fn.body if isinstance(x, ast.If))
    sig = {
        "source_roles": {
            EXPECTED: {"parameter_index": 0},
            CURRENT: {"parameter_index": 1},
            OTHER: {"parameter_index": 2},
        }
    }
    env, params, bad = prefix_binding_environment(fn, guard_if, sig)
    return s, guard_if.test.left, env, params, bad


def receipt(left='expected["guard"]', raw=None, slot=None, rows=None, derivation_source="C1_RAW_BINDING_AST"):
    s, expr, env, params, bad = context(left)
    if raw is None:
        raw = {
            'expected["guard"]': EXPECTED + ".slot:guard",
            'expected["other"]': EXPECTED + ".slot:other",
            'other["guard"]': OTHER + ".slot:guard",
            "expected": EXPECTED,
        }.get(left, EXPECTED + ".slot:guard")
    r = derive_binding_authority_receipt(
        expr,
        case_id="CASE",
        binding_id="b",
        source_sha256=_digest_bytes(s.encode()),
        raw_origin=raw,
        binding_slot_identity=dict(slot or {"operand_index": 0}),
        env=env,
        param_by_name=params,
        authority_rows=AUTH if rows is None else rows,
        authority_provenance="SYNTHETIC_GATE2C8",
        derivation_source=derivation_source,
    )
    return s, raw, r, bad


def binding(raw, rec, allowed=None):
    return {
        "binding_id": "b",
        "coordinate_identity": "c",
        "resource_identity": "r",
        "slot_identity": {"operand_index": 0},
        "allowed_origins": list(allowed or [EXPECTED]),
        "observed_origins": [raw],
        "binding_complete": True,
        "definitions_complete": True,
        "lineage_paths": [
            {
                "origin": raw,
                "edges": [
                    {
                        "kind": "BINDS_TO",
                        "from": raw,
                        "to": "b",
                        "path_id": "guard-direct",
                    }
                ],
            }
        ],
        "definition_trace": [],
        "representation": {"required": False},
        "binding_authority_receipts": [] if rec is None else [rec],
    }


def doc(b, sha):
    return {
        "case_id": "CASE",
        "binding_authority_source_sha256": sha,
        "bindings": [copy.deepcopy(b)],
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
                "path_id": "t",
                "guard_polarity": "true",
                "events": ["ENTRY", "GUARD:g0", "EFFECT:E", "SUCCESS:S", "EXIT"],
                "complete": True,
                "realizable": True,
            },
            {
                "path_id": "f",
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
            {"id": "a", "kappa": {"x": 0}, "rho": {"o": "success"}},
            {"id": "b", "kappa": {"x": 1}, "rho": {"o": "reject"}},
        ],
    }


class Gate2C8BindingAuthorityTests(unittest.TestCase):
    def test_protocol_identity_and_frozen_production_fingerprints(self):
        self.assertEqual(
            "11433abadf2f2b322d9e4209ed5e721ebe059d80",
            GATE2C8_PROTOCOL_COMMIT,
        )
        self.assertEqual(
            "46b183206947fe72743af0b3b2315476edd30bb940018ea9ebb4feb0ebee1647",
            FROZEN_BINDING_PROJECTION_AUTHORITY[0]["fingerprint_sha256"],
        )
        self.assertEqual(
            "b904de65bc61791bdde2e896aa5513de3862cb5d73f00642bf4755ca27ab9845",
            FROZEN_BINDING_PROJECTION_AUTHORITY[1]["fingerprint_sha256"],
        )

    def test_allowed_origins_is_not_a_derivation_input(self):
        self.assertNotIn(
            "allowed_origins",
            inspect.signature(derive_binding_authority_receipt).parameters,
        )

    def test_projected_match_keeps_raw_origin_and_lineage(self):
        s, raw, rec, bad = receipt()
        self.assertEqual([], bad)
        b = binding(raw, rec)
        before = copy.deepcopy((b["observed_origins"], b["lineage_paths"]))
        rel = classify_binding_origin_relation(
            b,
            raw_origin=raw,
            case_id="CASE",
            source_sha256=_digest_bytes(s.encode()),
        )
        after = (b["observed_origins"], b["lineage_paths"])
        self.assertEqual(CERTIFIED_PROJECTION_MATCH, rel["relation"])
        self.assertEqual(before, after)
        self.assertEqual(EXPECTED, rel["certified_role"])

    def test_exact_base_match_needs_no_projection_receipt(self):
        s = source("expected")
        b = binding(EXPECTED, None)
        rel = classify_binding_origin_relation(
            b,
            raw_origin=EXPECTED,
            case_id="CASE",
            source_sha256=_digest_bytes(s.encode()),
        )
        self.assertEqual(EXACT_BASE_MATCH, rel["relation"])

    def test_wrong_projection_and_dynamic_projection_fail_closed(self):
        s, raw, rec, _ = receipt(left='expected["other"]')
        b = binding(raw, rec)
        rel = classify_binding_origin_relation(
            b,
            raw_origin=raw,
            case_id="CASE",
            source_sha256=_digest_bytes(s.encode()),
        )
        self.assertEqual(UNRESOLVED_AUTHORITY, rel["relation"])
        _, _, dynamic, _ = receipt(left="expected[key]")
        self.assertEqual("REJECT", dynamic["decision"])

    def test_context_replay_cannot_authorize(self):
        s, raw, rec, _ = receipt()
        rec = copy.deepcopy(rec)
        rec["binding_wrapper"]["case_id"] = "OTHER"
        rec["binding_wrapper_digest_sha256"] = _digest_json(rec["binding_wrapper"])
        b = binding(raw, rec)
        rel = classify_binding_origin_relation(
            b,
            raw_origin=raw,
            case_id="CASE",
            source_sha256=_digest_bytes(s.encode()),
        )
        self.assertEqual(UNRESOLVED_AUTHORITY, rel["relation"])
        self.assertEqual("BINDING_AUTHORITY_CASE_MISMATCH", rel["reason"])

    def test_world_receipt_and_primary_mirror_are_forbidden(self):
        s, raw, rec, _ = receipt()
        world = copy.deepcopy(rec)
        world["world_evaluation_receipt_reused"] = True
        b = binding(raw, world)
        rel = classify_binding_origin_relation(
            b,
            raw_origin=raw,
            case_id="CASE",
            source_sha256=_digest_bytes(s.encode()),
        )
        self.assertEqual(UNRESOLVED_AUTHORITY, rel["relation"])
        _, _, primary, _ = receipt(derivation_source="PRIMARY_ADAPTER")
        self.assertEqual("REJECT", primary["decision"])

    def test_unresolved_authority_is_incomplete_not_regression(self):
        s, raw, _, _ = receipt()
        b = binding(raw, None)
        out = _independent_semantic_eval(doc(b, _digest_bytes(s.encode())))
        self.assertEqual(INCOMPLETE, out["prediction"])
        self.assertFalse(
            {
                "A3_R1_WRONG_BINDING_IDENTITY",
                "A3_R2_DEFINITE_OVERWRITE_TO_WRONG_CARRIER",
                "A3_R3_EXPLICIT_CARRIER_SUBSTITUTION_OR_DROP",
            }
            & set(out["witness_ids"])
        )

    def test_certified_other_role_can_support_nonmatch(self):
        s, raw, rec, _ = receipt(left='other["guard"]')
        b = binding(raw, rec, allowed=[EXPECTED])
        rel = classify_binding_origin_relation(
            b,
            raw_origin=raw,
            case_id="CASE",
            source_sha256=_digest_bytes(s.encode()),
        )
        self.assertEqual(CERTIFIED_NONMATCH, rel["relation"])

    def test_non_role_a3_and_a4_obligations_are_unchanged(self):
        s, raw, rec, _ = receipt()
        sha = _digest_bytes(s.encode())
        before = _independent_semantic_eval(doc(binding(raw, None), sha))
        after = _independent_semantic_eval(doc(binding(raw, rec), sha))
        for k in (
            "A3_P2_BINDING_IDENTITY",
            "A3_P3_DEFINITION_SENSITIVITY",
            "A3_P4_REPRESENTATION_SURVIVAL",
            "A3_P5_PATH_REALIZABILITY",
        ):
            self.assertEqual(before["obligations"][k], after["obligations"][k])
        self.assertEqual(
            {k: v for k, v in before["obligations"].items() if k.startswith("A4_")},
            {k: v for k, v in after["obligations"].items() if k.startswith("A4_")},
        )
        self.assertEqual(
            [x for x in before["witness_ids"] if x.startswith("A4_")],
            [x for x in after["witness_ids"] if x.startswith("A4_")],
        )


if __name__ == "__main__":
    unittest.main()
