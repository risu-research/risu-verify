from __future__ import annotations

import ast
import unittest

from risu_e2_c1.common import _digest_bytes, _digest_json
from risu_e2_c1.projection_authority import (
    FROZEN_PRODUCTION_AUTHORITY,
    GATE2C7_PROTOCOL_COMMIT,
    _trace_expr,
    admit_projection_trace,
    evaluate_compare_with_projection_authority,
)


def step(kind: str, token: str) -> dict[str, str]:
    d = _digest_bytes(token.encode("utf-8")) if kind == "ATTRIBUTE" else _digest_json(token)
    return {"kind": kind, "token_digest_sha256": d}


def authority(role: str, operand: int, steps):
    payload = {"root_role": role, "terminal_guard_operand_index": operand, "steps": list(steps)}
    return {**payload, "fingerprint_sha256": _digest_json(payload)}


class Gate2C7ProjectionAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.expected = {"root_role": "SYN:expected", "steps": [step("SUBSCRIPT_LITERAL", "guard")]}
        self.current = {"root_role": "SYN:current", "steps": []}
        self.rows = [authority("SYN:expected", 0, self.expected["steps"]), authority("SYN:current", 1, [])]

    def admit(self, trace, operand=0, rows=None, provenance="SYNTHETIC_GATE2C7"):
        return admit_projection_trace(trace, operand_index=operand, authority_rows=self.rows if rows is None else rows, authority_provenance=provenance)

    def test_protocol_commit_and_frozen_fingerprints_are_exact(self):
        self.assertEqual("c9b0e1b805fa7193972894bd6a83f3390cb4be75", GATE2C7_PROTOCOL_COMMIT)
        self.assertEqual("46b183206947fe72743af0b3b2315476edd30bb940018ea9ebb4feb0ebee1647", FROZEN_PRODUCTION_AUTHORITY[0]["fingerprint_sha256"])
        self.assertEqual("b904de65bc61791bdde2e896aa5513de3862cb5d73f00642bf4755ca27ab9845", FROZEN_PRODUCTION_AUTHORITY[1]["fingerprint_sha256"])

    def test_exact_projection_admits_and_base_passthrough_is_unchanged(self):
        self.assertEqual("ADMIT", self.admit(self.expected)["decision"])
        self.assertEqual("ADMIT", self.admit(self.current, operand=1)["decision"])
        base = self.admit({"root_role": "SYN:expected", "steps": []})
        self.assertEqual(("ADMIT", "BASE_ORIGIN_PASSTHROUGH"), (base["decision"], base["reason"]))

    def test_suffix_spelling_without_certificate_never_admits(self):
        out = self.admit(None)
        self.assertEqual(("REJECT", "PROJECTION_AUTHORITY_MISSING"), (out["decision"], out["reason"]))

    def test_wrong_token_root_operand_kind_and_ambiguity_fail_closed(self):
        self.assertEqual("REJECT", self.admit({"root_role": "SYN:expected", "steps": [step("SUBSCRIPT_LITERAL", "other")]})["decision"])
        self.assertEqual("PROJECTION_ROOT_ROLE_MISMATCH", self.admit({"root_role": "SYN:other", "steps": [step("SUBSCRIPT_LITERAL", "guard")]})["reason"])
        self.assertEqual("PROJECTION_TERMINAL_OPERAND_MISMATCH", self.admit(self.expected, operand=1)["reason"])
        self.assertEqual("PROJECTION_KIND_SEQUENCE_MISMATCH", self.admit({"root_role": "SYN:expected", "steps": [step("ATTRIBUTE", "guard")]})["reason"])
        self.assertEqual("PROJECTION_AUTHORITY_AMBIGUOUS", self.admit(self.expected, rows=[*self.rows, dict(self.rows[0])])["reason"])

    def test_primary_derived_authority_is_not_accepted(self):
        out = self.admit(self.expected, provenance="PRIMARY_DERIVED")
        self.assertEqual(("REJECT", "PROJECTION_AUTHORITY_MISSING"), (out["decision"], out["reason"]))

    def test_dynamic_subscript_fails_before_admission(self):
        expr = ast.parse("expected[key]", mode="eval").body
        with self.assertRaisesRegex(ValueError, "PROJECTION_DYNAMIC_OR_UNSUPPORTED"):
            _trace_expr(expr, {}, {"expected": {"root_role": "SYN:expected", "steps": []}})

    def test_raw_ast_world_evaluation_uses_structural_certificate(self):
        guard = ast.parse('expected["guard"] != current', mode="eval").body
        pmap = {"expected": {"root_role": "SYN:expected", "steps": []}, "current": {"root_role": "SYN:current", "steps": []}}
        polarity, receipts = evaluate_compare_with_projection_authority(guard, world={"role_values": {"SYN:expected": 2, "SYN:current": 1}}, env={}, param_by_name=pmap, authority_rows=self.rows, authority_provenance="SYNTHETIC_GATE2C7")
        self.assertIs(True, polarity)
        self.assertEqual(["ADMIT", "ADMIT"], [x["decision"] for x in receipts])
        self.assertEqual("CANONICAL_OPAQUE_PROJECTION_MATCH", receipts[0]["reason"])

    def test_extra_projection_fails_closed(self):
        out = self.admit({"root_role": "SYN:expected", "steps": [step("SUBSCRIPT_LITERAL", "guard"), step("ATTRIBUTE", "extra")]})
        self.assertEqual("REJECT", out["decision"])


if __name__ == "__main__": unittest.main()
