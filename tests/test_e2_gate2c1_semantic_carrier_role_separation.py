from __future__ import annotations

import inspect
import unittest

from risu_e2.observability_overlay import _unique_anchor_scope
from risu_e2_semantic.adapter_support import _guard_operator


def edge(idx, ops, *, target="g", source=None):
    return {
        "id": f"e:{idx}:{source or idx}:{repr(ops)}",
        "kind": "COMPARES",
        "source": source or f"v{idx}",
        "target": target,
        "attrs": {"operand_index": idx, "operators": ops},
    }


def overlay(*edges):
    return {"edges": list(edges)}


class Gate2C1SemanticAuthorityTests(unittest.TestCase):
    def test_unique_structured_scope_is_authoritative(self):
        controls={"f":{"span":(1,0,10,0)}}
        self.assertEqual(_unique_anchor_scope(controls,(3,4,3,9)),"f")

    def test_missing_structured_scope_remains_unresolved(self):
        controls={"f":{"span":(1,0,2,0)}}
        self.assertIsNone(_unique_anchor_scope(controls,(3,4,3,9)))

    def test_ambiguous_nested_structured_scope_remains_unresolved(self):
        controls={"outer":{"span":(1,0,20,0)},"inner":{"span":(3,0,8,0)}}
        self.assertIsNone(_unique_anchor_scope(controls,(4,2,4,8)))

    def test_structural_control_condition_only_is_not_operator_authority(self):
        ov=overlay(edge(-1,["CONTROL_CONDITION"]))
        self.assertIsNone(_guard_operator(ov,"g",[0,1]))

    def test_structural_control_edge_coexists_without_contaminating_eq(self):
        ov=overlay(edge(-1,["CONTROL_CONDITION"]),edge(0,["Eq"]),edge(1,["=="]))
        self.assertEqual(_guard_operator(ov,"g",[0,1]),"EQ")

    def test_extra_negative_structural_edges_do_not_change_operator(self):
        ov=overlay(edge(-2,["CONTROL_PREDICATE_RESULT"]),edge(-1,["CONTROL_CONDITION"]),edge(0,["NotEq"]),edge(1,["!=="]))
        self.assertEqual(_guard_operator(ov,"g",[0,1]),"NE")

    def test_missing_expected_comparison_operand_fails_closed(self):
        ov=overlay(edge(-1,["CONTROL_CONDITION"]),edge(0,["Eq"]))
        self.assertIsNone(_guard_operator(ov,"g",[0,1]))

    def test_unsupported_authoritative_token_fails_closed(self):
        ov=overlay(edge(0,["LT"]),edge(1,["LT"]))
        self.assertIsNone(_guard_operator(ov,"g",[0,1]))

    def test_multiple_tokens_on_authoritative_operand_fail_closed(self):
        ov=overlay(edge(0,["Eq","NotEq"]),edge(1,["Eq"]))
        self.assertIsNone(_guard_operator(ov,"g",[0,1]))

    def test_normalized_disagreement_fails_closed(self):
        ov=overlay(edge(0,["Eq"]),edge(1,["NotEq"]))
        self.assertIsNone(_guard_operator(ov,"g",[0,1]))

    def test_noncanonical_positive_operand_is_non_authoritative(self):
        ov=overlay(edge(0,["Eq"]),edge(1,["=="]),edge(2,["LT"]))
        self.assertEqual(_guard_operator(ov,"g",[0,1]),"EQ")

    def test_empty_expected_operand_authority_fails_closed(self):
        ov=overlay(edge(0,["Eq"]),edge(1,["Eq"]))
        self.assertIsNone(_guard_operator(ov,"g",[]))

    def test_repair_helpers_have_no_case_language_or_truth_inputs(self):
        op_params=set(inspect.signature(_guard_operator).parameters)
        scope_params=set(inspect.signature(_unique_anchor_scope).parameters)
        forbidden={"case_id","language","truth","expected_label","mutation_operator","seed_id"}
        self.assertFalse(op_params & forbidden)
        self.assertFalse(scope_params & forbidden)


if __name__ == "__main__":
    unittest.main()
