from __future__ import annotations

import unittest

from tools.ctv_finite_primary import evaluate_finite_model
from tools.ctv_finite_independent import independent_compute


def finite_model(worlds, target_map=None):
    return {
        "schema": "risu.ctv-finite-model/v0.1alpha1",
        "unit_id": "synthetic-unit",
        "worlds": worlds,
        "target_to_source_consequence_map": target_map,
        "claim_scope": {"synthetic": True},
        "effect_cut": {"synthetic": True},
    }


class FinitePrimaryTests(unittest.TestCase):
    def test_collapse_with_distinct_source_consequences_is_regression(self):
        model = finite_model([
            {"id": "A", "source_consequence": "YES", "target_realization": "R", "target_consequence": None},
            {"id": "B", "source_consequence": "NO", "target_realization": "R", "target_consequence": None},
        ])
        out = evaluate_finite_model(model)
        self.assertEqual(out["verdict"], "CONSEQUENCE_REGRESSION")
        self.assertEqual(out["reason"], "DETERMINISTIC_FACTORIZATION_VIOLATION")
        self.assertFalse(out["deterministic_factorization_exists"])
        self.assertEqual(out["witness"]["world_1"], "A")
        self.assertEqual(out["witness"]["world_2"], "B")

    def test_no_collapse_without_interpretation_is_incomplete(self):
        model = finite_model([
            {"id": "A", "source_consequence": "YES", "target_realization": "R1", "target_consequence": None},
            {"id": "B", "source_consequence": "NO", "target_realization": "R2", "target_consequence": None},
        ])
        out = evaluate_finite_model(model)
        self.assertEqual(out["verdict"], "ASSURANCE_INCOMPLETE")
        self.assertTrue(out["deterministic_factorization_exists"])
        self.assertFalse(out["refinement_checked"])

    def test_explicit_interpretation_can_establish_stability(self):
        model = finite_model([
            {"id": "A", "source_consequence": "YES", "target_realization": "R1", "target_consequence": "TY"},
            {"id": "B", "source_consequence": "NO", "target_realization": "R2", "target_consequence": "TN"},
        ], {"TY": "YES", "TN": "NO"})
        out = evaluate_finite_model(model)
        self.assertEqual(out["verdict"], "CONSEQUENCE_STABLE_IN_DECLARED_SCOPE")
        self.assertTrue(out["refinement_checked"])

    def test_explicit_interpretation_mismatch_is_regression(self):
        model = finite_model([
            {"id": "A", "source_consequence": "YES", "target_realization": "R1", "target_consequence": "TN"},
        ], {"TN": "NO"})
        out = evaluate_finite_model(model)
        self.assertEqual(out["verdict"], "CONSEQUENCE_REGRESSION")
        self.assertEqual(out["reason"], "CONSEQUENCE_REFINEMENT_VIOLATION")
        self.assertEqual(out["witness"]["world"], "A")

    def test_permutation_does_not_change_constructive_witness(self):
        rows = [
            {"id": "C", "source_consequence": "X", "target_realization": "R", "target_consequence": None},
            {"id": "A", "source_consequence": "X", "target_realization": "R", "target_consequence": None},
            {"id": "B", "source_consequence": "Y", "target_realization": "R", "target_consequence": None},
        ]
        a = evaluate_finite_model(finite_model(rows))
        b = evaluate_finite_model(finite_model(list(reversed(rows))))
        self.assertEqual(a["verdict"], b["verdict"])
        self.assertEqual(a["witness"], b["witness"])


class IndependentCheckerTests(unittest.TestCase):
    def test_independent_pair_enumeration_matches_theory(self):
        author = {}
        source = {
            "unit_id": "synthetic-unit",
            "bounded_worlds": [
                {"world": "A", "required_consequence": "YES"},
                {"world": "B", "required_consequence": "NO"},
            ],
        }
        target = {"unit_id": "synthetic-unit"}
        boundary = {
            "unit_id": "synthetic-unit",
            "worlds": [
                {"id": "A", "required_source_consequence": "YES"},
                {"id": "B", "required_source_consequence": "NO"},
            ],
            "target_observation_model": {"target_realization_label": "R"},
        }
        out = independent_compute(author, boundary, source, target)
        self.assertEqual(out["verdict"], "CONSEQUENCE_REGRESSION")
        self.assertEqual(out["pair_witness_count"], 1)

    def test_independent_checker_does_not_treat_realization_difference_as_regression(self):
        author = {}
        source = {
            "unit_id": "synthetic-unit",
            "bounded_worlds": [
                {"world": "A", "required_consequence": "YES"},
                {"world": "B", "required_consequence": "NO"},
            ],
        }
        target = {"unit_id": "synthetic-unit"}
        boundary = {
            "unit_id": "synthetic-unit",
            "worlds": [
                {"id": "A", "required_source_consequence": "YES"},
                {"id": "B", "required_source_consequence": "NO"},
            ],
            "target_observation_model": {
                "world_realizations": {"A": "R1", "B": "R2"}
            },
        }
        out = independent_compute(author, boundary, source, target)
        self.assertEqual(out["verdict"], "ASSURANCE_INCOMPLETE")
        self.assertEqual(out["pair_witness_count"], 0)


if __name__ == "__main__":
    unittest.main()
