from __future__ import annotations

import unittest

from risu_e0.baselines import b0_surface, b1_name_shape, b2_flow_only, require_non_authoritative
from risu_e0.cegar import refinement_requests
from risu_e0.engine import PRED_STABLE
from risu_e0.extractor import extract_coordinate_candidates


class DiscoveryAndBaselineQualification(unittest.TestCase):
    def test_static_extractor_never_self_establishes_semantics(self):
        source = """
def update(reviewed_sha, current_sha):
    if reviewed_sha == current_sha:
        return commit(current_sha)
    return stale()
"""
        result = extract_coordinate_candidates(source)
        self.assertFalse(result["semantic_authority"])
        self.assertGreaterEqual(len(result["coordinate_candidates"]), 2)
        for candidate in result["coordinate_candidates"] + result["comparison_candidates"]:
            self.assertEqual(candidate["status"], "DECLARED")
            self.assertEqual(candidate["semantic_role"], "UNRESOLVED")

    def test_cegar_requests_cannot_rewrite_science(self):
        obligations = {
            "guard_established": False,
            "guard_guards_effect": False,
            "current_coordinate_established": True,
        }
        reqs = refinement_requests(obligations)
        self.assertEqual(len(reqs), 2)
        for req in reqs:
            self.assertTrue(req["target_only"])
            self.assertFalse(req["may_change_source_contract"])
            self.assertFalse(req["may_change_evaluation_metric"])
            self.assertFalse(req["may_upgrade_without_evidence"])

    def test_all_baselines_are_non_authoritative(self):
        extraction = extract_coordinate_candidates("if etag == current_etag: pass")
        results = [
            b0_surface({"name": "update", "arguments": ["etag"]}),
            b1_name_shape("reviewed_sha current_sha etag"),
            b2_flow_only(extraction),
        ]
        for result in results:
            require_non_authoritative(result)
            self.assertFalse(result["consequence_authority"])
            self.assertIsNone(result["authoritative_prediction"])

    def test_baselines_have_no_prediction_namespace(self):
        extraction = extract_coordinate_candidates("if sha == current_sha: pass")
        results = [b0_surface({"name": "x", "arguments": []}), b1_name_shape("sha"), b2_flow_only(extraction)]
        for result in results:
            self.assertNotIn("prediction", result)
            self.assertIsNone(result["authoritative_prediction"])

    def test_semantically_suggestive_names_still_do_not_self_establish(self):
        result = extract_coordinate_candidates("""
def dangerous(authoritative_version, current_version):
    if authoritative_version == current_version:
        return irreversible_effect()
""")
        self.assertTrue(result["coordinate_candidates"])
        self.assertTrue(result["comparison_candidates"])
        self.assertTrue(all(x["semantic_role"] == "UNRESOLVED" for x in result["coordinate_candidates"] + result["comparison_candidates"]))

    def test_baseline_authority_escalation_is_rejected(self):
        bad = b0_surface({"name": "update", "arguments": []})
        bad["authoritative_prediction"] = PRED_STABLE
        with self.assertRaises(ValueError):
            require_non_authoritative(bad)


