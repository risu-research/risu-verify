import json
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "protocols" / "RISU_DIFF_E0_EVALUATION_CONTRACT_v0.1.json"


class RisuDiffE0FirewallTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.c = json.loads(CONTRACT.read_text())

    def test_prediction_namespace_is_explicitly_noncanonical(self):
        preds = set(self.c["prediction_namespace"])
        self.assertTrue(preds)
        self.assertTrue(all(p.startswith("E0_") for p in preds))
        canonical = {
            "PRESERVED",
            "PRESERVED_IN_DECLARED_SCOPE",
            "CONSEQUENCE_REGRESSION",
            "CONSEQUENCE_STABLE_IN_DECLARED_SCOPE",
            "ASSURANCE_INCOMPLETE",
        }
        self.assertTrue(preds.isdisjoint(canonical))

    def test_guard_only_metadata_is_not_training_data(self):
        fw = self.c["development_firewall"]
        self.assertTrue(set(fw["guard_only_paths"]).isdisjoint(set(fw["semantic_training_allowlist"])))
        self.assertIn("corpus/0.1/ENROLLMENT.json", fw["guard_only_paths"])
        for banned in [
            "corpus/0.1/CANDIDATE_POOL.json",
            "corpus/0.1/SCREENING_LOG.jsonl",
            "corpus/0.1/SCREENING_PROCEDURE.json",
        ]:
            self.assertNotIn(banned, fw["semantic_training_allowlist"])

    def test_gold_isolation_is_two_freeze_protocol(self):
        g = self.c["gold_isolation"]
        self.assertIs(g["machine_first_must_be_sealed_before_gold_authoring"], True)
        self.assertIs(g["gold_authoring_must_be_blind_to_machine_first_output_until_gold_freeze"], True)
        self.assertIn("held-out", g["contamination_policy"].lower())

    def test_prequential_rule_is_test_then_learn(self):
        self.assertTrue(self.c["prequential_rule"].startswith("TEST_THEN_LEARN"))
        self.assertEqual(self.c["heldout_sequence"], [f"corpus01-unit-{i:03d}" for i in range(3, 9)])

    def test_false_stable_and_unsupported_established_are_hard_stops(self):
        text = "\n".join(self.c["hard_stops"]).lower()
        self.assertIn("false stable", text)
        self.assertIn("unsupported established fact", text)
        self.assertIn("silent unknown", text)

    def test_vbe_material_role_set_is_frozen(self):
        self.assertEqual(
            self.c["evaluation_metrics"]["material_role_set"],
            [
                "authoritative_version_coordinate",
                "current_version_at_effect_coordinate",
                "binding_or_compare_guard",
                "declared_effect",
                "stale_mismatch_outcome_or_interpreter",
            ],
        )

    def test_baselines_do_not_claim_ctv_authority(self):
        b = self.c["baseline_contract"]
        self.assertIn("prohibited from claiming consequence preservation", b["B0_SURFACE"])
        self.assertIn("without operative flow", b["B1_NAME_SHAPE"])
        self.assertIn("source consequence", b["B2_FLOW_ONLY"])
        self.assertIn("never available", b["ORACLE_HUMAN_GOLD"])

    def test_cegar_cannot_edit_semantics_to_remove_counterexample(self):
        c = self.c["cegar_policy"]
        self.assertIn("minimum additional evidence", c["allowed_refinement"])
        self.assertIn("forbidden", "forbidden")
        self.assertIn("source consequence", c["forbidden_refinement"])
        self.assertIn("metric", c["forbidden_refinement"])
        self.assertIn("verdict semantics", c["forbidden_refinement"])

    def test_witness_validity_precedes_minimality(self):
        w = self.c["witness_policy"]
        self.assertIs(w["validity_before_minimality"], True)
        self.assertEqual(len(w["objective_order"]), 3)
        self.assertIn("differing world coordinates", w["objective_order"][0])


if __name__ == "__main__":
    unittest.main()
