import itertools
import json
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
AMENDMENT = ROOT / "protocols" / "CTV_META_THEORY_v0.1_AMENDMENT_001.json"


def relational_refines_nonvacuously(source_allowed, target_realizations, mapping):
    for world, allowed in source_allowed.items():
        realizations = target_realizations[world]
        if not realizations:
            return False
        induced = set()
        for realization in realizations:
            interpreted = mapping.get(realization)
            if interpreted is None or len(interpreted) == 0:
                return False
            induced.update(interpreted)
        if not induced.issubset(allowed):
            return False
    return True


class CTVMetaTheoryAmendment001Tests(unittest.TestCase):
    def test_empty_interpretation_cannot_manufacture_refinement(self):
        source = {0: {"OK"}}
        target = {0: {"opaque"}}
        mapping = {"opaque": set()}
        self.assertFalse(relational_refines_nonvacuously(source, target, mapping))

    def test_supported_nonempty_interpretation_can_refine(self):
        source = {0: {"OK", "REJECT"}, 1: {"REJECT"}}
        target = {0: {"success"}, 1: {"stale"}}
        mapping = {"success": {"OK"}, "stale": {"REJECT"}}
        self.assertTrue(relational_refines_nonvacuously(source, target, mapping))

    def test_extra_consequence_still_breaks_refinement(self):
        source = {0: {"OK"}}
        target = {0: {"bad"}}
        mapping = {"bad": {"OK", "MUTATE_STALE"}}
        self.assertFalse(relational_refines_nonvacuously(source, target, mapping))

    def test_deterministic_collapse_cannot_hide_behind_nonempty_mapping(self):
        # Two worlds with distinct singleton source consequences collapse to one target realization.
        # Exhaust every nonempty mapping subset over the two-consequence domain: none can refine both worlds.
        consequences = {"C0", "C1"}
        nonempty_subsets = [
            set(s)
            for n in range(1, len(consequences) + 1)
            for s in itertools.combinations(sorted(consequences), n)
        ]
        source = {0: {"C0"}, 1: {"C1"}}
        target = {0: {"r"}, 1: {"r"}}
        for mapped in nonempty_subsets:
            self.assertFalse(relational_refines_nonvacuously(source, target, {"r": mapped}))

    def test_compatibility_is_named_vector_without_implicit_edges(self):
        a = json.loads(AMENDMENT.read_text())
        compat = a["normative_overrides"]["compatibility_structure"]
        self.assertEqual(compat["kind"], "NAMED_OBLIGATION_VECTOR_NOT_TOTAL_ORDER")
        self.assertEqual(compat["implicit_level_implications"], [])

    def test_amendment_is_pre_unit003_and_nonretroactive(self):
        a = json.loads(AMENDMENT.read_text())
        self.assertEqual(a["status"], "FROZEN_PRE_UNIT003_PRE_VERDICT")
        self.assertEqual(a["timing"]["effective_from_unit"], "corpus01-unit-003")
        self.assertFalse(a["timing"]["unit003_authoring_started_at_amendment"])
        self.assertFalse(a["timing"]["unit003_verdict_observed_at_amendment"])
        self.assertTrue(a["anti_retroactivity"]["historical_recompute_forbidden"])


if __name__ == "__main__":
    unittest.main()
