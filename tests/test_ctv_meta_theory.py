import itertools
import json
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "protocols" / "CTV_META_THEORY_v0.1.json"


def factorizes(kappa, rho):
    decoder = {}
    for w in range(len(kappa)):
        realization = rho[w]
        consequence = kappa[w]
        if realization in decoder and decoder[realization] != consequence:
            return False
        decoder[realization] = consequence
    return True


def kernel_inclusion(kappa, rho):
    n = len(kappa)
    return all(
        rho[i] != rho[j] or kappa[i] == kappa[j]
        for i in range(n)
        for j in range(n)
    )


def collapse_witness_exists(kappa, rho):
    n = len(kappa)
    return any(
        rho[i] == rho[j] and kappa[i] != kappa[j]
        for i in range(n)
        for j in range(i + 1, n)
    )


def relational_refines(source_allowed, target_realizations, mapping):
    for world, allowed in source_allowed.items():
        induced = set()
        for realization in target_realizations[world]:
            induced.update(mapping[realization])
        if not induced.issubset(allowed):
            return False
    return True


class CTVMetaTheoryTests(unittest.TestCase):
    def test_factorization_kernel_witness_equivalence_exhaustive_small(self):
        # Executable finite sanity check, not a formal proof.
        # Exhaust all 3-world functions into three consequence/realization labels.
        checked = 0
        for kappa in itertools.product(range(3), repeat=3):
            for rho in itertools.product(range(3), repeat=3):
                f = factorizes(kappa, rho)
                k = kernel_inclusion(kappa, rho)
                w = collapse_witness_exists(kappa, rho)
                self.assertEqual(f, k)
                self.assertEqual(f, not w)
                checked += 1
        self.assertEqual(checked, 729)

    def test_relational_refinement_accepts_subset_and_rejects_extra_consequence(self):
        source = {0: {"OK", "REJECT"}, 1: {"REJECT"}}
        mapping = {"success": {"OK"}, "stale": {"REJECT"}, "bad": {"MUTATE_STALE"}}
        self.assertTrue(relational_refines(source, {0: {"success"}, 1: {"stale"}}, mapping))
        self.assertFalse(relational_refines(source, {0: {"success"}, 1: {"bad"}}, mapping))

    def test_pure_behavior_subset_is_not_declared_to_imply_operativeness(self):
        c = json.loads(CONTRACT.read_text())
        levels = c["compatibility_levels"]
        self.assertIn("L3_OPERATIVE", levels)
        self.assertIn("L4_CONSEQUENCE_REFINEMENT", levels)
        self.assertNotEqual(levels.index("L3_OPERATIVE"), levels.index("L4_CONSEQUENCE_REFINEMENT"))

    def test_contract_is_prospective_and_nonretroactive(self):
        c = json.loads(CONTRACT.read_text())
        self.assertEqual(c["status"], "FROZEN_BEFORE_UNIT003_AUTHORING")
        self.assertEqual(c["effective_from_unit"], "corpus01-unit-003")
        self.assertEqual(c["retroactivity_rule"], "NO_REINTERPRETATION_NO_UPGRADE")
        u2 = c["canonical_prior_results"]["corpus01-unit-002"]
        self.assertEqual(u2["canonical_result"], "PRESERVED_IN_DECLARED_SCOPE")
        self.assertIs(u2["coverage_complete"], False)

    def test_future_verdict_namespace_is_disjoint_from_closed_product_vocabulary(self):
        c = json.loads(CONTRACT.read_text())
        future = set(c["future_verdicts"])
        forbidden = {"PRESERVED", "PRESERVED_IN_DECLARED_SCOPE", "CLOSED"}
        self.assertTrue(future.isdisjoint(forbidden))


if __name__ == "__main__":
    unittest.main()
