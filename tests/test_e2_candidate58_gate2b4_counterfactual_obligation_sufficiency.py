import importlib.util
from pathlib import Path
import unittest

P = Path(__file__).resolve().parents[1] / "tools" / "e2_candidate58_gate2b4_counterfactual_obligation_sufficiency.py"
spec = importlib.util.spec_from_file_location("gate2b4", P)
g = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(g)

class Gate2B4CounterfactualTests(unittest.TestCase):
    def test_all_taxa_and_frontier(self):
        def cid(i): return f"{i:064x}"
        g2=[]; g3=[]
        cases=[
            (1,["GUARD_SCOPE_UNRESOLVED"],True),
            (2,["GUARD_OPERATOR_UNRESOLVED","GUARD_SCOPE_UNRESOLVED"],True),
            (3,["A","B","GUARD_SCOPE_UNRESOLVED"],True),
            (4,["GUARD_SCOPE_UNRESOLVED","WORLD_ROLE_VALUE_MISSING"],False),
        ]
        cases += [(i,["GUARD_OPERATOR_UNRESOLVED","GUARD_SCOPE_UNRESOLVED"],True) for i in range(5,34)]
        cases += [(i,["GUARD_SCOPE_UNRESOLVED","WORLD_ROLE_VALUE_MISSING"],False) for i in range(34,40)]
        self.assertEqual(len(cases),39)
        self.assertEqual(sum(primary for _,_,primary in cases),32)
        for i,primitive,primary in cases:
            c=cid(i); unresolved=["FINITE_WORLD_TARGET_REALIZATION_INCOMPLETE"]+primitive
            g2.append({"case_id":c,"primitive_atom_prefixes":primitive,"F_unresolved_atom_instances":unresolved})
            g3.append({"case_id":c,"gate2b2_primitive_atom_prefixes":primitive,"gate2b2_F_unresolved_atom_instances":unresolved,"causal_taxonomy_id":g.PRIMARY_G2B3 if primary else "X","predicates":{"P_GUARD_SCOPE_CARRIER_SURVIVAL_FAILURE":primary}})
        ledger,summary=g.analyze_population({"schema":g.G2B2_SCHEMA,"case_count":39,"rows":g2},{"schema":g.G2B3_SCHEMA,"case_count":39,"rows":g3})
        self.assertEqual(ledger["primary_case_count"],32)
        self.assertEqual(ledger["secondary_case_count"],7)
        self.assertEqual(summary["taxonomy_counts"][g.TAXONOMY[0]],1)
        self.assertEqual(summary["taxonomy_counts"][g.TAXONOMY[1]],30)
        self.assertEqual(summary["taxonomy_counts"][g.TAXONOMY[2]],1)
        self.assertEqual(summary["taxonomy_counts"][g.SECONDARY],7)
        self.assertEqual(summary["scope_only_known_primitive_F_closure_sufficient_count"],1)
        self.assertEqual(summary["two_family_closure_frontier"]["GUARD_OPERATOR_UNRESOLVED"]["count"],31)

    def test_population_mismatch_fails_closed(self):
        with self.assertRaises(ValueError):
            g.analyze_population({"schema":g.G2B2_SCHEMA,"case_count":39,"rows":[]},{"schema":g.G2B3_SCHEMA,"case_count":39,"rows":[]})

if __name__ == "__main__":
    unittest.main()
