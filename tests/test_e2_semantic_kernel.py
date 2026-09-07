from __future__ import annotations

import copy
import unittest

from risu_e2_semantic.kernel import (
    INCOMPLETE, PRESERVATION, REGRESSION, evaluate, sha256_json,
)


def stable_slice():
    return {
        "schema":"risu.e2-semantic-slice/v0.1","case_id":"synthetic-stable","canonical_signature_digest":"sig",
        "bindings":[
            {"binding_id":"guard0","coordinate_identity":"coord:expected","resource_identity":"resource:r","slot_identity":{"operand_index":0},"allowed_origins":["expected"],"observed_origins":["expected"],"binding_complete":True,"definitions_complete":True,"lineage_paths":[{"origin":"expected","edges":[{"kind":"BINDS_TO","from":"expected","to":"guard0","path_id":"p0"}]}],"definition_trace":[],"representation":{"required":False}},
            {"binding_id":"effect0","coordinate_identity":"coord:payload","resource_identity":"resource:r","slot_identity":{"arg_index":0},"allowed_origins":["desired"],"observed_origins":["desired"],"binding_complete":True,"definitions_complete":True,"lineage_paths":[{"origin":"desired","edges":[{"kind":"CARRIES","from":"desired","to":"effect0","path_id":"p-eff"}]}],"definition_trace":[],"representation":{"required":False}},
        ],
        "guard":{"form":"DIRECT_CONTROL","effective_guard_id":"g0","effective_guard_count":1,"net_polarity":"PRESERVE","helper_chain":[],"effect_polarity":"false","rejection_polarity":"true"},
        "control_paths":[
            {"path_id":"p-true","guard_polarity":"true","events":["ENTRY","GUARD:g0","POLARITY:true","REJECTION:reject","EXIT"],"complete":True,"realizable":True},
            {"path_id":"p-false","guard_polarity":"false","events":["ENTRY","GUARD:g0","POLARITY:false","EFFECT:eff","SUCCESS:ok","EXIT"],"complete":True,"realizable":True},
        ],
        "effect":{"surfaces":["eff"],"equivalence_proof_id":None,"success_outcome_id":"ok","rejection_outcome_id":"reject","effect_before_success_structural":True},
        "scope":{"scope_id":"scope0","complete":True,"unresolved":[],"aliases_complete":True,"call_targets_complete":True,"reaching_definitions_complete":True,"branches_complete":True,"representations_complete":True,"effects_complete":True,"exceptions_exits_complete":True,"resources_complete":True,"helper_polarity_complete":True,"all_entry_paths_enumerated":True},
        "worlds":[
            {"id":"w1","kappa":{"effect":"A"},"rho":{"outcome":"effect","payload":"A"}},
            {"id":"w2","kappa":{"effect":"B"},"rho":{"outcome":"effect","payload":"B"}},
            {"id":"w3","kappa":{"reject":True},"rho":{"outcome":"reject"}},
        ],
    }


class KernelTests(unittest.TestCase):
    def test_stable_full_six_admissions_promotes_preservation(self):
        out=evaluate(stable_slice())
        self.assertEqual(PRESERVATION,out["prediction"])
        self.assertTrue(all(v["satisfied"] for v in out["admissions"].values()))
        self.assertTrue(all(out["obligations"].values()))

    def test_wrong_binding_plus_ctv_collapse_is_regression(self):
        d=stable_slice(); d["case_id"]="wrong"
        b=d["bindings"][1]; b["observed_origins"]=["other"]; b["lineage_paths"]=[{"origin":"other","edges":[{"kind":"CARRIES","from":"other","to":"effect0","path_id":"p-eff"}]}]
        d["worlds"][0]["rho"]={"outcome":"effect","payload":"X"}; d["worlds"][1]["rho"]={"outcome":"effect","payload":"X"}
        out=evaluate(d)
        self.assertEqual(REGRESSION,out["prediction"])
        ids={x["witness_id"] for x in out["witnesses"]}
        self.assertIn("A3_R1_WRONG_BINDING_IDENTITY",ids)
        self.assertIn("A3_R3_EXPLICIT_CARRIER_SUBSTITUTION_OR_DROP",ids)

    def test_ctv_collapse_without_constructive_witness_abstains(self):
        d=stable_slice(); d["worlds"][1]["rho"]=copy.deepcopy(d["worlds"][0]["rho"])
        out=evaluate(d)
        self.assertEqual(INCOMPLETE,out["prediction"])
        self.assertIn("CTV_COLLAPSE_WITHOUT_ADMITTED_CONSTRUCTIVE_WITNESS",out["unresolved"])

    def test_scope_gap_blocks_preservation(self):
        d=stable_slice(); d["scope"]["exceptions_exits_complete"]=False
        out=evaluate(d)
        self.assertEqual(INCOMPLETE,out["prediction"])
        self.assertFalse(out["admissions"]["F"]["satisfied"])

    def test_may_flow_union_blocks_carrier_admission(self):
        d=stable_slice(); d["bindings"][1]["may_flow_only"]=True
        out=evaluate(d)
        self.assertEqual(INCOMPLETE,out["prediction"])
        self.assertFalse(out["admissions"]["B"]["satisfied"])

    def test_helper_unknown_polarity_blocks_guard_admission(self):
        d=stable_slice(); d["guard"].update({"form":"HELPER_CONTROL","helper_chain":[{"transform":"UNKNOWN"}],"net_polarity":"PRESERVE"})
        out=evaluate(d)
        self.assertEqual(INCOMPLETE,out["prediction"])
        self.assertFalse(out["admissions"]["C"]["satisfied"])

    def test_guard_bypass_witness_needs_world_collapse_to_promote(self):
        d=stable_slice(); d["control_paths"][1]["events"]=["ENTRY","EFFECT:eff","SUCCESS:ok","EXIT"]
        # create a CTV collapse pair so the constructive A4 witness can promote
        d["worlds"][1]["rho"]=copy.deepcopy(d["worlds"][0]["rho"])
        out=evaluate(d)
        self.assertEqual(REGRESSION,out["prediction"])
        self.assertIn("A4_R1_GUARD_BYPASS",{x["witness_id"] for x in out["witnesses"]})


    def test_ambiguous_coordinate_identity_blocks_A(self):
        d=stable_slice(); d["bindings"][0]["identity_ambiguous"]=True
        out=evaluate(d)
        self.assertEqual(INCOMPLETE,out["prediction"])
        self.assertFalse(out["admissions"]["A"]["satisfied"])

    def test_collapsed_outcome_identity_blocks_E(self):
        d=stable_slice(); d["effect"]["rejection_outcome_id"]="ok"
        out=evaluate(d)
        self.assertEqual(INCOMPLETE,out["prediction"])
        self.assertFalse(out["admissions"]["E"]["satisfied"])

    def test_result_digest_is_deterministic(self):
        a=evaluate(stable_slice()); b=evaluate(stable_slice())
        self.assertEqual(a,b); self.assertEqual(a["result_digest_sha256"],sha256_json({k:v for k,v in a.items() if k!="result_digest_sha256"}))


if __name__ == "__main__": unittest.main()
