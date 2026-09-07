from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

P=Path(__file__).resolve().parents[1]/"tools"/"e2_gate2c4_projection_shape_triangulation.py"
spec=importlib.util.spec_from_file_location("g2c4",P);g=importlib.util.module_from_spec(spec);assert spec and spec.loader;spec.loader.exec_module(g)


class Taxonomy(unittest.TestCase):
    def test_unresolved_precedence(self):
        self.assertEqual(g.classify(None,[],[]),"CANONICAL_PROJECTION_SHAPE_UNRESOLVED")
        self.assertEqual(g.classify([],None,[]),"C1_PROJECTION_SHAPE_UNRESOLVED")
        self.assertEqual(g.classify([],[],None),"PRIMARY_PROJECTION_SHAPE_UNRESOLVED")
    def test_mismatch_precedence(self):
        self.assertEqual(g.classify(["DERIVES"],[],["DERIVES"]),"C1_VS_CANONICAL_SHAPE_MISMATCH")
        self.assertEqual(g.classify(["DERIVES"],["DERIVES"],[]),"PRIMARY_VS_CANONICAL_SHAPE_MISMATCH")
    def test_three_way(self):
        self.assertEqual(g.classify(["DERIVES"],["DERIVES"],["DERIVES"]),"THREE_WAY_PROJECTION_SHAPE_MATCH")
        self.assertEqual(g.classify([],[],[]),"THREE_WAY_PROJECTION_SHAPE_MATCH")


class ShapeExtraction(unittest.TestCase):
    def profiles(self):
        return {"profiles":[{"seed_id":"SYN-PY-01","source_roles":{
            "BOUND_VALUE:expected_coordinate":{"lineage_edge_shapes":[["DERIVES"]]},
            "BOUND_VALUE:current_coordinate":{"lineage_edge_shapes":[[]]},
        }}]}
    def ledger_row(self):
        return {"case_id":"c","taxonomy":"WORLD_ROLE_VALUE_MISSING_LEFT","primitive":{
            "left_origin":"BOUND_VALUE:expected_coordinate.slot:any_opaque_token",
            "right_origin":"BOUND_VALUE:current_coordinate",
        }}
    def primary_doc(self):
        return {"case_id":"c","bindings":[
            {"binding_id":"GUARD_SLOT:expected_coordinate","lineage_paths":[{"origin":"BOUND_VALUE:expected_coordinate","edges":[
                {"kind":"DERIVES","from":"BOUND_VALUE:expected_coordinate","to":"root","projection":"ROLE_TO_PROVENANCE_ROOT"},
                {"kind":"DERIVES","from":"root","to":"value","primary_edge_id":"edge1"},
                {"kind":"BINDS_TO","from":"value","to":"GUARD_SLOT:expected_coordinate","projection":"PRIMARY_VALUE_TO_SEMANTIC_BINDING"},
            ]}]},
            {"binding_id":"GUARD_SLOT:current_coordinate","lineage_paths":[{"origin":"BOUND_VALUE:current_coordinate","edges":[
                {"kind":"DERIVES","from":"BOUND_VALUE:current_coordinate","to":"root2","projection":"ROLE_TO_PROVENANCE_ROOT"},
                {"kind":"BINDS_TO","from":"root2","to":"GUARD_SLOT:current_coordinate","projection":"PRIMARY_VALUE_TO_SEMANTIC_BINDING"},
            ]}]},
        ]}
    def test_canonical_shapes(self):
        self.assertEqual(g.canonical_shape(self.profiles(),"BOUND_VALUE:expected_coordinate"),["DERIVES"])
        self.assertEqual(g.canonical_shape(self.profiles(),"BOUND_VALUE:current_coordinate"),[])
    def test_c1_discards_slot_spelling(self):
        r=self.ledger_row();self.assertEqual(g.c1_shape(r,"BOUND_VALUE:expected_coordinate"),["DERIVES"]);self.assertEqual(g.c1_shape(r,"BOUND_VALUE:current_coordinate"),[])
    def test_primary_uses_only_real_primary_edges(self):
        d=self.primary_doc();self.assertEqual(g.primary_shape(d,"BOUND_VALUE:expected_coordinate"),["DERIVES"]);self.assertEqual(g.primary_shape(d,"BOUND_VALUE:current_coordinate"),[])
    def test_malformed_or_nonunique_fail_closed(self):
        r=self.ledger_row();r["primitive"]["left_origin"]="BOUND_VALUE:expected_coordinate.slot:a.b";self.assertIsNone(g.c1_shape(r,"BOUND_VALUE:expected_coordinate"))
        d=self.primary_doc();d["bindings"][0]["lineage_paths"].append(d["bindings"][0]["lineage_paths"][0].copy());self.assertIsNone(g.primary_shape(d,"BOUND_VALUE:expected_coordinate"))


class PopulationAggregation(unittest.TestCase):
    def test_pilot_is_excluded_from_confirmatory_numerator(self):
        pilot="p";confirm=[f"c{i}" for i in range(6)]
        protocol={"schema":g.PROTOCOL_SCHEMA,"population":{"pilot_case_id":pilot,"confirmatory_case_ids":confirm}}
        profiles=ShapeExtraction().profiles();rows=[];mrows=[];docs={}
        for cid in [pilot]+confirm:
            rr=ShapeExtraction().ledger_row();rr["case_id"]=cid;rows.append(rr);mrows.append({"case_id":cid,"semantic_slice_sha256":"x"});dd=ShapeExtraction().primary_doc();dd["case_id"]=cid;docs[cid]=dd
        ledger,summary=g.diagnose(protocol=protocol,profiles=profiles,ledger={"cases":rows},matrix={"cases":mrows},primary_docs=docs)
        self.assertEqual(len(ledger["observations"]),14)
        self.assertEqual(summary["taxonomy_counts_pilot"]["THREE_WAY_PROJECTION_SHAPE_MATCH"],2)
        self.assertEqual(summary["taxonomy_counts_confirmatory"]["THREE_WAY_PROJECTION_SHAPE_MATCH"],12)
        self.assertTrue(summary["confirmatory_success_condition_met"])
    def test_integrity_failure_is_counted_and_blocks_success(self):
        pilot="p";confirm=[f"c{i}" for i in range(6)];protocol={"schema":g.PROTOCOL_SCHEMA,"population":{"pilot_case_id":pilot,"confirmatory_case_ids":confirm}}
        profiles=ShapeExtraction().profiles();rows=[];mrows=[];docs={}
        for cid in [pilot]+confirm:
            rr=ShapeExtraction().ledger_row();rr["case_id"]=cid;rows.append(rr);mrows.append({"case_id":cid,"semantic_slice_sha256":"x"});dd=ShapeExtraction().primary_doc();dd["case_id"]=cid;docs[cid]=dd
        del docs[confirm[0]]
        _,summary=g.diagnose(protocol=protocol,profiles=profiles,ledger={"cases":rows},matrix={"cases":mrows},primary_docs=docs)
        self.assertEqual(summary["taxonomy_counts_confirmatory"]["TRACE_INPUT_INTEGRITY_FAILURE"],2)
        self.assertFalse(summary["confirmatory_success_condition_met"])

if __name__=="__main__":unittest.main()
