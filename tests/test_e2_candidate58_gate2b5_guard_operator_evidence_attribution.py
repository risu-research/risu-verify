import importlib.util
from pathlib import Path
import unittest

P=Path(__file__).resolve().parents[1]/"tools"/"e2_candidate58_gate2b5_guard_operator_evidence_attribution.py"
s=importlib.util.spec_from_file_location("g2b5",P);g=importlib.util.module_from_spec(s);assert s and s.loader;s.loader.exec_module(g)

def overlay(operator_lists, *, anchor_count=1, include_edges=True, operand_indexes=None):
    nodes=[]
    for i in range(anchor_count):nodes.append({"id":f"guard{i}","attrs":{"anchor_role":"GUARD_COMPARISON"}})
    edges=[]
    if include_edges and anchor_count:
        for i,ops in enumerate(operator_lists):
            attrs={"operand_index":(operand_indexes or list(range(len(operator_lists))))[i],"operators":ops}
            edges.append({"id":f"e{i}","kind":"COMPARES","source":f"v{i}","target":"guard0","attrs":attrs})
    return {"schema":g.OVERLAY_SCHEMA,"nodes":nodes,"edges":edges}

class Gate2B5Tests(unittest.TestCase):
    def test_no_linkage(self):
        self.assertEqual(g.classify_overlay(overlay([],include_edges=False))["taxonomy"],"ANCHOR_COMPARE_LINKAGE_UNRESOLVED")
    def test_empty_all_edges(self):
        r=g.classify_overlay(overlay([[],[]]));self.assertEqual(r["taxonomy"],"OPERATOR_CARRIER_EMPTY_ALL_EDGES");self.assertIsNone(r["reconstructed_operator"])
    def test_partial_nonunique(self):
        self.assertEqual(g.classify_overlay(overlay([["Eq"],["Eq","NotEq"]]))["taxonomy"],"OPERATOR_CARRIER_PARTIAL_OR_NONUNIQUE")
    def test_unsupported_token(self):
        self.assertEqual(g.classify_overlay(overlay([["LT"],["LT"]]))["taxonomy"],"OPERATOR_TOKEN_NORMALIZATION_UNSUPPORTED")
    def test_normalized_conflict(self):
        self.assertEqual(g.classify_overlay(overlay([["Eq"],["NotEq"]]))["taxonomy"],"OPERATOR_NORMALIZED_CONFLICT")
    def test_supported_aliases_resolve_consistently(self):
        r=g.classify_overlay(overlay([["Eq"],["=="]]));self.assertEqual(r["taxonomy"],"FROZEN_CHAIN_INCONSISTENT");self.assertEqual(r["reconstructed_operator"],"EQ")
    def test_ne_aliases_resolve_consistently(self):
        r=g.classify_overlay(overlay([["NE"],["!=="]]));self.assertEqual(r["reconstructed_operator"],"NE")
    def test_duplicate_anchor_is_trace_incomplete(self):
        self.assertEqual(g.classify_overlay(overlay([[]],anchor_count=2))["taxonomy"],"TRACE_EVIDENCE_INCOMPLETE")
    def test_missing_anchor_is_trace_incomplete(self):
        self.assertEqual(g.classify_overlay(overlay([],anchor_count=0))["taxonomy"],"TRACE_EVIDENCE_INCOMPLETE")
    def test_malformed_operators_field_is_trace_incomplete(self):
        ov=overlay([[]]);ov["edges"][0]["attrs"]["operators"]="Eq";self.assertEqual(g.classify_overlay(ov)["taxonomy"],"TRACE_EVIDENCE_INCOMPLETE")

if __name__=="__main__":unittest.main()
