from __future__ import annotations

import ast
import importlib.util
import tempfile
import unittest
from pathlib import Path

P=Path(__file__).resolve().parents[1]/"tools"/"e2_gate2c3_python_c1_world_eval_provenance.py"
spec=importlib.util.spec_from_file_location("gate2c3",P);g=importlib.util.module_from_spec(spec);assert spec and spec.loader;spec.loader.exec_module(g)


def fixture(source_text:str, *, world_keys=None):
    raw=source_text.encode();tree=ast.parse(source_text);fn=next(n for n in ast.walk(tree) if isinstance(n,ast.FunctionDef));iff=next(n for n in ast.walk(fn) if isinstance(n,ast.If));guard=iff.test
    signature={
        "source_roles":{
            "BOUND_VALUE:expected_coordinate":{"parameter_index":0,"scope_role":"GUARD_ANCHOR_SCOPE"},
            "BOUND_VALUE:current_coordinate":{"parameter_index":1,"scope_role":"GUARD_ANCHOR_SCOPE"},
        },
        "worlds":[{"id":"SYN-PY-01:effect","role_values":{k:i for i,k in enumerate(world_keys or ["BOUND_VALUE:expected_coordinate","BOUND_VALUE:current_coordinate"])}}],
    }
    adapter={"execution_signature":signature}
    ss={"source_contract":{"target_function_span":list(g.span(fn)),"effective_if_span":list(g.span(iff)),"anchors":{"guard":{"span":list(g.span(guard))}}}}
    c1={"schema":g.C1_SCHEMA,"reasons":["WORLD_GUARD_EVAL_UNRESOLVED:SYN-PY-01:effect"]}
    row={"candidate_source_sha256":g.sha(raw),"language":"python","tentative_kernel_prediction":"E2_PREDICTED_PRESERVATION_EVIDENCE","c1_report_sha256":g.sha(g.cb(c1)),"adapter_receipt_sha256":g.sha(g.cb(adapter)),"semantic_slice_sha256":g.sha(g.cb(ss))}
    return raw,adapter,ss,c1,row


class PrimitiveTaxonomy(unittest.TestCase):
    def tax(self,l,r,keys):return g.classify_world_primitives(l,r,set(keys))[0]
    def test_left_unresolved(self):self.assertEqual(self.tax(None,{"r"},{"r"}),"LEFT_ORIGIN_UNRESOLVED")
    def test_left_nonunique(self):self.assertEqual(self.tax({"a","b"},{"r"},{"a","b","r"}),"LEFT_ORIGIN_NONUNIQUE")
    def test_right_unresolved(self):self.assertEqual(self.tax({"l"},None,{"l"}),"RIGHT_ORIGIN_UNRESOLVED")
    def test_right_nonunique(self):self.assertEqual(self.tax({"l"},{"a","b"},{"l","a","b"}),"RIGHT_ORIGIN_NONUNIQUE")
    def test_missing_both(self):self.assertEqual(self.tax({"l"},{"r"},set()),"WORLD_ROLE_VALUE_MISSING_BOTH")
    def test_missing_left(self):self.assertEqual(self.tax({"l"},{"r"},{"r"}),"WORLD_ROLE_VALUE_MISSING_LEFT")
    def test_missing_right(self):self.assertEqual(self.tax({"l"},{"r"},{"l"}),"WORLD_ROLE_VALUE_MISSING_RIGHT")
    def test_all_present_is_inconsistency(self):self.assertEqual(self.tax({"l"},{"r"},{"l","r"}),"FROZEN_REASON_INCONSISTENT")


class EndToEndDiagnostic(unittest.TestCase):
    GOOD="def f(a,b):\n    x=a\n    if x != b:\n        return 1\n    else:\n        return 0\n"
    def run_case(self,source=None,**kw):
        raw,adapter,ss,c1,row=fixture(source or self.GOOD,**kw)
        return g.diagnose_case(case_id="c",source=raw,expected_source_sha256=g.sha(raw),adapter=adapter,semantic_slice=ss,c1=c1,matrix_row=row)
    def test_assignment_alias_preserves_origin_and_all_present_is_inconsistency(self):
        r=self.run_case();self.assertEqual(r["taxonomy"],"FROZEN_REASON_INCONSISTENT");self.assertEqual(r["primitive"]["left_origin"],"BOUND_VALUE:expected_coordinate");self.assertEqual(r["primitive"]["right_origin"],"BOUND_VALUE:current_coordinate")
    def test_world_missing_right(self):
        r=self.run_case(world_keys=["BOUND_VALUE:expected_coordinate"]);self.assertEqual(r["taxonomy"],"WORLD_ROLE_VALUE_MISSING_RIGHT")
    def test_chained_compare_is_shape_failure(self):
        src="def f(a,b,c):\n    if a != b != c:\n        return 1\n    else:\n        return 0\n";r=self.run_case(source=src);self.assertEqual(r["taxonomy"],"COMPARE_SHAPE_UNRESOLVED")
    def test_source_hash_mismatch_is_integrity_failure(self):
        raw,adapter,ss,c1,row=fixture(self.GOOD);r=g.diagnose_case(case_id="c",source=raw+b"#x",expected_source_sha256=g.sha(raw),adapter=adapter,semantic_slice=ss,c1=c1,matrix_row=row);self.assertEqual(r["taxonomy"],"TRACE_INPUT_INTEGRITY_FAILURE")
    def test_wrong_frozen_reason_is_integrity_failure(self):
        raw,adapter,ss,c1,row=fixture(self.GOOD);c1={"schema":g.C1_SCHEMA,"reasons":["OTHER"]};row["c1_report_sha256"]=g.sha(g.cb(c1));r=g.diagnose_case(case_id="c",source=raw,expected_source_sha256=g.sha(raw),adapter=adapter,semantic_slice=ss,c1=c1,matrix_row=row);self.assertEqual(r["taxonomy"],"TRACE_INPUT_INTEGRITY_FAILURE")


class LocatorFirewall(unittest.TestCase):
    def test_exact_58_hashes_only_7_retained(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)/"cells";out=Path(td)/"out";root.mkdir();cases=[];selected=set()
            for i in range(58):
                q=root/f"Q{i+1:03d}";q.mkdir();raw=f"# synthetic {i}\n".encode();p=q/"SYN-PY-01.py";p.write_bytes(raw);cid=f"c{i:02d}";cases.append({"transport_case_id":cid,"seed_id":"SYN-PY-01","language":"python","candidate_source_sha256":g.sha(raw)});
                if i<7:selected.add(cid)
            rec=g.locate_selected_sources(cells_dir=root,manifest={"cases":cases},selected=selected,output_dir=out)
            self.assertEqual(rec["source_files_stream_hashed"],58);self.assertEqual(rec["selected_source_count"],7);self.assertEqual(rec["source_files_semantically_parsed"],0);self.assertFalse(rec["nonselected_source_bytes_retained"]);self.assertEqual(len(list(out.glob("*.py"))),7)
    def test_nonunique_selected_hash_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)/"cells";out=Path(td)/"out";root.mkdir();raw=b"same\n"
            for i in range(58):
                q=root/f"Q{i+1:03d}";q.mkdir();(q/"SYN-PY-01.py").write_bytes(raw if i<2 else f"x{i}\n".encode())
            manifest={"cases":[{"transport_case_id":"c","seed_id":"SYN-PY-01","language":"python","candidate_source_sha256":g.sha(raw)}]}
            with self.assertRaises(ValueError):g.locate_selected_sources(cells_dir=root,manifest=manifest,selected={"c"},output_dir=out)

if __name__=="__main__":unittest.main()
