from __future__ import annotations

import ast
import hashlib
import json
import unittest
from pathlib import Path

from risu_e2_semantic import candidate58_harness as h
from risu_e2_semantic.kernel import INCOMPLETE, PRESERVATION, REGRESSION


def oid(i: int) -> str:
    return hashlib.sha256(f"case-{i:02d}".encode()).hexdigest()


def digest(i: int) -> str:
    return hashlib.sha256(f"blob-{i:02d}".encode()).hexdigest()


class Candidate58MechanicalHarnessTests(unittest.TestCase):
    def make_plan(self):
        rows=[]
        langs=("python","go","typescript_javascript")
        suffix={"python":"py","go":"go","typescript_javascript":"mjs"}
        for i in range(58):
            cid=oid(i); lang=langs[i%3]
            rows.append({
                "case_id":cid,"seed_id":"SYN-PY-01" if lang=="python" else ("SYN-GO-01" if lang=="go" else "SYN-TS-01"),"language":lang,
                "candidate_source_path":f"candidates/{cid}.{suffix[lang]}","candidate_source_sha256":digest(i),
                "overlay_path":f"evidence/{cid}.overlay.json","overlay_sha256":digest(100+i),
                "path_observability_path":f"evidence/{cid}.path.json","path_observability_sha256":digest(200+i),
            })
        rows.sort(key=lambda r:r["case_id"])
        return {"schema":h.PLAN_SCHEMA,"semantic_authority":False,"case_count":58,"cases":rows}

    def test_exact_58_plan_is_canonical_and_deterministic(self):
        plan=self.make_plan(); a=h.validate_plan(plan); b=h.validate_plan(json.loads(json.dumps(plan)))
        self.assertEqual(a,b); self.assertEqual(len(a),58); self.assertEqual([x["case_id"] for x in a],sorted(x["case_id"] for x in a))

    def test_plan_rejects_forbidden_semantic_metadata_recursively(self):
        plan=self.make_plan(); plan["nested"]={"operator_id":"forbidden"}
        with self.assertRaises(ValueError): h.validate_plan(plan)

    def test_plan_rejects_case_reselection_and_duplicates(self):
        plan=self.make_plan(); plan["cases"][-1]=dict(plan["cases"][0])
        with self.assertRaises(ValueError): h.validate_plan(plan)

    def test_valid_c1_is_required_for_definitive_promotion(self):
        self.assertEqual(h._promote(tentative=REGRESSION,c1_report={"checker_output":"VALID_C1","machine_prediction":REGRESSION})[0],REGRESSION)
        self.assertEqual(h._promote(tentative=PRESERVATION,c1_report={"checker_output":"VALID_C1","machine_prediction":PRESERVATION})[0],PRESERVATION)
        self.assertEqual(h._promote(tentative=REGRESSION,c1_report={"checker_output":"UNSUPPORTED_CERTIFICATE","machine_prediction":INCOMPLETE})[0],INCOMPLETE)
        self.assertEqual(h._promote(tentative=PRESERVATION,c1_report={"checker_output":"INVALID_CERTIFICATE","machine_prediction":INCOMPLETE})[0],INCOMPLETE)
        self.assertEqual(h._promote(tentative=REGRESSION,c1_report={"checker_output":"VALID_C1","machine_prediction":PRESERVATION})[0],INCOMPLETE)

    def test_case_receipt_is_closed_and_source_bound(self):
        src="candidates/"+oid(0)+".py"; policy=digest(900)
        receipt=h.make_case_read_receipt(policy_digest_sha256=policy,reads=[{"path":src,"sha256":digest(0),"purpose":"candidate_source","role":"candidate"}],source_path=src)
        self.assertTrue(receipt["closed"]); self.assertEqual(receipt["forbidden_reads"],[]); self.assertEqual(receipt["read_paths"],[src])
        with self.assertRaises(ValueError): h.make_case_read_receipt(policy_digest_sha256=policy,reads=[],source_path=src)

    def test_assemble_requires_exact_opaque_58(self):
        expected=sorted(oid(i) for i in range(58)); outputs=[]
        for cid in expected:
            outputs.append({"record":{"case_id":cid,"machine_prediction":INCOMPLETE},"certificate":{"x":cid},"c1_report":{"checker_output":"UNSUPPORTED_CERTIFICATE"}})
        result=h.assemble_outputs(outputs,expected_case_ids=expected)
        self.assertEqual(result["matrix"]["case_count"],58); self.assertTrue(result["matrix"]["machine_only"])
        with self.assertRaises(ValueError): h.assemble_outputs(outputs[:-1],expected_case_ids=expected)

    def test_mechanical_core_does_not_reimplement_semantic_witness_rules(self):
        text=Path("risu_e2_semantic/candidate58_harness.py").read_text(); tree=ast.parse(text)
        forbidden=("A3_R1_","A3_R2_","A3_R3_","A3_R4_","A4_R1_","A4_R2_","A4_R3_","A4_R4_","A4_R5_","A4_R6_","A4_R7_")
        self.assertFalse(any(token in text for token in forbidden))
        funcs={n.name for n in ast.walk(tree) if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))}
        self.assertFalse(any(name.startswith(("_a3_","_a4_","_admit_")) for name in funcs))

    def test_v2_upstream_incomplete_does_not_call_primary_adapter_or_c1(self):
        text=Path("tools/e2_candidate58_execution_harness_v2.py").read_text(); tree=ast.parse(text)
        fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=="upstream_incomplete")
        calls=[]
        for node in ast.walk(fn):
            if isinstance(node,ast.Call):
                if isinstance(node.func,ast.Name): calls.append(node.func.id)
                elif isinstance(node.func,ast.Attribute): calls.append(node.func.attr)
        self.assertNotIn("execute_prepared_case",calls); self.assertNotIn("recheck",calls); self.assertNotIn("adapt_primary",calls)


if __name__=="__main__": unittest.main()
