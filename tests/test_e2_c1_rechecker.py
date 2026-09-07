from __future__ import annotations

import ast
import copy
import platform
from pathlib import Path
import sys
import unittest

from risu_e2_c1 import rechecker as c1
from risu_e2_semantic.certificate import produce_certificate
from risu_e2_semantic.kernel import PRESERVATION, REGRESSION, sha256_json

GOOD = '''def apply_effect(x):\n    return x\n\ndef target(current, expected, desired, other):\n    payload = desired\n    if expected != current:\n        return "STALE_REJECTED_NO_EFFECT"\n    return apply_effect(payload)\n'''
WRONG = GOOD.replace("payload = desired", "payload = other")
LOOP = GOOD.replace("payload = desired", "payload = desired\n    while False:\n        payload = desired")


def nodes(source: str):
    tree=ast.parse(source)
    target=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=="target")
    iff=next(n for n in target.body if isinstance(n,ast.If))
    guard=next(n for n in ast.walk(iff.test) if isinstance(n,ast.Compare))
    rejection=next(n for n in iff.body if isinstance(n,ast.Return))
    success=next(n for n in target.body if isinstance(n,ast.Return) and n is not rejection)
    effect=next(n for n in ast.walk(success) if isinstance(n,ast.Call))
    sp=lambda n:[n.lineno,n.col_offset,n.end_lineno,n.end_col_offset]
    return tree,target,iff,guard,rejection,success,effect,sp


def signature():
    return {
        "schema":"synthetic.canonical-signature/v0.1",
        "source_roles":{"current":{"parameter_index":0},"expected":{"parameter_index":1},"desired":{"parameter_index":2},"other":{"parameter_index":3}},
        "guard":{"form":"DIRECT_CONTROL","effect_polarity":"false","rejection_polarity":"true"},
        "required_bindings":[
            {"binding_id":"guard_expected","kind":"guard_operand","operand_index":0,"coordinate_identity":"guard.expected","resource_identity":"target.resource","allowed_origins":["expected"]},
            {"binding_id":"guard_current","kind":"guard_operand","operand_index":1,"coordinate_identity":"guard.current","resource_identity":"target.resource","allowed_origins":["current"]},
            {"binding_id":"effect_payload","kind":"effect_call_argument","arg_index":0,"coordinate_identity":"effect.payload","resource_identity":"target.resource","allowed_origins":["desired"]},
        ],
        "effect":{"surface_id":"effect0","success_outcome_id":"WRITE_APPLIED","rejection_outcome_id":"STALE_REJECTED_NO_EFFECT"},
        "worlds":[
            {"id":"wA","role_values":{"current":1,"expected":1,"desired":"A","other":"X"},"kappa":{"effect":"A"}},
            {"id":"wB","role_values":{"current":1,"expected":1,"desired":"B","other":"X"},"kappa":{"effect":"B"}},
            {"id":"wR","role_values":{"current":1,"expected":2,"desired":"A","other":"X"},"kappa":{"reject":True}},
        ],
    }


def contract_for(source: str):
    _,target,iff,guard,rejection,success,effect,sp=nodes(source)
    return {"path":"case.py","target_function_span":sp(target),"effective_if_span":sp(iff),"anchors":{
        "guard":{"span":sp(guard),"syntax_kind":"COMPARE"},
        "effect":{"span":sp(effect),"syntax_kind":"CALL"},
        "success":{"span":sp(success),"syntax_kind":"RETURN"},
        "rejection":{"span":sp(rejection),"syntax_kind":"RETURN"},
    }}


def make_cert(source: str):
    sig=signature(); contract=contract_for(source); raw=source.encode()
    reconstructed,bad=c1._extract_direct(source=raw,tree=ast.parse(source),signature=sig,contract=contract,case_id="case-1")
    assert reconstructed is not None, bad
    protocols={"verdict_protocol":"8b69568fdb4c0ffe66a46562ba2673ea8d9f19ae","minimal_fragment":"abb06d4b71a66100b04b225d1d3c0d5ac22e887c","trust_boundary":"30a2330babc28a012acbd2eee5e0b7b020495755"}
    ids={"semantic_engine":"TEST_KERNEL","certificate_producer":"TEST_PRODUCER","source_evidence_checker":"TEST_C1_SOURCE","semantic_checker":"TEST_C1_SEMANTIC","minimal_semantic_fragment":"TEST_FRAGMENT"}
    cert=produce_certificate(case_id="case-1",semantic_slice=reconstructed,source_files={"case.py":raw},identities=ids,protocol_digests=protocols,canonical_signature_digest=sha256_json(sig),read_set_receipt={"closed":True,"read_paths":["case.py"],"forbidden_reads":[]})
    return sig,protocols,ids,cert

def runtime_id():
    return {"implementation":platform.python_implementation(),"python_major":sys.version_info.major,"python_minor":sys.version_info.minor,"python_micro":sys.version_info.micro,"parser":"python_stdlib_ast"}

def do_recheck(cert, source, sig, protocols, ids):
    return c1.recheck(certificate=cert,source_files={"case.py":source.encode()},canonical_signature=sig,expected_protocol_digests=protocols,expected_identities=ids,expected_runtime=runtime_id())


class C1Tests(unittest.TestCase):
    def test_good_raw_source_rederives_valid_c1_preservation(self):
        sig,protocols,ids,cert=make_cert(GOOD)
        out=do_recheck(cert,GOOD,sig,protocols,ids)
        self.assertEqual("VALID_C1",out["checker_output"])
        self.assertEqual(PRESERVATION,out["machine_prediction"])
        self.assertFalse(out["trusted_import_boundary"]["imports_primary_e2"])
        self.assertFalse(out["trusted_import_boundary"]["imports_producer_kernel"])

    def test_wrong_carrier_is_independently_rederived_as_regression(self):
        sig,protocols,ids,cert=make_cert(WRONG)
        out=do_recheck(cert,WRONG,sig,protocols,ids)
        self.assertEqual("VALID_C1",out["checker_output"])
        self.assertEqual(REGRESSION,out["machine_prediction"])
        self.assertIn("A3_R1_WRONG_BINDING_IDENTITY",out["c1_semantic_result"]["witness_ids"])

    def test_tampered_producer_verdict_fails_certificate_integrity(self):
        sig,protocols,ids,cert=make_cert(GOOD)
        bad=copy.deepcopy(cert); bad["producer_kernel_result"]["prediction"]=REGRESSION
        # even if attacker updates outer certificate digest, the separately bound producer-result digest catches it
        body=dict(bad); body.pop("certificate_digest_sha256",None); bad["certificate_digest_sha256"]=sha256_json(body)
        out=do_recheck(bad,GOOD,sig,protocols,ids)
        self.assertEqual("INVALID_CERTIFICATE",out["checker_output"])
        self.assertIn("PRODUCER_KERNEL_RESULT_DIGEST_MISMATCH",out["reasons"])

    def test_raw_source_substitution_fails_hash_binding(self):
        sig,protocols,ids,cert=make_cert(GOOD)
        out=do_recheck(cert,WRONG,sig,protocols,ids)
        self.assertEqual("INVALID_CERTIFICATE",out["checker_output"])
        self.assertTrue(any(x.startswith("SOURCE_HASH_MISMATCH") for x in out["reasons"]))

    def test_loop_is_fail_closed_unsupported_not_safe(self):
        sig=signature(); contract=contract_for(LOOP); raw=LOOP.encode()
        # Build a structurally valid untrusted proposal envelope from GOOD, then bind it to LOOP to test C1 admission.
        _,protocols,ids0,good_cert=make_cert(GOOD)
        proposal=copy.deepcopy(good_cert["semantic_slice"]); proposal["source_contract"]=contract; proposal["source_evidence"]=[]
        from risu_e2_semantic.certificate import produce_certificate
        ids={"semantic_engine":"x","certificate_producer":"x","source_evidence_checker":"x","semantic_checker":"x","minimal_semantic_fragment":"x"}
        cert=produce_certificate(case_id="case-1",semantic_slice=proposal,source_files={"case.py":raw},identities=ids,protocol_digests=protocols,canonical_signature_digest=sha256_json(sig),read_set_receipt={"closed":True,"read_paths":["case.py"],"forbidden_reads":[]})
        out=c1.recheck(certificate=cert,source_files={"case.py":raw},canonical_signature=sig,expected_protocol_digests=protocols,expected_identities=ids,expected_runtime=runtime_id())
        self.assertEqual("UNSUPPORTED_CERTIFICATE",out["checker_output"])
        self.assertEqual("E2_PREDICTED_ASSURANCE_INCOMPLETE",out["machine_prediction"])
        self.assertIn("While",out["reasons"])

    def test_helper_control_not_silently_claimed(self):
        sig,protocols,ids,cert=make_cert(GOOD)
        helper=copy.deepcopy(sig); helper["guard"]["form"]="HELPER_CONTROL"
        # Signature digest mismatch itself is invalid unless envelope is rebuilt; rebuild to isolate unsupported boundary.
        proposal=copy.deepcopy(cert["semantic_slice"]); proposal["canonical_signature_digest"]=sha256_json(helper)
        ids={"semantic_engine":"x","certificate_producer":"x","source_evidence_checker":"x","semantic_checker":"x","minimal_semantic_fragment":"x"}
        rebuilt=produce_certificate(case_id="case-1",semantic_slice=proposal,source_files={"case.py":GOOD.encode()},identities=ids,protocol_digests=protocols,canonical_signature_digest=sha256_json(helper),read_set_receipt={"closed":True,"read_paths":["case.py"],"forbidden_reads":[]})
        out=c1.recheck(certificate=rebuilt,source_files={"case.py":GOOD.encode()},canonical_signature=helper,expected_protocol_digests=protocols,expected_identities=ids,expected_runtime=runtime_id())
        self.assertEqual("UNSUPPORTED_CERTIFICATE",out["checker_output"])
        self.assertIn("C1_V0_1_HELPER_CONTROL_NOT_SUPPORTED",out["reasons"])


    def test_open_read_set_can_never_be_valid_c1(self):
        sig,protocols,ids,cert=make_cert(GOOD)
        bad=copy.deepcopy(cert); bad["closed_read_set_receipt"]["closed"]=False
        bad["closed_read_set_receipt_digest"]=sha256_json(bad["closed_read_set_receipt"])
        body=dict(bad); body.pop("certificate_digest_sha256",None); bad["certificate_digest_sha256"]=sha256_json(body)
        out=do_recheck(bad,GOOD,sig,protocols,ids)
        self.assertEqual("INVALID_CERTIFICATE",out["checker_output"])
        self.assertIn("READ_SET_NOT_CLOSED",out["reasons"])

    def test_implementation_identity_mismatch_can_never_be_valid_c1(self):
        sig,protocols,ids,cert=make_cert(GOOD)
        wrong_ids=dict(ids); wrong_ids["semantic_checker"]="DIFFERENT_CHECKER"
        out=c1.recheck(certificate=cert,source_files={"case.py":GOOD.encode()},canonical_signature=sig,expected_protocol_digests=protocols,expected_identities=wrong_ids,expected_runtime=runtime_id())
        self.assertEqual("INVALID_CERTIFICATE",out["checker_output"])
        self.assertIn("IMPLEMENTATION_IDENTITY_MISMATCH:semantic_checker",out["reasons"])

    def test_source_has_no_forbidden_import_dependency(self):
        root=Path(c1.__file__).parent
        forbidden=[]
        for path in sorted(root.glob("*.py")):
            tree=ast.parse(path.read_text())
            for node in ast.walk(tree):
                if isinstance(node,ast.Import):
                    for alias in node.names:
                        if alias.name=="risu_e2" or alias.name.startswith("risu_e2.") or alias.name=="risu_e2_semantic" or alias.name.startswith("risu_e2_semantic."):
                            forbidden.append((path.name,alias.name))
                elif isinstance(node,ast.ImportFrom) and node.module:
                    if node.module=="risu_e2" or node.module.startswith("risu_e2.") or node.module=="risu_e2_semantic" or node.module.startswith("risu_e2_semantic."):
                        forbidden.append((path.name,node.module))
        self.assertEqual([],forbidden)


if __name__ == "__main__": unittest.main()
