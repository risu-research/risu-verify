from __future__ import annotations

import ast
import copy
import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


T = load_module("gate2c6_tracer", "tools/e2_gate2c6_candidate_projection_match.py")
C = load_module("gate2c6_checker", "tools/e2_gate2c6_check_candidate_projection_match.py")


def span(node: ast.AST) -> list[int]:
    return [node.lineno, node.col_offset, node.end_lineno, node.end_col_offset]


def h(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def source_contract(raw: bytes, *, corrupt_guard_span: bool = False):
    tree = ast.parse(raw.decode())
    fn = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef))
    guard = next(n for n in ast.walk(tree) if isinstance(n, ast.Compare))
    target_if = next(n for n in ast.walk(tree) if isinstance(n, ast.If))
    gs = span(guard)
    if corrupt_guard_span:
        gs = [gs[0], gs[1] + 1, gs[2], gs[3]]
    return {"target_function_span": span(fn), "anchors": {"guard": {"span": gs}}, "effective_if_span": span(target_if)}


def signature(*, expected_root: int = 1, current_root: int = 0, expected_operand: int = 0, current_operand: int = 1):
    return {
        "source_roles": {
            "BOUND_VALUE:expected_coordinate": {"parameter_index": expected_root, "scope_role": "GUARD_ANCHOR_SCOPE"},
            "BOUND_VALUE:current_coordinate": {"parameter_index": current_root, "scope_role": "GUARD_ANCHOR_SCOPE"},
        },
        "required_bindings": [
            {"kind": "guard_operand", "binding_id": "GUARD_SLOT:expected_coordinate", "operand_index": expected_operand, "allowed_origins": ["BOUND_VALUE:expected_coordinate"]},
            {"kind": "guard_operand", "binding_id": "GUARD_SLOT:current_coordinate", "operand_index": current_operand, "allowed_origins": ["BOUND_VALUE:current_coordinate"]},
        ],
    }


def token_digest(kind: str, token):
    if kind == "ATTRIBUTE":
        return h(str(token).encode())
    if kind == "SUBSCRIPT_LITERAL":
        return h(T.canonical_bytes(token))
    raise AssertionError(kind)


def canonical_authority(*, expected_kind: str = "SUBSCRIPT_LITERAL", expected_token="guard"):
    expected_steps = [{"kind": expected_kind, "token_digest_sha256": token_digest(expected_kind, expected_token)}]
    rows = []
    for role, operand, steps, shape in (
        ("BOUND_VALUE:expected_coordinate", 0, expected_steps, ["DERIVES"]),
        ("BOUND_VALUE:current_coordinate", 1, [], []),
    ):
        payload = {"root_role": role, "terminal_guard_operand_index": operand, "steps": steps}
        rows.append({**payload, "root_parameter_index": 1 if role.endswith("expected_coordinate") else 0, "shape": shape, "fingerprint_sha256": T.digest_json(payload)})
    out = {"schema": T.CANONICAL_SCHEMA, "seed_id": "SYN-PY-01", "role_count": 2, "roles": rows, "authority": {"source_sha256": "s" * 64}, "raw_source_bytes_emitted": False, "raw_projection_tokens_emitted": False, "identifier_spelling_interpreted_as_semantic_role": False, "semantic_scope": "synthetic"}
    body = dict(out)
    out["authority_digest_sha256"] = T.digest_json(body)
    return out


def protocol_for(source_hashes, canonical, *, ids=None):
    if ids is None:
        ids = [f"{i:064x}" for i in range(1, 8)]
    by = {r["root_role"]: r for r in canonical["roles"]}
    return {
        "schema": T.PROTOCOL_SCHEMA,
        "population": {"case_count": 7, "case_ids": ids, "role_observation_count": 14, "roles": list(T.ROLES), "source_sha256_by_case": dict(source_hashes)},
        "canonical_match_authority": {"authority_digest_sha256": canonical["authority_digest_sha256"], "expected_fingerprint_sha256": by[T.ROLES[0]]["fingerprint_sha256"], "current_fingerprint_sha256": by[T.ROLES[1]]["fingerprint_sha256"]},
        "candidate_role_authority": {"terminal_operand_indices": {T.ROLES[0]: 0, T.ROLES[1]: 1}, "shape_precondition": {"required_expected_shape": ["DERIVES"], "required_current_shape": []}},
    }


def single_fixture(source_text: str, *, canonical=None, sig=None, corrupt_guard_span=False):
    raw = source_text.encode()
    cid = "1" * 64
    canonical = canonical or canonical_authority()
    p = protocol_for({cid: h(raw)}, canonical, ids=[cid] + [f"{i:064x}" for i in range(2, 8)])
    adapter = {"execution_signature": sig or signature()}
    semantic = {"source_contract": source_contract(raw, corrupt_guard_span=corrupt_guard_span)}
    return cid, raw, adapter, semantic, canonical, p


def tax(rows, role=T.ROLES[0]):
    return next(r["taxonomy"] for r in rows if r["role"] == role)


class SyntheticTaxonomy(unittest.TestCase):
    def test_exact_match(self):
        fx = single_fixture('def f(cur, req):\n    if req["guard"] != cur:\n        return 0\n    return 1\n')
        rows = T.diagnose_case(case_id=fx[0], source=fx[1], adapter=fx[2], semantic_slice=fx[3], canonical=fx[4], protocol=fx[5])
        self.assertEqual([r["taxonomy"] for r in rows], ["CANONICAL_OPAQUE_PROJECTION_MATCH"] * 2)

    def test_same_depth_different_subscript_token(self):
        fx = single_fixture('def f(cur, req):\n    if req["other"] != cur:\n        return 0\n    return 1\n')
        rows = T.diagnose_case(case_id=fx[0], source=fx[1], adapter=fx[2], semantic_slice=fx[3], canonical=fx[4], protocol=fx[5])
        self.assertEqual(tax(rows), "PROJECTION_TOKEN_DIGEST_MISMATCH")

    def test_same_depth_different_attribute_token(self):
        can = canonical_authority(expected_kind="ATTRIBUTE", expected_token="guard")
        fx = single_fixture('def f(cur, req):\n    if req.other != cur:\n        return 0\n    return 1\n', canonical=can)
        rows = T.diagnose_case(case_id=fx[0], source=fx[1], adapter=fx[2], semantic_slice=fx[3], canonical=fx[4], protocol=fx[5])
        self.assertEqual(tax(rows), "PROJECTION_TOKEN_DIGEST_MISMATCH")

    def test_attribute_vs_subscript_kind(self):
        fx = single_fixture('def f(cur, req):\n    if req.guard != cur:\n        return 0\n    return 1\n')
        rows = T.diagnose_case(case_id=fx[0], source=fx[1], adapter=fx[2], semantic_slice=fx[3], canonical=fx[4], protocol=fx[5])
        self.assertEqual(tax(rows), "PROJECTION_STEP_KIND_MISMATCH")

    def test_extra_projection_shape(self):
        fx = single_fixture('def f(cur, req):\n    if req["guard"].inner != cur:\n        return 0\n    return 1\n')
        rows = T.diagnose_case(case_id=fx[0], source=fx[1], adapter=fx[2], semantic_slice=fx[3], canonical=fx[4], protocol=fx[5])
        self.assertEqual(tax(rows), "PROJECTION_SHAPE_MISMATCH")

    def test_wrong_root_parameter(self):
        fx = single_fixture('def f(cur, req, other):\n    if other["guard"] != cur:\n        return 0\n    return 1\n')
        rows = T.diagnose_case(case_id=fx[0], source=fx[1], adapter=fx[2], semantic_slice=fx[3], canonical=fx[4], protocol=fx[5])
        self.assertEqual(tax(rows), "ROOT_PARAMETER_ORIGIN_MISMATCH")

    def test_wrong_terminal_operand(self):
        fx = single_fixture('def f(cur, req):\n    if req["guard"] != cur:\n        return 0\n    return 1\n', sig=signature(expected_operand=1))
        rows = T.diagnose_case(case_id=fx[0], source=fx[1], adapter=fx[2], semantic_slice=fx[3], canonical=fx[4], protocol=fx[5])
        self.assertEqual(tax(rows), "TERMINAL_OPERAND_INDEX_MISMATCH")

    def test_alias_rename_invariant(self):
        s1 = 'def f(cur, req):\n    alias = req\n    if alias["guard"] != cur:\n        return 0\n    return 1\n'
        s2 = 'def f(cur, req):\n    renamed = req\n    if renamed["guard"] != cur:\n        return 0\n    return 1\n'
        fps = []
        for src in (s1, s2):
            fx = single_fixture(src)
            rows = T.diagnose_case(case_id=fx[0], source=fx[1], adapter=fx[2], semantic_slice=fx[3], canonical=fx[4], protocol=fx[5])
            self.assertEqual(tax(rows), "CANONICAL_OPAQUE_PROJECTION_MATCH")
            fps.append(next(r["candidate_fingerprint_sha256"] for r in rows if r["role"] == T.ROLES[0]))
        self.assertEqual(fps[0], fps[1])

    def test_alias_redefinition_fails_closed(self):
        fx = single_fixture('def f(cur, req):\n    alias = req\n    alias = req\n    if alias["guard"] != cur:\n        return 0\n    return 1\n')
        rows = T.diagnose_case(case_id=fx[0], source=fx[1], adapter=fx[2], semantic_slice=fx[3], canonical=fx[4], protocol=fx[5])
        self.assertTrue(all(r["taxonomy"] == "GUARD_OR_SCOPE_RESOLUTION_FAILURE" for r in rows))

    def test_dynamic_subscript_fails_closed(self):
        fx = single_fixture('def f(cur, req, key):\n    if req[key] != cur:\n        return 0\n    return 1\n')
        rows = T.diagnose_case(case_id=fx[0], source=fx[1], adapter=fx[2], semantic_slice=fx[3], canonical=fx[4], protocol=fx[5])
        self.assertEqual(tax(rows), "PROJECTION_TOKEN_DIGEST_MISMATCH")

    def test_wrong_guard_span_fails_closed(self):
        fx = single_fixture('def f(cur, req):\n    if req["guard"] != cur:\n        return 0\n    return 1\n', corrupt_guard_span=True)
        rows = T.diagnose_case(case_id=fx[0], source=fx[1], adapter=fx[2], semantic_slice=fx[3], canonical=fx[4], protocol=fx[5])
        self.assertTrue(all(r["taxonomy"] == "GUARD_OR_SCOPE_RESOLUTION_FAILURE" for r in rows))

    def test_canonical_digest_corruption_fails_integrity(self):
        fx = list(single_fixture('def f(cur, req):\n    if req["guard"] != cur:\n        return 0\n    return 1\n'))
        fx[4] = copy.deepcopy(fx[4]); fx[4]["authority_digest_sha256"] = "0" * 64
        rows = T.diagnose_case(case_id=fx[0], source=fx[1], adapter=fx[2], semantic_slice=fx[3], canonical=fx[4], protocol=fx[5])
        self.assertTrue(all(r["taxonomy"] == "TRACE_INPUT_INTEGRITY_FAILURE" for r in rows))

    def test_population_not_exact_seven(self):
        can = canonical_authority(); p = protocol_for({}, can, ids=["a", "b"]); p["population"]["case_count"] = 2; p["population"]["role_observation_count"] = 4
        with self.assertRaisesRegex(ValueError, "POPULATION_NOT_EXACT_SEVEN"):
            T.validate_population(p)


class EndToEndIndependentChecker(unittest.TestCase):
    def test_seven_case_tracer_checker_agreement(self):
        source = b'def f(cur, req):\n    if req["guard"] != cur:\n        return 0\n    return 1\n'
        can = canonical_authority(); ids = [f"{i:064x}" for i in range(1, 8)]; p = protocol_for({cid: h(source) for cid in ids}, can, ids=ids)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); src = root / "sources"; cases = root / "cases"; src.mkdir(); cases.mkdir()
            contract = source_contract(source)
            for cid in ids:
                (src / f"{cid}.py").write_bytes(source); d = cases / cid; d.mkdir()
                (d / "adapter_receipt.json").write_text(json.dumps({"execution_signature": signature()}))
                (d / "semantic_slice.json").write_text(json.dumps({"source_contract": contract}))
            ledger, summary = T.run_real(protocol=p, canonical=can, sources_dir=src, cases_dir=cases)
            self.assertEqual(summary["canonical_match_count"], 14)
            checked = C.check(protocol=p, canonical=can, tracer_ledger=ledger, sources_dir=src, cases_dir=cases)
            self.assertEqual(checked["status"], "PASS")
            self.assertTrue(checked["all_taxonomy_agree"] and checked["all_fingerprints_agree"])

    def test_checker_rejects_tracer_fingerprint_tamper(self):
        source = b'def f(cur, req):\n    if req["guard"] != cur:\n        return 0\n    return 1\n'
        can = canonical_authority(); ids = [f"{i:064x}" for i in range(1, 8)]; p = protocol_for({cid: h(source) for cid in ids}, can, ids=ids)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); src = root / "sources"; cases = root / "cases"; src.mkdir(); cases.mkdir(); contract = source_contract(source)
            for cid in ids:
                (src / f"{cid}.py").write_bytes(source); d = cases / cid; d.mkdir()
                (d / "adapter_receipt.json").write_text(json.dumps({"execution_signature": signature()})); (d / "semantic_slice.json").write_text(json.dumps({"source_contract": contract}))
            ledger, _ = T.run_real(protocol=p, canonical=can, sources_dir=src, cases_dir=cases)
            ledger = copy.deepcopy(ledger); ledger["observations"][0]["candidate_fingerprint_sha256"] = "f" * 64
            checked = C.check(protocol=p, canonical=can, tracer_ledger=ledger, sources_dir=src, cases_dir=cases)
            self.assertEqual(checked["status"], "FAIL_CLOSED")
            self.assertTrue(any("FINGERPRINT_DISAGREEMENT" in x for x in checked["reasons"]))


if __name__ == "__main__":
    unittest.main()
