from __future__ import annotations

import ast
import hashlib
import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


B = load_module("gate2c5_builder", "tools/e2_gate2c5_build_canonical_projection_identity.py")
C = load_module("gate2c5_checker", "tools/e2_gate2c5_check_canonical_projection_identity.py")


def h(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def coords(n: ast.AST) -> list[int]:
    return [n.lineno, n.col_offset, n.end_lineno, n.end_col_offset]


def raw_slice(raw: bytes, s: list[int]) -> bytes:
    sl, sc, el, ec = s; lines = raw.splitlines(keepends=True)
    if sl == el:
        return lines[sl - 1][sc:ec]
    return b"".join([lines[sl - 1][sc:]] + lines[sl:el - 1] + [lines[el - 1][:ec]])


def fixture(source_text: str, *, expected_param: int = 1, current_param: int = 0, expected_operand: int = 0, current_operand: int = 1, expected_shape=None, current_shape=None):
    raw = source_text.encode(); tree = ast.parse(source_text); comps = [n for n in ast.walk(tree) if isinstance(n, ast.Compare)]; assert len(comps) == 1
    g = comps[0]; gs = coords(g); graw = raw_slice(raw, gs); sha = h(raw); contract_digest = "c" * 64; blob = "b" * 40
    protocol = {"schema": "risu.e2-gate2c5-canonical-opaque-projection-identity-protocol/v0.1"}
    resolution = {"schema": "risu.e2-gate2c5-canonical-guard-anchor-resolution/v0.1", "selected_contract": {"seed_id": "SYN-PY-01", "contract_id": "SYN", "contract_canonical_sha256": contract_digest, "source": {"path": "seed.py", "git_blob": blob, "sha256": sha, "language": "python"}, "guard": {"span": gs, "slice_bytes": len(graw), "slice_sha256": h(graw), "syntax_kind": "comparison_expression", "unique_in_source": True}, "binding_slots": {"expected_coordinate": {"anchor": "guard_comparison", "operand_index": expected_operand}, "current_coordinate": {"anchor": "guard_comparison", "operand_index": current_operand}}}}
    anchor = {"contracts": [{"seed_id": "SYN-PY-01", "contract_canonical_sha256": contract_digest, "declaration": {"seed_id": "SYN-PY-01", "contract_id": "SYN", "source": {"path": "seed.py", "git_blob_sha": blob, "sha256": sha, "language": "python"}, "anchors": {"guard_comparison": {"span": gs, "slice_bytes": len(graw), "slice_sha256": h(graw), "syntax_kind": "comparison_expression", "unique_in_source": True}}, "binding_slots": {"expected_coordinate": {"anchor": "guard_comparison", "operand_index": expected_operand}, "current_coordinate": {"anchor": "guard_comparison", "operand_index": current_operand}}}}]}
    catalog = {"seeds": [{"seed_id": "SYN-PY-01", "program_sha256": sha, "program_git_blob": blob, "program_path": "seed.py"}]}
    signatures = {"signatures": [{"seed_id": "SYN-PY-01", "anchor_contract_sha256": contract_digest, "required_binding_slot_roles": {"expected_coordinate": {"anchor": "guard_comparison", "cardinality": 1, "operand_index": expected_operand}, "current_coordinate": {"anchor": "guard_comparison", "cardinality": 1, "operand_index": current_operand}}}]}
    profiles = {"profiles": [{"seed_id": "SYN-PY-01", "source_roles": {"BOUND_VALUE:expected_coordinate": {"status": "RESOLVED", "parameter_index": expected_param, "scope_role": "GUARD_ANCHOR_SCOPE", "lineage_edge_shapes": [expected_shape if expected_shape is not None else ["DERIVES"]]}, "BOUND_VALUE:current_coordinate": {"status": "RESOLVED", "parameter_index": current_param, "scope_role": "GUARD_ANCHOR_SCOPE", "lineage_edge_shapes": [current_shape if current_shape is not None else []]}}}]}
    return protocol, resolution, anchor, catalog, signatures, profiles, raw


def derive(fx):
    p, r, a, c, s, prof, raw = fx
    return B.derive_authority(protocol=p, resolution=r, anchor_bundle=a, seed_catalog=c, signatures=s, profiles=prof, source=raw)


class FullAgreement(unittest.TestCase):
    def test_builder_checker_agree(self):
        fx = fixture('def f(cur, req):\n    if req["guard"] != cur:\n        return 0\n    return 1\n'); auth = derive(fx)
        result = C.check_authority(authority=auth, resolution=fx[1], anchor_bundle=fx[2], seed_catalog=fx[3], signatures=fx[4], profiles=fx[5], source=fx[6])
        self.assertEqual(result["status"], "PASS"); self.assertEqual(set(result["rederived_fingerprints"]), set(B.ROLES))

    def test_straight_line_alias_name_is_not_identity(self):
        s1 = 'def f(cur, req):\n    a = req\n    if a["guard"] != cur:\n        return 0\n    return 1\n'
        s2 = 'def f(cur, req):\n    renamed = req\n    if renamed["guard"] != cur:\n        return 0\n    return 1\n'
        a1, a2 = derive(fixture(s1)), derive(fixture(s2)); f1 = {x["root_role"]: x["fingerprint_sha256"] for x in a1["roles"]}; f2 = {x["root_role"]: x["fingerprint_sha256"] for x in a2["roles"]}
        self.assertEqual(f1, f2)


class FingerprintSeparation(unittest.TestCase):
    def fp(self, src):
        auth = derive(fixture(src)); return {x["root_role"]: x["fingerprint_sha256"] for x in auth["roles"]}

    def test_same_root_same_depth_different_subscript_literal_mismatches(self):
        a = self.fp('def f(cur, req):\n    if req["guard"] != cur:\n        return 0\n    return 1\n'); b = self.fp('def f(cur, req):\n    if req["other"] != cur:\n        return 0\n    return 1\n')
        self.assertNotEqual(a["BOUND_VALUE:expected_coordinate"], b["BOUND_VALUE:expected_coordinate"])

    def test_same_root_same_depth_different_attribute_mismatches(self):
        a = self.fp('def f(cur, req):\n    if req.guard != cur:\n        return 0\n    return 1\n'); b = self.fp('def f(cur, req):\n    if req.other != cur:\n        return 0\n    return 1\n')
        self.assertNotEqual(a["BOUND_VALUE:expected_coordinate"], b["BOUND_VALUE:expected_coordinate"])

    def test_extra_projection_mismatches(self):
        base = derive(fixture('def f(cur, req):\n    if req.guard != cur:\n        return 0\n    return 1\n')); extra = derive(fixture('def f(cur, req):\n    if req.guard.inner != cur:\n        return 0\n    return 1\n', expected_shape=["DERIVES", "DERIVES"]))
        b = {x["root_role"]: x["fingerprint_sha256"] for x in base["roles"]}; e = {x["root_role"]: x["fingerprint_sha256"] for x in extra["roles"]}; self.assertNotEqual(b["BOUND_VALUE:expected_coordinate"], e["BOUND_VALUE:expected_coordinate"])


class FailClosed(unittest.TestCase):
    def test_wrong_root_same_projection(self):
        with self.assertRaisesRegex(ValueError, "ROOT_ROLE_MISMATCH"):
            derive(fixture('def f(cur, req, other):\n    if other["guard"] != cur:\n        return 0\n    return 1\n', expected_param=1))

    def test_wrong_required_operand_index(self):
        fx = fixture('def f(cur, req):\n    if req["guard"] != cur:\n        return 0\n    return 1\n'); fx[4]["signatures"][0]["required_binding_slot_roles"]["expected_coordinate"]["operand_index"] = 1
        with self.assertRaisesRegex(ValueError, "TERMINAL_OPERAND_INDEX_MISMATCH"):
            derive(fx)

    def test_ambiguous_alias_assignment(self):
        with self.assertRaisesRegex(ValueError, "AMBIGUOUS_ALIAS_OR_ASSIGNMENT"):
            derive(fixture('def f(cur, req):\n    alias = req = cur\n    if alias["guard"] != cur:\n        return 0\n    return 1\n'))

    def test_dynamic_subscript(self):
        with self.assertRaisesRegex(ValueError, "UNSUPPORTED_DYNAMIC_SUBSCRIPT"):
            derive(fixture('def f(cur, req, key):\n    if req[key] != cur:\n        return 0\n    return 1\n'))

    def test_profile_shape_mismatch(self):
        with self.assertRaisesRegex(ValueError, "CANONICAL_PROFILE_SHAPE_MISMATCH"):
            derive(fixture('def f(cur, req):\n    if req["guard"] != cur:\n        return 0\n    return 1\n', expected_shape=[]))

    def test_wrong_frozen_span_no_fallback(self):
        fx = fixture('def f(cur, req):\n    if req["guard"] != cur:\n        return 0\n    return 1\n'); fx[1]["selected_contract"]["guard"]["span"] = [1, 0, 1, 1]
        with self.assertRaises(ValueError):
            derive(fx)


if __name__ == "__main__":
    unittest.main()
