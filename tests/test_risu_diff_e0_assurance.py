from __future__ import annotations

import copy
import random
import unittest

from risu_e0.adapters import evaluate_calibration, graph_from_vbe_instance
from risu_e0.engine import (
    PRED_INCOMPLETE,
    PRED_REGRESSION,
    evaluate_vbe,
    find_collapse_witness,
    find_relational_witness,
)
from risu_e0.graph import ConsequenceGraph, GraphInvariantError
from tests.e0_support import load, run_checker


class AdversarialAssuranceQualification(unittest.TestCase):
    def setUp(self):
        self.instance = load("002-azure-wiki-etag.instance.json")
        self.graph, self.roles = graph_from_vbe_instance(self.instance)

    def test_empty_interpretation_is_hard_stop_not_stable(self):
        result = evaluate_vbe(
            self.graph,
            self.roles,
            refinement_complete=True,
            material_interpretation_nonempty=False,
        )
        self.assertEqual(result["prediction"], PRED_INCOMPLETE)
        self.assertEqual(result["hard_stop"], "EMPTY_OR_UNESTABLISHED_MATERIAL_INTERPRETATION")

    def test_unresolved_obligation_is_incomplete(self):
        data = self.graph.canonical_dict()
        for edge in data["edges"]:
            if edge["id"] == "e.compare":
                edge["status"] = "UNRESOLVED"
                edge.pop("evidence_refs", None)
        graph = ConsequenceGraph.from_dict(data)
        result = evaluate_vbe(graph, self.roles, refinement_complete=True, material_interpretation_nonempty=True)
        self.assertEqual(result["prediction"], PRED_INCOMPLETE)
        self.assertFalse(result["obligations"]["current_compared_by_guard"])

    def test_evidence_less_established_edge_rejected(self):
        data = self.graph.canonical_dict()
        for edge in data["edges"]:
            if edge["id"] == "e.compare":
                edge.pop("evidence_refs", None)
        with self.assertRaises(GraphInvariantError):
            ConsequenceGraph.from_dict(data)

    def test_evidence_less_established_material_node_rejected(self):
        data = self.graph.canonical_dict()
        for node in data["nodes"]:
            if node["id"] == self.roles["current_coordinate"]:
                node["attributes"].pop("evidence_refs", None)
        with self.assertRaises(GraphInvariantError):
            ConsequenceGraph.from_dict(data)

    def test_graph_order_digest_invariance(self):
        data = self.graph.canonical_dict()
        # add set-like evidence refs and reverse every intentionally unordered surface
        for edge in data["edges"]:
            edge["evidence_refs"] = ["z-proof", "a-proof"]
        g1 = ConsequenceGraph.from_dict(copy.deepcopy(data))
        permuted = copy.deepcopy(data)
        permuted["nodes"] = list(reversed(permuted["nodes"]))
        permuted["edges"] = list(reversed(permuted["edges"]))
        for edge in permuted["edges"]:
            edge["evidence_refs"] = list(reversed(edge["evidence_refs"]))
        g2 = ConsequenceGraph.from_dict(permuted)
        self.assertEqual(g1.digest(), g2.digest())

    def test_semantic_change_changes_digest(self):
        data = self.graph.canonical_dict()
        g1 = ConsequenceGraph.from_dict(copy.deepcopy(data))
        changed = copy.deepcopy(data)
        for edge in changed["edges"]:
            if edge["id"] == "e.compare":
                edge["status"] = "UNRESOLVED"
                edge.pop("evidence_refs", None)
        g2 = ConsequenceGraph.from_dict(changed)
        self.assertNotEqual(g1.digest(), g2.digest())

    def test_relational_extra_consequence_is_hard_stop_regression(self):
        worlds = [{"current_etag": "E0"}, {"current_etag": "E1"}]
        keys = [repr(tuple(sorted(w.items()))) for w in worlds]
        allowed = {
            keys[0]: ["UPDATE_COMMITTED"],
            keys[1]: ["STALE_EDIT_REJECTED"],
        }
        target = {
            keys[0]: ["UPDATE_COMMITTED"],
            keys[1]: ["STALE_EDIT_REJECTED", "UPDATE_COMMITTED"],
        }
        witness = find_relational_witness(worlds, allowed, target)
        self.assertIsNotNone(witness)
        result = evaluate_vbe(
            self.graph,
            self.roles,
            refinement_complete=True,
            material_interpretation_nonempty=True,
            relational_witness=witness,
        )
        self.assertEqual(result["prediction"], PRED_REGRESSION)
        self.assertIn("UPDATE_COMMITTED", result["witness"]["extra_consequences"])

    def test_relational_subset_has_no_witness(self):
        worlds = [{"v": 0}]
        k = repr(tuple(sorted(worlds[0].items())))
        self.assertIsNone(find_relational_witness(worlds, {k: ["A", "B"]}, {k: ["A"]}))


    def test_digest_invariant_under_deterministic_permutation_fuzz(self):
        data = self.graph.canonical_dict()
        for node in data["nodes"]:
            if node.get("attributes", {}).get("evidence_refs"):
                node["attributes"]["evidence_refs"] = ["proof-z", "proof-a", "proof-m"]
        for edge in data["edges"]:
            edge["evidence_refs"] = ["proof-z", "proof-a", "proof-m"]
        expected = ConsequenceGraph.from_dict(copy.deepcopy(data)).digest()
        rng = random.Random(20260905)
        for _ in range(64):
            candidate = copy.deepcopy(data)
            rng.shuffle(candidate["nodes"])
            rng.shuffle(candidate["edges"])
            for node in candidate["nodes"]:
                refs = node.get("attributes", {}).get("evidence_refs")
                if refs:
                    rng.shuffle(refs)
            for edge in candidate["edges"]:
                rng.shuffle(edge["evidence_refs"])
            self.assertEqual(ConsequenceGraph.from_dict(candidate).digest(), expected)

    def test_every_established_material_edge_requires_evidence(self):
        base = self.graph.canonical_dict()
        material = [e["id"] for e in base["edges"] if e["kind"] in {"BINDS_TO", "COMPARES", "GUARDS", "REJECTS_AS", "INTERPRETS_AS"}]
        self.assertGreaterEqual(len(material), 4)
        for edge_id in material:
            with self.subTest(edge=edge_id):
                data = copy.deepcopy(base)
                for edge in data["edges"]:
                    if edge["id"] == edge_id:
                        edge.pop("evidence_refs", None)
                with self.assertRaises(GraphInvariantError):
                    ConsequenceGraph.from_dict(data)

    def test_every_established_material_node_requires_evidence(self):
        base = self.graph.canonical_dict()
        material = [n["id"] for n in base["nodes"] if n["kind"] in {"SEMANTIC_COORDINATE", "GUARD", "EFFECT", "OUTCOME", "FAILURE", "INTERPRETER"}]
        self.assertGreaterEqual(len(material), 5)
        for node_id in material:
            with self.subTest(node=node_id):
                data = copy.deepcopy(base)
                for node in data["nodes"]:
                    if node["id"] == node_id:
                        node.get("attributes", {}).pop("evidence_refs", None)
                with self.assertRaises(GraphInvariantError):
                    ConsequenceGraph.from_dict(data)

    def test_collapse_tamper_matrix_rejected(self):
        witness = copy.deepcopy(evaluate_calibration(load("001-github-guarded-merge.instance.json"))["witness"])
        mutations = [
            ("source_a", "FORGED_SOURCE"),
            ("source_b", "FORGED_SOURCE"),
            ("target_a", "FORGED_TARGET"),
            ("target_b", "FORGED_TARGET"),
        ]
        for field, value in mutations:
            with self.subTest(field=field):
                bad = copy.deepcopy(witness)
                bad[field] = value
                self.assertEqual(run_checker(bad).returncode, 2)

    def test_relational_tamper_matrix_rejected(self):
        world = {"v": "old"}
        k = repr(tuple(sorted(world.items())))
        witness = find_relational_witness([world], {k: ["STALE"]}, {k: ["STALE", "WRITE"]})
        bads = []
        x = copy.deepcopy(witness); x["source_allowed"] = ["STALE", "WRITE"]; bads.append(x)
        x = copy.deepcopy(witness); x["observed_target"] = ["STALE"]; bads.append(x)
        x = copy.deepcopy(witness); x["extra_consequences"] = ["OTHER"]; bads.append(x)
        x = copy.deepcopy(witness); x["world"] = {"v": "new"}; bads.append(x)
        for idx, bad in enumerate(bads):
            with self.subTest(tamper=idx):
                self.assertEqual(run_checker(bad).returncode, 2)

    def test_collapse_witness_prefers_minimal_coordinate_difference(self):
        worlds = [
            {"v": 0, "tenant": "A"},
            {"v": 1, "tenant": "A"},
            {"v": 2, "tenant": "B"},
        ]
        keys = [repr(tuple(sorted(w.items()))) for w in worlds]
        source = {keys[0]: "OK", keys[1]: "STALE", keys[2]: "STALE2"}
        target = {keys[0]: "ACCEPT", keys[1]: "ACCEPT", keys[2]: "ACCEPT"}
        witness = find_collapse_witness(worlds, source, target)
        self.assertEqual(witness["difference_count"], 1)
        self.assertEqual(witness["world_a"]["tenant"], witness["world_b"]["tenant"])

    def test_valid_shrunken_collapse_witness_passes_independent_checker(self):
        worlds = [
            {"current": "V0", "tenant": "same", "noise": 7},
            {"current": "V1", "tenant": "same", "noise": 7},
        ]
        keys = [repr(tuple(sorted(w.items()))) for w in worlds]
        witness = find_collapse_witness(
            worlds,
            {keys[0]: "OK", keys[1]: "STALE"},
            {keys[0]: "ACCEPT", keys[1]: "ACCEPT"},
        )
        result = evaluate_vbe(
            self.graph,
            self.roles,
            refinement_complete=True,
            material_interpretation_nonempty=True,
            collapse_witness=witness,
        )
        shrunk = result["witness"]
        self.assertEqual(shrunk["world_a"], {"current": "V0"})
        self.assertEqual(shrunk["world_b"], {"current": "V1"})
        checked = run_checker(shrunk)
        self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)

    def test_tampered_collapse_witness_rejected(self):
        instance = load("001-github-guarded-merge.instance.json")
        result = evaluate_calibration(instance)
        witness = copy.deepcopy(result["witness"])
        witness["target_b"] = "TAMPERED_ACCEPT"
        checked = run_checker(witness)
        self.assertEqual(checked.returncode, 2)
        self.assertIn("REJECT", checked.stdout)

    def test_valid_relational_witness_passes_independent_checker(self):
        world = {"v": "old"}
        k = repr(tuple(sorted(world.items())))
        witness = find_relational_witness([world], {k: ["STALE"]}, {k: ["STALE", "WRITE"]})
        checked = run_checker(witness)
        self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)

    def test_tampered_relational_witness_rejected(self):
        world = {"v": "old"}
        k = repr(tuple(sorted(world.items())))
        witness = find_relational_witness([world], {k: ["STALE"]}, {k: ["STALE", "WRITE"]})
        witness["extra_consequences"] = []
        checked = run_checker(witness)
        self.assertEqual(checked.returncode, 2)



