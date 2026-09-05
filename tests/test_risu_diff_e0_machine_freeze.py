from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from risu_e0.baselines import require_non_authoritative
from risu_e0.machine_first import (
    CONTROL_ARTIFACT,
    OBSERVATION_ARTIFACT,
    REQUIRED_ARTIFACTS,
    MachineInputError,
    OutputSealError,
    build_semantic_outputs,
    canonical_bytes,
    execution_observation,
    load_machine_packet,
    verify_output_dir,
    write_semantic_outputs,
)

ENGINE = {
    "freeze_id": "RISU_DIFF_E0_MACHINE_FIRST_E0",
    "freeze_protocol_id": "RISU_DIFF_E0_MACHINE_FIRST_FREEZE_001",
    "foundation_qualification_id": "RISU_DIFF_E0_FOUNDATION_001",
    "engine_identity_digest": "a" * 64,
    "identity_authority": "COMMITTED_GIT_OBJECT_SHA256",
}


def _packet(root: Path, *, source: bytes = b"def f(current_version, expected_version):\n    return current_version == expected_version\n", mutate_input=None):
    evidence = root / "evidence" / "target.py"
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_bytes(source)
    data = {
        "schema": "risu.diff-e0-machine-input/v0.1",
        "run_id": "fixture-run-001",
        "unit_id": "fixture-unit",
        "target_revision": "deadbeef",
        "screened_operation": "fixture_update",
        "surface": {"name": "fixture_update", "arguments": ["resource", "version"]},
        "evidence_files": [{
            "path": "evidence/target.py",
            "sha256": hashlib.sha256(source).hexdigest(),
            "kind": "TARGET_TEXT",
            "language": "python",
        }],
        "acquisition": {"mode": "TEST_FIXTURE", "provenance_refs": ["fixture:target.py"]},
    }
    if mutate_input:
        mutate_input(data)
    (root / "MACHINE_INPUT.json").write_bytes(canonical_bytes(data))
    return data


class MachineFirstFreezeQualification(unittest.TestCase):
    def test_canonical_json_is_order_invariant(self):
        self.assertEqual(canonical_bytes({"b": 1, "a": 2}), canonical_bytes({"a": 2, "b": 1}))

    def test_valid_packet_hash_closure(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _packet(root)
            packet = load_machine_packet(root)
            self.assertEqual(packet["packet_identity"]["evidence_sha256"]["evidence/target.py"],
                             hashlib.sha256((root / "evidence/target.py").read_bytes()).hexdigest())

    def test_path_traversal_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _packet(root, mutate_input=lambda d: d["evidence_files"][0].update(path="../target.py"))
            with self.assertRaises(MachineInputError):
                load_machine_packet(root)

    def test_backslash_path_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _packet(root, mutate_input=lambda d: d["evidence_files"][0].update(path="evidence\\target.py"))
            with self.assertRaises(MachineInputError):
                load_machine_packet(root)

    def test_duplicate_evidence_path_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            def mutate(d):
                d["evidence_files"].append(dict(d["evidence_files"][0]))
            _packet(root, mutate_input=mutate)
            with self.assertRaises(MachineInputError):
                load_machine_packet(root)

    def test_hash_mismatch_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _packet(root, mutate_input=lambda d: d["evidence_files"][0].update(sha256="0" * 64))
            with self.assertRaises(MachineInputError):
                load_machine_packet(root)

    def test_unlisted_evidence_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _packet(root)
            (root / "evidence" / "hidden.txt").write_text("hidden")
            with self.assertRaises(MachineInputError):
                load_machine_packet(root)

    def test_unknown_root_field_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _packet(root, mutate_input=lambda d: d.update(secret="x"))
            with self.assertRaises(MachineInputError):
                load_machine_packet(root)

    def test_canonical_verdict_injection_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _packet(root, mutate_input=lambda d: d["acquisition"].update(canonical_verdict="PRESERVED"))
            with self.assertRaises(MachineInputError):
                load_machine_packet(root)

    def test_human_gold_injection_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _packet(root, mutate_input=lambda d: d["acquisition"].update(human_gold={"x": 1}))
            with self.assertRaises(MachineInputError):
                load_machine_packet(root)

    def test_established_semantics_injection_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _packet(root, mutate_input=lambda d: d["acquisition"].update(established_semantics=["guard"]))
            with self.assertRaises(MachineInputError):
                load_machine_packet(root)

    def test_surface_argument_duplicates_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _packet(root, mutate_input=lambda d: d["surface"].update(arguments=["version", "version"]))
            with self.assertRaises(MachineInputError):
                load_machine_packet(root)

    def test_required_artifacts_present_even_when_incomplete(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _packet(root)
            outputs = build_semantic_outputs(root, ENGINE)
            for name in REQUIRED_ARTIFACTS:
                self.assertIn(name, outputs)
            self.assertIn(CONTROL_ARTIFACT, outputs)
            prediction = json.loads(outputs["E0_PREDICTION.json"])
            self.assertEqual(prediction["prediction"], "E0_PREDICTED_ASSURANCE_INCOMPLETE")

    def test_static_extractor_never_self_establishes_material_semantics(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _packet(root)
            outputs = build_semantic_outputs(root, ENGINE)
            cir = json.loads(outputs["CIR_CANDIDATE.json"])
            self.assertTrue(cir["candidate_extraction"]["coordinate_candidates"])
            self.assertTrue(all(n["status"] == "UNRESOLVED" for n in cir["nodes"]))
            self.assertFalse(cir["semantic_authority"])

    def test_refinement_map_is_explicitly_unresolved(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _packet(root)
            outputs = build_semantic_outputs(root, ENGINE)
            ref = json.loads(outputs["REFINEMENT_MAP_CANDIDATE.json"])
            self.assertFalse(ref["refinement_complete"])
            self.assertTrue(all(r["status"] == "UNRESOLVED" for r in ref["relations"]))

    def test_silent_unknown_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _packet(root, source=b"def f(x):\n    return x\n")
            outputs = build_semantic_outputs(root, ENGINE)
            pred = json.loads(outputs["E0_PREDICTION.json"])
            self.assertEqual(pred["prediction"], "E0_PREDICTED_ASSURANCE_INCOMPLETE")
            self.assertEqual(pred["hard_stop"], "UNRESOLVED_MATERIAL_OBLIGATION")

    def test_all_vbe_obligations_are_reported(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _packet(root)
            outputs = build_semantic_outputs(root, ENGINE)
            ob = json.loads(outputs["VBE_OBLIGATIONS.json"])
            self.assertEqual(len(ob["obligations"]), 9)
            self.assertEqual(sorted(ob["unresolved"]), sorted(ob["obligations"]))
            self.assertFalse(ob["all_satisfied"])

    def test_refinement_requests_are_target_only(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _packet(root)
            outputs = build_semantic_outputs(root, ENGINE)
            req = json.loads(outputs["REFINEMENT_REQUESTS.json"])
            self.assertTrue(req["requests"])
            self.assertTrue(all(r["target_only"] for r in req["requests"]))
            self.assertTrue(all(not r["may_change_source_contract"] for r in req["requests"]))
            self.assertTrue(all(not r["may_change_evaluation_metric"] for r in req["requests"]))

    def test_probe_plan_order_is_deterministic(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _packet(root)
            a = json.loads(build_semantic_outputs(root, ENGINE)["PROBE_PLAN.json"])
            b = json.loads(build_semantic_outputs(root, ENGINE)["PROBE_PLAN.json"])
            self.assertEqual(a, b)
            self.assertEqual([p["sequence"] for p in a["probes"]], list(range(1, len(a["probes"]) + 1)))

    def test_baselines_are_non_authoritative(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _packet(root)
            baseline = json.loads(build_semantic_outputs(root, ENGINE)["BASELINE_RESULTS.json"])
            self.assertFalse(baseline["consequence_authority"])
            for result in baseline["results"]:
                require_non_authoritative(result)

    def test_machine_input_cannot_inject_witness(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _packet(root, mutate_input=lambda d: d.update(witness={"world": {"x": 1}}))
            with self.assertRaises(MachineInputError):
                load_machine_packet(root)

    def test_deterministic_replay_is_byte_identical(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _packet(root)
            a = build_semantic_outputs(root, ENGINE)
            b = build_semantic_outputs(root, ENGINE)
            self.assertEqual(a, b)

    def test_semantic_change_changes_output_seal(self):
        with tempfile.TemporaryDirectory() as a_td, tempfile.TemporaryDirectory() as b_td:
            a_root, b_root = Path(a_td), Path(b_td)
            _packet(a_root, source=b"def f(version):\n    return version\n")
            _packet(b_root, source=b"def f(version):\n    return version == 7\n")
            a = json.loads(build_semantic_outputs(a_root, ENGINE)[CONTROL_ARTIFACT])
            b = json.loads(build_semantic_outputs(b_root, ENGINE)[CONTROL_ARTIFACT])
            self.assertNotEqual(a["seal_digest"], b["seal_digest"])

    def test_nonsemantic_observation_is_excluded_from_seal(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _packet(root)
            outputs = build_semantic_outputs(root, ENGINE)
            seal_before = json.loads(outputs[CONTROL_ARTIFACT])["seal_digest"]
            obs_a = execution_observation(run_id="fixture-run-001", elapsed_seconds=1.0, host="A")
            obs_b = execution_observation(run_id="fixture-run-001", elapsed_seconds=99.0, host="B")
            self.assertNotEqual(obs_a, obs_b)
            self.assertEqual(seal_before, json.loads(outputs[CONTROL_ARTIFACT])["seal_digest"])

    def test_manifest_contains_no_wall_clock_fields(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _packet(root)
            manifest = json.loads(build_semantic_outputs(root, ENGINE)["E0_RUN_MANIFEST.json"])
            serialized = json.dumps(manifest).lower()
            self.assertNotIn("elapsed", serialized)
            self.assertNotIn("timestamp", serialized)
            self.assertFalse(manifest["wall_clock_fields_present"])

    def test_output_tamper_is_detected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "packet"
            out = Path(td) / "out"
            root.mkdir()
            _packet(root)
            write_semantic_outputs(root, out, ENGINE)
            verify_output_dir(out)
            (out / "E0_PREDICTION.json").write_text("{}\n")
            with self.assertRaises(OutputSealError):
                verify_output_dir(out)

    def test_unsealed_extra_output_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "packet"
            out = Path(td) / "out"
            root.mkdir()
            _packet(root)
            write_semantic_outputs(root, out, ENGINE)
            (out / "UNSEALED.json").write_text("{}\n")
            with self.assertRaises(OutputSealError):
                verify_output_dir(out)

    def test_seal_digest_tamper_is_detected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "packet"
            out = Path(td) / "out"
            root.mkdir()
            _packet(root)
            write_semantic_outputs(root, out, ENGINE)
            seal_path = out / CONTROL_ARTIFACT
            seal = json.loads(seal_path.read_text())
            seal["seal_digest"] = "0" * 64
            seal_path.write_bytes(canonical_bytes(seal))
            with self.assertRaises(OutputSealError):
                verify_output_dir(out)

    def test_observation_sidecar_does_not_break_seal_verification(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "packet"
            out = Path(td) / "out"
            root.mkdir()
            _packet(root)
            write_semantic_outputs(root, out, ENGINE)
            (out / OBSERVATION_ARTIFACT).write_bytes(
                execution_observation(run_id="fixture-run-001", elapsed_seconds=3.2, host="fixture")
            )
            result = verify_output_dir(out)
            self.assertTrue(result["observation_sidecar_excluded"])

    def test_required_artifact_closure_is_exact(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _packet(root)
            outputs = build_semantic_outputs(root, ENGINE)
            seal = json.loads(outputs[CONTROL_ARTIFACT])
            self.assertEqual(sorted(seal["semantic_artifact_sha256"]), sorted(REQUIRED_ARTIFACTS))

    def test_canonical_scientific_authority_is_never_claimed(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _packet(root)
            outputs = build_semantic_outputs(root, ENGINE)
            pred = json.loads(outputs["E0_PREDICTION.json"])
            manifest = json.loads(outputs["E0_RUN_MANIFEST.json"])
            self.assertFalse(pred["canonical_scientific_authority"])
            self.assertFalse(pred["consequence_authority"])
            self.assertFalse(manifest["canonical_scientific_authority"])


if __name__ == "__main__":
    unittest.main()
