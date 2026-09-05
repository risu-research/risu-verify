#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import corpus01_primary_v08 as p


def write_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class PrimaryV08Tests(unittest.TestCase):
    def test_report_metadata_comes_only_from_current_frozen_records(self):
        with tempfile.TemporaryDirectory() as td:
            case = Path(td) / "case"
            assurance = case / "assurance"
            assurance.mkdir(parents=True)
            write_json(assurance / "adapter.json", {"semantic": "adapter"})
            write_json(assurance / "source-contract.json", {"semantic": "source"})
            write_json(case / "case.json", {
                "case_id": "x",
                "title": "x",
                "display": {"action": "historical"},
                "external_system": {"pinned_projection_ref": "OLD"},
                "claim_boundary": {"historical": True},
            })
            adapter_before = sha(assurance / "adapter.json")
            source_before = sha(assurance / "source-contract.json")
            target = {"target": {
                "repository": "org/current",
                "operation": "write_current",
                "revision": "NEWREV",
                "source_library_pin": "lib@pin",
            }}
            boundary = {
                "claim_scope": {"profile": "CURRENT_ONLY", "model_relative": True},
                "effect_cut": {"name": "CURRENT_EFFECT"},
            }
            result = p.sanitize_report_metadata(case, target, boundary)
            current = json.loads((case / "case.json").read_text())
            self.assertNotIn("display", current)
            self.assertEqual(current["external_system"]["pinned_projection_ref"], "NEWREV")
            self.assertEqual(current["claim_boundary"]["source"], "FROZEN_BOUNDARY_MODEL")
            self.assertEqual(current["claim_boundary"]["claim_scope"]["profile"], "CURRENT_ONLY")
            self.assertEqual(sha(assurance / "adapter.json"), adapter_before)
            self.assertEqual(sha(assurance / "source-contract.json"), source_before)
            self.assertTrue(result["semantic_assurance_inputs_unchanged"])

    def test_verify_seal_binds_exact_manifest_bytes(self):
        with tempfile.TemporaryDirectory() as td:
            old_root = p.ROOT
            try:
                p.ROOT = Path(td)
                manifest = Path(td) / "unit" / "PRIMARY_RUN_MANIFEST.json"
                seal = Path(td) / "unit" / "UNIT_SEAL.json"
                write_json(manifest, {
                    "unit_id": "u",
                    "authoring_freeze_commit": "abc",
                    "seal_record_path": "unit/UNIT_SEAL.json",
                })
                write_json(seal, {
                    "schema": "risu.corpus-unit-seal/v0.8alpha1",
                    "status": "READY_FOR_PRIMARY",
                    "unit_id": "u",
                    "authoring_freeze_commit": "abc",
                    "manifest_sha256": sha(manifest),
                    "gates": {
                        "read_only_audit": "PASS",
                        "freeze_gate": "PASS",
                        "bound_evidence_compile": "PASS",
                        "provenance_preflight": "PASS",
                    },
                    "controls": {
                        "primary_verifier_executed_during_seal": False,
                        "scientific_input_bytes_modified": False,
                    },
                })
                self.assertEqual(p.verify_seal(manifest, json.loads(manifest.read_text()))["status"], "PASS")
                with manifest.open("a", encoding="utf-8") as f:
                    f.write(" ")
                with self.assertRaisesRegex(RuntimeError, "pin current primary manifest"):
                    p.verify_seal(manifest, json.loads(manifest.read_text()))
            finally:
                p.ROOT = old_root


if __name__ == "__main__":
    unittest.main()
