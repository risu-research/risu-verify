#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import corpus01_unit_harness as h


class CorpusUnitHarnessTests(unittest.TestCase):
    def test_provenance_gap_is_fail_closed(self):
        envelope = {
            "adapter_base": {
                "provenance": {
                    "nodes": [{"id": "FACT"}, {"id": "DERIVE"}, {"id": "CLAIM"}],
                    "edges": [{"from": "DERIVE", "relation": "DERIVES", "to": "CLAIM"}],
                    "claim_roots": {"EXACT": ["CLAIM"]},
                }
            },
            "derivation_facts": [
                {"id": "F1", "status": "ESTABLISHED", "provenance_node": "FACT"}
            ],
        }
        findings = h.provenance_findings(envelope)
        self.assertEqual(
            [x["key"] for x in findings],
            ["PROVENANCE_NOT_UPSTREAM_OF_EXACT:F1"],
        )

        envelope["adapter_base"]["provenance"]["edges"].append(
            {"from": "FACT", "relation": "USES", "to": "DERIVE"}
        )
        self.assertEqual(h.provenance_findings(envelope), [])

    def test_metadata_sanitation_cannot_touch_assurance_inputs(self):
        with tempfile.TemporaryDirectory() as td:
            case = Path(td)
            (case / "assurance").mkdir()
            (case / "case.json").write_text(
                json.dumps(
                    {
                        "display": {"action": "stale"},
                        "external_system": {"pinned_projection_ref": "OLD"},
                    }
                ),
                encoding="utf-8",
            )
            (case / "assurance" / "adapter.json").write_text('{"a":1}\n', encoding="utf-8")
            (case / "assurance" / "source-contract.json").write_text('{"s":1}\n', encoding="utf-8")
            adapter_before = h.sha256_file(case / "assurance" / "adapter.json")
            source_before = h.sha256_file(case / "assurance" / "source-contract.json")

            rec = h.sanitize_compiled_case_metadata(
                case,
                {
                    "target": {
                        "repository": "org/repo",
                        "operation": "write",
                        "revision": "NEW",
                    }
                },
            )
            after = h.read_json(case / "case.json")
            self.assertNotIn("display", after)
            self.assertEqual(after["external_system"]["pinned_projection_ref"], "NEW")
            self.assertEqual(adapter_before, h.sha256_file(case / "assurance" / "adapter.json"))
            self.assertEqual(source_before, h.sha256_file(case / "assurance" / "source-contract.json"))
            self.assertTrue(rec["semantic_assurance_inputs_unchanged"])

    def test_deterministic_zip_ignores_filesystem_mtime(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            staging = root / "staging"
            staging.mkdir()
            (staging / "z.txt").write_text("z", encoding="utf-8")
            (staging / "a.txt").write_text("a", encoding="utf-8")
            first = root / "first.zip"
            second = root / "second.zip"
            sha1 = h._deterministic_zip(staging, first)
            os.utime(staging / "a.txt", (1700000000, 1700000000))
            os.utime(staging / "z.txt", (1800000000, 1800000000))
            sha2 = h._deterministic_zip(staging, second)
            self.assertEqual(sha1, sha2)
            self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_bundle_contains_complete_compiled_tree(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            case = root / "case"
            out = root / "out"
            case.mkdir()
            (case / "assurance").mkdir()
            out.mkdir()
            (case / "case.json").write_text("{}\n", encoding="utf-8")
            (case / "assurance" / "adapter.json").write_text("{}\n", encoding="utf-8")
            (out / "report.json").write_text("{}\n", encoding="utf-8")
            console = root / "console.json"
            exit_code = root / "exit.txt"
            observation = root / "observation.json"
            console.write_text("{}\n", encoding="utf-8")
            exit_code.write_text("0\n", encoding="utf-8")
            observation.write_text("{}\n", encoding="utf-8")

            manifest = {
                "unit_id": "corpus01-unit-test",
                "instance_id": "instance-test",
                "authoring_freeze_commit": "abc",
            }
            zip_path, result = h.build_self_contained_bundle(
                manifest, case, out, console, exit_code, observation, root / "bundle"
            )
            self.assertTrue(zip_path.is_file())
            self.assertTrue(result["compiled_case_file_count"] >= 2)
            self.assertEqual(result["verifier_output_file_count"], 1)

            import zipfile
            with zipfile.ZipFile(zip_path) as zf:
                names = set(zf.namelist())
            self.assertIn("compiled-case/case.json", names)
            self.assertIn("compiled-case/assurance/adapter.json", names)
            self.assertIn("verifier-output/report.json", names)
            self.assertIn("BUNDLE.json", names)
            self.assertIn("MANIFEST.sha256", names)


if __name__ == "__main__":
    unittest.main()
