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

import corpus01_bound_evidence as b


def h(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class BoundEvidenceTests(unittest.TestCase):
    def test_explicit_binding_surface_removes_inherited_bytes(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            unit = root / "unit"
            case = root / "case"
            assurance = case / "assurance"
            (assurance / "evidence" / "legacy").mkdir(parents=True)
            (assurance / "qualification").mkdir(parents=True)
            unit.mkdir()

            evidence_bytes = b"current empirical evidence\n"
            qualification_bytes = b"sealed qualification\n"
            frozen = root / "frozen" / "target.json"
            frozen.parent.mkdir()
            frozen.write_bytes(evidence_bytes)

            (assurance / "adapter.json").write_text('{"adapter":"semantic"}\n', encoding="utf-8")
            (assurance / "source-contract.json").write_text('{"source":"semantic"}\n', encoding="utf-8")
            (assurance / "evidence" / "legacy" / "stale.json").write_text("stale\n", encoding="utf-8")
            (assurance / "qualification" / "sealed.zip").write_bytes(qualification_bytes)
            (assurance / "qualification" / "unbound.zip").write_bytes(b"old")

            envelope = {
                "adapter_base": {
                    "bindings": [
                        {
                            "id": "E1", "kind": "EVIDENCE", "role": "PINNED_TARGET",
                            "path": "evidence/current/target.json", "sha256": h(evidence_bytes),
                        },
                        {
                            "id": "Q1", "kind": "QUALIFICATION", "role": "SEALED_EXACT_QUALIFICATION",
                            "path": "qualification/sealed.zip", "sha256": h(qualification_bytes),
                        },
                    ]
                }
            }
            (unit / "vbe.envelope.json").write_text(json.dumps(envelope), encoding="utf-8")
            (unit / "vbe.instance.json").write_text(
                json.dumps({"carrier_envelope": "vbe.envelope.json"}), encoding="utf-8"
            )
            manifest = {
                "unit_id": "test-unit",
                "instance_path": "unit/vbe.instance.json",
                "frozen_paths": [{"path": "frozen/target.json", "sha256": h(evidence_bytes)}],
            }

            adapter_before = (assurance / "adapter.json").read_bytes()
            source_before = (assurance / "source-contract.json").read_bytes()
            result = b.apply_bound_evidence(case, unit, manifest, root=root)

            self.assertEqual(result["binding_count"], 2)
            self.assertEqual(result["unbound_managed_file_count_after"], 0)
            self.assertIn("evidence/legacy/stale.json", result["removed_unbound_paths"])
            self.assertIn("qualification/unbound.zip", result["removed_unbound_paths"])
            self.assertEqual((assurance / "evidence/current/target.json").read_bytes(), evidence_bytes)
            self.assertEqual((assurance / "qualification/sealed.zip").read_bytes(), qualification_bytes)
            self.assertFalse((assurance / "evidence/legacy/stale.json").exists())
            self.assertFalse((assurance / "qualification/unbound.zip").exists())
            self.assertEqual((assurance / "adapter.json").read_bytes(), adapter_before)
            self.assertEqual((assurance / "source-contract.json").read_bytes(), source_before)

    def test_empirical_binding_requires_unique_frozen_sha_source(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            unit = root / "unit"; unit.mkdir()
            case = root / "case"; assurance = case / "assurance"; assurance.mkdir(parents=True)
            (assurance / "adapter.json").write_text("{}\n", encoding="utf-8")
            (assurance / "source-contract.json").write_text("{}\n", encoding="utf-8")
            data = b"same"
            for name in ("a", "b"):
                p = root / "frozen" / f"{name}.json"; p.parent.mkdir(exist_ok=True); p.write_bytes(data)
            envelope = {"adapter_base": {"bindings": [{
                "id": "E", "kind": "EVIDENCE", "role": "PINNED",
                "path": "evidence/x.json", "sha256": h(data)
            }]}}
            (unit / "vbe.envelope.json").write_text(json.dumps(envelope), encoding="utf-8")
            (unit / "vbe.instance.json").write_text(json.dumps({"carrier_envelope":"vbe.envelope.json"}), encoding="utf-8")
            manifest = {
                "unit_id":"u", "instance_path":"unit/vbe.instance.json",
                "frozen_paths":[
                    {"path":"frozen/a.json","sha256":h(data)},
                    {"path":"frozen/b.json","sha256":h(data)},
                ],
            }
            with self.assertRaisesRegex(RuntimeError, "one-to-one"):
                b.apply_bound_evidence(case, unit, manifest, root=root)


if __name__ == "__main__":
    unittest.main()
