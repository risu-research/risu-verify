from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tools.risu_e1_machine_first import engine_identity
from tools.unit004_e1_exam import execute, make_round0


class Unit004E1ExamHarnessTests(unittest.TestCase):
    def _binding(self, root: Path) -> Path:
        path = root / "binding.json"
        path.write_text(json.dumps({
            "binding_id": "SYNTHETIC_BINDING",
            "status": "BOUND_BEFORE_TARGET_TREE_OR_CONTENT_ACCESS",
            "selection": {"substitution_used": False},
            "enrollment": {"unit_id": "synthetic-heldout-unit"},
            "target": {
                "materializable": True,
                "revision": "deadbeef",
                "tree_sha": "tree-deadbeef",
                "screened_operation": "rotate_item",
            },
            "frozen_e1": {"engine_identity_digest": engine_identity()["engine_identity_digest"]},
        }, sort_keys=True), encoding="utf-8")
        return path

    def test_round0_is_deterministic_and_positive_only(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            binding = self._binding(root)
            tree = root / "tree.txt"
            tree.write_text("docs/readme.md\nsrc/filler.py\ncmd/rotate_item.py\n", encoding="utf-8")
            a = root / "a.json"; b = root / "b.json"
            one = make_round0(binding, tree, a)
            two = make_round0(binding, tree, b)
            self.assertEqual(a.read_bytes(), b.read_bytes())
            self.assertEqual(one["round0_selected_count"], 1)
            self.assertEqual(one["round0"][0]["path"], "cmd/rotate_item.py")
            self.assertEqual(one, two)

    def test_zero_round0_is_valid_data_not_filler(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            binding = self._binding(root)
            tree = root / "tree.txt"
            tree.write_text("docs/readme.md\nsrc/unrelated.py\nconfig/settings.json\n", encoding="utf-8")
            out = root / "round0.json"
            result = make_round0(binding, tree, out)
            self.assertEqual(result["round0"], [])
            self.assertEqual(result["round0_selected_count"], 0)
            self.assertEqual(result["target_content_bytes_consumed"], 0)

    def test_zero_seed_execution_seals_incomplete_without_human_fill(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            binding = self._binding(root)
            tree = root / "tree.txt"
            tree.write_text("docs/readme.md\nsrc/unrelated.py\n", encoding="utf-8")
            round0 = root / "round0.json"
            make_round0(binding, tree, round0)
            artifact = root / "artifact"
            record = execute(binding, round0, tree, root / "unused-target-git", artifact)
            prediction = json.loads((artifact / "output" / "E1_PREDICTION.json").read_text(encoding="utf-8"))
            acquisition = json.loads((artifact / "ACQUISITION_MANIFEST.json").read_text(encoding="utf-8"))
            self.assertEqual(prediction["prediction"], "E1_PREDICTED_ASSURANCE_INCOMPLETE")
            self.assertEqual(acquisition["round_counts"], [0, 0, 0])
            self.assertEqual(acquisition["evidence_count"], 0)
            self.assertEqual(record["evidence_count"], 0)
            self.assertTrue(record["prediction_value_intentionally_not_copied_into_record"])
            self.assertFalse(record["canonical_scientific_authority"])


if __name__ == "__main__":
    unittest.main()
