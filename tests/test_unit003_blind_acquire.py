from __future__ import annotations

import hashlib
import unittest

from tools import unit003_blind_acquire as u


class Unit003BlindAcquisitionTests(unittest.TestCase):
    def test_policy_identity_is_stable(self):
        self.assertEqual(
            u.policy_sha256(),
            hashlib.sha256(u.canonical_bytes(u.POLICY)).hexdigest(),
        )

    def test_surface_is_derived_only_from_screened_operation(self):
        self.assertEqual(
            u.surface_from_screened_operation("kubectl annotate --resource-version"),
            {"name": "kubectl annotate", "arguments": ["resource-version"]},
        )

    def test_path_features_are_lexical_only(self):
        row = u.path_features("pkg/cmd/annotate/annotate.go")
        self.assertTrue(row["exact_annotate"])
        self.assertTrue(row["cmd_or_command_near_annotate"])
        self.assertFalse(row["resource_version"])

    def test_resource_version_normalizations(self):
        for path in (
            "docs/resource-version.md",
            "docs/resource_version.md",
            "docs/resourceVersion.md",
            "docs/resourceversion.md",
        ):
            self.assertTrue(u.path_features(path)["resource_version"], path)

    def test_ranking_order_is_frozen(self):
        paths = [
            "zzz/plain.go",
            "aaa/resourceVersion.md",
            "pkg/cmd/annotate/annotate.go",
            "pkg/annotate/readme.md",
        ]
        rows = [{"path": p, "git_blob_sha": "0" * 40, "features": u.path_features(p)} for p in paths]
        ordered = [r["path"] for r in sorted(rows, key=u.ranking_key)]
        self.assertEqual(
            ordered,
            [
                "pkg/cmd/annotate/annotate.go",
                "pkg/annotate/readme.md",
                "aaa/resourceVersion.md",
                "zzz/plain.go",
            ],
        )

    def test_no_score_threshold_top_cut(self):
        rows = []
        for i in range(30):
            path = f"z/{i:02d}.go"
            rows.append({"path": path, "git_blob_sha": f"{i:040x}"[-40:], "features": u.path_features(path)})
        rows.sort(key=u.ranking_key)
        self.assertEqual(len(rows[:u.MAX_FILES]), 24)
        self.assertEqual(rows[0]["path"], "z/00.go")

    def test_exclusions_and_extensions(self):
        self.assertFalse(u.eligible_path("vendor/pkg/cmd/annotate.go"))
        self.assertFalse(u.eligible_path("third_party/x.go"))
        self.assertFalse(u.eligible_path("translations/readme.md"))
        self.assertFalse(u.eligible_path("pkg/cmd/annotate.bin"))
        self.assertTrue(u.eligible_path("pkg/cmd/annotate.go"))

    def test_git_blob_sha_is_content_exact(self):
        raw = b"abc\n"
        expected = hashlib.sha1(b"blob 4\0abc\n").hexdigest()
        self.assertEqual(u.git_blob_sha1(raw), expected)

    def test_selection_digest_tamper_rejected(self):
        selected = [{
            "rank": 1,
            "path": "pkg/cmd/annotate/annotate.go",
            "git_blob_sha": "1" * 40,
            "features": u.path_features("pkg/cmd/annotate/annotate.go"),
        }]
        basis = {
            "exam_id": u.EXAM_ID,
            "unit_id": u.UNIT_ID,
            "repository": u.REPOSITORY,
            "target_revision": u.TARGET_REVISION,
            "target_tree_sha": u.TARGET_TREE_SHA,
            "screened_operation": u.SCREENED_OPERATION,
            "policy_sha256": u.policy_sha256(),
            "selected": selected,
        }
        manifest = {
            "schema": u.SELECTION_SCHEMA,
            **basis,
            "selection_sha256": u.sha256_bytes(u.canonical_bytes(basis)),
            "path_metadata_only": True,
            "target_file_contents_read_for_selection": False,
            "local_target_blob_objects_before_selection": 0,
            "selection_policy": u.POLICY,
        }
        u.verify_selection(manifest)
        manifest["selected"][0]["path"] = "tampered.go"
        with self.assertRaises(u.AcquisitionError):
            u.verify_selection(manifest)

    def test_selection_rejects_non_tree_only_flag(self):
        selected = []
        basis = {
            "exam_id": u.EXAM_ID,
            "unit_id": u.UNIT_ID,
            "repository": u.REPOSITORY,
            "target_revision": u.TARGET_REVISION,
            "target_tree_sha": u.TARGET_TREE_SHA,
            "screened_operation": u.SCREENED_OPERATION,
            "policy_sha256": u.policy_sha256(),
            "selected": selected,
        }
        manifest = {
            "schema": u.SELECTION_SCHEMA,
            **basis,
            "selection_sha256": u.sha256_bytes(u.canonical_bytes(basis)),
            "path_metadata_only": True,
            "target_file_contents_read_for_selection": False,
            "local_target_blob_objects_before_selection": 1,
            "selection_policy": u.POLICY,
        }
        with self.assertRaises(u.AcquisitionError):
            u.verify_selection(manifest)


if __name__ == "__main__":
    unittest.main()
