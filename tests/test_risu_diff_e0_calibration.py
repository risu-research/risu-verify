from __future__ import annotations

import copy
import unittest

from risu_e0.adapters import discriminator_collapse_mutation, evaluate_calibration
from risu_e0.engine import PRED_REGRESSION, PRED_STABLE
from tests.e0_support import load


class CalibrationQualification(unittest.TestCase):
    def test_001_omitted_guard_regresses(self):
        result = evaluate_calibration(load("001-github-guarded-merge.instance.json"))
        self.assertEqual(result["prediction"], PRED_REGRESSION)
        self.assertEqual(result["witness"]["witness_kind"], "DETERMINISTIC_COLLAPSE")

    def test_002_azure_preserved_is_stable(self):
        result = evaluate_calibration(load("002-azure-wiki-etag.instance.json"))
        self.assertEqual(result["prediction"], PRED_STABLE)

    def test_003_after_preserved_is_stable(self):
        result = evaluate_calibration(load("003-after-github-blob-sha.instance.json"))
        self.assertEqual(result["prediction"], PRED_STABLE)

    def test_003_before_wrong_validator_regresses(self):
        result = evaluate_calibration(load("003-before-github-blob-sha.instance.json"))
        self.assertEqual(result["prediction"], PRED_REGRESSION)

    def test_unit002m_style_discriminator_collapse_regresses(self):
        result = discriminator_collapse_mutation(load("002-azure-wiki-etag.instance.json"))
        self.assertEqual(result["prediction"], PRED_REGRESSION)
        self.assertEqual(result["witness"]["witness_kind"], "DETERMINISTIC_COLLAPSE")

    def test_metadata_only_mutation_is_semantically_inert(self):
        instance = load("002-azure-wiki-etag.instance.json")
        baseline = evaluate_calibration(instance)
        mutated = copy.deepcopy(instance)
        mutated["metadata_only"] = {"display": "changed", "order": [3, 2, 1]}
        after = evaluate_calibration(mutated)
        self.assertEqual(baseline["prediction"], PRED_STABLE)
        self.assertEqual(after["prediction"], baseline["prediction"])


