from __future__ import annotations

"""Tiny shared primitives/constants for the independent C1 lane."""

import hashlib
import json
from typing import Any

CERT_SCHEMA = "risu.e2-semantic-certificate/v0.1"
SLICE_SCHEMA = "risu.e2-semantic-slice/v0.1"
C1_SCHEMA = "risu.e2-c1-recheck/v0.1"

REGRESSION = "E2_PREDICTED_REGRESSION_WITNESS"
PRESERVATION = "E2_PREDICTED_PRESERVATION_EVIDENCE"
INCOMPLETE = "E2_PREDICTED_ASSURANCE_INCOMPLETE"
INFRA_INVALID = "INFRASTRUCTURE_INVALID_BEFORE_PREDICTION"

VALID = "VALID_C1"
INVALID = "INVALID_CERTIFICATE"
UNSUPPORTED = "UNSUPPORTED_CERTIFICATE"

def _canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def _digest_json(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()
