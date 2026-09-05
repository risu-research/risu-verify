#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UNIT = ROOT / "corpus/0.1/units/002-octokit-pulls-merge"
AMENDMENT = ROOT / "corpus/0.1/AUTHORING_PROTOCOL_AMENDMENT_003.json"
EXPECTED_ENVELOPE_SHA256 = "0243c54dc7042a808b8e6ef0dce968f2b78f3148374d90b5e2a234dfe0499ce1"


def load(name: str):
    return json.loads((UNIT / name).read_text(encoding="utf-8"))


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    draft = load("vbe.instance.draft.json")
    accepted = load("vbe.instance.json")
    acceptance = load("AUTHOR_ACCEPTANCE.json")
    selection = load("SELECTION_FREEZE.json")
    amendment = json.loads(AMENDMENT.read_text(encoding="utf-8"))

    errors: list[str] = []
    if draft.get("status") != "DRAFT_UNVERIFIED":
        errors.append("draft status is not DRAFT_UNVERIFIED")
    if accepted.get("status") != "AUTHOR_ACCEPTED":
        errors.append("accepted instance status is not AUTHOR_ACCEPTED")

    normalized = json.loads(json.dumps(draft))
    normalized["status"] = "AUTHOR_ACCEPTED"
    if normalized != accepted:
        errors.append("accepted instance differs from corrected draft beyond the top-level status field")

    actual_envelope = sha256(UNIT / "vbe.envelope.json")
    if actual_envelope != EXPECTED_ENVELOPE_SHA256:
        errors.append(f"envelope bytes changed: {actual_envelope}")
    for label, obj in (("draft", draft), ("accepted", accepted)):
        pin = (((obj.get("authoring_inputs") or {}).get("carrier_envelope") or {}).get("sha256"))
        if pin != actual_envelope:
            errors.append(f"{label} envelope checksum pointer does not bind current frozen bytes")

    if amendment.get("amendment_id") != "RISU_CORPUS_0.1_AUTHORING_PROTOCOL_AMENDMENT_003":
        errors.append("Amendment 003 identity mismatch")
    if amendment.get("primary_verdict_observed_before_amendment") is not False:
        errors.append("Amendment 003 does not preserve pre-primary timing")
    if amendment.get("could_alter_primary_semantic_outcome") is not False:
        errors.append("Amendment 003 is not bounded as nonsemantic")
    diagnosis = amendment.get("diagnosis") or {}
    if diagnosis.get("actual_committed_sha256") != actual_envelope:
        errors.append("Amendment 003 does not bind the actual envelope digest")

    applied = {x.get("id") for x in acceptance.get("amendments_applied") or []}
    if amendment.get("amendment_id") not in applied:
        errors.append("AUTHOR_ACCEPTANCE does not record Amendment 003")
    frozen = {x.get("path"): x.get("sha256") for x in acceptance.get("frozen_inputs") or []}
    if frozen.get("corpus/0.1/units/002-octokit-pulls-merge/vbe.envelope.json") != actual_envelope:
        errors.append("AUTHOR_ACCEPTANCE envelope pin is not corrected")

    if acceptance.get("status") != "AUTHOR_ACCEPTED":
        errors.append("AUTHOR_ACCEPTANCE status mismatch")
    if acceptance.get("primary_verdict_observed_before_acceptance") is not False:
        errors.append("acceptance does not preserve verdict blindness")
    required = acceptance.get("required_statements") or {}
    if not required or not all(v is True for v in required.values()):
        errors.append("not all required human-acceptance statements are true")

    if selection.get("selected_target", {}).get("unit_id") != "corpus01-unit-002":
        errors.append("selection freeze does not bind corpus01-unit-002")
    if selection.get("independence_guarantees", {}).get("unit002_m_outcomes_used_for_selection") is not False:
        errors.append("selection independence from Unit 002-M is not recorded")

    out = {
        "schema": "risu.unit002-r-acceptance-verification/v0.2alpha1",
        "status": "PASS" if not errors else "FAIL",
        "status_only_transformation_after_amendment_003": not errors,
        "amendment_003_verified": not errors,
        "envelope_sha256": actual_envelope,
        "primary_verdict_observed": False,
        "errors": errors,
    }
    print(json.dumps(out, indent=2, sort_keys=True))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
