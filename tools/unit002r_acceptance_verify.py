#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UNIT = ROOT / "corpus/0.1/units/002-octokit-pulls-merge"


def load(name: str):
    return json.loads((UNIT / name).read_text(encoding="utf-8"))


def main() -> int:
    draft = load("vbe.instance.draft.json")
    accepted = load("vbe.instance.json")
    acceptance = load("AUTHOR_ACCEPTANCE.json")
    selection = load("SELECTION_FREEZE.json")

    errors: list[str] = []
    if draft.get("status") != "DRAFT_UNVERIFIED":
        errors.append("draft status is not DRAFT_UNVERIFIED")
    if accepted.get("status") != "AUTHOR_ACCEPTED":
        errors.append("accepted instance status is not AUTHOR_ACCEPTED")

    normalized = json.loads(json.dumps(draft))
    normalized["status"] = "AUTHOR_ACCEPTED"
    if normalized != accepted:
        errors.append("accepted instance differs from draft beyond the top-level status field")

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
        "schema": "risu.unit002-r-acceptance-verification/v0.1alpha1",
        "status": "PASS" if not errors else "FAIL",
        "status_only_transformation": not errors,
        "primary_verdict_observed": False,
        "errors": errors,
    }
    print(json.dumps(out, indent=2, sort_keys=True))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
