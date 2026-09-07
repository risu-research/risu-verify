#!/usr/bin/env python3
from __future__ import annotations

from typing import Any, Mapping

import e2_frozen48_requalification_independent_v2 as base
from risu_e2.path_observability_v2 import build_path_observability as build_path_observability_v2

_last_pathdoc: dict[str, Any] | None = None
_original_one_heldout_row = base.one_heldout_row

def _capture_path_observability(**kwargs: Any) -> dict[str, Any]:
    global _last_pathdoc
    _last_pathdoc = build_path_observability_v2(**kwargs)
    return _last_pathdoc

def _truths(pathdoc: Mapping[str, Any], collection: str) -> list[bool]:
    out: list[bool] = []
    for row in pathdoc.get(collection, []):
        for decision in row.get("guard_decisions", []):
            value = decision.get("transported_guard_truth")
            if type(value) is bool:
                out.append(value)
    return sorted(out)

def _evidence(pathdoc: Mapping[str, Any] | None) -> dict[str, Any]:
    if pathdoc is None:
        return {
            "status": "NOT_EVALUATED_TRANSPORT_INELIGIBLE",
            "effective_guard_form": "UNPROVEN",
            "certificate_status": "NOT_EVALUATED",
            "relation": None,
            "certificate_sha256": None,
            "certificate_reason": None,
            "flip_count": None,
            "transported_guard_truths": {"effect": [], "rejection": [], "success": []},
            "path_observability_v1_digest_sha256": None,
            "path_observability_v2_digest_sha256": None,
        }
    guard = pathdoc.get("effective_guard_observability", {})
    return {
        "status": "EVALUATED",
        "effective_guard_form": guard.get("form"),
        "certificate_status": guard.get("polarity_certificate_status"),
        "relation": guard.get("polarity_to_transported_guard"),
        "certificate_sha256": guard.get("polarity_certificate_sha256"),
        "certificate_reason": guard.get("polarity_certificate_reason"),
        "flip_count": guard.get("polarity_certificate_flip_count"),
        "transported_guard_truths": {
            "effect": _truths(pathdoc, "entry_effect_paths"),
            "rejection": _truths(pathdoc, "rejection_paths"),
            "success": _truths(pathdoc, "success_paths"),
        },
        "path_observability_v1_digest_sha256": pathdoc.get("path_observability_v1_digest_sha256"),
        "path_observability_v2_digest_sha256": pathdoc.get("path_observability_digest_sha256"),
    }

def _one_heldout_row_v2(*args: Any, **kwargs: Any) -> dict[str, Any]:
    global _last_pathdoc
    _last_pathdoc = None
    row = _original_one_heldout_row(*args, **kwargs)
    row["helper_polarity_evidence"] = _evidence(_last_pathdoc)
    return row

base.build_path_observability = _capture_path_observability
base.one_heldout_row = _one_heldout_row_v2

if __name__ == "__main__":
    raise SystemExit(base.main())
