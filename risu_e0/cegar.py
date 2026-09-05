from __future__ import annotations

from typing import Any, Dict, List


PROBE_BY_OBLIGATION = {
    "authoritative_coordinate_established": "AUTHORITATIVE_VERSION_BINDING_PROBE",
    "current_coordinate_established": "CURRENT_AT_EFFECT_DISCOVERY_PROBE",
    "guard_established": "VERSION_MISMATCH_DISCRIMINATION_PROBE",
    "effect_established": "PRE_EFFECT_PLACEMENT_PROBE",
    "stale_outcome_established": "STALE_FAILURE_INTERPRETATION_PROBE",
    "authoritative_bound_to_guard": "AUTHORITATIVE_TO_GUARD_FLOW_PROBE",
    "current_compared_by_guard": "CURRENT_TO_GUARD_FLOW_PROBE",
    "guard_guards_effect": "PRE_EFFECT_GUARD_PROBE",
    "guard_rejects_as_stale": "STALE_REJECTION_PROBE",
}


def refinement_requests(obligations: Dict[str, bool]) -> List[Dict[str, Any]]:
    out = []
    for key in sorted(obligations):
        if not obligations[key]:
            out.append({
                "obligation": key,
                "request": PROBE_BY_OBLIGATION.get(key, "SEMANTIC_EVIDENCE_REQUEST"),
                "target_only": True,
                "may_change_source_contract": False,
                "may_change_evaluation_metric": False,
                "may_upgrade_without_evidence": False,
            })
    return out
