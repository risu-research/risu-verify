from __future__ import annotations

import re
from typing import Any, Dict


def _base(name: str, signals: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "baseline": name,
        "signals": signals,
        "consequence_authority": False,
        "authoritative_prediction": None,
    }


def b0_surface(surface: Dict[str, Any]) -> Dict[str, Any]:
    return _base("B0_SURFACE", {
        "callable": bool(surface.get("name")),
        "argument_names": sorted(surface.get("arguments", [])),
    })


def b1_name_shape(text: str) -> Dict[str, Any]:
    names = sorted(set(re.findall(r"\b[a-zA-Z_][a-zA-Z0-9_]*\b", text)))
    versionish = [n for n in names if any(tok in n.lower() for tok in ("sha", "etag", "version", "revision"))]
    return _base("B1_NAME_SHAPE", {"versionish_names": versionish})


def b2_flow_only(extraction: Dict[str, Any]) -> Dict[str, Any]:
    return _base("B2_FLOW_ONLY", {
        "candidate_count": len(extraction.get("coordinate_candidates", [])),
        "comparison_count": len(extraction.get("comparison_candidates", [])),
    })


def require_non_authoritative(result: Dict[str, Any]) -> None:
    if result.get("consequence_authority") is not False:
        raise ValueError("baseline authority escalation")
    if result.get("authoritative_prediction") is not None:
        raise ValueError("baseline emitted authoritative prediction")
