from __future__ import annotations

import copy
import hashlib
from typing import Any, Mapping, Sequence

from .model import canonical_bytes
from .path_observability import build_path_observability as build_path_observability_v1
from .predicate_polarity_v1 import prove_python_helper_polarity

SCHEMA = "risu.e2-path-observability/v0.2"


def _sp(node: Mapping[str, Any]) -> tuple[int, int, int, int]:
    span = node["span"]
    return (int(span["start_line"]), int(span["start_col"]), int(span["end_line"]), int(span["end_col"]))


def _contains(outer: Sequence[int], inner: Sequence[int]) -> bool:
    return (int(outer[0]), int(outer[1])) <= (int(inner[0]), int(inner[1])) and (int(inner[2]), int(inner[3])) <= (int(outer[2]), int(outer[3]))


def _branch_bearing(overlay: Mapping[str, Any], guard_id: str) -> bool:
    polarities = {
        edge.get("attrs", {}).get("branch_polarity")
        for edge in overlay.get("edges", [])
        if edge.get("kind") == "GUARDS" and edge.get("source") == guard_id
    }
    return True in polarities and False in polarities


def _transported_comparison_span(overlay: Mapping[str, Any]) -> list[int] | None:
    rows = [
        node for node in overlay.get("nodes", [])
        if node.get("kind") == "GUARD" and node.get("attrs", {}).get("anchor_role") == "GUARD_COMPARISON"
    ]
    if len(rows) != 1:
        return None
    return list(_sp(rows[0]))


def _bind_branch_guard(overlay: Mapping[str, Any], branch_span: Sequence[int]) -> str | None:
    candidates = []
    for node in overlay.get("nodes", []):
        if node.get("kind") != "GUARD" or not _branch_bearing(overlay, str(node.get("id"))):
            continue
        span = list(_sp(node))
        if span == list(map(int, branch_span)) or _contains(span, branch_span) or _contains(branch_span, span):
            candidates.append(node)
    if not candidates:
        return None
    candidates.sort(key=lambda node: (((_sp(node)[2] - _sp(node)[0]) * 100000 + (_sp(node)[3] - _sp(node)[1])), str(node["id"])))
    best = candidates[0]
    best_size = ((_sp(best)[2] - _sp(best)[0]) * 100000 + (_sp(best)[3] - _sp(best)[1]))
    tied = [node for node in candidates if ((_sp(node)[2] - _sp(node)[0]) * 100000 + (_sp(node)[3] - _sp(node)[1])) == best_size]
    return str(best["id"]) if len(tied) == 1 else None


def _normalize_guard_decisions(document: dict[str, Any], guard_id: str, relation: str, certificate_sha256: str) -> None:
    for state in document.get("path_states", []):
        for decision in state.get("guard_decisions", []):
            if decision.get("guard_id") != guard_id or type(decision.get("polarity")) is not bool:
                continue
            branch_truth = bool(decision["polarity"])
            transported_truth = branch_truth if relation == "SAME" else (not branch_truth)
            decision["transported_guard_truth"] = transported_truth
            decision["polarity_to_transported_guard"] = relation
            decision["polarity_certificate_sha256"] = certificate_sha256
    for collection in ("entry_effect_paths", "rejection_paths", "success_paths"):
        for row in document.get(collection, []):
            for decision in row.get("guard_decisions", []):
                if decision.get("guard_id") != guard_id or type(decision.get("polarity")) is not bool:
                    continue
                branch_truth = bool(decision["polarity"])
                decision["transported_guard_truth"] = branch_truth if relation == "SAME" else (not branch_truth)
                decision["polarity_to_transported_guard"] = relation
                decision["polarity_certificate_sha256"] = certificate_sha256


def build_path_observability(
    *, path: str, source: str, source_sha256: str, language: str,
    facts: Sequence[Mapping[str, Any]], overlay: Mapping[str, Any],
    canonical_signature: Mapping[str, Any],
) -> dict[str, Any]:
    base = build_path_observability_v1(
        path=path,
        source=source,
        source_sha256=source_sha256,
        language=language,
        facts=facts,
        overlay=overlay,
        canonical_signature=canonical_signature,
    )
    document = copy.deepcopy(base)
    document["schema"] = SCHEMA
    guard = document.get("effective_guard_observability", {})
    guard.setdefault("polarity_certificate_status", "NOT_APPLICABLE")
    guard.setdefault("polarity_to_transported_guard", None)
    guard.setdefault("polarity_certificate_sha256", None)

    eligible_for_additive_proof = (
        language == "python"
        and guard.get("form") == "UNPROVEN"
        and guard.get("reason") == "HELPER_PREDICATE_POLARITY_UNPROVEN"
    )
    if eligible_for_additive_proof:
        root_span = _transported_comparison_span(overlay)
        if root_span is None:
            guard["polarity_certificate_status"] = "UNKNOWN"
            guard["reason"] = "HELPER_PREDICATE_POLARITY_UNPROVEN"
        else:
            certificate = prove_python_helper_polarity(source, root_span)
            guard["polarity_certificate_status"] = certificate["status"]
            guard["polarity_to_transported_guard"] = certificate["final_relation"] if certificate["status"] == "PROVED" else None
            guard["polarity_certificate_sha256"] = certificate["certificate_sha256"]
            guard["polarity_certificate_reason"] = certificate["reason"]
            guard["polarity_certificate_flip_count"] = certificate["flip_count"]
            if certificate["status"] == "PROVED" and certificate["branch_consumer_span"] is not None:
                branch_guard_id = _bind_branch_guard(overlay, certificate["branch_consumer_span"])
                if branch_guard_id is not None:
                    guard["form"] = "HELPER_CONTROL"
                    guard["guard_id"] = branch_guard_id
                    guard["reason"] = None
                    _normalize_guard_decisions(document, branch_guard_id, certificate["final_relation"], certificate["certificate_sha256"])
                else:
                    guard["reason"] = "HELPER_POLARITY_BRANCH_BINDING_UNPROVEN"
            else:
                guard["reason"] = "HELPER_PREDICATE_POLARITY_UNPROVEN"

    document["path_observability_v1_digest_sha256"] = base.get("path_observability_digest_sha256")
    document.pop("path_observability_digest_sha256", None)
    document["path_observability_digest_sha256"] = hashlib.sha256(canonical_bytes(document)).hexdigest()
    return document
