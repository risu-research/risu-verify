from __future__ import annotations

"""Canonical-only finite-world derivation for Gate1B/1C.

The output contains canonical source-role values plus source consequence kappa.
It never contains target rho.  Candidate, mutant, truth, operator metadata, and
fresh-target bytes are outside this module's input surface.
"""

import hashlib
import json
from typing import Any, Mapping

from risu_e2.predicate_polarity_v1 import prove_python_helper_polarity

WORLD_SCHEMA = "risu.e2-declared-finite-worlds/v0.1"
BUNDLE_SCHEMA = "risu.e2-declared-finite-worlds-bundle/v0.1"


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _normalize_operator(raw: str) -> str | None:
    if raw in {"Eq", "EQ", "==", "===", "EQL"}:
        return "EQ"
    if raw in {"NotEq", "NE", "!=", "!==", "NEQ"}:
        return "NE"
    return None


def _anchor_node(overlay: Mapping[str, Any], role: str) -> Mapping[str, Any]:
    rows = [n for n in overlay.get("nodes", []) if n.get("attrs", {}).get("anchor_role") == role]
    if len(rows) != 1:
        raise ValueError(f"anchor cardinality:{role}:{len(rows)}")
    return rows[0]


def _guard_operator(overlay: Mapping[str, Any], guard_id: str) -> str:
    rows: list[str] = []
    for edge in overlay.get("edges", []):
        if edge.get("kind") != "COMPARES" or str(edge.get("target")) != guard_id:
            continue
        idx = edge.get("attrs", {}).get("operand_index")
        if idx not in {0, 1}:
            continue
        ops = list(edge.get("attrs", {}).get("operators", []) or [])
        if len(ops) != 1:
            raise ValueError("canonical comparison operator cardinality")
        op = _normalize_operator(str(ops[0]))
        if op is None:
            raise ValueError("canonical comparison operator unsupported")
        rows.append(op)
    if not rows or len(set(rows)) != 1:
        raise ValueError("canonical comparison operator unresolved")
    return rows[0]


def _transported_truth(op: str, current: int, expected: int) -> bool:
    equal = current == expected
    if op == "EQ":
        return equal
    if op == "NE":
        return not equal
    raise ValueError("unsupported operator")


def _helper_relation(*, source: bytes, guard_span: list[int], form: str, language: str) -> tuple[str, dict[str, Any] | None]:
    if form == "DIRECT_CONTROL":
        return "SAME", None
    if form != "HELPER_CONTROL":
        raise ValueError("canonical guard form unsupported")
    if language != "python":
        raise ValueError("canonical helper extractor scope exceeded")
    cert = prove_python_helper_polarity(source.decode("utf-8"), guard_span)
    if cert.get("status") != "PROVED" or cert.get("final_relation") not in {"SAME", "INVERTED"}:
        raise ValueError("canonical helper polarity unproved")
    return str(cert["final_relation"]), cert


def _effective_truth(transported: bool, relation: str) -> bool:
    if relation == "SAME":
        return transported
    if relation == "INVERTED":
        return not transported
    raise ValueError("bad helper relation")


def derive_worlds(*, anchor_bundle: Mapping[str, Any], overlay_bundle: Mapping[str, Any],
                  signature_bundle: Mapping[str, Any], sources: Mapping[str, bytes]) -> dict[str, Any]:
    contracts = {str(x["seed_id"]): x for x in anchor_bundle.get("contracts", [])}
    overlays = {str(x["seed_id"]): x for x in overlay_bundle.get("overlays", [])}
    signatures = {str(x["seed_id"]): x for x in signature_bundle.get("signatures", [])}
    if set(contracts) != set(overlays) or set(contracts) != set(signatures) or len(contracts) != 6:
        raise ValueError("canonical six-seed identity mismatch")
    docs: list[dict[str, Any]] = []
    helper_receipts: list[dict[str, Any]] = []
    for seed_id in sorted(contracts):
        decl = contracts[seed_id]["declaration"]
        overlay = overlays[seed_id]["overlay"]
        sig = signatures[seed_id]
        source = sources.get(seed_id)
        if source is None or hashlib.sha256(source).hexdigest() != decl["source"]["sha256"]:
            raise ValueError(f"canonical source digest mismatch:{seed_id}")
        if sig.get("canonical_signature_digest_sha256") != digest({k:v for k,v in sig.items() if k != "canonical_signature_digest_sha256"}):
            raise ValueError(f"canonical signature digest mismatch:{seed_id}")
        guard = _anchor_node(overlay, "GUARD_COMPARISON")
        op = _guard_operator(overlay, str(guard["id"]))
        relation, cert = _helper_relation(source=source, guard_span=list(decl["anchors"]["guard_comparison"]["span"]),
                                          form=str(sig["effective_guard_form"]), language=str(decl["source"]["language"]))
        if cert is not None:
            helper_receipts.append({"seed_id":seed_id,"status":cert["status"],"final_relation":cert["final_relation"],
                                    "flip_count":cert["flip_count"],"certificate_sha256":cert["certificate_sha256"]})
        effect_pol = bool(sig["effect_polarity"]); rejection_pol = bool(sig["rejection_polarity"])
        if effect_pol == rejection_pol:
            raise ValueError(f"canonical polarities collapsed:{seed_id}")
        chosen: dict[bool, tuple[int,int]] = {}
        for current, expected in ((0,0),(0,1)):
            branch = _effective_truth(_transported_truth(op,current,expected), relation)
            chosen.setdefault(branch, (current,expected))
        if set(chosen) != {True, False}:
            raise ValueError(f"finite world separation failed:{seed_id}")
        worlds=[]
        for name, polarity, outcome in (
            ("effect", effect_pol, "SUCCESS_EFFECT"),
            ("rejection", rejection_pol, "REJECTION_NO_EFFECT"),
        ):
            current, expected = chosen[polarity]
            worlds.append({
                "id": f"{seed_id}:{name}",
                "role_values": {
                    "BOUND_VALUE:current_coordinate": current,
                    "BOUND_VALUE:expected_coordinate": expected,
                },
                "kappa": {"outcome": outcome},
            })
        doc={
            "schema":WORLD_SCHEMA,
            "seed_id":seed_id,
            "canonical_signature_digest_sha256":sig["canonical_signature_digest_sha256"],
            "worlds":worlds,
        }
        doc["document_digest_sha256"] = digest(doc)
        docs.append(doc)
    bundle={
        "schema":BUNDLE_SCHEMA,
        "semantic_authority":False,
        "seed_count":len(docs),
        "world_documents":docs,
        "helper_polarity_receipts":helper_receipts,
        "firewall":{
            "candidate_or_mutant_bytes_read":False,
            "mutation_truth_read":False,
            "operator_metadata_read":False,
            "target_rho_stored":False,
            "fresh_target_bytes_read":False,
        },
    }
    bundle["bundle_digest_sha256"] = digest(bundle)
    return bundle
