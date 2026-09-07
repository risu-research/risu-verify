from __future__ import annotations

"""Small fail-closed semantic kernel for E2 Gate 1B/1C.

This module intentionally does *not* parse source code and does not import the
primary E2 frontend/IR.  It evaluates a finite, proof-carrying semantic slice.
The certificate producer is untrusted; C1 independently reconstructs the slice
from raw bytes before treating a result as definitive.
"""

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Iterable, Mapping, Sequence

SLICE_SCHEMA = "risu.e2-semantic-slice/v0.1"
RESULT_SCHEMA = "risu.e2-semantic-kernel-result/v0.1"

REGRESSION = "E2_PREDICTED_REGRESSION_WITNESS"
PRESERVATION = "E2_PREDICTED_PRESERVATION_EVIDENCE"
INCOMPLETE = "E2_PREDICTED_ASSURANCE_INCOMPLETE"
INFRA_INVALID = "INFRASTRUCTURE_INVALID_BEFORE_PREDICTION"

ALLOWED_LINEAGE = frozenset({"DERIVES", "CARRIES", "BINDS_TO"})
SCOPE_FLAGS = (
    "aliases_complete",
    "call_targets_complete",
    "reaching_definitions_complete",
    "branches_complete",
    "representations_complete",
    "effects_complete",
    "exceptions_exits_complete",
    "resources_complete",
    "helper_polarity_complete",
    "all_entry_paths_enumerated",
)


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _nonempty(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, (str, bytes, Sequence, Mapping)) and len(value) == 0:
        return False
    return True


def _stable(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


@dataclass(frozen=True)
class Admission:
    id: str
    satisfied: bool
    reasons: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {"id": self.id, "satisfied": self.satisfied, "reasons": list(self.reasons)}


def _fail(admission_id: str, reasons: Iterable[str]) -> Admission:
    rows = tuple(sorted(set(str(x) for x in reasons if x)))
    return Admission(admission_id, not rows, rows)


def _binding_map(doc: Mapping[str, Any]) -> tuple[dict[str, Mapping[str, Any]], list[str]]:
    out: dict[str, Mapping[str, Any]] = {}
    bad: list[str] = []
    for row in doc.get("bindings", []) or []:
        bid = str(row.get("binding_id", ""))
        if not bid:
            bad.append("A_BINDING_ID_MISSING")
            continue
        if bid in out:
            bad.append(f"A_DUPLICATE_BINDING:{bid}")
            continue
        out[bid] = row
    return out, bad


def _admit_A(doc: Mapping[str, Any]) -> Admission:
    bindings, bad = _binding_map(doc)
    if not bindings:
        bad.append("A_NO_MATERIAL_BINDINGS")
    for bid, b in bindings.items():
        for key in ("coordinate_identity", "resource_identity", "slot_identity"):
            if not _nonempty(b.get(key)):
                bad.append(f"A_UNRESOLVED_{key.upper()}:{bid}")
        observed = [str(x) for x in b.get("observed_origins", [])]
        if not observed:
            bad.append(f"A_NO_OBSERVED_ORIGIN:{bid}")
        if len(set(observed)) != len(observed):
            bad.append(f"A_DUPLICATE_OBSERVED_ORIGIN:{bid}")
        if b.get("identity_ambiguous") is True:
            bad.append(f"A_IDENTITY_AMBIGUOUS:{bid}")
    return _fail("A_COORDINATE_RESOURCE_IDENTITY", bad)


def _lineage_path_ok(path: Sequence[Mapping[str, Any]], *, origin: str, binding_id: str) -> tuple[bool, str | None]:
    if not path:
        return False, "EMPTY"
    first = path[0]
    last = path[-1]
    if str(first.get("from")) != origin:
        return False, "WRONG_START"
    if str(last.get("to")) != binding_id:
        return False, "WRONG_END"
    pid = str(first.get("path_id", ""))
    if not pid:
        return False, "PATH_ID_MISSING"
    previous = str(first.get("from"))
    for edge in path:
        if edge.get("kind") not in ALLOWED_LINEAGE:
            return False, "BAD_EDGE_KIND"
        if str(edge.get("path_id", "")) != pid:
            return False, "PATH_ID_SPLIT"
        if str(edge.get("from")) != previous:
            return False, "NONCONTIGUOUS"
        previous = str(edge.get("to"))
    return True, None


def _admit_B(doc: Mapping[str, Any]) -> Admission:
    bad: list[str] = []
    bindings, _ = _binding_map(doc)
    for bid, b in bindings.items():
        observed = [str(x) for x in b.get("observed_origins", [])]
        rows = b.get("lineage_paths", []) or []
        by_origin: dict[str, list[Sequence[Mapping[str, Any]]]] = {}
        for row in rows:
            by_origin.setdefault(str(row.get("origin", "")), []).append(row.get("edges", []) or [])
        for origin in observed:
            paths = by_origin.get(origin, [])
            if len(paths) != 1:
                bad.append(f"B_LINEAGE_NOT_UNIQUE:{bid}:{origin}")
                continue
            ok, why = _lineage_path_ok(paths[0], origin=origin, binding_id=bid)
            if not ok:
                bad.append(f"B_LINEAGE_{why}:{bid}:{origin}")
        if b.get("may_flow_only") is True:
            bad.append(f"B_MAY_FLOW_ONLY:{bid}")
    return _fail("B_CARRIER_SURVIVAL", bad)


def _helper_net_polarity(chain: Sequence[Mapping[str, Any]]) -> str | None:
    parity = 0
    for hop in chain:
        transform = hop.get("transform")
        if transform == "PRESERVE":
            continue
        if transform == "FLIP":
            parity ^= 1
            continue
        return None
    return "FLIP" if parity else "PRESERVE"


def _admit_C(doc: Mapping[str, Any]) -> Admission:
    g = doc.get("guard", {}) or {}
    bad: list[str] = []
    form = g.get("form")
    if form not in {"DIRECT_CONTROL", "HELPER_CONTROL"}:
        bad.append("C_EFFECTIVE_GUARD_FORM_UNRESOLVED")
    if not _nonempty(g.get("effective_guard_id")):
        bad.append("C_EFFECTIVE_GUARD_NOT_UNIQUE")
    if g.get("effective_guard_count", 1) != 1:
        bad.append("C_EFFECTIVE_GUARD_NOT_UNIQUE")
    if form == "HELPER_CONTROL":
        chain = g.get("helper_chain", []) or []
        if not chain:
            bad.append("C_HELPER_CHAIN_MISSING")
        else:
            net = _helper_net_polarity(chain)
            if net is None:
                bad.append("C_HELPER_POLARITY_UNKNOWN")
            elif net != g.get("net_polarity"):
                bad.append("C_HELPER_NET_POLARITY_MISMATCH")
    elif form == "DIRECT_CONTROL" and g.get("net_polarity", "PRESERVE") != "PRESERVE":
        bad.append("C_DIRECT_CONTROL_NONPRESERVE_POLARITY")
    return _fail("C_GUARD_SEMANTICS", bad)


def _path_events(row: Mapping[str, Any]) -> list[str]:
    return [str(x) for x in row.get("events", [])]


def _index_prefix(events: Sequence[str], prefix: str) -> int | None:
    for i, item in enumerate(events):
        if item == prefix or item.startswith(prefix + ":"):
            return i
    return None


def _effect_paths(doc: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    return [p for p in doc.get("control_paths", []) or [] if _index_prefix(_path_events(p), "EFFECT") is not None]


def _admit_D(doc: Mapping[str, Any]) -> Admission:
    bad: list[str] = []
    paths = doc.get("control_paths", []) or []
    if not paths:
        bad.append("D_NO_COMPLETE_CONTROL_PATHS")
    guard_id = str((doc.get("guard", {}) or {}).get("effective_guard_id", ""))
    for row in paths:
        pid = str(row.get("path_id", "<missing>"))
        if row.get("complete") is not True:
            bad.append(f"D_PATH_INCOMPLETE:{pid}")
        events = _path_events(row)
        if not events or events[0] != "ENTRY":
            bad.append(f"D_PATH_NO_ENTRY:{pid}")
        ei = _index_prefix(events, "EFFECT")
        if ei is not None:
            gi = _index_prefix(events, f"GUARD:{guard_id}") if guard_id else None
            if gi is None:
                bad.append(f"D_GUARD_BYPASS:{pid}")
            elif gi > ei:
                bad.append(f"D_EFFECT_BEFORE_GUARD:{pid}")
    return _fail("D_GUARD_EFFECT_CONTROL", bad)


def _admit_E(doc: Mapping[str, Any]) -> Admission:
    e = doc.get("effect", {}) or {}
    bad: list[str] = []
    surfaces = e.get("surfaces", []) or []
    if len(surfaces) != 1 and not _nonempty(e.get("equivalence_proof_id")):
        bad.append("E_EFFECT_SURFACE_NOT_UNIQUE")
    if not _nonempty(e.get("success_outcome_id")):
        bad.append("E_SUCCESS_OUTCOME_MISSING")
    if not _nonempty(e.get("rejection_outcome_id")):
        bad.append("E_REJECTION_OUTCOME_MISSING")
    if e.get("success_outcome_id") == e.get("rejection_outcome_id") and _nonempty(e.get("success_outcome_id")):
        bad.append("E_OUTCOMES_COLLAPSED")
    if e.get("effect_before_success_structural") is not True:
        bad.append("E_EFFECT_BEFORE_SUCCESS_UNPROVEN")
    return _fail("E_EFFECT_AND_OUTCOME", bad)


def _admit_F(doc: Mapping[str, Any]) -> Admission:
    s = doc.get("scope", {}) or {}
    bad: list[str] = []
    if s.get("complete") is not True:
        bad.append("F_SCOPE_NOT_COMPLETE")
    unresolved = s.get("unresolved", []) or []
    for item in unresolved:
        bad.append(f"F_UNRESOLVED:{item}")
    for flag in SCOPE_FLAGS:
        if s.get(flag) is not True:
            bad.append(f"F_FLAG_FALSE:{flag}")
    return _fail("F_CLOSED_SCOPE", bad)


def _world_relation(doc: Mapping[str, Any]) -> tuple[bool, list[tuple[str, str]]]:
    worlds = doc.get("worlds", []) or []
    if not worlds:
        return False, []
    for w in worlds:
        if not _nonempty(w.get("kappa")) or not _nonempty(w.get("rho")):
            return False, []
    violating: list[tuple[str, str]] = []
    for i, a in enumerate(worlds):
        for b in worlds[i + 1 :]:
            if _stable(a.get("rho")) == _stable(b.get("rho")) and _stable(a.get("kappa")) != _stable(b.get("kappa")):
                violating.append((str(a.get("id")), str(b.get("id"))))
    return True, violating


def _binding_preserved(b: Mapping[str, Any]) -> bool:
    allowed = set(str(x) for x in b.get("allowed_origins", []) or [])
    observed = set(str(x) for x in b.get("observed_origins", []) or [])
    return bool(allowed) and bool(observed) and observed.issubset(allowed)


def _a3_witnesses(doc: Mapping[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    bindings, _ = _binding_map(doc)
    for bid, b in bindings.items():
        if b.get("binding_complete") is not True:
            continue
        allowed = set(str(x) for x in b.get("allowed_origins", []) or [])
        observed = set(str(x) for x in b.get("observed_origins", []) or [])
        wrong = sorted(observed - allowed)
        if len(observed) == 1 and wrong and _nonempty(b.get("slot_identity")):
            out.append({"witness_id": "A3_R1_WRONG_BINDING_IDENTITY", "binding_id": bid, "wrong_origin": wrong[0]})
        trace = b.get("definition_trace", []) or []
        kills = [r for r in trace if r.get("kind") == "KILL" and r.get("required_definition_killed") is True]
        if kills and wrong:
            out.append({"witness_id": "A3_R2_DEFINITE_OVERWRITE_TO_WRONG_CARRIER", "binding_id": bid, "wrong_origin": wrong[0]})
        if allowed and observed and not (allowed & observed):
            out.append({"witness_id": "A3_R3_EXPLICIT_CARRIER_SUBSTITUTION_OR_DROP", "binding_id": bid, "alternative_origins": sorted(observed)})
        rep = b.get("representation", {}) or {}
        if rep.get("closure_complete") is True and rep.get("required_slot_present") is False:
            out.append({"witness_id": "A3_R4_CLOSED_REPRESENTATION_OMISSION", "binding_id": bid, "representation_instance_id": rep.get("instance_id")})
    # Deterministic de-duplication.
    seen: set[str] = set()
    rows: list[dict[str, Any]] = []
    for item in out:
        key = _stable(item)
        if key not in seen:
            rows.append(item); seen.add(key)
    return rows


def _polarity_paths(doc: Mapping[str, Any], polarity: str) -> list[Mapping[str, Any]]:
    return [p for p in doc.get("control_paths", []) or [] if str(p.get("guard_polarity")) == polarity and p.get("complete") is True]


def _a4_witnesses(doc: Mapping[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    g = doc.get("guard", {}) or {}
    gid = str(g.get("effective_guard_id", ""))
    effect_pol = str(g.get("effect_polarity", ""))
    reject_pol = str(g.get("rejection_polarity", ""))
    paths = [p for p in doc.get("control_paths", []) or [] if p.get("complete") is True]

    for p in paths:
        events = _path_events(p); pid = str(p.get("path_id"))
        ei = _index_prefix(events, "EFFECT")
        gi = _index_prefix(events, f"GUARD:{gid}") if gid else None
        ri = _index_prefix(events, "REJECTION")
        si = _index_prefix(events, "SUCCESS")
        if ei is not None and gi is None:
            out.append({"witness_id": "A4_R1_GUARD_BYPASS", "path_id": pid})
        elif ei is not None and gi is not None and ei < gi:
            out.append({"witness_id": "A4_R2_EFFECT_BEFORE_GUARD", "path_id": pid})
        if str(p.get("guard_polarity")) == reject_pol and ei is not None and (ri is None or ei < ri):
            out.append({"witness_id": "A4_R3_REJECTION_BRANCH_REACHES_EFFECT", "path_id": pid})
        if str(p.get("guard_polarity")) == reject_pol and si is not None:
            out.append({"witness_id": "A4_R6_REJECTION_COLLAPSED_TO_SUCCESS", "path_id": pid})

    if effect_pol and reject_pol:
        ep = _polarity_paths(doc, effect_pol); rp = _polarity_paths(doc, reject_pol)
        if ep and rp and any(_index_prefix(_path_events(p), "EFFECT") is not None for p in ep) and any(_index_prefix(_path_events(p), "EFFECT") is not None for p in rp):
            out.append({"witness_id": "A4_R4_EFFECT_ON_BOTH_POLARITIES"})
        if ep and rp:
            reject_has_effect_success = any(_index_prefix(_path_events(p), "EFFECT") is not None and _index_prefix(_path_events(p), "SUCCESS") is not None for p in rp)
            effect_only_rejects = all(_index_prefix(_path_events(p), "EFFECT") is None and _index_prefix(_path_events(p), "REJECTION") is not None for p in ep)
            if reject_has_effect_success and effect_only_rejects:
                out.append({"witness_id": "A4_R5_POLARITY_INVERSION"})
            if effect_only_rejects:
                out.append({"witness_id": "A4_R7_REQUIRED_EFFECT_PATH_REJECTED"})

    seen: set[str] = set(); rows: list[dict[str, Any]] = []
    for item in out:
        key = _stable(item)
        if key not in seen:
            rows.append(item); seen.add(key)
    return rows


def _preservation_obligations(doc: Mapping[str, Any], admissions: Mapping[str, Admission]) -> dict[str, bool]:
    bindings = list((doc.get("bindings", []) or []))
    paths = [p for p in doc.get("control_paths", []) or [] if p.get("complete") is True]
    g = doc.get("guard", {}) or {}
    e = doc.get("effect", {}) or {}
    gid = str(g.get("effective_guard_id", ""))
    effect_pol = str(g.get("effect_polarity", "")); reject_pol = str(g.get("rejection_polarity", ""))
    ep = _polarity_paths(doc, effect_pol) if effect_pol else []
    rp = _polarity_paths(doc, reject_pol) if reject_pol else []

    def guarded_effect(p: Mapping[str, Any]) -> bool:
        ev = _path_events(p); ei = _index_prefix(ev, "EFFECT")
        if ei is None: return True
        gi = _index_prefix(ev, f"GUARD:{gid}")
        return gi is not None and gi < ei

    p = {
        "A3_P1_REQUIRED_ROLE_REACHABILITY": bool(bindings) and all(_binding_preserved(b) for b in bindings),
        "A3_P2_BINDING_IDENTITY": admissions["A"].satisfied,
        "A3_P3_DEFINITION_SENSITIVITY": all(b.get("definitions_complete") is True for b in bindings),
        "A3_P4_REPRESENTATION_SURVIVAL": all((b.get("representation", {}) or {}).get("required", False) is False or ((b.get("representation", {}) or {}).get("closure_complete") is True and (b.get("representation", {}) or {}).get("required_slot_present") is True) for b in bindings),
        "A3_P5_PATH_REALIZABILITY": admissions["B"].satisfied and bool(paths) and all(pth.get("realizable") is True for pth in paths),
        "A4_P1_EFFECT_BOUNDARY": admissions["E"].satisfied,
        "A4_P2_EFFECTIVE_GUARD": admissions["C"].satisfied,
        "A4_P3_GUARD_DOMINATES_EFFECT": bool(paths) and all(guarded_effect(pth) for pth in paths),
        "A4_P4_CANONICAL_POLARITY": bool(ep) and bool(rp) and all(_index_prefix(_path_events(x), "EFFECT") is not None and _index_prefix(_path_events(x), "SUCCESS") is not None for x in ep) and all(_index_prefix(_path_events(x), "EFFECT") is None and _index_prefix(_path_events(x), "REJECTION") is not None for x in rp),
        "A4_P5_NO_BYPASS_OR_FALLBACK": admissions["D"].satisfied and bool(rp) and all(_index_prefix(_path_events(x), "EFFECT") is None for x in rp),
        "A4_P6_ORDERING": bool(ep) and all((_index_prefix(_path_events(x), "EFFECT") is not None and _index_prefix(_path_events(x), "SUCCESS") is not None and _index_prefix(_path_events(x), "EFFECT") < _index_prefix(_path_events(x), "SUCCESS")) for x in ep),
        "A4_P7_OUTCOME_DISTINCTION": _nonempty(e.get("success_outcome_id")) and _nonempty(e.get("rejection_outcome_id")) and e.get("success_outcome_id") != e.get("rejection_outcome_id"),
    }
    return p


def evaluate(doc: Mapping[str, Any]) -> dict[str, Any]:
    """Evaluate a finite semantic slice. Never upgrades missing evidence."""
    infrastructure: list[str] = []
    if doc.get("schema") != SLICE_SCHEMA:
        infrastructure.append("SEMANTIC_SLICE_SCHEMA_MISMATCH")
    if not _nonempty(doc.get("case_id")):
        infrastructure.append("CASE_ID_MISSING")
    if not _nonempty(doc.get("canonical_signature_digest")):
        infrastructure.append("CANONICAL_SIGNATURE_DIGEST_MISSING")
    if infrastructure:
        result = {
            "schema": RESULT_SCHEMA,
            "prediction": INFRA_INVALID,
            "infrastructure_reasons": sorted(infrastructure),
            "admissions": {}, "obligations": {}, "witnesses": [], "world_relation": {},
        }
        result["result_digest_sha256"] = sha256_json(result)
        return result

    admissions = {
        "A": _admit_A(doc), "B": _admit_B(doc), "C": _admit_C(doc),
        "D": _admit_D(doc), "E": _admit_E(doc), "F": _admit_F(doc),
    }
    world_complete, violating_pairs = _world_relation(doc)
    a3 = _a3_witnesses(doc); a4 = _a4_witnesses(doc)
    witnesses = a3 + a4
    obligations = _preservation_obligations(doc, admissions)

    # A constructive preregistered witness is necessary but not sufficient: the
    # world relation must also exhibit a CTV collapse pair. This prevents local
    # anomalies from being promoted beyond the frozen consequence semantics.
    if witnesses and violating_pairs:
        prediction = REGRESSION
    else:
        all_admitted = all(x.satisfied for x in admissions.values())
        all_obligations = bool(obligations) and all(obligations.values())
        if world_complete and not violating_pairs and all_admitted and all_obligations:
            prediction = PRESERVATION
        else:
            prediction = INCOMPLETE

    unresolved = sorted({reason for a in admissions.values() for reason in a.reasons})
    if not world_complete:
        unresolved.append("WORLD_INTERPRETATION_INCOMPLETE")
    if violating_pairs and not witnesses:
        unresolved.append("CTV_COLLAPSE_WITHOUT_ADMITTED_CONSTRUCTIVE_WITNESS")
    for key, ok in obligations.items():
        if not ok:
            unresolved.append(f"OBLIGATION_UNPROVEN:{key}")
    result = {
        "schema": RESULT_SCHEMA,
        "prediction": prediction,
        "infrastructure_reasons": [],
        "admissions": {k: v.as_dict() for k, v in admissions.items()},
        "obligations": obligations,
        "witnesses": witnesses,
        "world_relation": {"complete": world_complete, "violating_pairs": [list(x) for x in violating_pairs]},
        "unresolved": sorted(set(unresolved)),
        "declared_scope_id": (doc.get("scope", {}) or {}).get("scope_id"),
    }
    result["result_digest_sha256"] = sha256_json(result)
    return result
