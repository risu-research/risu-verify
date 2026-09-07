from __future__ import annotations

"""Independent semantic recomputation for reconstructed C1 slices."""

from typing import Any, Mapping

from .common import INCOMPLETE, PRESERVATION, REGRESSION, _canonical_bytes

def _lineage_ok(binding: Mapping[str, Any]) -> bool:
    observed = list(binding.get("observed_origins", []) or [])
    rows = binding.get("lineage_paths", []) or []
    for origin in observed:
        ps = [r.get("edges", []) or [] for r in rows if r.get("origin") == origin]
        if len(ps) != 1 or not ps[0]: return False
        edges = ps[0]; prev = origin; pid = edges[0].get("path_id")
        for e in edges:
            if e.get("kind") not in {"DERIVES", "CARRIES", "BINDS_TO"}: return False
            if e.get("from") != prev or e.get("path_id") != pid: return False
            prev = e.get("to")
        if prev != binding.get("binding_id"): return False
    return True


def _independent_semantic_eval(doc: Mapping[str, Any]) -> dict[str, Any]:
    """Small independent recomputation; intentionally not code-shared with producer kernel."""
    reasons: list[str] = []
    admissions: dict[str, bool] = {}
    bindings = list(doc.get("bindings", []) or [])
    admissions["A"] = bool(bindings) and all(b.get("coordinate_identity") and b.get("resource_identity") and b.get("slot_identity") and b.get("observed_origins") and not b.get("identity_ambiguous") for b in bindings)
    admissions["B"] = admissions["A"] and all(_lineage_ok(b) and not b.get("may_flow_only") for b in bindings)
    g = doc.get("guard", {}) or {}
    admissions["C"] = g.get("form") == "DIRECT_CONTROL" and g.get("effective_guard_count") == 1 and bool(g.get("effective_guard_id")) and g.get("net_polarity") == "PRESERVE"
    paths = list(doc.get("control_paths", []) or [])
    gid = str(g.get("effective_guard_id", ""))
    d_ok = bool(paths)
    for p in paths:
        ev = list(p.get("events", []) or []); effect = next((i for i,x in enumerate(ev) if str(x).startswith("EFFECT:")), None); guard = next((i for i,x in enumerate(ev) if x == f"GUARD:{gid}"), None)
        if p.get("complete") is not True or not ev or ev[0] != "ENTRY": d_ok = False
        if effect is not None and (guard is None or guard > effect): d_ok = False
    admissions["D"] = d_ok
    e = doc.get("effect", {}) or {}
    admissions["E"] = len(e.get("surfaces", []) or []) == 1 and bool(e.get("success_outcome_id")) and bool(e.get("rejection_outcome_id")) and e.get("success_outcome_id") != e.get("rejection_outcome_id") and e.get("effect_before_success_structural") is True
    s = doc.get("scope", {}) or {}
    flags = ("aliases_complete","call_targets_complete","reaching_definitions_complete","branches_complete","representations_complete","effects_complete","exceptions_exits_complete","resources_complete","helper_polarity_complete","all_entry_paths_enumerated")
    admissions["F"] = s.get("complete") is True and not (s.get("unresolved", []) or []) and all(s.get(k) is True for k in flags)

    witnesses: list[str] = []
    for b in bindings:
        allowed = set(b.get("allowed_origins", []) or []); observed = set(b.get("observed_origins", []) or [])
        if b.get("binding_complete") is True and len(observed) == 1 and observed - allowed:
            witnesses.append("A3_R1_WRONG_BINDING_IDENTITY")
        if b.get("binding_complete") is True and allowed and observed and not (allowed & observed):
            witnesses.append("A3_R3_EXPLICIT_CARRIER_SUBSTITUTION_OR_DROP")
        if any(x.get("kind") == "KILL" and x.get("required_definition_killed") is True for x in b.get("definition_trace", []) or []) and observed - allowed:
            witnesses.append("A3_R2_DEFINITE_OVERWRITE_TO_WRONG_CARRIER")
    effect_pol = str(g.get("effect_polarity")); reject_pol = str(g.get("rejection_polarity"))
    for p in paths:
        ev = list(p.get("events", []) or []); pid = str(p.get("path_id"))
        ei = next((i for i,x in enumerate(ev) if str(x).startswith("EFFECT:")), None); gi = next((i for i,x in enumerate(ev) if x == f"GUARD:{gid}"), None)
        ri = next((i for i,x in enumerate(ev) if str(x).startswith("REJECTION:")), None); si = next((i for i,x in enumerate(ev) if str(x).startswith("SUCCESS:")), None)
        if ei is not None and gi is None: witnesses.append("A4_R1_GUARD_BYPASS")
        if ei is not None and gi is not None and ei < gi: witnesses.append("A4_R2_EFFECT_BEFORE_GUARD")
        if p.get("guard_polarity") == reject_pol and ei is not None and (ri is None or ei < ri): witnesses.append("A4_R3_REJECTION_BRANCH_REACHES_EFFECT")
        if p.get("guard_polarity") == reject_pol and si is not None: witnesses.append("A4_R6_REJECTION_COLLAPSED_TO_SUCCESS")
    ep = [p for p in paths if p.get("guard_polarity") == effect_pol]; rp = [p for p in paths if p.get("guard_polarity") == reject_pol]
    has_eff = lambda p: any(str(x).startswith("EFFECT:") for x in p.get("events", []) or [])
    has_rej = lambda p: any(str(x).startswith("REJECTION:") for x in p.get("events", []) or [])
    has_suc = lambda p: any(str(x).startswith("SUCCESS:") for x in p.get("events", []) or [])
    if ep and rp and any(map(has_eff,ep)) and any(map(has_eff,rp)): witnesses.append("A4_R4_EFFECT_ON_BOTH_POLARITIES")
    effect_only_rejects = bool(ep) and all((not has_eff(p)) and has_rej(p) for p in ep)
    reject_eff_success = bool(rp) and any(has_eff(p) and has_suc(p) for p in rp)
    if effect_only_rejects and reject_eff_success: witnesses.append("A4_R5_POLARITY_INVERSION")
    if effect_only_rejects: witnesses.append("A4_R7_REQUIRED_EFFECT_PATH_REJECTED")

    worlds = list(doc.get("worlds", []) or []); world_complete = bool(worlds) and all(w.get("kappa") not in (None,"",[],{}) and w.get("rho") not in (None,"",[],{}) for w in worlds)
    pairs: list[list[str]] = []
    for i,a in enumerate(worlds):
        for b in worlds[i+1:]:
            if _canonical_bytes(a.get("rho")) == _canonical_bytes(b.get("rho")) and _canonical_bytes(a.get("kappa")) != _canonical_bytes(b.get("kappa")):
                pairs.append([str(a.get("id")),str(b.get("id"))])

    binding_preserved = bool(bindings) and all(set(b.get("observed_origins", []) or []).issubset(set(b.get("allowed_origins", []) or [])) and bool(b.get("observed_origins")) for b in bindings)
    polarity_ok = bool(ep) and bool(rp) and all(has_eff(p) and has_suc(p) for p in ep) and all((not has_eff(p)) and has_rej(p) for p in rp)
    obligations = {
        "A3_P1_REQUIRED_ROLE_REACHABILITY": binding_preserved,
        "A3_P2_BINDING_IDENTITY": admissions["A"],
        "A3_P3_DEFINITION_SENSITIVITY": all(b.get("definitions_complete") is True for b in bindings),
        "A3_P4_REPRESENTATION_SURVIVAL": all(not (b.get("representation", {}) or {}).get("required") or ((b.get("representation", {}) or {}).get("closure_complete") is True and (b.get("representation", {}) or {}).get("required_slot_present") is True) for b in bindings),
        "A3_P5_PATH_REALIZABILITY": admissions["B"] and all(p.get("realizable") is True for p in paths),
        "A4_P1_EFFECT_BOUNDARY": admissions["E"], "A4_P2_EFFECTIVE_GUARD": admissions["C"],
        "A4_P3_GUARD_DOMINATES_EFFECT": admissions["D"], "A4_P4_CANONICAL_POLARITY": polarity_ok,
        "A4_P5_NO_BYPASS_OR_FALLBACK": admissions["D"] and bool(rp) and all(not has_eff(p) for p in rp),
        "A4_P6_ORDERING": bool(ep) and all(next(i for i,x in enumerate(p["events"]) if str(x).startswith("EFFECT:")) < next(i for i,x in enumerate(p["events"]) if str(x).startswith("SUCCESS:")) for p in ep if has_eff(p) and has_suc(p)),
        "A4_P7_OUTCOME_DISTINCTION": admissions["E"],
    }
    if pairs and witnesses: prediction = REGRESSION
    elif world_complete and not pairs and all(admissions.values()) and all(obligations.values()): prediction = PRESERVATION
    else: prediction = INCOMPLETE
    return {"prediction":prediction,"admissions":admissions,"obligations":obligations,"witness_ids":sorted(set(witnesses)),"world_relation":{"complete":world_complete,"violating_pairs":pairs}}
