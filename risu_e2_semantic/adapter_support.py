from __future__ import annotations

"""Pure helper calculus for the ultra-thin primary semantic-slice adapter.

No source parsing and no file I/O occur here.
"""

import hashlib
import json
from collections import defaultdict
from typing import Any, Mapping, Sequence

SLICE_SCHEMA = "risu.e2-semantic-slice/v0.1"
WORLDS_SCHEMA = "risu.e2-declared-finite-worlds/v0.1"
ALLOWED_LINEAGE = {"DERIVES", "CARRIES", "BINDS_TO"}


def _canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _sp(node: Mapping[str, Any]) -> list[int]:
    s=node["span"]; return [int(s["start_line"]),int(s["start_col"]),int(s["end_line"]),int(s["end_col"])]


def _graph(overlay: Mapping[str, Any]):
    nodes={str(n["id"]):n for n in overlay.get("nodes",[])}
    incoming=defaultdict(list); outgoing=defaultdict(list)
    for e in overlay.get("edges",[]):
        incoming[str(e["target"])].append(e); outgoing[str(e["source"])].append(e)
    return nodes,incoming,outgoing


def _roots_and_path(overlay: Mapping[str, Any], value_id: str) -> list[tuple[str,list[Mapping[str,Any]]]]:
    nodes,incoming,_=_graph(overlay); out=[]; stack=[(value_id,[])]; seen=set()
    while stack:
        cur, rev=stack.pop(); key=(cur,tuple(str(x.get("id")) for x in rev))
        if key in seen: continue
        seen.add(key)
        parents=[e for e in incoming.get(cur,[]) if e.get("kind") in ALLOWED_LINEAGE]
        if nodes.get(cur,{}).get("attrs",{}).get("definition_role")=="function_parameter" or not parents:
            out.append((cur,list(reversed(rev)))); continue
        if len(rev)>=64: continue
        for e in parents: stack.append((str(e["source"]),rev+[e]))
    uniq={ (r,tuple(str(e.get("id")) for e in p)):(r,p) for r,p in out }
    return [uniq[k] for k in sorted(uniq)]


def _branch_guard_count(overlay: Mapping[str, Any], guard_id: str) -> int:
    _,_,outgoing=_graph(overlay)
    pol={e.get("attrs",{}).get("branch_polarity") for e in outgoing.get(guard_id,[]) if e.get("kind")=="GUARDS"}
    return 1 if True in pol and False in pol else 0


def _execution_signature(canonical: Mapping[str, Any], profile: Mapping[str, Any], worlds_doc: Mapping[str, Any]) -> dict[str, Any]:
    if worlds_doc.get("schema") != WORLDS_SCHEMA:
        raise ValueError("world declaration schema mismatch")
    if worlds_doc.get("seed_id") != canonical.get("seed_id"):
        raise ValueError("world declaration seed mismatch")
    if worlds_doc.get("canonical_signature_digest_sha256") != canonical.get("canonical_signature_digest_sha256"):
        raise ValueError("world declaration canonical digest mismatch")
    for world in worlds_doc.get("worlds",[]) or []:
        if "rho" in world:
            raise ValueError("world declaration may not supply target rho")
    source_roles={}
    for role,row in sorted((profile.get("source_roles",{}) or {}).items()):
        if row.get("status")!="RESOLVED":
            continue
        source_roles[role]={"parameter_index":int(row["parameter_index"]),"scope_role":"GUARD_ANCHOR_SCOPE"}
    required=[]
    for slot,row in sorted((canonical.get("required_binding_slot_roles",{}) or {}).items()):
        role=f"BOUND_VALUE:{slot}"
        required.append({
            "kind":"guard_operand","binding_id":f"GUARD_SLOT:{slot}",
            "operand_index":int(row["operand_index"]),
            "coordinate_identity":f"GUARD_SLOT:{slot}",
            "resource_identity":"RESOURCE:NOT_MATERIAL_IN_CANONICAL_SIGNATURE",
            "allowed_origins":[role],
        })
    return {
        "schema":"risu.e2-gate1b1c-execution-signature/v0.1",
        "seed_id":canonical["seed_id"],
        "canonical_signature_digest_sha256":canonical["canonical_signature_digest_sha256"],
        "source_roles":source_roles,
        "required_bindings":required,
        "guard":{
            "form":canonical["effective_guard_form"],
            "effect_polarity":str(bool(canonical["effect_polarity"])).lower(),
            "rejection_polarity":str(bool(canonical["rejection_polarity"])).lower(),
        },
        "effect":{"surface_id":"effect0","success_outcome_id":"success0","rejection_outcome_id":"rejection0"},
        "worlds":list(worlds_doc.get("worlds",[])),
    }


def _candidate_role_for_root(nodes: Mapping[str,Mapping[str,Any]], root: str, source_roles: Mapping[str,Any], guard_scope: str) -> str | None:
    attrs=nodes.get(root,{}).get("attrs",{})
    if attrs.get("definition_role")!="function_parameter" or not isinstance(attrs.get("parameter_index"),int): return None
    idx=int(attrs["parameter_index"]); scope=str(attrs.get("scope"))
    if scope != guard_scope:
        return None
    matches=[role for role,row in source_roles.items() if row.get("status")=="RESOLVED" and row.get("scope_role")=="GUARD_ANCHOR_SCOPE" and int(row.get("parameter_index",-1))==idx]
    return matches[0] if len(matches)==1 else None


def _normalize_compare_operator(raw: str) -> str | None:
    if raw in {"Eq", "EQ", "==", "===", "EQL"}:
        return "EQ"
    if raw in {"NotEq", "NE", "!=", "!==", "NEQ"}:
        return "NE"
    return None


def _guard_operator(overlay: Mapping[str,Any], transported_guard_id: str) -> str | None:
    rows=[]
    for e in overlay.get("edges",[]) or []:
        if e.get("kind")!="COMPARES" or str(e.get("target"))!=transported_guard_id:
            continue
        ops=e.get("attrs",{}).get("operators",[]) or []
        if len(ops)!=1:
            return None
        op=_normalize_compare_operator(str(ops[0]))
        if op is None:
            return None
        rows.append(op)
    return rows[0] if rows and len(set(rows))==1 else None


def _path_outcome(path: Mapping[str,Any]) -> str | None:
    events=[str(x) for x in path.get("events",[]) or []]
    effect=any(x.startswith("EFFECT:") for x in events)
    success=any(x.startswith("SUCCESS:") for x in events)
    rejection=any(x.startswith("REJECTION:") for x in events)
    if effect and success and not rejection:
        return "SUCCESS_EFFECT"
    if rejection and not effect and not success:
        return "REJECTION_NO_EFFECT"
    return None


def _derive_worlds(*, execution_signature: Mapping[str,Any], bindings: Sequence[Mapping[str,Any]], control_paths: Sequence[Mapping[str,Any]], operator: str, guard_form: str, guardobs: Mapping[str,Any]) -> tuple[list[dict[str,Any]], list[str]]:
    bad=[]; out=[]
    by_index={}
    for b in bindings:
        slot=b.get("slot_identity",{}) or {}; idx=slot.get("operand_index")
        if not isinstance(idx,int):
            continue
        origins=list(b.get("observed_origins",[]) or [])
        if len(origins)!=1 or idx in by_index:
            bad.append(f"WORLD_GUARD_OPERAND_ORIGIN_NOT_UNIQUE:{idx}")
            continue
        by_index[idx]=str(origins[0])
    if set(by_index)!={0,1}:
        bad.append("WORLD_REQUIRES_EXACT_TWO_GUARD_OPERANDS")
    helper_relation=None
    if guard_form=="HELPER_CONTROL":
        if guardobs.get("polarity_certificate_status")!="PROVED" or guardobs.get("polarity_to_transported_guard") not in {"SAME","INVERTED"}:
            bad.append("WORLD_HELPER_POLARITY_UNPROVEN")
        else:
            helper_relation=str(guardobs["polarity_to_transported_guard"])
    for world in execution_signature.get("worlds",[]) or []:
        wid=str(world.get("id") or "")
        values=world.get("role_values",{}) or {}
        if not wid or not world.get("kappa"):
            bad.append(f"WORLD_DECLARATION_INCOMPLETE:{wid or '<missing>'}"); continue
        if "rho" in world:
            bad.append(f"WORLD_DECLARATION_MUST_NOT_SUPPLY_RHO:{wid}"); continue
        if any(origin not in values for origin in by_index.values()):
            bad.append(f"WORLD_ROLE_VALUE_MISSING:{wid}"); continue
        if set(by_index)!={0,1}:
            continue
        eq=values[by_index[0]]==values[by_index[1]]
        transported_truth=eq if operator=="EQ" else (not eq)
        branch_truth=transported_truth
        if guard_form=="HELPER_CONTROL" and helper_relation=="INVERTED":
            branch_truth=not transported_truth
        matches=[p for p in control_paths if p.get("complete") is True and str(p.get("guard_polarity"))==str(bool(branch_truth)).lower()]
        outcomes={x for x in (_path_outcome(p) for p in matches) if x is not None}
        if not matches or len(outcomes)!=1 or any(_path_outcome(p) is None for p in matches):
            bad.append(f"WORLD_TARGET_REALIZATION_NOT_UNIQUE:{wid}"); continue
        out.append({"id":wid,"role_values":dict(values),"kappa":world.get("kappa"),"rho":{"outcome":next(iter(outcomes)),"effect_carriers":{}}})
    return out,sorted(set(bad))
