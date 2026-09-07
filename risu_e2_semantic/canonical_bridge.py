from __future__ import annotations

"""Scope-binding remediation wrapper for the frozen canonical bridge v1.

Only execution-profile scope discovery is changed: if the canonical guard
anchor node carries no scope attribute, the unique smallest COMPLETE function
span containing the guard span supplies the internal scope join key.  Concrete
scope spelling is never exported as semantic role authority.
"""

from typing import Any, Mapping

from . import canonical_bridge_v1 as _v1

canonical_bytes = _v1.canonical_bytes
sha256_bytes = _v1.sha256_bytes
sha256_json = _v1.sha256_json
SCHEMA = _v1.SCHEMA
PROFILE_SCHEMA = _v1.PROFILE_SCHEMA


def _contains_span(outer: list[int], inner: tuple[int,int,int,int]) -> bool:
    a=(int(outer[0]),int(outer[1])); b=(int(outer[2]),int(outer[3]))
    c=(int(inner[0]),int(inner[1])); d=(int(inner[2]),int(inner[3]))
    return a <= c and d <= b


def _span_size(span: list[int]) -> int:
    return (int(span[2])-int(span[0]))*100000 + (int(span[3])-int(span[1]))


def _execution_source_profiles(overlay: Mapping[str, Any], signature: Mapping[str, Any]) -> dict[str, Any]:
    nodes={str(n["id"]):n for n in overlay.get("nodes",[])}
    slots=overlay.get("binding_slots",{}) or {}
    anchors=_v1._anchor_nodes(overlay)
    guard=nodes.get(anchors.get("GUARD_COMPARISON",""),{})
    guard_scope=str(guard.get("attrs",{}).get("scope") or "")
    if not guard_scope:
        gspan=_v1._span(guard)
        candidates=[]
        for row in overlay.get("control_completeness",[]) or []:
            fspan=list(row.get("function_span",[]) or [])
            if len(fspan)!=4 or row.get("status")!="COMPLETE":
                continue
            if _contains_span(fspan,gspan):
                candidates.append(row)
        if not candidates:
            raise ValueError("canonical guard scope unresolved")
        candidates.sort(key=lambda row:(_span_size(list(row["function_span"])), list(row["function_span"]), str(row.get("scope"))))
        best_size=_span_size(list(candidates[0]["function_span"]))
        best=[row for row in candidates if _span_size(list(row["function_span"]))==best_size]
        if len(best)!=1 or not best[0].get("scope"):
            raise ValueError("canonical guard scope ambiguous")
        guard_scope=str(best[0]["scope"])
    roles:dict[str,Any]={}
    for slot_name in sorted(signature.get("required_binding_slot_roles",{})):
        row=slots.get(slot_name,{}) or {}
        vals=list(row.get("value_instance_ids",[]) or [])
        roots:set[int]=set(); projection_paths:list[list[str]]=[]
        for value_id in vals:
            for root,path in _v1._root_paths(overlay,str(value_id)):
                n=nodes.get(root,{}); attrs=n.get("attrs",{})
                if attrs.get("definition_role")!="function_parameter" or not isinstance(attrs.get("parameter_index"),int):
                    continue
                if str(attrs.get("scope"))!=guard_scope:
                    continue
                roots.add(int(attrs["parameter_index"]))
                projection_paths.append([str(e.get("kind")) for e in path])
        key=f"BOUND_VALUE:{slot_name}"
        if len(roots)!=1:
            roles[key]={"status":"UNRESOLVED","candidate_count":len(roots)}
        else:
            roles[key]={"status":"RESOLVED","scope_role":"GUARD_ANCHOR_SCOPE","parameter_index":next(iter(roots)),
                        "lineage_edge_shapes":sorted({tuple(x) for x in projection_paths})}
    return roles


def derive(*, anchor_bundle: Mapping[str,Any], anchor_bundle_raw: bytes,
           overlay_bundle: Mapping[str,Any], overlay_bundle_raw: bytes) -> tuple[dict[str,Any],dict[str,Any]]:
    old=_v1._execution_source_profiles
    _v1._execution_source_profiles=_execution_source_profiles
    try:
        return _v1.derive(anchor_bundle=anchor_bundle,anchor_bundle_raw=anchor_bundle_raw,
                          overlay_bundle=overlay_bundle,overlay_bundle_raw=overlay_bundle_raw)
    finally:
        _v1._execution_source_profiles=old
