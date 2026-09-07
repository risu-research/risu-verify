from __future__ import annotations

"""Ultra-thin primary-E2 -> Gate1B/1C semantic-slice projection.

This adapter performs no source parsing and no file I/O.  It projects only
already-frozen primary graph/path evidence plus canonical-only profiles and a
frozen finite-world declaration.  Unknown facts fail closed.
"""

import hashlib
from typing import Any, Mapping

from .adapter_support import (
    SLICE_SCHEMA, _branch_guard_count, _candidate_role_for_root, _derive_worlds, _digest,
    _execution_signature, _graph, _guard_operator, _roots_and_path, _sp,
)

def adapt_primary(*, case_id: str, language: str, source_path: str,
                  overlay: Mapping[str,Any], path_observability: Mapping[str,Any],
                  canonical_signature: Mapping[str,Any], canonical_profile: Mapping[str,Any],
                  worlds_document: Mapping[str,Any]) -> tuple[dict[str,Any], dict[str,Any]]:
    unresolved=[]
    if overlay.get("schema")!="risu.e2-observability-overlay/v0.1": raise ValueError("overlay schema mismatch")
    if path_observability.get("schema") not in {"risu.e2-path-observability/v0.1","risu.e2-path-observability/v0.2"}: raise ValueError("path schema mismatch")
    if path_observability.get("base_overlay_digest_sha256")!=overlay.get("overlay_digest_sha256"): raise ValueError("path/overlay digest mismatch")
    if canonical_profile.get("canonical_signature_digest_sha256")!=canonical_signature.get("canonical_signature_digest_sha256"): raise ValueError("profile/signature mismatch")
    exec_sig=_execution_signature(canonical_signature,canonical_profile,worlds_document)
    nodes,incoming,outgoing=_graph(overlay)
    anchors={}
    for n in overlay.get("nodes",[]):
        role=n.get("attrs",{}).get("anchor_role")
        if role:
            if role in anchors: unresolved.append(f"DUPLICATE_ANCHOR:{role}")
            anchors[str(role)]=str(n["id"])
    for role in ("GUARD_COMPARISON","EFFECT_BOUNDARY","SUCCESS_OUTCOME","REJECTION_NO_EFFECT_OUTCOME"):
        if role not in anchors: unresolved.append(f"MISSING_ANCHOR:{role}")
    guardobs=path_observability.get("effective_guard_observability",{}) or {}
    guard_id=str(guardobs.get("guard_id") or "")
    guard_form=str(guardobs.get("form") or "UNPROVEN")
    if guard_form!=canonical_signature.get("effective_guard_form"): unresolved.append("EFFECTIVE_GUARD_FORM_MISMATCH")
    if not guard_id: unresolved.append("EFFECTIVE_GUARD_UNRESOLVED")
    if guard_id and _branch_guard_count(overlay,guard_id)!=1: unresolved.append("EFFECTIVE_GUARD_NOT_BRANCH_BEARING_UNIQUE")

    # Material guard scope is taken from the primary node's provenance, not a name lookup.
    guard_scope=str(nodes.get(anchors.get("GUARD_COMPARISON",""),{}).get("attrs",{}).get("scope") or "")
    if not guard_scope: unresolved.append("GUARD_SCOPE_UNRESOLVED")
    source_roles=canonical_profile.get("source_roles",{}) or {}
    guard_operator=_guard_operator(overlay,anchors.get("GUARD_COMPARISON",""))
    if guard_operator is None: unresolved.append("GUARD_OPERATOR_UNRESOLVED")
    bindings=[]; binding_role_roots={}
    for spec in exec_sig["required_bindings"]:
        slot=spec["binding_id"].split(":",1)[1]
        brow=(overlay.get("binding_slots",{}) or {}).get(slot,{}) or {}
        values=list(brow.get("value_instance_ids",[]) or [])
        roots=[]; paths=[]
        for value in values:
            for root,path in _roots_and_path(overlay,str(value)):
                roots.append(root); paths.append((root,str(value),path))
        roots=sorted(set(roots)); binding_role_roots[slot]=set(roots)
        observed=[]; lineage=[]
        for root,value,path in paths:
            role=_candidate_role_for_root(nodes,root,source_roles,guard_scope)
            if role is None:
                role="OPAQUE_ORIGIN:"+hashlib.sha256(root.encode()).hexdigest()[:16]
            observed.append(role)
            pid=f"adapter:{case_id}:{slot}:{len(lineage)}"
            edges=[]
            # projection boundary: canonical semantic-role token -> exact primary origin node
            edges.append({"kind":"DERIVES","from":role,"to":root,"path_id":pid,"projection":"ROLE_TO_PROVENANCE_ROOT"})
            for e in path:
                edges.append({"kind":e["kind"],"from":str(e["source"]),"to":str(e["target"]),"path_id":pid,"primary_edge_id":e.get("id")})
            edges.append({"kind":"BINDS_TO","from":value,"to":spec["binding_id"],"path_id":pid,"projection":"PRIMARY_VALUE_TO_SEMANTIC_BINDING"})
            lineage.append({"origin":role,"edges":edges})
        complete=(len(values)==int(canonical_signature["required_binding_slot_roles"][slot]["cardinality"])==1 and len(roots)==1 and len(paths)==1)
        if not complete: unresolved.append(f"BINDING_PROVENANCE_NOT_UNIQUE:{slot}")
        bindings.append({
            "binding_id":spec["binding_id"],"coordinate_identity":spec["coordinate_identity"],"resource_identity":spec["resource_identity"],
            "slot_identity":{"anchor":canonical_signature["required_binding_slot_roles"][slot]["anchor"],"operand_index":int(spec["operand_index"])},
            "allowed_origins":list(spec["allowed_origins"]),"observed_origins":sorted(set(observed)),
            "binding_complete":complete,"definitions_complete":complete,"lineage_paths":lineage,
            "definition_trace":[],"representation":{"required":False},"may_flow_only":not complete,
        })

    # Preserve canonical relational origin requirements without naming candidate variables.
    for rel in canonical_signature.get("opaque_lineage_equivalence",{}).get("relations",[]) or []:
        if rel.get("relation")!="DISTINCT_ORIGIN":
            unresolved.append("CANONICAL_ORIGIN_RELATION_OUTSIDE_ADAPTER_V0_1"); continue
        a=str(rel["role_a"]).split(":",1)[1]; b=str(rel["role_b"]).split(":",1)[1]
        if binding_role_roots.get(a,set()) & binding_role_roots.get(b,set()):
            # Do not relabel the shared root.  Its exact parameter-index role is
            # retained on both bindings so the kernel can identify the precise
            # wrong carrier and finite worlds can evaluate the reused value.
            pass

    # Structured leaf paths are already present in the primary path sidecar.
    pred_edges=path_observability.get("path_state_predecessor_edges",[]) or []
    has_child={str(e["source"]) for e in pred_edges}
    leaves=[x for x in path_observability.get("path_states",[]) or [] if str(x.get("path_state_id")) not in has_child]
    control_paths=[]
    for leaf in sorted(leaves,key=lambda x:str(x.get("path_state_id"))):
        decisions=[d for d in leaf.get("guard_decisions",[]) or [] if str(d.get("guard_id"))==guard_id]
        events=["ENTRY"]
        if len(decisions)==1 and type(decisions[0].get("polarity")) is bool:
            pol=str(bool(decisions[0]["polarity"])).lower(); events += [f"GUARD:{guard_id}",f"POLARITY:{pol}"]
        else:
            pol="UNGUARDED"
            if len(decisions)>1: unresolved.append(f"MULTIPLE_EFFECTIVE_GUARD_DECISIONS:{leaf.get('path_state_id')}")
        for ev in leaf.get("events",[]) or []:
            if ev=="EFFECT_BOUNDARY": events.append("EFFECT:effect0")
            elif ev=="SUCCESS_OUTCOME": events.append("SUCCESS:success0")
            elif ev=="REJECTION_NO_EFFECT_OUTCOME": events.append("REJECTION:rejection0")
        events.append("EXIT")
        control_paths.append({"path_id":str(leaf.get("path_state_id")),"guard_polarity":pol,"events":events,"complete":path_observability.get("material_control_complete") is True,"realizable":True})
    if not control_paths: unresolved.append("NO_PRIMARY_LEAF_PATHS")

    helper_chain=[]; net="PRESERVE"
    if guard_form=="HELPER_CONTROL":
        status=guardobs.get("polarity_certificate_status"); relation=guardobs.get("polarity_to_transported_guard")
        if status!="PROVED" or relation not in {"SAME","INVERTED"}: unresolved.append("HELPER_POLARITY_NOT_PROVED")
        else:
            transform="PRESERVE" if relation=="SAME" else "FLIP"; net=transform
            helper_chain=[{"transform":transform,"certificate_sha256":guardobs.get("polarity_certificate_sha256")}]

    surface=path_observability.get("effect_binding_surface",{}) or {}
    surfaces=list(surface.get("operation_ids",[]) or [])
    if surface.get("status")!="UNIQUE" or len(surfaces)!=1: unresolved.append("EFFECT_SURFACE_NOT_UNIQUE")
    all_success=[p for p in control_paths if any(x.startswith("SUCCESS:") for x in p["events"])]
    effect_before_success=bool(all_success) and all(next((i for i,x in enumerate(p["events"]) if x.startswith("EFFECT:")),10**9)<next((i for i,x in enumerate(p["events"]) if x.startswith("SUCCESS:")),10**9) for p in all_success)

    cc=overlay.get("control_completeness",[]) or []
    control_complete=bool(cc) and all(x.get("status")=="COMPLETE" for x in cc) and path_observability.get("material_control_complete") is True
    dynamic_calls=[n for n in overlay.get("nodes",[]) if n.get("attrs",{}).get("operation_role")=="call" and str(n.get("attrs",{}).get("callee")) in {"","<dynamic>","None"}]
    repr_required=bool(canonical_signature.get("effect_invocation_binding_surface",{}).get("coordinate_carrier_slots",[]))
    flags={
        "aliases_complete":not any(not b["definitions_complete"] for b in bindings),
        "call_targets_complete":not dynamic_calls,
        "reaching_definitions_complete":all(b["definitions_complete"] for b in bindings) and path_observability.get("path_dataflow_correlation")=="COMPLETE",
        "branches_complete":control_complete,
        "representations_complete":not repr_required,
        "effects_complete":surface.get("status")=="UNIQUE",
        "exceptions_exits_complete":control_complete,
        "resources_complete":canonical_profile.get("resource_identity_policy")=="NO_MATERIAL_RESOURCE_ROLE",
        "helper_polarity_complete":guard_form=="DIRECT_CONTROL" or not any(x=="HELPER_POLARITY_NOT_PROVED" for x in unresolved),
        "all_entry_paths_enumerated":control_complete and bool(control_paths),
    }
    complete=not unresolved and all(flags.values())

    # Exact primary anchor spans become the certificate's source-evidence surface.
    source_evidence=[]
    amap={"GUARD_COMPARISON":"guard","EFFECT_BOUNDARY":"effect","SUCCESS_OUTCOME":"success","REJECTION_NO_EFFECT_OUTCOME":"rejection"}
    for role,key in sorted(amap.items(), key=lambda x:x[1]):
        if role in anchors:
            source_evidence.append({"evidence_id":f"anchor:{key}","path":source_path,"span":_sp(nodes[anchors[role]])})

    source_contract={"path":source_path,"anchors":{}}
    for role,key in amap.items():
        if role in anchors:
            syntax="RETURN" if role in {"EFFECT_BOUNDARY","SUCCESS_OUTCOME","REJECTION_NO_EFFECT_OUTCOME"} else "COMPARE"
            source_contract["anchors"][key]={"span":_sp(nodes[anchors[role]]),"syntax_kind":syntax}
    # Bind the material structured scope and whole If span from primary provenance.
    scope_rows=[x for x in cc if str(x.get("scope"))==guard_scope]
    if len(scope_rows)==1: source_contract["target_function_span"]=list(scope_rows[0].get("function_span",[]))
    branch_states=[x for x in path_observability.get("path_states",[]) or [] if x.get("transition",{}).get("kind")=="STRUCTURED_BRANCH" and str(x.get("transition",{}).get("guard_id"))==guard_id]
    spans={tuple(x.get("transition",{}).get("statement_span",[])) for x in branch_states}
    if len(spans)==1: source_contract["effective_if_span"]=list(next(iter(spans)))
    else: unresolved.append("EFFECTIVE_IF_SPAN_UNRESOLVED")

    worlds=[]
    if guard_operator is not None:
        worlds,world_bad=_derive_worlds(execution_signature=exec_sig,bindings=bindings,control_paths=control_paths,operator=guard_operator,guard_form=guard_form,guardobs=guardobs)
        unresolved.extend(world_bad)
    if len(worlds)!=len(exec_sig.get("worlds",[]) or []):
        unresolved.append("FINITE_WORLD_TARGET_REALIZATION_INCOMPLETE")
    doc={
        "schema":SLICE_SCHEMA,"case_id":case_id,"canonical_signature_digest":_digest(exec_sig),
        "language":language,"source_contract":source_contract,"source_evidence":source_evidence,
        "bindings":bindings,
        "guard":{"form":guard_form,"effective_guard_id":guard_id,"effective_guard_count":1 if guard_id else 0,"net_polarity":net,"helper_chain":helper_chain,
                 "effect_polarity":exec_sig["guard"]["effect_polarity"],"rejection_polarity":exec_sig["guard"]["rejection_polarity"],"operator":guard_operator},
        "control_paths":control_paths,
        "effect":{"surfaces":surfaces,"equivalence_proof_id":None,"success_outcome_id":"success0","rejection_outcome_id":"rejection0","effect_before_success_structural":effect_before_success},
        "scope":{"scope_id":f"primary:{case_id}","complete":complete,"unresolved":sorted(set(unresolved)),**flags},
        "worlds":worlds,
    }
    receipt={
        "schema":"risu.e2-primary-semantic-slice-adapter-receipt/v0.1","case_id":case_id,
        "overlay_digest_sha256":overlay.get("overlay_digest_sha256"),"path_observability_digest_sha256":path_observability.get("path_observability_digest_sha256"),
        "canonical_signature_digest_sha256":canonical_signature.get("canonical_signature_digest_sha256"),
        "execution_signature":exec_sig,"execution_signature_digest_sha256":_digest(exec_sig),
        "world_declaration_digest_sha256":_digest(worlds_document),"target_rho_derived_from_primary":True,
        "semantic_slice_digest_sha256":_digest(doc),"unresolved":sorted(set(unresolved)),
        "source_parsed_by_adapter":False,"identifier_spelling_used_as_role_authority":False,"semantic_authority":False,
    }
    return doc,receipt
