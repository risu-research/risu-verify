from __future__ import annotations

"""Canonical-only consequence-signature derivation for the Gate1B/1C bridge.

The public canonical signature is intentionally byte-compatible with the
already-frozen A3/A4 signature artifact.  No candidate/mutant bytes, truth,
operator metadata, target identity, or identifier spelling participate.
"""

import hashlib
import json
from collections import defaultdict, deque
from typing import Any, Mapping, Sequence

SCHEMA = "risu.e2-a3-a4-canonical-consequence-signature-bundle/v0.1"
PROFILE_SCHEMA = "risu.e2-gate1b1c-canonical-execution-profile-bundle/v0.1"
PREREGISTRATION_COMMIT = "1efc11b4f5b3a3e51cc1168c076be67213f335e0"
ALLOWED_LINEAGE = {"DERIVES", "CARRIES", "BINDS_TO"}


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def sha256_json(value: Any) -> str:
    return sha256_bytes(canonical_bytes(value))


def _span(node: Mapping[str, Any]) -> tuple[int, int, int, int]:
    s = node["span"]
    return int(s["start_line"]), int(s["start_col"]), int(s["end_line"]), int(s["end_col"])


def _contains(outer: Sequence[int], inner: Sequence[int]) -> bool:
    a = (int(outer[0]), int(outer[1])); b = (int(outer[2]), int(outer[3]))
    c = (int(inner[0]), int(inner[1])); d = (int(inner[2]), int(inner[3]))
    return a <= c and d <= b


def _graph(overlay: Mapping[str, Any]) -> tuple[dict[str, Mapping[str, Any]], dict[str, list[Mapping[str, Any]]], dict[str, list[Mapping[str, Any]]]]:
    nodes = {str(n["id"]): n for n in overlay.get("nodes", [])}
    incoming: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    outgoing: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for e in overlay.get("edges", []):
        outgoing[str(e["source"])].append(e); incoming[str(e["target"])].append(e)
    return nodes, incoming, outgoing


def _anchor_nodes(overlay: Mapping[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    for node in overlay.get("nodes", []):
        role = node.get("attrs", {}).get("anchor_role")
        if role:
            if role in out:
                raise ValueError(f"duplicate anchor role:{role}")
            out[str(role)] = str(node["id"])
    return out


def _branch_edges(outgoing: Mapping[str, Sequence[Mapping[str, Any]]], guard: str) -> dict[bool, str]:
    rows: dict[bool, str] = {}
    for e in outgoing.get(guard, []):
        if e.get("kind") != "GUARDS" or type(e.get("attrs", {}).get("branch_polarity")) is not bool:
            continue
        pol = bool(e["attrs"]["branch_polarity"])
        if pol in rows:
            raise ValueError("duplicate guard polarity")
        rows[pol] = str(e["target"])
    return rows


def _reachable(outgoing: Mapping[str, Sequence[Mapping[str, Any]]], start: str, target: str) -> bool:
    q = deque([start]); seen = {start}
    while q:
        cur = q.popleft()
        if cur == target:
            return True
        for e in outgoing.get(cur, []):
            if e.get("kind") != "PRECEDES":
                continue
            nxt = str(e["target"])
            if nxt not in seen:
                seen.add(nxt); q.append(nxt)
    return False


def _branch_bearing(outgoing: Mapping[str, Sequence[Mapping[str, Any]]], guard: str) -> bool:
    try:
        rows = _branch_edges(outgoing, guard)
    except ValueError:
        return False
    return set(rows) == {True, False}


def _effective_guard(overlay: Mapping[str, Any], transported: str) -> tuple[str, str, list[str]]:
    nodes, _, outgoing = _graph(overlay)
    if _branch_bearing(outgoing, transported):
        return transported, "DIRECT_CONTROL", []

    # The frozen helper form is a unique provenance chain from transported
    # comparison result to one branch-bearing consumer.  Intermediate concrete
    # identifiers and wrapper depth are deliberately erased in the signature.
    q = deque([transported]); seen = {transported}; consumers: set[str] = set()
    while q:
        cur = q.popleft()
        for e in outgoing.get(cur, []):
            if e.get("kind") == "DERIVES":
                nxt = str(e["target"])
                if nxt not in seen:
                    seen.add(nxt); q.append(nxt)
            elif e.get("kind") == "BINDS_TO" and e.get("attrs", {}).get("binding") == "call_argument_to_parameter":
                nxt = str(e["target"])
                if nxt not in seen:
                    seen.add(nxt); q.append(nxt)
            elif e.get("kind") == "COMPARES":
                nxt = str(e["target"])
                if _branch_bearing(outgoing, nxt):
                    consumers.add(nxt)
        # COMPARES can also be indexed outside the current outgoing loop in
        # older overlays, so scan only graph edges already admitted in overlay.
        for e in overlay.get("edges", []):
            if e.get("kind") == "COMPARES" and str(e.get("source")) == cur:
                nxt = str(e["target"])
                if _branch_bearing(outgoing, nxt):
                    consumers.add(nxt)
    if len(consumers) != 1:
        raise ValueError("helper guard not uniquely resolved")
    guard = next(iter(consumers))
    # Exact normalized shape frozen by the original canonical signature.
    return guard, "HELPER_CONTROL", ["GUARD_COMPARISON_RESULT", "RETURN_BOUNDARY", "CALL_RESULT", "CONSUMER_GUARD"]


def _root_paths(overlay: Mapping[str, Any], value_id: str) -> list[tuple[str, list[Mapping[str, Any]]]]:
    nodes, incoming, _ = _graph(overlay)
    out: list[tuple[str, list[Mapping[str, Any]]]] = []
    stack: list[tuple[str, list[Mapping[str, Any]]]] = [(value_id, [])]
    seen_states: set[tuple[str, tuple[str, ...]]] = set()
    while stack:
        cur, reversed_edges = stack.pop()
        key = (cur, tuple(str(x.get("id")) for x in reversed_edges))
        if key in seen_states:
            continue
        seen_states.add(key)
        parents = [e for e in incoming.get(cur, []) if e.get("kind") in ALLOWED_LINEAGE]
        role = nodes.get(cur, {}).get("attrs", {}).get("definition_role")
        if role == "function_parameter" or not parents:
            out.append((cur, list(reversed(reversed_edges))))
            continue
        for e in parents:
            if len(reversed_edges) >= 64:
                raise ValueError("lineage depth exceeds canonical bound")
            stack.append((str(e["source"]), reversed_edges + [e]))
    # Exact duplicate graph paths are irrelevant; distinct roots/paths remain.
    unique: dict[tuple[str, tuple[str, ...]], tuple[str, list[Mapping[str, Any]]]] = {}
    for root, path in out:
        unique[(root, tuple(str(e.get("id")) for e in path))] = (root, path)
    return [unique[k] for k in sorted(unique)]


def _execution_source_profiles(overlay: Mapping[str, Any], signature: Mapping[str, Any]) -> dict[str, Any]:
    """Derive opaque source-role bindings needed later by the execution adapter.

    Only parameter *position within the guard-anchor scope* is normative.  A
    concrete function/parameter identifier is never exported as semantic
    authority, which keeps alpha-renames outside the role calculus.
    """
    nodes = {str(n["id"]): n for n in overlay.get("nodes", [])}
    slots = overlay.get("binding_slots", {}) or {}
    anchors = _anchor_nodes(overlay)
    guard = nodes.get(anchors.get("GUARD_COMPARISON", ""), {})
    guard_scope = str(guard.get("attrs", {}).get("scope") or "")
    if not guard_scope:
        raise ValueError("canonical guard scope unresolved")
    roles: dict[str, Any] = {}
    for slot_name in sorted(signature.get("required_binding_slot_roles", {})):
        row = slots.get(slot_name, {}) or {}
        vals = list(row.get("value_instance_ids", []) or [])
        roots: set[int] = set()
        projection_paths: list[list[str]] = []
        for value_id in vals:
            for root, path in _root_paths(overlay, str(value_id)):
                n = nodes.get(root, {})
                attrs = n.get("attrs", {})
                if attrs.get("definition_role") != "function_parameter" or not isinstance(attrs.get("parameter_index"), int):
                    continue
                if str(attrs.get("scope")) != guard_scope:
                    continue
                roots.add(int(attrs["parameter_index"]))
                projection_paths.append([str(e.get("kind")) for e in path])
        if len(roots) != 1:
            roles[f"BOUND_VALUE:{slot_name}"] = {"status": "UNRESOLVED", "candidate_count": len(roots)}
        else:
            index = next(iter(roots))
            roles[f"BOUND_VALUE:{slot_name}"] = {
                "status": "RESOLVED",
                "scope_role": "GUARD_ANCHOR_SCOPE",
                "parameter_index": index,
                "lineage_edge_shapes": sorted({tuple(x) for x in projection_paths}),
            }
    return roles


def derive(
    *, anchor_bundle: Mapping[str, Any], anchor_bundle_raw: bytes,
    overlay_bundle: Mapping[str, Any], overlay_bundle_raw: bytes,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if anchor_bundle.get("schema") != "risu.e2-canonical-seed-consequence-anchor-bundle/v0.1":
        raise ValueError("anchor bundle schema mismatch")
    if overlay_bundle.get("schema") != "risu.e2-observability-overlay-seed-bundle/v0.1":
        raise ValueError("overlay bundle schema mismatch")
    contracts = {str(x["seed_id"]): x for x in anchor_bundle.get("contracts", [])}
    overlays = {str(x["seed_id"]): x for x in overlay_bundle.get("overlays", [])}
    if set(contracts) != set(overlays) or len(contracts) != 6:
        raise ValueError("canonical six-seed set mismatch")

    signatures: list[dict[str, Any]] = []
    profiles: list[dict[str, Any]] = []
    for seed_id in sorted(contracts):
        crow = contracts[seed_id]; decl = crow["declaration"]
        orow = overlays[seed_id]; overlay = orow["overlay"]
        if orow.get("contract_canonical_sha256") != crow.get("contract_canonical_sha256"):
            raise ValueError(f"contract digest mismatch:{seed_id}")
        if overlay.get("consequence_anchor_contract_sha256") != crow.get("contract_canonical_sha256"):
            raise ValueError(f"overlay/contract mismatch:{seed_id}")
        if overlay.get("files", [{}])[0].get("sha256") != decl["source"]["sha256"]:
            raise ValueError(f"source digest mismatch:{seed_id}")
        anchors = _anchor_nodes(overlay)
        for role in ("GUARD_COMPARISON", "EFFECT_BOUNDARY", "SUCCESS_OUTCOME", "REJECTION_NO_EFFECT_OUTCOME"):
            if role not in anchors:
                raise ValueError(f"canonical anchor missing:{seed_id}:{role}")
        nodes, _, outgoing = _graph(overlay)
        effective_guard, form, helper_shape = _effective_guard(overlay, anchors["GUARD_COMPARISON"])
        branches = _branch_edges(outgoing, effective_guard)
        if set(branches) != {True, False}:
            raise ValueError(f"branch polarity incomplete:{seed_id}")
        outcome_by_pol: dict[bool, str] = {}
        for pol, entry in branches.items():
            reaches_effect = _reachable(outgoing, entry, anchors["EFFECT_BOUNDARY"])
            reaches_success = _reachable(outgoing, entry, anchors["SUCCESS_OUTCOME"])
            reaches_reject = _reachable(outgoing, entry, anchors["REJECTION_NO_EFFECT_OUTCOME"])
            if reaches_effect and reaches_success and not reaches_reject:
                outcome_by_pol[pol] = "EFFECT"
            elif reaches_reject and not reaches_effect:
                outcome_by_pol[pol] = "REJECTION"
            else:
                raise ValueError(f"canonical polarity not unique:{seed_id}:{pol}")
        effect_polarities = [p for p, v in outcome_by_pol.items() if v == "EFFECT"]
        reject_polarities = [p for p, v in outcome_by_pol.items() if v == "REJECTION"]
        if len(effect_polarities) != 1 or len(reject_polarities) != 1:
            raise ValueError(f"canonical polarity cardinality:{seed_id}")

        effect_span = _span(nodes[anchors["EFFECT_BOUNDARY"]])
        effect_ops = [
            n for n in overlay.get("nodes", [])
            if n.get("kind") == "OPERATION"
            and n.get("attrs", {}).get("operation_role") in {"call", "representation_instance"}
            and _contains(effect_span, _span(n))
        ]
        if len(effect_ops) != 1:
            raise ValueError(f"effect structural operation not unique:{seed_id}")
        effect_op = effect_ops[0]

        req_slots: dict[str, Any] = {}
        obligations: list[dict[str, Any]] = []
        role_universe: list[str] = []
        root_sets: dict[str, set[str]] = {}
        for slot_name in sorted(decl.get("binding_slots", {})):
            spec = decl["binding_slots"][slot_name]
            b = (overlay.get("binding_slots", {}) or {}).get(slot_name, {}) or {}
            vals = list(b.get("value_instance_ids", []) or [])
            req_slots[slot_name] = {"anchor": spec["anchor"], "cardinality": len(vals), "operand_index": int(spec["operand_index"])}
            terminal = f"GUARD_SLOT:{slot_name}"; source_role = f"BOUND_VALUE:{slot_name}"
            role_universe.append(terminal)
            obligations.append({"relation": "REACHES", "slot": {"anchor": spec["anchor"], "operand_index": int(spec["operand_index"])}, "source_role": source_role, "terminal_role": terminal})
            roots: set[str] = set()
            for v in vals:
                roots.update(root for root, _ in _root_paths(overlay, str(v)))
            root_sets[slot_name] = roots
        relations: list[dict[str, Any]] = []
        slot_names = sorted(root_sets)
        for i, a in enumerate(slot_names):
            for b in slot_names[i+1:]:
                if not root_sets[a] or not root_sets[b]:
                    raise ValueError(f"canonical origin unresolved:{seed_id}:{a}:{b}")
                if root_sets[a].isdisjoint(root_sets[b]):
                    rel = {"relation": "DISTINCT_ORIGIN", "role_a": f"GUARD_SLOT:{a}", "role_b": f"GUARD_SLOT:{b}"}
                else:
                    rel = {"relation": "SAME_ORIGIN", "role_a": f"GUARD_SLOT:{a}", "role_b": f"GUARD_SLOT:{b}"}
                relations.append(rel); obligations.append(dict(rel))

        # Only consequence-relevant coordinate carriers are promoted.  The six
        # frozen seeds have representation-only effect objects whose noncoordinate
        # fields are intentionally outside A3 role authority.
        coordinate_carriers: list[dict[str, Any]] = []
        sig = {
            "seed_id": seed_id,
            "semantic_authority": False,
            "source_sha256": decl["source"]["sha256"],
            "anchor_contract_sha256": crow["contract_canonical_sha256"],
            "guard_anchor_role": "GUARD_COMPARISON",
            "effective_guard_form": form,
            "helper_passthrough_shape": helper_shape,
            "effect_polarity": effect_polarities[0],
            "rejection_polarity": reject_polarities[0],
            "required_binding_slot_roles": req_slots,
            "required_lineage_obligations": obligations,
            "effect_invocation_binding_surface": {
                "resolution": "UNIQUE_STRUCTURAL_OPERATION_WITHIN_EFFECT_ANCHOR",
                "operation_role": effect_op.get("attrs", {}).get("operation_role"),
                "coordinate_carrier_slots": coordinate_carriers,
                "noncoordinate_representation_fields_not_promoted_to_a3_roles": True,
            },
            "opaque_lineage_equivalence": {"role_universe": sorted(role_universe), "relations": relations},
            "control_scope_status": "COMPLETE" if all(x.get("status") == "COMPLETE" for x in overlay.get("control_completeness", [])) else "INCOMPLETE",
            "ordering_obligations": ["EFFECT_BOUNDARY PRECEDES SUCCESS_OUTCOME", "EFFECTIVE_GUARD PRECEDES EFFECT_BOUNDARY on effect polarity"],
            "terminal_obligations": ["rejection polarity reaches REJECTION_NO_EFFECT_OUTCOME without prior EFFECT_BOUNDARY", "effect polarity reaches EFFECT_BOUNDARY then SUCCESS_OUTCOME"],
        }
        sig["canonical_signature_digest_sha256"] = sha256_json(sig)
        signatures.append(sig)
        profiles.append({
            "seed_id": seed_id,
            "canonical_signature_digest_sha256": sig["canonical_signature_digest_sha256"],
            "source_roles": _execution_source_profiles(overlay, sig),
            "resource_identity_policy": "NO_MATERIAL_RESOURCE_ROLE" if not decl.get("resource_identity_required") else "RESOURCE_ROLE_REQUIRED",
        })

    bundle = {
        "schema": SCHEMA,
        "semantic_authority": False,
        "preregistration_commit": PREREGISTRATION_COMMIT,
        "seed_count": len(signatures),
        "signatures": signatures,
        "source_anchor_bundle_sha256": sha256_bytes(anchor_bundle_raw),
        "source_overlay_file_sha256": sha256_bytes(overlay_bundle_raw),
        "source_overlay_internal_digest_sha256": overlay_bundle.get("bundle_digest_sha256"),
        "firewall": {
            "candidate_or_mutant_bytes_read": False,
            "mutation_truth_read": False,
            "operator_metadata_read": False,
            "fresh_target_bytes_read": False,
            "identifier_spelling_used_as_semantic_role_authority": False,
            "callee_spelling_used_as_effect_semantic_authority": False,
        },
    }
    bundle["bundle_digest_sha256"] = sha256_json(bundle)
    profile_bundle = {
        "schema": PROFILE_SCHEMA,
        "semantic_authority": False,
        "canonical_signature_bundle_digest_sha256": bundle["bundle_digest_sha256"],
        "seed_count": len(profiles),
        "profiles": profiles,
        "claim_boundary": "EXECUTION_BINDING_PROFILE_ONLY_NO_CANDIDATE_PREDICTION",
    }
    profile_bundle["bundle_digest_sha256"] = sha256_json(profile_bundle)
    return bundle, profile_bundle
