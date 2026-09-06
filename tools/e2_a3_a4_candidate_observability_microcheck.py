#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
from pathlib import Path
from typing import Any, Mapping, Sequence

from risu_e2.acquisition import AcquisitionConfig, acquire
from risu_e2.frontend_python import extract as extract_python
from risu_e2.frontend_js import extract as extract_js
from risu_e2.frontend_go import extract_many as extract_go_many
from risu_e2.ir import build_ir
from risu_e2.model import canonical_bytes
from risu_e2.observability_overlay import build_overlay, validate_overlay
from risu_e2.overlay_control import CStmt, _control_functions, _function_for_span, _smallest_stmt

AUDIT_SCHEMA = "risu.e2-a3-a4-candidate-observability-microqualification-independent-audit/v0.1"
PRIMARY_SCHEMA = "risu.e2-a3-a4-candidate-observability-microqualification/v0.1"
ALLOWED_HELPER_DERIVATIONS = {
    "comparison_result_to_return",
    "function_return_to_call_result",
    "call_result_to_assignment",
}


def canon(value: Any) -> bytes:
    return canonical_bytes(value)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def root_label(label: str) -> str:
    value = label.strip()
    for sep in (".", "["):
        if sep in value:
            value = value.split(sep, 1)[0]
    return value


def fact_span(fact: Mapping[str, Any]) -> tuple[int, int, int, int]:
    s = fact["span"]
    return (int(s["start_line"]), int(s["start_col"]), int(s["end_line"]), int(s["end_col"]))


def node_span(node: Mapping[str, Any]) -> tuple[int, int, int, int]:
    s = node["span"]
    return (int(s["start_line"]), int(s["start_col"]), int(s["end_line"]), int(s["end_col"]))


def contains(outer: tuple[int, int, int, int], inner: tuple[int, int, int, int]) -> bool:
    return (outer[0], outer[1]) <= (inner[0], inner[1]) and (inner[2], inner[3]) <= (outer[2], outer[3])


def source_slice(source: str, span: tuple[int, int, int, int]) -> bytes:
    sl, sc, el, ec = span
    lines = source.splitlines(keepends=True)
    if sl == el:
        return lines[sl - 1].encode("utf-8")[sc:ec]
    out = lines[sl - 1].encode("utf-8")[sc:]
    for line in lines[sl:el - 1]:
        out += line.encode("utf-8")
    out += lines[el - 1].encode("utf-8")[:ec]
    return out


def frontend(language: str, path: str, data: bytes, go_helper: Path) -> dict[str, Any]:
    text = data.decode("utf-8")
    if language == "python":
        return extract_python(text)
    if language == "go":
        return extract_go_many([{"path": path, "data": data}], go_helper)[path]
    if language == "typescript_javascript":
        return extract_js(text)
    raise ValueError(language)


def select_fact(facts: list[Mapping[str, Any]], source: str, locator: Mapping[str, Any]) -> Mapping[str, Any]:
    needle = str(locator["source_contains"])
    rows = [
        f for f in facts
        if f.get("kind") == locator["fact_kind"] and needle in source_slice(source, fact_span(f)).decode("utf-8")
    ]
    rows.sort(key=lambda f: (fact_span(f), repr(sorted(f.items()))))
    idx = int(locator.get("occurrence", 0))
    if idx >= len(rows):
        raise ValueError("independent anchor locator unresolved")
    return rows[idx]


def independent_contract(fixture: Mapping[str, Any], facts: list[Mapping[str, Any]], source: str, source_sha: str) -> tuple[dict[str, Any], str]:
    loc = fixture["anchor_locators"]
    chosen = {
        "guard_comparison": select_fact(facts, source, loc["guard_comparison"]),
        "rejection_no_effect": select_fact(facts, source, loc["rejection_no_effect"]),
        "effect_applied": select_fact(facts, source, loc["effect_applied"]),
    }
    roles = {
        "guard_comparison": ["GUARD_COMPARISON"],
        "rejection_no_effect": ["REJECTION_NO_EFFECT_OUTCOME"],
        "effect_applied": ["EFFECT_BOUNDARY", "SUCCESS_OUTCOME"],
    }
    anchors = {}
    for key, fact in chosen.items():
        sp = fact_span(fact)
        raw = source_slice(source, sp)
        anchors[key] = {
            "roles": roles[key], "slice_bytes": len(raw), "slice_sha256": sha(raw),
            "span": list(sp), "syntax_kind": str(fact["kind"]).lower(), "unique_in_source": True,
        }
    doc = {
        "schema": "risu.e2-consequence-anchor-contract/v0.1",
        "contract_id": "MICRO_" + str(fixture["fixture_id"]).replace("::", "_").replace("-", "_"),
        "seed_id": str(fixture["fixture_id"]),
        "source": {"git_blob_sha": "SYNTHETIC_MICROFIXTURE", "language": fixture["language"], "path": fixture["filename"], "sha256": source_sha},
        "scope_authority": True, "verdict_authority": False, "resource_identity_required": False,
        "failure_outcome_required": False, "locator_convention": "L1_C0_END_EXCLUSIVE_UTF8_BYTE",
        "anchors": anchors,
        "binding_slots": {
            "expected_coordinate": {"anchor": "guard_comparison", "operand_index": int(fixture["binding_slots"]["expected_coordinate"]["operand_index"])},
            "current_coordinate": {"anchor": "guard_comparison", "operand_index": int(fixture["binding_slots"]["current_coordinate"]["operand_index"])},
        },
        "transport": {"mutant_revision_authorized": False, "fresh_revision_authorized": False},
    }
    return doc, sha(canon(doc))


def independent_signature(fixture: Mapping[str, Any]) -> dict[str, Any]:
    doc = {
        "schema": "risu.e2-a3-a4-microfixture-consequence-signature/v0.1",
        "semantic_authority": False,
        "fixture_id": fixture["fixture_id"],
        "effect_invocation_binding_surface": {"operation_role": fixture["effect_operation_role"], "resolution": "MICROFIXTURE_DECLARED_STRUCTURAL_SURFACE"},
    }
    doc["canonical_signature_digest_sha256"] = sha(canon(doc))
    return doc


def verify_overlay_content_addressing(overlay: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    ids = {n["id"] for n in overlay["nodes"]}
    for node in overlay["nodes"]:
        body = {k: node[k] for k in ("kind", "label", "span", "attrs")}
        expected = "on_" + sha(canon(body))[:24]
        if node["id"] != expected:
            errors.append("OVERLAY_NODE_ID_MISMATCH")
        if node["kind"] != "EVIDENCE" and not any(e["kind"] == "EVIDENCED_BY" and e["source"] == node["id"] for e in overlay["edges"]):
            errors.append("OVERLAY_NODE_PROVENANCE_MISSING")
    for edge in overlay["edges"]:
        body = {k: edge[k] for k in ("kind", "source", "target", "span", "attrs")}
        expected = "oe_" + sha(canon(body))[:24]
        if edge["id"] != expected:
            errors.append("OVERLAY_EDGE_ID_MISMATCH")
        if edge["source"] not in ids or edge["target"] not in ids:
            errors.append("OVERLAY_DANGLING_EDGE")
    tmp = dict(overlay)
    observed = tmp.pop("overlay_digest_sha256", None)
    if observed != sha(canon(tmp)):
        errors.append("OVERLAY_DIGEST_MISMATCH")
    return sorted(set(errors))


def independent_path(source: str, source_sha: str, language: str, facts: list[Mapping[str, Any]], overlay: Mapping[str, Any], signature: Mapping[str, Any]) -> dict[str, Any]:
    nodes = {n["id"]: n for n in overlay["nodes"]}
    incoming: dict[str, list[Mapping[str, Any]]] = {}
    outgoing: dict[str, list[Mapping[str, Any]]] = {}
    for edge in overlay["edges"]:
        incoming.setdefault(edge["target"], []).append(edge)
        outgoing.setdefault(edge["source"], []).append(edge)

    controls = _control_functions(source, language, [f for f in facts if f.get("kind") == "FUNCTION"])
    scoped_facts: dict[str, list[Mapping[str, Any]]] = {name: [] for name in controls}
    for fact in facts:
        if fact.get("kind") == "FUNCTION":
            continue
        scope = _function_for_span(controls, fact_span(fact))
        if scope:
            scoped_facts.setdefault(scope, []).append(fact)

    params: dict[str, dict[str, set[str]]] = {}
    defs_at: dict[tuple[str, tuple[int, int, int, int]], list[Mapping[str, Any]]] = {}
    anchors: dict[str, str] = {}
    for node in overlay["nodes"]:
        attrs = node.get("attrs", {})
        scope = str(attrs.get("scope"))
        role = attrs.get("definition_role")
        if role == "function_parameter":
            params.setdefault(scope, {}).setdefault(root_label(node["label"]), set()).add(node["id"])
        if role in {"assignment", "representation_field_write", "call_result"}:
            defs_at.setdefault((scope, node_span(node)), []).append(node)
        if attrs.get("anchor_role"):
            anchors[str(attrs["anchor_role"])] = node["id"]

    def has_two_branches(gid: str) -> bool:
        pol = {e.get("attrs", {}).get("branch_polarity") for e in outgoing.get(gid, []) if e["kind"] == "GUARDS"}
        return True in pol and False in pol

    def stmt_guard(stmt: CStmt) -> str | None:
        target = stmt.condition_span or stmt.span
        rows = [n for n in overlay["nodes"] if n["kind"] == "GUARD" and contains(target, node_span(n))]
        anchored = [n for n in rows if n.get("attrs", {}).get("anchor_role") == "GUARD_COMPARISON"]
        pool = anchored or rows
        pool.sort(key=lambda n: ((node_span(n)[2] - node_span(n)[0]) * 100000 + (node_span(n)[3] - node_span(n)[1]), n["id"]))
        return pool[0]["id"] if pool else None

    def facts_for_stmt(scope: str, stmt: CStmt) -> list[Mapping[str, Any]]:
        rows = []
        for fact in scoped_facts.get(scope, []):
            sp = fact_span(fact)
            if contains(stmt.span, sp) and _smallest_stmt([stmt], sp) is stmt:
                rows.append(fact)
        return sorted(rows, key=lambda f: (fact_span(f), str(f.get("kind")), repr(sorted(f.items()))))

    path_states: dict[str, dict[str, Any]] = {}
    pred_edges: dict[str, dict[str, Any]] = {}
    terminals: list[dict[str, Any]] = []

    def emit_state(scope: str, reaching: Mapping[str, set[str]], decisions: list[dict[str, Any]], events: list[str], predecessors: Sequence[str], transition: Mapping[str, Any], terminal: str | None = None) -> str:
        body = {
            "scope": scope,
            "predecessor_path_state_ids": sorted(set(predecessors)),
            "transition": dict(transition),
            "reaching_definitions": {k: sorted(v) for k, v in sorted(reaching.items())},
            "guard_decisions": list(decisions),
            "events": list(events),
        }
        pid = "ps_" + sha(canon(body))[:24]
        path_states[pid] = {"path_state_id": pid, **body}
        for parent in body["predecessor_path_state_ids"]:
            eb = {"source": parent, "target": pid, "transition": dict(transition)}
            eid = "pt_" + sha(canon(eb))[:24]
            pred_edges[eid] = {"id": eid, **eb}
        if terminal:
            terminals.append({"terminal_role": terminal, "path_state_id": pid, "guard_decisions": list(decisions), "events": list(events)})
        return pid

    State = tuple[dict[str, set[str]], list[dict[str, Any]], list[str], bool, str]

    effect_id = anchors.get("EFFECT_BOUNDARY")
    reject_id = anchors.get("REJECTION_NO_EFFECT_OUTCOME")
    success_id = anchors.get("SUCCESS_OUTCOME")

    def walk(scope: str, stmts: Sequence[CStmt], states: list[State]) -> list[State]:
        active = states
        for stmt in stmts:
            produced: list[State] = []
            for reaching0, decisions0, events0, alive, parent in active:
                if not alive:
                    produced.append((reaching0, decisions0, events0, alive, parent))
                    continue
                reaching = {k: set(v) for k, v in reaching0.items()}
                decisions = list(decisions0)
                events = list(events0)
                if stmt.kind == "IF":
                    gid = stmt_guard(stmt)
                    for polarity, body in ((True, stmt.then_body or []), (False, stmt.else_body or [])):
                        d2 = list(decisions)
                        if gid:
                            d2.append({"guard_id": gid, "polarity": polarity})
                        bid = emit_state(scope, reaching, d2, events, [parent], {"kind": "STRUCTURED_BRANCH", "guard_id": gid, "polarity": polarity, "statement_span": list(stmt.span)})
                        state: State = ({k: set(v) for k, v in reaching.items()}, d2, list(events), True, bid)
                        produced.extend(walk(scope, body, [state]) if body else [state])
                    continue

                wrote = False
                for fact in facts_for_stmt(scope, stmt):
                    if fact.get("kind") != "ASSIGN":
                        continue
                    sp = fact_span(fact)
                    candidates = defs_at.get((scope, sp), [])
                    for label in map(str, fact.get("lhs", [])):
                        match = [n for n in candidates if n["label"] == label and n.get("attrs", {}).get("definition_role") == "assignment"]
                        if match:
                            reaching[root_label(label)] = {match[0]["id"]}
                            wrote = True
                event_rows = []
                for role, nid in (("EFFECT_BOUNDARY", effect_id), ("SUCCESS_OUTCOME", success_id), ("REJECTION_NO_EFFECT_OUTCOME", reject_id)):
                    if nid and contains(stmt.span, node_span(nodes[nid])):
                        event_rows.append((role, nid))
                event_rows.sort(key=lambda x: ({"EFFECT_BOUNDARY": 0, "SUCCESS_OUTCOME": 1, "REJECTION_NO_EFFECT_OUTCOME": 0}[x[0]], node_span(nodes[x[1]])))
                cursor = parent
                if wrote and not event_rows:
                    cursor = emit_state(scope, reaching, decisions, events, [cursor], {"kind": "DEFINITION_TRANSFER", "statement_span": list(stmt.span)})
                for role, nid in event_rows:
                    events.append(role)
                    cursor = emit_state(scope, reaching, decisions, events, [cursor], {"kind": "TERMINAL_EVENT", "terminal_role": role, "anchor_node_id": nid, "statement_span": list(stmt.span)}, role)
                if not wrote and not event_rows:
                    cursor = emit_state(scope, reaching, decisions, events, [cursor], {"kind": "STRUCTURED_STATEMENT", "statement_kind": stmt.kind, "statement_span": list(stmt.span)})
                produced.append((reaching, decisions, events, stmt.kind != "RETURN", cursor))
            active = produced
        return active

    anchored_scopes: set[str] = set()
    for nid in anchors.values():
        scope = _function_for_span(controls, node_span(nodes[nid]))
        if scope:
            anchored_scopes.add(scope)
    for scope in sorted(anchored_scopes):
        initial = {k: set(v) for k, v in params.get(scope, {}).items()}
        entry = emit_state(scope, initial, [], [], [], {"kind": "ENTRY"})
        walk(scope, controls[scope]["stmts"], [(initial, [], [], True, entry)])

    transported_guard = anchors.get("GUARD_COMPARISON")
    effective_guard = None
    effective_form = "UNPROVEN"
    helper_reason = None
    if transported_guard and has_two_branches(transported_guard):
        effective_guard = transported_guard
        effective_form = "DIRECT_CONTROL"
    elif transported_guard:
        visited = {transported_guard}
        frontier = [transported_guard]
        consumers: set[str] = set()
        forbidden_transform = False
        while frontier:
            cur = frontier.pop()
            for edge in outgoing.get(cur, []):
                if edge["kind"] == "DERIVES":
                    deriv = edge.get("attrs", {}).get("derivation")
                    if deriv and deriv not in ALLOWED_HELPER_DERIVATIONS and deriv != "call_result":
                        forbidden_transform = True
                        continue
                    if edge["target"] not in visited:
                        visited.add(edge["target"]); frontier.append(edge["target"])
                elif edge["kind"] == "BINDS_TO" and edge.get("attrs", {}).get("binding") == "call_argument_to_parameter":
                    if edge["target"] not in visited:
                        visited.add(edge["target"]); frontier.append(edge["target"])
            for edge in overlay["edges"]:
                if edge["kind"] == "COMPARES" and edge["source"] == cur and has_two_branches(edge["target"]):
                    consumers.add(edge["target"])
        if len(consumers) == 1 and not forbidden_transform:
            effective_guard = next(iter(consumers)); effective_form = "HELPER_CONTROL"
        else:
            helper_reason = "HELPER_PREDICATE_POLARITY_UNPROVEN"
    if effective_form == "HELPER_CONTROL" and effective_guard:
        sp = node_span(nodes[effective_guard]); fragment = ""
        lines = source.splitlines()
        if sp[0] == sp[2] and 1 <= sp[0] <= len(lines):
            fragment = lines[sp[0] - 1][sp[1]:sp[3]].strip()
        if fragment.startswith("not ") or fragment.startswith("!") or "==" in fragment or "!=" in fragment or "&&" in fragment or "||" in fragment:
            effective_guard = None; effective_form = "UNPROVEN"; helper_reason = "HELPER_PREDICATE_POLARITY_UNPROVEN"

    completeness = {str(r["scope"]): str(r["status"]) for r in overlay.get("control_completeness", [])}
    material_complete = bool(anchored_scopes) and all(completeness.get(s) == "COMPLETE" for s in anchored_scopes)
    op_role = signature["effect_invocation_binding_surface"]["operation_role"]
    effect_ops = []
    if effect_id:
        esp = node_span(nodes[effect_id])
        effect_ops = [n["id"] for n in overlay["nodes"] if n.get("attrs", {}).get("operation_role") == op_role and contains(esp, node_span(n))]
    surface_status = "UNIQUE" if len(effect_ops) == 1 else ("MISSING" if not effect_ops else "AMBIGUOUS")

    def origins(nid: str) -> set[str]:
        seen: set[str] = set(); stack = [nid]; out: set[str] = set()
        while stack:
            cur = stack.pop()
            if cur in seen: continue
            seen.add(cur)
            if nodes.get(cur, {}).get("attrs", {}).get("definition_site_key"): out.add(cur)
            for edge in incoming.get(cur, []):
                if edge["kind"] in {"DERIVES", "BINDS_TO"}: stack.append(edge["source"])
        return out

    terminal_reaching = []
    for terminal in terminals:
        if terminal["terminal_role"] != "EFFECT_BOUNDARY" or not effect_id:
            continue
        state = path_states[terminal["path_state_id"]]
        live = {x for vals in state["reaching_definitions"].values() for x in vals}
        esp = node_span(nodes[effect_id])
        operations = [n["id"] for n in overlay["nodes"] if n.get("attrs", {}).get("operation_role") in {"call", "representation_instance"} and contains(esp, node_span(n))]
        for op in operations:
            for edge in incoming.get(op, []):
                if edge["kind"] not in {"CARRIES", "BINDS_TO"}: continue
                corr = sorted(origins(edge["source"]) & live)
                if corr:
                    terminal_reaching.append({"path_state_id": terminal["path_state_id"], "terminal_role": "EFFECT_BOUNDARY", "terminal_operation_id": op, "carrier_value_id": edge["source"], "carrier_edge_id": edge["id"], "active_origin_definition_ids": corr, "carrier_attrs": edge.get("attrs", {})})

    effect_paths = [t for t in terminals if t["terminal_role"] == "EFFECT_BOUNDARY"]
    rejection_paths = [t for t in terminals if t["terminal_role"] == "REJECTION_NO_EFFECT_OUTCOME"]
    success_paths = [t for t in terminals if t["terminal_role"] == "SUCCESS_OUTCOME"]
    doc = {
        "schema": "risu.e2-path-observability/v0.1",
        "semantic_authority": False,
        "source_sha256": source_sha,
        "base_overlay_digest_sha256": overlay.get("overlay_digest_sha256"),
        "canonical_signature_digest_sha256": signature.get("canonical_signature_digest_sha256"),
        "control_scope_completeness": completeness,
        "material_control_complete": material_complete,
        "effective_guard_observability": {"form": effective_form, "guard_id": effective_guard, "reason": helper_reason},
        "path_states": sorted(path_states.values(), key=lambda r: r["path_state_id"]),
        "path_state_predecessor_edges": sorted(pred_edges.values(), key=lambda r: r["id"]),
        "path_state_separation_policy": "NO_JOIN_UNION_FOR_WITNESS_CORRELATION",
        "terminal_reaching_facts": sorted(terminal_reaching, key=lambda r: (r["path_state_id"], r["terminal_operation_id"], r["carrier_edge_id"])),
        "entry_effect_paths": effect_paths,
        "rejection_paths": rejection_paths,
        "success_paths": success_paths,
        "path_dataflow_correlation": "COMPLETE" if material_complete and effect_paths else "INCOMPLETE",
        "effect_binding_surface": {"status": surface_status, "operation_role": op_role, "operation_ids": sorted(effect_ops)},
        "representation_closure_status": "REPRESENTATION_CLOSURE_UNPROVEN",
        "claim_boundary": "PATH_AND_DATAFLOW_OBSERVABILITY_ONLY_NO_A3_A4_VERDICT",
    }
    doc["path_observability_digest_sha256"] = sha(canon(doc))
    return doc


def assignments(overlay: Mapping[str, Any], label: str) -> list[Mapping[str, Any]]:
    rows = [n for n in overlay["nodes"] if n["label"] == label and n.get("attrs", {}).get("definition_role") == "assignment"]
    return sorted(rows, key=lambda n: (n["span"]["start_line"], n["span"]["start_col"], n["id"]))


def graph_origins(overlay: Mapping[str, Any], start: str) -> set[str]:
    nodes = {n["id"]: n for n in overlay["nodes"]}; incoming: dict[str, list[Mapping[str, Any]]] = {}
    for edge in overlay["edges"]: incoming.setdefault(edge["target"], []).append(edge)
    seen: set[str] = set(); stack = [start]; out: set[str] = set()
    while stack:
        cur = stack.pop()
        if cur in seen: continue
        seen.add(cur)
        if nodes.get(cur, {}).get("attrs", {}).get("definition_site_key"): out.add(cur)
        for edge in incoming.get(cur, []):
            if edge["kind"] in {"DERIVES", "BINDS_TO"}: stack.append(edge["source"])
    return out


def independent_observation(fixture: Mapping[str, Any], overlay: Mapping[str, Any], pathdoc: Mapping[str, Any]) -> str:
    family = fixture["family_id"]
    eg = pathdoc["effective_guard_observability"]
    effects = list(pathdoc["entry_effect_paths"]); rejects = list(pathdoc["rejection_paths"]); successes = list(pathdoc["success_paths"])
    states = {r["path_state_id"]: r for r in pathdoc["path_states"]}
    complete = pathdoc["material_control_complete"] is True and pathdoc["path_dataflow_correlation"] == "COMPLETE" and pathdoc["effect_binding_surface"]["status"] == "UNIQUE" and effects and rejects and successes
    if family == "CQ_DIRECT_STABLE" and complete and eg["form"] == "DIRECT_CONTROL": return "COMPLETE_EVIDENCE_SURFACE"
    if family == "CQ_HELPER_IDENTITY" and complete and eg["form"] == "HELPER_CONTROL": return "COMPLETE_IDENTITY_HELPER_SURFACE"
    if family == "CQ_HELPER_NEGATED" and eg["form"] == "UNPROVEN" and eg.get("reason") == "HELPER_PREDICATE_POLARITY_UNPROVEN": return "HELPER_PREDICATE_POLARITY_UNPROVEN"
    if family == "CQ_STRAIGHT_LINE_KILL":
        xs = assignments(overlay, "x")
        sets = [set(r["active_origin_definition_ids"]) for r in pathdoc["terminal_reaching_facts"]]
        if len(xs) == 2 and sets and all(xs[1]["id"] in s and xs[0]["id"] not in s for s in sets): return "KILL_CORRELATION_PROVED"
    if family == "CQ_BRANCH_JOIN":
        xs = assignments(overlay, "x"); rs = [set(states[p["path_state_id"]]["reaching_definitions"].get("x", [])) for p in effects]
        if len(xs) == 2 and len(rs) >= 2 and all(len(s) == 1 for s in rs) and set().union(*rs) >= {xs[0]["id"], xs[1]["id"]}: return "DISTINCT_PATH_STATES_AT_JOIN"
    if family == "CQ_FALSE_CROSS_PRODUCT_TRAP":
        xs = assignments(overlay, "x"); rs = [set(states[p["path_state_id"]]["reaching_definitions"].get("x", [])) for p in effects]
        if len(xs) == 2 and rs and all(xs[1]["id"] not in s for s in rs): return "NO_FABRICATED_WRONGDEF_EFFECT_PATH"
    if family == "CQ_WRONG_BINDING_COMPLETE_PATH":
        vals = overlay.get("binding_slots", {}).get("current_coordinate", {}).get("value_instance_ids", [])
        other = [n["id"] for n in overlay["nodes"] if n["label"] == "other" and n.get("attrs", {}).get("definition_role") == "function_parameter" and n.get("attrs", {}).get("scope") == "target"]
        if len(vals) == 1 and len(other) == 1 and other[0] in graph_origins(overlay, vals[0]) and complete: return "WRONG_BINDING_PATH_FACT_OBSERVABLE_NO_VERDICT"
    if family == "CQ_EFFECT_SURFACE_UNIQUE" and pathdoc["effect_binding_surface"]["status"] == "UNIQUE": return "UNIQUE_EFFECT_SURFACE"
    if family == "CQ_EFFECT_SURFACE_AMBIGUOUS" and pathdoc["effect_binding_surface"]["status"] == "AMBIGUOUS": return "EFFECT_SURFACE_INCOMPLETE"
    if family == "CQ_CONTROL_INCOMPLETE_UNSUPPORTED" and pathdoc["material_control_complete"] is False: return "CONTROL_INCOMPLETE"
    if family in {"CQ_GUARD_BYPASS_PATH", "CQ_EFFECT_BEFORE_GUARD_PATH"}:
        gid = eg.get("guard_id")
        if gid and effects and any(all(d.get("guard_id") != gid for d in p["guard_decisions"]) for p in effects):
            return "BYPASS_PATH_FACT_OBSERVABLE_NO_VERDICT" if family == "CQ_GUARD_BYPASS_PATH" else "ORDER_PATH_FACT_OBSERVABLE_NO_VERDICT"
    if family == "CQ_REJECTION_FALLBACK_PATH":
        if any("EFFECT_BOUNDARY" in p["events"] and p["events"].index("EFFECT_BOUNDARY") < p["events"].index("REJECTION_NO_EFFECT_OUTCOME") for p in rejects): return "REJECTION_EFFECT_PATH_FACT_OBSERVABLE_NO_VERDICT"
    if family == "CQ_OUTCOME_DISTINCT":
        rid = {p["path_state_id"] for p in rejects}; sid = {p["path_state_id"] for p in successes}
        if rid and sid and rid.isdisjoint(sid) and any("EFFECT_BOUNDARY" not in p["events"] for p in rejects) and any("EFFECT_BOUNDARY" in p["events"] for p in successes): return "DISTINCT_OUTCOME_PATHS_OBSERVABLE"
    if family == "CQ_REPRESENTATION_SURVIVAL":
        fields = [str(n.get("attrs", {}).get("field", "")).lower() for n in overlay["nodes"] if n.get("attrs", {}).get("definition_role") == "representation_field_write"]
        if "guard" in fields and pathdoc["effect_binding_surface"]["status"] == "UNIQUE": return "REPRESENTATION_SURVIVAL_OBSERVABLE"
    if family == "CQ_REPRESENTATION_OMISSION_UNQUALIFIED" and pathdoc["representation_closure_status"] == "REPRESENTATION_CLOSURE_UNPROVEN": return "REPRESENTATION_CLOSURE_UNPROVEN"
    return "MICROQUALIFICATION_EXPECTATION_NOT_MET"


def compact(pathdoc: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "effective_guard_observability": pathdoc["effective_guard_observability"],
        "material_control_complete": pathdoc["material_control_complete"],
        "control_scope_completeness": pathdoc["control_scope_completeness"],
        "path_dataflow_correlation": pathdoc["path_dataflow_correlation"],
        "effect_binding_surface": pathdoc["effect_binding_surface"],
        "representation_closure_status": pathdoc["representation_closure_status"],
        "path_state_ids": [r["path_state_id"] for r in pathdoc["path_states"]],
        "predecessor_edge_ids": [r["id"] for r in pathdoc["path_state_predecessor_edges"]],
        "effect_path_state_ids": [r["path_state_id"] for r in pathdoc["entry_effect_paths"]],
        "rejection_path_state_ids": [r["path_state_id"] for r in pathdoc["rejection_paths"]],
        "success_path_state_ids": [r["path_state_id"] for r in pathdoc["success_paths"]],
        "terminal_reaching_facts": pathdoc["terminal_reaching_facts"],
    }


def rerun(fixture: Mapping[str, Any], go_helper: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], str]:
    raw = str(fixture["source"]).encode("utf-8"); source = raw.decode("utf-8"); source_sha = sha(raw)
    parsed = frontend(fixture["language"], fixture["filename"], raw, go_helper)
    if parsed.get("status") != "PASS": raise ValueError("independent frontend parse failure")
    contract, csha = independent_contract(fixture, parsed["facts"], source, source_sha)
    sig = independent_signature(fixture)
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / fixture["filename"]; p.write_bytes(raw)
        acq, acquired = acquire(Path(td), entrypoints=[p.name], config=AcquisitionConfig())
        base_ir, status = build_ir(acquired, acquisition_doc=acq, go_helper_path=go_helper)
    if status.get("status") != "PASS": raise ValueError("independent base IR failure")
    overlay = build_overlay(path=fixture["filename"], source=source, source_sha256=source_sha, language=fixture["language"], facts=parsed["facts"], base_ir=base_ir, anchor_contract=contract, anchor_contract_sha256=csha)
    validate_overlay(overlay)
    addr_errors = verify_overlay_content_addressing(overlay)
    if addr_errors: raise ValueError(";".join(addr_errors))
    pathdoc = independent_path(source, source_sha, fixture["language"], parsed["facts"], overlay, sig)
    observed = independent_observation(fixture, overlay, pathdoc)
    return base_ir, overlay, pathdoc, observed


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--protocol", required=True)
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--primary", required=True)
    ap.add_argument("--go-helper", required=True)
    ap.add_argument("--output", required=True)
    args = ap.parse_args()
    protocol_raw = Path(args.protocol).read_bytes(); protocol = json.loads(protocol_raw)
    corpus_raw = Path(args.corpus).read_bytes(); corpus = json.loads(corpus_raw)
    primary_raw = Path(args.primary).read_bytes(); primary = json.loads(primary_raw)
    errors: list[str] = []
    if primary.get("schema") != PRIMARY_SCHEMA or primary.get("fixture_count") != 48: errors.append("PRIMARY_SCHEMA_OR_COUNT")
    if corpus.get("fixture_count") != 48 or corpus.get("family_count") != 16: errors.append("CORPUS_COUNT")
    ctmp = dict(corpus); cint = ctmp.pop("corpus_digest_sha256", None)
    if cint != sha(canon(ctmp)): errors.append("CORPUS_INTERNAL_DIGEST")
    frozen = {x["id"]: x["expected"] for x in protocol["preimplementation_end_to_end_microqualification"]["families"]}
    if {x["family_id"]: x["expected_observation"] for x in corpus["fixtures"]} != frozen: errors.append("PROTOCOL_CORPUS_FAMILY_BINDING")
    primary_rows = {r["fixture_id"]: r for r in primary.get("rows", [])}
    if len(primary_rows) != 48: errors.append("PRIMARY_ROW_BIJECTION")
    audit_rows = []
    for fixture in sorted(corpus["fixtures"], key=lambda x: x["fixture_id"]):
        fid = fixture["fixture_id"]
        try:
            base_ir, overlay, pathdoc, observed = rerun(fixture, Path(args.go_helper))
            prow = primary_rows.get(fid)
            if prow is None:
                errors.append(fid + ":PRIMARY_ROW_MISSING"); continue
            checks = {
                "source_sha256": prow.get("source_sha256") == sha(str(fixture["source"]).encode("utf-8")),
                "base_ir_digest": prow.get("base_ir_digest_sha256") == base_ir.get("ir_digest_sha256"),
                "overlay_digest": prow.get("overlay_digest_sha256") == overlay.get("overlay_digest_sha256"),
                "path_digest": prow.get("path_observability_digest_sha256") == pathdoc.get("path_observability_digest_sha256"),
                "path_summary": prow.get("path_summary") == compact(pathdoc),
                "observed_observation": prow.get("observed_observation") == observed,
                "expected_observation": observed == fixture["expected_observation"],
                "primary_pass": prow.get("passed") is True,
            }
            bad = [k for k, v in checks.items() if not v]
            for item in bad: errors.append(fid + ":" + item)
            audit_rows.append({"fixture_id": fid, "observed_observation": observed, "checks": checks, "pass": not bad, "independent_path_digest_sha256": pathdoc["path_observability_digest_sha256"]})
        except Exception as exc:
            errors.append(fid + ":INDEPENDENT_EXCEPTION:" + type(exc).__name__)
            audit_rows.append({"fixture_id": fid, "pass": False, "diagnostic_type": type(exc).__name__})
    if primary.get("status") != "PASS": errors.append("PRIMARY_STATUS_NOT_PASS")
    if primary.get("bundle_digest_sha256"):
        ptmp = dict(primary); observed = ptmp.pop("bundle_digest_sha256")
        if observed != sha(canon(ptmp)): errors.append("PRIMARY_INTERNAL_DIGEST")
    out = {
        "schema": AUDIT_SCHEMA,
        "semantic_authority": False,
        "status": "PASS" if not errors else "FAIL",
        "fixture_count": 48,
        "family_count": 16,
        "protocol_sha256": sha(protocol_raw),
        "corpus_sha256": sha(corpus_raw),
        "primary_sha256": sha(primary_raw),
        "rows": audit_rows,
        "errors": sorted(errors),
        "independence_attestation": {
            "imports_primary_microqualifier": False,
            "imports_primary_path_observability": False,
            "recomputes_frontend_base_ir_overlay": True,
            "recomputes_overlay_node_edge_content_addressing": True,
            "recomputes_path_state_transition_identities": True,
            "recomputes_kill_and_branch_state_separation": True,
            "recomputes_false_cross_product_exclusion": True,
            "recomputes_effective_guard_and_effect_surface": True,
            "recomputes_family_observation": True,
        },
        "read_set_attestation": {
            "candidate_58_bytes": False, "sanitized_58_manifest": False, "raw_blind_58_transport": False,
            "mutation_truth": False, "operator_metadata": False, "expected_e2_predictions": False,
            "fresh_target_bytes": False,
        },
        "claim_boundary": {"microqualification_audit_only": True, "a3_a4_semantic_verdicts_emitted": False, "mutant_58_observability_executed": False},
    }
    out["audit_digest_sha256"] = sha(canon(out))
    Path(args.output).write_bytes(canon(out))
    print(json.dumps({"status": out["status"], "errors": len(errors), "sha256": sha(Path(args.output).read_bytes())}, sort_keys=True, separators=(",", ":")))
    return 0 if out["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
