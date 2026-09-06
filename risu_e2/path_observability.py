from __future__ import annotations

import hashlib
from typing import Any, Mapping, Sequence

from .model import canonical_bytes
from .overlay_common import _contains, _root_label, _span_tuple
from .overlay_control import CStmt, _control_functions, _function_for_span, _smallest_stmt

SCHEMA = "risu.e2-path-observability/v0.1"
ALLOWED_HELPER_DERIVATIONS = {
    "comparison_result_to_return",
    "function_return_to_call_result",
    "call_result_to_assignment",
}


def _sha(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _sp(node: Mapping[str, Any]) -> tuple[int, int, int, int]:
    s = node["span"]
    return (int(s["start_line"]), int(s["start_col"]), int(s["end_line"]), int(s["end_col"]))


def build_path_observability(
    *, path: str, source: str, source_sha256: str, language: str,
    facts: Sequence[Mapping[str, Any]], overlay: Mapping[str, Any],
    canonical_signature: Mapping[str, Any],
) -> dict[str, Any]:
    """Build an additive path-state sidecar over a frozen A2O overlay.

    This routine deliberately does not emit an A3/A4 verdict.  Its only job is
    to preserve mutually exclusive structured-control states long enough to
    correlate reaching definitions with terminal consequence observations.
    """
    nodes = {n["id"]: n for n in overlay["nodes"]}
    edges = list(overlay["edges"])
    incoming: dict[str, list[Mapping[str, Any]]] = {}
    outgoing: dict[str, list[Mapping[str, Any]]] = {}
    for edge in edges:
        incoming.setdefault(edge["target"], []).append(edge)
        outgoing.setdefault(edge["source"], []).append(edge)

    controls = _control_functions(source, language, [f for f in facts if f.get("kind") == "FUNCTION"])
    facts_by_scope: dict[str, list[Mapping[str, Any]]] = {scope: [] for scope in controls}
    for fact in facts:
        if fact.get("kind") == "FUNCTION":
            continue
        scope = _function_for_span(controls, _span_tuple(fact))
        if scope:
            facts_by_scope.setdefault(scope, []).append(fact)

    definitions_by_scope_span: dict[tuple[str, tuple[int, int, int, int]], list[Mapping[str, Any]]] = {}
    params_by_scope: dict[str, dict[str, set[str]]] = {}
    anchors: dict[str, str] = {}
    for node in overlay["nodes"]:
        attrs = node.get("attrs", {})
        role = attrs.get("definition_role")
        scope = str(attrs.get("scope"))
        if role == "function_parameter":
            params_by_scope.setdefault(scope, {}).setdefault(_root_label(node["label"]), set()).add(node["id"])
        if role in {"assignment", "representation_field_write", "call_result"}:
            definitions_by_scope_span.setdefault((scope, _sp(node)), []).append(node)
        anchor_role = attrs.get("anchor_role")
        if anchor_role:
            anchors[str(anchor_role)] = node["id"]

    def branch_bearing(guard_id: str) -> bool:
        polarities = {
            e.get("attrs", {}).get("branch_polarity")
            for e in outgoing.get(guard_id, []) if e["kind"] == "GUARDS"
        }
        return True in polarities and False in polarities

    def guard_for(stmt: CStmt) -> str | None:
        condition_span = stmt.condition_span or stmt.span
        rows = [n for n in overlay["nodes"] if n["kind"] == "GUARD" and _contains(condition_span, _sp(n))]
        if not rows:
            return None
        anchored = [n for n in rows if n.get("attrs", {}).get("anchor_role") == "GUARD_COMPARISON"]
        use = anchored or rows
        use.sort(key=lambda n: ((_sp(n)[2] - _sp(n)[0]) * 100000 + (_sp(n)[3] - _sp(n)[1]), n["id"]))
        return use[0]["id"]

    def reverse_origins(node_id: str) -> set[str]:
        seen: set[str] = set()
        stack = [node_id]
        origins: set[str] = set()
        while stack:
            current = stack.pop()
            if current in seen:
                continue
            seen.add(current)
            node = nodes.get(current, {})
            if node.get("attrs", {}).get("definition_site_key"):
                origins.add(current)
            for edge in incoming.get(current, []):
                if edge["kind"] in {"DERIVES", "BINDS_TO"}:
                    stack.append(edge["source"])
        return origins

    effect_id = anchors.get("EFFECT_BOUNDARY")
    rejection_id = anchors.get("REJECTION_NO_EFFECT_OUTCOME")
    success_id = anchors.get("SUCCESS_OUTCOME")
    state_rows: dict[str, dict[str, Any]] = {}
    predecessor_edges: dict[str, dict[str, Any]] = {}
    terminal_events: list[dict[str, Any]] = []

    def snapshot(
        scope: str,
        defs: Mapping[str, set[str]],
        decisions: list[dict[str, Any]],
        events: list[str],
        predecessors: Sequence[str],
        transition: Mapping[str, Any],
        terminal: str | None = None,
    ) -> str:
        pred = sorted(set(predecessors))
        body = {
            "scope": scope,
            "predecessor_path_state_ids": pred,
            "transition": dict(transition),
            "reaching_definitions": {k: sorted(v) for k, v in sorted(defs.items())},
            "guard_decisions": list(decisions),
            "events": list(events),
        }
        pid = "ps_" + _sha(body)[:24]
        state_rows[pid] = {"path_state_id": pid, **body}
        for parent in pred:
            edge_body = {"source": parent, "target": pid, "transition": dict(transition)}
            eid = "pt_" + _sha(edge_body)[:24]
            predecessor_edges[eid] = {"id": eid, **edge_body}
        if terminal:
            terminal_events.append({
                "terminal_role": terminal,
                "path_state_id": pid,
                "guard_decisions": list(decisions),
                "events": list(events),
            })
        return pid

    def statement_facts(scope: str, stmt: CStmt) -> list[Mapping[str, Any]]:
        rows = []
        for fact in facts_by_scope.get(scope, []):
            span = _span_tuple(fact)
            if _contains(stmt.span, span) and _smallest_stmt([stmt], span) is stmt:
                rows.append(fact)
        return sorted(rows, key=lambda f: (_span_tuple(f), str(f.get("kind")), repr(sorted(f.items()))))

    State = tuple[dict[str, set[str]], list[dict[str, Any]], list[str], bool, str]

    def process(scope: str, stmts: Sequence[CStmt], states: list[State]) -> list[State]:
        current = states
        for stmt in stmts:
            next_states: list[State] = []
            for state_defs, state_decisions, state_events, alive, parent_id in current:
                if not alive:
                    next_states.append((state_defs, state_decisions, state_events, alive, parent_id))
                    continue
                defs = {k: set(v) for k, v in state_defs.items()}
                decisions = list(state_decisions)
                events = list(state_events)
                if stmt.kind == "IF":
                    guard_id = guard_for(stmt)
                    for polarity, body in ((True, stmt.then_body or []), (False, stmt.else_body or [])):
                        branch_decisions = list(decisions)
                        if guard_id:
                            branch_decisions.append({"guard_id": guard_id, "polarity": polarity})
                        branch_id = snapshot(
                            scope, defs, branch_decisions, events, [parent_id],
                            {"kind": "STRUCTURED_BRANCH", "guard_id": guard_id, "polarity": polarity,
                             "statement_span": list(stmt.span)},
                        )
                        branch_state: State = ({k: set(v) for k, v in defs.items()}, branch_decisions, list(events), True, branch_id)
                        if body:
                            next_states.extend(process(scope, body, [branch_state]))
                        else:
                            next_states.append(branch_state)
                    continue

                changed = False
                for fact in statement_facts(scope, stmt):
                    if fact.get("kind") != "ASSIGN":
                        continue
                    span = _span_tuple(fact)
                    candidates = definitions_by_scope_span.get((scope, span), [])
                    for label in map(str, fact.get("lhs", [])):
                        exact = [n for n in candidates if n["label"] == label and n.get("attrs", {}).get("definition_role") == "assignment"]
                        if exact:
                            defs[_root_label(label)] = {exact[0]["id"]}
                            changed = True

                local_events: list[tuple[str, str]] = []
                for role, node_id in (
                    ("EFFECT_BOUNDARY", effect_id),
                    ("SUCCESS_OUTCOME", success_id),
                    ("REJECTION_NO_EFFECT_OUTCOME", rejection_id),
                ):
                    if node_id and _contains(stmt.span, _sp(nodes[node_id])):
                        local_events.append((role, node_id))
                local_events.sort(key=lambda row: ({"EFFECT_BOUNDARY": 0, "SUCCESS_OUTCOME": 1, "REJECTION_NO_EFFECT_OUTCOME": 0}[row[0]], _sp(nodes[row[1]])))

                current_parent = parent_id
                if changed and not local_events:
                    current_parent = snapshot(
                        scope, defs, decisions, events, [current_parent],
                        {"kind": "DEFINITION_TRANSFER", "statement_span": list(stmt.span)},
                    )
                for role, node_id in local_events:
                    events.append(role)
                    current_parent = snapshot(
                        scope, defs, decisions, events, [current_parent],
                        {"kind": "TERMINAL_EVENT", "terminal_role": role, "anchor_node_id": node_id,
                         "statement_span": list(stmt.span)},
                        role,
                    )
                if not changed and not local_events:
                    current_parent = snapshot(
                        scope, defs, decisions, events, [current_parent],
                        {"kind": "STRUCTURED_STATEMENT", "statement_kind": stmt.kind, "statement_span": list(stmt.span)},
                    )
                alive_after = stmt.kind != "RETURN"
                next_states.append((defs, decisions, events, alive_after, current_parent))
            current = next_states
        return current

    anchored_scopes: set[str] = set()
    for node_id in anchors.values():
        scope = _function_for_span(controls, _sp(nodes[node_id]))
        if scope:
            anchored_scopes.add(scope)
    for scope in sorted(anchored_scopes):
        initial = {k: set(v) for k, v in params_by_scope.get(scope, {}).items()}
        entry_id = snapshot(scope, initial, [], [], [], {"kind": "ENTRY"})
        process(scope, controls[scope]["stmts"], [(initial, [], [], True, entry_id)])

    transported_guard = anchors.get("GUARD_COMPARISON")
    effective_guard: str | None = None
    effective_form = "UNPROVEN"
    helper_reason: str | None = None
    if transported_guard and branch_bearing(transported_guard):
        effective_guard = transported_guard
        effective_form = "DIRECT_CONTROL"
    elif transported_guard:
        seen = {transported_guard}
        stack = [transported_guard]
        reachable_consumers: set[str] = set()
        bad_transform = False
        while stack:
            current = stack.pop()
            for edge in outgoing.get(current, []):
                if edge["kind"] == "DERIVES":
                    derivation = edge.get("attrs", {}).get("derivation")
                    if derivation and derivation not in ALLOWED_HELPER_DERIVATIONS and derivation != "call_result":
                        bad_transform = True
                        continue
                    target = edge["target"]
                    if target not in seen:
                        seen.add(target)
                        stack.append(target)
                elif edge["kind"] == "BINDS_TO" and edge.get("attrs", {}).get("binding") == "call_argument_to_parameter":
                    target = edge["target"]
                    if target not in seen:
                        seen.add(target)
                        stack.append(target)
            for edge in edges:
                if edge["kind"] == "COMPARES" and edge["source"] == current and branch_bearing(edge["target"]):
                    reachable_consumers.add(edge["target"])
        if len(reachable_consumers) == 1 and not bad_transform:
            effective_guard = next(iter(reachable_consumers))
            effective_form = "HELPER_CONTROL"
        else:
            helper_reason = "HELPER_PREDICATE_POLARITY_UNPROVEN"

    if effective_form == "HELPER_CONTROL" and effective_guard:
        span = _sp(nodes[effective_guard])
        fragment = ""
        lines = source.splitlines()
        if span[0] == span[2] and 1 <= span[0] <= len(lines):
            fragment = lines[span[0] - 1][span[1]:span[3]].strip()
        if fragment.startswith("not ") or fragment.startswith("!") or "==" in fragment or "!=" in fragment or "&&" in fragment or "||" in fragment:
            helper_reason = "HELPER_PREDICATE_POLARITY_UNPROVEN"
            effective_form = "UNPROVEN"
            effective_guard = None

    completeness = {str(row["scope"]): str(row["status"]) for row in overlay.get("control_completeness", [])}
    material_control_complete = bool(anchored_scopes) and all(completeness.get(scope) == "COMPLETE" for scope in anchored_scopes)

    surface = canonical_signature.get("effect_invocation_binding_surface", {})
    operation_role = surface.get("operation_role")
    effect_operations: list[str] = []
    if effect_id and operation_role:
        effect_span = _sp(nodes[effect_id])
        effect_operations = [
            n["id"] for n in overlay["nodes"]
            if n.get("attrs", {}).get("operation_role") == operation_role and _contains(effect_span, _sp(n))
        ]
    effect_surface_status = "UNIQUE" if len(effect_operations) == 1 else ("MISSING" if not effect_operations else "AMBIGUOUS")

    terminal_reaching: list[dict[str, Any]] = []
    for terminal in terminal_events:
        if terminal["terminal_role"] != "EFFECT_BOUNDARY":
            continue
        state = state_rows[terminal["path_state_id"]]
        active = {node_id for values in state["reaching_definitions"].values() for node_id in values}
        if not effect_id:
            continue
        effect_span = _sp(nodes[effect_id])
        operations = [
            n["id"] for n in overlay["nodes"]
            if n.get("attrs", {}).get("operation_role") in {"call", "representation_instance"} and _contains(effect_span, _sp(n))
        ]
        for operation_id in operations:
            for edge in incoming.get(operation_id, []):
                if edge["kind"] not in {"CARRIES", "BINDS_TO"}:
                    continue
                origins = reverse_origins(edge["source"])
                correlated = sorted(origins & active)
                if correlated:
                    terminal_reaching.append({
                        "path_state_id": terminal["path_state_id"],
                        "terminal_role": "EFFECT_BOUNDARY",
                        "terminal_operation_id": operation_id,
                        "carrier_value_id": edge["source"],
                        "carrier_edge_id": edge["id"],
                        "active_origin_definition_ids": correlated,
                        "carrier_attrs": edge.get("attrs", {}),
                    })

    entry_effect_paths = [row for row in terminal_events if row["terminal_role"] == "EFFECT_BOUNDARY"]
    rejection_paths = [row for row in terminal_events if row["terminal_role"] == "REJECTION_NO_EFFECT_OUTCOME"]
    success_paths = [row for row in terminal_events if row["terminal_role"] == "SUCCESS_OUTCOME"]
    correlation = "COMPLETE" if material_control_complete and entry_effect_paths else "INCOMPLETE"

    document = {
        "schema": SCHEMA,
        "semantic_authority": False,
        "source_sha256": source_sha256,
        "base_overlay_digest_sha256": overlay.get("overlay_digest_sha256"),
        "canonical_signature_digest_sha256": canonical_signature.get("canonical_signature_digest_sha256"),
        "control_scope_completeness": completeness,
        "material_control_complete": material_control_complete,
        "effective_guard_observability": {"form": effective_form, "guard_id": effective_guard, "reason": helper_reason},
        "path_states": sorted(state_rows.values(), key=lambda row: row["path_state_id"]),
        "path_state_predecessor_edges": sorted(predecessor_edges.values(), key=lambda row: row["id"]),
        "path_state_separation_policy": "NO_JOIN_UNION_FOR_WITNESS_CORRELATION",
        "terminal_reaching_facts": sorted(terminal_reaching, key=lambda row: (row["path_state_id"], row["terminal_operation_id"], row["carrier_edge_id"])),
        "entry_effect_paths": entry_effect_paths,
        "rejection_paths": rejection_paths,
        "success_paths": success_paths,
        "path_dataflow_correlation": correlation,
        "effect_binding_surface": {"status": effect_surface_status, "operation_role": operation_role, "operation_ids": sorted(effect_operations)},
        "representation_closure_status": "REPRESENTATION_CLOSURE_UNPROVEN",
        "claim_boundary": "PATH_AND_DATAFLOW_OBSERVABILITY_ONLY_NO_A3_A4_VERDICT",
    }
    document["path_observability_digest_sha256"] = _sha(document)
    return document
