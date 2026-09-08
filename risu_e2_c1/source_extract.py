from __future__ import annotations

"""Independent direct-control reconstruction from Python raw source."""

import ast
import copy
from typing import Any, Mapping

from .binding_authority import (
    derive_binding_authority_receipt,
    prefix_binding_environment,
)
from .common import SLICE_SCHEMA, _digest_bytes, _digest_json
from .projection_authority import (
    evaluate_compare_with_projection_authority,
    prefix_projection_environment,
)
from .source_python import (
    ALLOWED_ASSIGN,
    _anchor_node,
    _apply_assign,
    _compare_op_name,
    _contains,
    _effect_expr,
    _eval_compare,
    _find_target_function,
    _origins,
    _role_state,
    _slice_bytes,
    _span,
    _unsupported_in_function,
)


def _extract_direct(
    *,
    source: bytes,
    tree: ast.Module,
    signature: Mapping[str, Any],
    contract: Mapping[str, Any],
    case_id: str,
) -> tuple[dict[str, Any] | None, list[str]]:
    bad: list[str] = []
    fn, err = _find_target_function(tree, contract.get("target_function_span", []))
    if err or fn is None:
        return None, [err or "TARGET_SCOPE_MISSING"]
    bad.extend(_unsupported_in_function(fn))
    if bad:
        return None, bad

    state0, role_bad = _role_state(fn, signature)
    bad.extend(role_bad)
    guard_node, e1 = _anchor_node(tree, "guard", contract)
    effect_node, e2 = _anchor_node(tree, "effect", contract)
    success_node, e3 = _anchor_node(tree, "success", contract)
    rejection_node, e4 = _anchor_node(tree, "rejection", contract)
    bad.extend(x for x in (e1, e2, e3, e4) if x)
    if (
        bad
        or not isinstance(guard_node, ast.Compare)
        or effect_node is None
        or not isinstance(success_node, ast.Return)
        or not isinstance(rejection_node, ast.Return)
    ):
        return None, sorted(set(bad))

    if_rows = [n for n in ast.walk(fn) if isinstance(n, ast.If)]
    if len(if_rows) != 1:
        return None, ["C1_REQUIRES_EXACTLY_ONE_IF"]
    guard_if = if_rows[0]
    if tuple(contract.get("effective_if_span", [])) != _span(guard_if):
        return None, ["EFFECTIVE_IF_SPAN_MISMATCH"]
    if not _contains(_span(guard_if.test), _span(guard_node)):
        return None, ["DIRECT_GUARD_NOT_BRANCH_BEARING"]
    if signature.get("guard", {}).get("form") != "DIRECT_CONTROL":
        return None, ["C1_V0_1_ONLY_DIRECT_CONTROL"]

    state = {k: set(v) for k, v in state0.items()}
    definition_trace: list[dict[str, Any]] = []
    prefix: list[ast.stmt] = []
    found_if = False
    suffix: list[ast.stmt] = []
    for stmt in fn.body:
        if stmt is guard_if:
            found_if = True
            continue
        if not found_if:
            prefix.append(stmt)
        else:
            suffix.append(stmt)
    for stmt in prefix:
        if isinstance(stmt, ALLOWED_ASSIGN):
            state, why = _apply_assign(stmt, state, definition_trace)
            if why:
                bad.append(why)
        elif isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant):
            continue
        else:
            bad.append("PREFIX_STATEMENT_OUTSIDE_MINIMAL_FRAGMENT")
    if bad:
        return None, sorted(set(bad))

    # Gate2C7 world-role projection authority and Gate2C8 binding authority are
    # deliberately reconstructed by separate code paths from the same raw AST.
    projection_env, projection_params, projection_sidecar_bad = (
        prefix_projection_environment(fn, guard_if, signature)
    )
    binding_env, binding_params, binding_sidecar_bad = prefix_binding_environment(
        fn, guard_if, signature
    )

    operands = [guard_node.left] + list(guard_node.comparators)
    guard_specs = [
        x
        for x in signature.get("required_bindings", []) or []
        if x.get("kind") == "guard_operand"
    ]
    bindings: list[dict[str, Any]] = []
    source_sha256 = _digest_bytes(source)
    for spec in guard_specs:
        idx = spec.get("operand_index")
        if not isinstance(idx, int) or idx < 0 or idx >= len(operands):
            bad.append(f"GUARD_OPERAND_INDEX_INVALID:{spec.get('binding_id')}")
            continue
        obs = _origins(operands[idx], state)
        if obs is None:
            bad.append(f"GUARD_OPERAND_ORIGIN_UNRESOLVED:{spec.get('binding_id')}")
            continue
        bid = str(spec.get("binding_id"))
        slot_identity = {"operand_index": idx}
        binding_receipts = [
            derive_binding_authority_receipt(
                operands[idx],
                case_id=case_id,
                binding_id=bid,
                source_sha256=source_sha256,
                raw_origin=o,
                binding_slot_identity=slot_identity,
                env=binding_env,
                param_by_name=binding_params,
            )
            for o in sorted(obs)
        ]
        bindings.append(
            {
                "binding_id": bid,
                "coordinate_identity": str(spec.get("coordinate_identity")),
                "resource_identity": str(spec.get("resource_identity")),
                "slot_identity": slot_identity,
                "allowed_origins": list(spec.get("allowed_origins", [])),
                "observed_origins": sorted(obs),
                "binding_complete": True,
                "definitions_complete": True,
                "lineage_paths": [
                    {
                        "origin": o,
                        "edges": [
                            {
                                "kind": "BINDS_TO",
                                "from": o,
                                "to": bid,
                                "path_id": "guard-direct",
                            }
                        ],
                    }
                    for o in sorted(obs)
                ],
                "definition_trace": copy.deepcopy(definition_trace),
                "representation": {"required": False},
                "binding_authority_receipts": binding_receipts,
            }
        )

    branch_rows: list[tuple[bool, list[ast.stmt]]] = [
        (True, list(guard_if.body)),
        (False, list(guard_if.orelse) + suffix),
    ]
    control_paths: list[dict[str, Any]] = []
    world_branch_states: dict[bool, tuple[dict[str, set[str]], ast.Return]] = {}
    surface_ids: set[str] = set()
    success_id = str(
        signature.get("effect", {}).get("success_outcome_id", "SUCCESS")
    )
    rejection_id = str(
        signature.get("effect", {}).get("rejection_outcome_id", "REJECTION")
    )
    effect_surface_id = str(signature.get("effect", {}).get("surface_id", "EFFECT"))

    for polarity, stmts in branch_rows:
        bst = {k: set(v) for k, v in state.items()}
        btrace = copy.deepcopy(definition_trace)
        ret: ast.Return | None = None
        events = ["ENTRY", "GUARD:g0", f"POLARITY:{str(polarity).lower()}"]
        for stmt in stmts:
            if isinstance(stmt, ALLOWED_ASSIGN):
                bst, why = _apply_assign(stmt, bst, btrace)
                if why:
                    bad.append(why)
            elif isinstance(stmt, ast.Return):
                if ret is not None:
                    bad.append("MULTIPLE_RETURNS_PER_BRANCH")
                ret = stmt
                if _contains(_span(stmt), _span(effect_node)):
                    events.append(f"EFFECT:{effect_surface_id}")
                    surface_ids.add(effect_surface_id)
                if _span(stmt) == _span(success_node):
                    events.append(f"SUCCESS:{success_id}")
                if _span(stmt) == _span(rejection_node):
                    events.append(f"REJECTION:{rejection_id}")
                events.append("EXIT")
            else:
                bad.append("BRANCH_STATEMENT_OUTSIDE_MINIMAL_FRAGMENT")
        if ret is None:
            bad.append("BRANCH_NOT_EXPLICITLY_TERMINAL")
        else:
            world_branch_states[polarity] = (bst, ret)
        control_paths.append(
            {
                "path_id": f"guard-{str(polarity).lower()}",
                "guard_polarity": str(polarity).lower(),
                "events": events,
                "complete": ret is not None,
                "realizable": True,
            }
        )
    if bad:
        return None, sorted(set(bad))

    effect_specs = [
        x
        for x in signature.get("required_bindings", []) or []
        if x.get("kind")
        in {"effect_call_argument", "effect_return_mapping_field"}
    ]
    effect_paths = [
        p
        for p in control_paths
        if any(x.startswith("EFFECT:") for x in p["events"])
    ]
    if len(effect_paths) != 1:
        return None, ["EFFECT_PATH_NOT_UNIQUE_IN_C1_V0_1"]
    epol = effect_paths[0]["guard_polarity"] == "true"
    effect_state, effect_return = world_branch_states[epol]
    for spec in effect_specs:
        expr = _effect_expr(effect_return, spec, effect_node)
        if expr is None:
            bad.append(
                f"EFFECT_BINDING_SURFACE_UNRESOLVED:{spec.get('binding_id')}"
            )
            continue
        obs = _origins(expr, effect_state)
        if obs is None:
            bad.append(
                f"EFFECT_BINDING_ORIGIN_UNRESOLVED:{spec.get('binding_id')}"
            )
            continue
        bid = str(spec.get("binding_id"))
        slot = (
            {"arg_index": spec.get("arg_index")}
            if spec.get("kind") == "effect_call_argument"
            else {"field_key": spec.get("field_key")}
        )
        lineage = []
        for o in sorted(obs):
            lineage.append(
                {
                    "origin": o,
                    "edges": [
                        {
                            "kind": "CARRIES",
                            "from": o,
                            "to": bid,
                            "path_id": effect_paths[0]["path_id"],
                        }
                    ],
                }
            )
        bindings.append(
            {
                "binding_id": bid,
                "coordinate_identity": str(spec.get("coordinate_identity")),
                "resource_identity": str(spec.get("resource_identity")),
                "slot_identity": slot,
                "allowed_origins": list(spec.get("allowed_origins", [])),
                "observed_origins": sorted(obs),
                "binding_complete": True,
                "definitions_complete": True,
                "lineage_paths": lineage,
                "definition_trace": copy.deepcopy(definition_trace),
                "representation": {
                    "required": spec.get("kind")
                    == "effect_return_mapping_field",
                    "closure_complete": True,
                    "required_slot_present": True,
                    "instance_id": "return-mapping",
                },
            }
        )

    if bad:
        return None, sorted(set(bad))

    op = _compare_op_name(guard_node.ops[0]) if len(guard_node.ops) == 1 else None
    if op is None:
        return None, ["GUARD_OPERATOR_OUTSIDE_MINIMAL_FRAGMENT"]
    worlds_out: list[dict[str, Any]] = []
    projection_authority_receipts: list[dict[str, Any]] = []
    for world in signature.get("worlds", []) or []:
        polarity = _eval_compare(guard_node, state, world)
        if polarity is None:
            polarity, receipts = evaluate_compare_with_projection_authority(
                guard_node,
                world=world,
                env=projection_env,
                param_by_name=projection_params,
            )
            projection_authority_receipts.append(
                {
                    "world_id": str(world.get("id")),
                    "operands": receipts,
                }
            )
        if polarity is None:
            reasons = [f"WORLD_GUARD_EVAL_UNRESOLVED:{world.get('id')}"]
            reasons.extend(
                f"GATE2C7:{x.get('reason')}"
                for x in (
                    projection_authority_receipts[-1].get("operands", [])
                    if projection_authority_receipts
                    else []
                )
                if x.get("decision") == "REJECT"
            )
            reasons.extend(
                f"GATE2C7_SIDECAR:{x}" for x in projection_sidecar_bad
            )
            return None, sorted(set(reasons))
        branch = next(
            (
                p
                for p in control_paths
                if p["guard_polarity"] == str(polarity).lower()
            ),
            None,
        )
        if branch is None:
            return None, [f"WORLD_BRANCH_UNRESOLVED:{world.get('id')}"]
        ev = branch["events"]
        if any(x.startswith("EFFECT:") for x in ev):
            outcome = "SUCCESS_EFFECT"
        elif any(x.startswith("REJECTION:") for x in ev):
            outcome = "REJECTION_NO_EFFECT"
        else:
            outcome = "EXIT_OTHER"
        carrier_values: dict[str, list[Any]] = {}
        values = world.get("role_values", {}) or {}
        for b in bindings:
            if not str(b["binding_id"]).startswith("effect") and not any(
                s.get("kind", "").startswith("effect_")
                and s.get("binding_id") == b["binding_id"]
                for s in effect_specs
            ):
                continue
            carrier_values[b["binding_id"]] = [
                values[o] if o in values else o for o in b["observed_origins"]
            ]
        rho = {
            "outcome": outcome,
            "effect_carriers": (
                carrier_values if outcome == "SUCCESS_EFFECT" else {}
            ),
        }
        worlds_out.append(
            {
                "id": str(world.get("id")),
                "kappa": world.get("kappa"),
                "rho": rho,
            }
        )

    source_evidence = []
    for role, row in sorted((contract.get("anchors", {}) or {}).items()):
        span = list(row.get("span", []))
        raw = _slice_bytes(source, span)
        source_evidence.append(
            {
                "evidence_id": f"anchor:{role}",
                "path": contract["path"],
                "span": span,
                "slice_sha256": _digest_bytes(raw),
            }
        )

    effect_polarity = str(signature.get("guard", {}).get("effect_polarity"))
    rejection_polarity = str(
        signature.get("guard", {}).get("rejection_polarity")
    )
    reconstructed = {
        "schema": SLICE_SCHEMA,
        "case_id": case_id,
        "canonical_signature_digest": _digest_json(signature),
        "language": "python",
        "source_contract": copy.deepcopy(contract),
        "source_evidence": source_evidence,
        "bindings": bindings,
        "projection_authority_receipts": projection_authority_receipts,
        "binding_authority_source_sha256": source_sha256,
        "binding_authority_derivation_errors": binding_sidecar_bad,
        "guard": {
            "form": "DIRECT_CONTROL",
            "effective_guard_id": "g0",
            "effective_guard_count": 1,
            "net_polarity": "PRESERVE",
            "helper_chain": [],
            "effect_polarity": effect_polarity,
            "rejection_polarity": rejection_polarity,
            "operator": op,
        },
        "control_paths": control_paths,
        "effect": {
            "surfaces": sorted(surface_ids),
            "equivalence_proof_id": None,
            "success_outcome_id": success_id,
            "rejection_outcome_id": rejection_id,
            "effect_before_success_structural": all(
                next(
                    (
                        i
                        for i, x in enumerate(p["events"])
                        if x.startswith("EFFECT:")
                    ),
                    10**9,
                )
                < next(
                    (
                        i
                        for i, x in enumerate(p["events"])
                        if x.startswith("SUCCESS:")
                    ),
                    10**9,
                )
                for p in effect_paths
            ),
        },
        "scope": {
            "scope_id": "python-direct:" + _digest_bytes(source)[:16],
            "complete": True,
            "unresolved": [],
            "aliases_complete": True,
            "call_targets_complete": True,
            "reaching_definitions_complete": True,
            "branches_complete": True,
            "representations_complete": True,
            "effects_complete": True,
            "exceptions_exits_complete": True,
            "resources_complete": True,
            "helper_polarity_complete": True,
            "all_entry_paths_enumerated": True,
        },
        "worlds": worlds_out,
    }
    return reconstructed, []
