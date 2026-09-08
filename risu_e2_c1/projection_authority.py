from __future__ import annotations

"""Gate2C7 projection-qualified origin authority for the independent C1 lane.

This module never interprets identifier spelling as semantic meaning.  It derives
an opaque structural projection certificate from raw Python AST and compares
that certificate with frozen authority.  Raw origins remain owned by
``source_python._origins`` and are never normalized here.
"""

import ast
from typing import Any, Mapping, Sequence

from .common import _digest_bytes, _digest_json

GATE2C7_PROTOCOL_COMMIT = "c9b0e1b805fa7193972894bd6a83f3390cb4be75"
GATE2C5_AUTHORITY_DIGEST_SHA256 = "23cc81e2c8c7be8dfe5496fd32cd56afb2cb9002f164f1a0d463812a6f97fbca"
GATE2C5_AUTHORITY_FILE_SHA256 = "943cafb73ef53c7d11c01ece51a429b67155fca95dec187f45897c4d2170ae24"

FROZEN_PRODUCTION_AUTHORITY: tuple[dict[str, Any], ...] = (
    {
        "root_role": "BOUND_VALUE:expected_coordinate",
        "terminal_guard_operand_index": 0,
        "steps": (
            {
                "kind": "SUBSCRIPT_LITERAL",
                "token_digest_sha256": "584ccb1063ae46fed1914e4852dae6968f10fac1336518ba581c37531df046bf",
            },
        ),
        "fingerprint_sha256": "46b183206947fe72743af0b3b2315476edd30bb940018ea9ebb4feb0ebee1647",
    },
    {
        "root_role": "BOUND_VALUE:current_coordinate",
        "terminal_guard_operand_index": 1,
        "steps": (),
        "fingerprint_sha256": "b904de65bc61791bdde2e896aa5513de3862cb5d73f00642bf4755ca27ab9845",
    },
)
FROZEN_PRODUCTION_AUTHORITY_PROVENANCE = "FROZEN_GATE2C5"


def _step(node: ast.AST) -> dict[str, str]:
    if isinstance(node, ast.Attribute):
        return {
            "kind": "ATTRIBUTE",
            "token_digest_sha256": _digest_bytes(node.attr.encode("utf-8")),
        }
    if isinstance(node, ast.Subscript):
        try:
            key = ast.literal_eval(node.slice)
        except Exception as exc:
            raise ValueError("PROJECTION_DYNAMIC_OR_UNSUPPORTED") from exc
        try:
            token_digest = _digest_json(key)
        except (TypeError, ValueError) as exc:
            raise ValueError("PROJECTION_DYNAMIC_OR_UNSUPPORTED") from exc
        return {"kind": "SUBSCRIPT_LITERAL", "token_digest_sha256": token_digest}
    raise ValueError("PROJECTION_DYNAMIC_OR_UNSUPPORTED")


def _trace_expr(
    expr: ast.AST,
    env: Mapping[str, Mapping[str, Any]],
    param_by_name: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    if isinstance(expr, ast.Name):
        row = env.get(expr.id) or param_by_name.get(expr.id)
        if row is None:
            raise ValueError("PROJECTION_AUTHORITY_MISSING")
        return {
            "root_role": str(row["root_role"]),
            "steps": [dict(x) for x in row.get("steps", ())],
        }
    if isinstance(expr, (ast.Attribute, ast.Subscript)):
        base = _trace_expr(expr.value, env, param_by_name)
        return {
            "root_role": base["root_role"],
            "steps": [*base["steps"], _step(expr)],
        }
    raise ValueError("PROJECTION_DYNAMIC_OR_UNSUPPORTED")


def prefix_projection_environment(
    fn: ast.FunctionDef | ast.AsyncFunctionDef,
    guard_if: ast.If,
    signature: Mapping[str, Any],
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]], list[str]]:
    """Independently derive straight-line pre-guard projection lineage.

    Failure is returned as evidence rather than widening the C1 fragment.  The
    caller only needs this sidecar when literal world-role lookup cannot resolve.
    """
    params = list(fn.args.posonlyargs) + list(fn.args.args) + list(fn.args.kwonlyargs)
    param_by_name: dict[str, dict[str, Any]] = {}
    bad: list[str] = []
    claimed: set[int] = set()
    for role, spec in sorted((signature.get("source_roles", {}) or {}).items()):
        idx = spec.get("parameter_index")
        if not isinstance(idx, int) or idx < 0 or idx >= len(params):
            bad.append(f"PROJECTION_ROOT_ROLE_MISMATCH:{role}")
            continue
        if idx in claimed:
            bad.append(f"PROJECTION_AUTHORITY_AMBIGUOUS:{idx}")
            continue
        claimed.add(idx)
        param_by_name[params[idx].arg] = {"root_role": str(role), "steps": []}

    env: dict[str, dict[str, Any]] = {}
    found = False
    for stmt in fn.body:
        if stmt is guard_if:
            found = True
            break
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant):
            continue
        target: ast.Name | None = None
        value: ast.expr | None = None
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
            target, value = stmt.targets[0], stmt.value
        elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name) and stmt.value is not None:
            target, value = stmt.target, stmt.value
        else:
            bad.append("PROJECTION_CERTIFICATE_INTERNAL_INCONSISTENCY")
            continue
        try:
            env[target.id] = _trace_expr(value, env, param_by_name)
        except ValueError as exc:
            bad.append(str(exc))
    if not found:
        bad.append("PROJECTION_CERTIFICATE_INTERNAL_INCONSISTENCY")
    return env, param_by_name, sorted(set(bad))


def _normalized_payload(trace: Mapping[str, Any], operand_index: int) -> dict[str, Any]:
    steps = []
    for step in trace.get("steps", ()) or ():
        if not isinstance(step, Mapping):
            raise ValueError("PROJECTION_CERTIFICATE_INTERNAL_INCONSISTENCY")
        kind = step.get("kind")
        token = step.get("token_digest_sha256")
        if kind not in {"ATTRIBUTE", "SUBSCRIPT_LITERAL"} or not isinstance(token, str) or len(token) != 64:
            raise ValueError("PROJECTION_CERTIFICATE_INTERNAL_INCONSISTENCY")
        steps.append({"kind": kind, "token_digest_sha256": token})
    return {
        "root_role": str(trace.get("root_role", "")),
        "terminal_guard_operand_index": int(operand_index),
        "steps": steps,
    }


def admit_projection_trace(
    trace: Mapping[str, Any] | None,
    *,
    operand_index: int,
    authority_rows: Sequence[Mapping[str, Any]] = FROZEN_PRODUCTION_AUTHORITY,
    authority_provenance: str = FROZEN_PRODUCTION_AUTHORITY_PROVENANCE,
) -> dict[str, Any]:
    """Return a typed admission receipt; never rewrite an origin string."""
    if trace is None:
        return {"decision": "REJECT", "reason": "PROJECTION_AUTHORITY_MISSING"}

    try:
        payload = _normalized_payload(trace, operand_index)
    except (TypeError, ValueError):
        return {"decision": "REJECT", "reason": "PROJECTION_CERTIFICATE_INTERNAL_INCONSISTENCY"}

    if not payload["steps"]:
        return {
            "decision": "ADMIT",
            "reason": "BASE_ORIGIN_PASSTHROUGH",
            "resolved_role": payload["root_role"],
            "certificate": payload,
            "fingerprint_sha256": _digest_json(payload),
            "authority_provenance": None,
        }

    if authority_provenance not in {"FROZEN_GATE2C5", "SYNTHETIC_GATE2C7"}:
        return {"decision": "REJECT", "reason": "PROJECTION_AUTHORITY_MISSING"}

    fingerprint = _digest_json(payload)
    internally_valid: list[Mapping[str, Any]] = []
    for row in authority_rows:
        try:
            row_payload = _normalized_payload(row, int(row.get("terminal_guard_operand_index")))
        except (TypeError, ValueError):
            continue
        if row.get("fingerprint_sha256") != _digest_json(row_payload):
            continue
        internally_valid.append(row)

    same_role = [r for r in internally_valid if str(r.get("root_role")) == payload["root_role"]]
    if not same_role:
        return {"decision": "REJECT", "reason": "PROJECTION_ROOT_ROLE_MISMATCH", "fingerprint_sha256": fingerprint}
    same_operand = [r for r in same_role if int(r.get("terminal_guard_operand_index")) == operand_index]
    if not same_operand:
        return {"decision": "REJECT", "reason": "PROJECTION_TERMINAL_OPERAND_MISMATCH", "fingerprint_sha256": fingerprint}

    matches = [r for r in same_operand if r.get("fingerprint_sha256") == fingerprint]
    if len(matches) > 1:
        return {"decision": "REJECT", "reason": "PROJECTION_AUTHORITY_AMBIGUOUS", "fingerprint_sha256": fingerprint}
    if len(matches) != 1:
        wanted_kinds = [[str(x.get("kind")) for x in (r.get("steps", ()) or ())] for r in same_operand]
        got_kinds = [str(x["kind"]) for x in payload["steps"]]
        if got_kinds not in wanted_kinds:
            reason = "PROJECTION_KIND_SEQUENCE_MISMATCH"
        elif any(len(r.get("steps", ()) or ()) != len(payload["steps"]) for r in same_operand):
            reason = "PROJECTION_EXTRA_CONSEQUENTIAL_HOP"
        else:
            reason = "PROJECTION_TOKEN_FINGERPRINT_MISMATCH"
        return {"decision": "REJECT", "reason": reason, "fingerprint_sha256": fingerprint}

    return {
        "decision": "ADMIT",
        "reason": "CANONICAL_OPAQUE_PROJECTION_MATCH",
        "resolved_role": payload["root_role"],
        "certificate": payload,
        "fingerprint_sha256": fingerprint,
        "authority_provenance": authority_provenance,
    }


def evaluate_compare_with_projection_authority(
    node: ast.Compare,
    *,
    world: Mapping[str, Any],
    env: Mapping[str, Mapping[str, Any]],
    param_by_name: Mapping[str, Mapping[str, Any]],
    authority_rows: Sequence[Mapping[str, Any]] = FROZEN_PRODUCTION_AUTHORITY,
    authority_provenance: str = FROZEN_PRODUCTION_AUTHORITY_PROVENANCE,
) -> tuple[bool | None, list[dict[str, Any]]]:
    """Evaluate one binary Eq/NotEq only after both operands have typed authority."""
    if len(node.ops) != 1 or len(node.comparators) != 1:
        return None, []
    if isinstance(node.ops[0], ast.Eq):
        op = "EQ"
    elif isinstance(node.ops[0], ast.NotEq):
        op = "NE"
    else:
        return None, []

    vals = world.get("role_values", {}) or {}
    receipts: list[dict[str, Any]] = []
    resolved_values: list[Any] = []
    for idx, expr in enumerate([node.left, node.comparators[0]]):
        try:
            trace = _trace_expr(expr, env, param_by_name)
        except ValueError as exc:
            receipts.append({"operand_index": idx, "decision": "REJECT", "reason": str(exc)})
            return None, receipts
        receipt = admit_projection_trace(
            trace,
            operand_index=idx,
            authority_rows=authority_rows,
            authority_provenance=authority_provenance,
        )
        receipt = {"operand_index": idx, **receipt}
        receipts.append(receipt)
        if receipt["decision"] != "ADMIT":
            return None, receipts
        role = receipt.get("resolved_role")
        if role not in vals:
            receipts[-1] = {**receipt, "decision": "REJECT", "reason": "PROJECTION_AUTHORITY_MISSING"}
            return None, receipts
        resolved_values.append(vals[role])
    eq = resolved_values[0] == resolved_values[1]
    return (eq if op == "EQ" else not eq), receipts
