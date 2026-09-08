from __future__ import annotations

"""Gate2C8 binding-scoped projection authority for independent C1 A3 semantics.

The certificate is derived from raw Python AST structure without consulting a
binding's allowed-role set. Raw observed origins and lineage remain immutable.
"""

import ast
from typing import Any, Mapping, Sequence

from .common import _digest_bytes, _digest_json

GATE2C8_PROTOCOL_COMMIT = "11433abadf2f2b322d9e4209ed5e721ebe059d80"
GATE2C5_AUTHORITY_DIGEST_SHA256 = "23cc81e2c8c7be8dfe5496fd32cd56afb2cb9002f164f1a0d463812a6f97fbca"

EXACT_BASE_MATCH = "EXACT_BASE_MATCH"
CERTIFIED_PROJECTION_MATCH = "CERTIFIED_PROJECTION_MATCH"
CERTIFIED_NONMATCH = "CERTIFIED_NONMATCH"
UNRESOLVED_AUTHORITY = "UNRESOLVED_AUTHORITY"
MATCH_RELATIONS = frozenset({EXACT_BASE_MATCH, CERTIFIED_PROJECTION_MATCH})

# Data-only copy of the frozen Gate2C5/Gate2C7 projection authority.
# Gate2C7 derivation/admission helpers are intentionally not imported.
FROZEN_BINDING_PROJECTION_AUTHORITY: tuple[dict[str, Any], ...] = (
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
FROZEN_AUTHORITY_PROVENANCE = "FROZEN_GATE2C5"


def _reject(reason: str, **extra: Any) -> dict[str, Any]:
    return {"decision": "REJECT", "reason": reason, **extra}


def _step(node: ast.AST) -> tuple[dict[str, str], str]:
    if isinstance(node, ast.Attribute):
        return (
            {
                "kind": "ATTRIBUTE",
                "token_digest_sha256": _digest_bytes(node.attr.encode("utf-8")),
            },
            str(node.attr),
        )
    if isinstance(node, ast.Subscript):
        if not isinstance(node.slice, ast.Constant) or node.slice.value is None:
            raise ValueError("BINDING_AUTHORITY_DYNAMIC_OR_UNSUPPORTED")
        key = node.slice.value
        try:
            token_digest = _digest_json(key)
        except (TypeError, ValueError) as exc:
            raise ValueError("BINDING_AUTHORITY_DYNAMIC_OR_UNSUPPORTED") from exc
        return (
            {"kind": "SUBSCRIPT_LITERAL", "token_digest_sha256": token_digest},
            str(key),
        )
    raise ValueError("BINDING_AUTHORITY_DYNAMIC_OR_UNSUPPORTED")


def _trace_expr(
    expr: ast.AST,
    env: Mapping[str, Mapping[str, Any]],
    param_by_name: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    if isinstance(expr, ast.Name):
        row = env.get(expr.id) or param_by_name.get(expr.id)
        if row is None:
            raise ValueError("BINDING_AUTHORITY_MISSING")
        return {
            "root_role": str(row["root_role"]),
            "steps": [dict(x) for x in row.get("steps", ())],
            "raw_origin": str(row["raw_origin"]),
        }
    if isinstance(expr, (ast.Attribute, ast.Subscript)):
        base = _trace_expr(expr.value, env, param_by_name)
        step, raw_token = _step(expr)
        return {
            "root_role": base["root_role"],
            "steps": [*base["steps"], step],
            "raw_origin": f"{base['raw_origin']}.slot:{raw_token}",
        }
    raise ValueError("BINDING_AUTHORITY_DYNAMIC_OR_UNSUPPORTED")


def prefix_binding_environment(
    fn: ast.FunctionDef | ast.AsyncFunctionDef,
    guard_if: ast.If,
    signature: Mapping[str, Any],
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]], list[str]]:
    """Fresh pre-guard trace; does not consume Gate2C7's projection environment."""
    params = list(fn.args.posonlyargs) + list(fn.args.args) + list(fn.args.kwonlyargs)
    param_by_name: dict[str, dict[str, Any]] = {}
    bad: list[str] = []
    claimed: set[int] = set()
    for role, spec in sorted((signature.get("source_roles", {}) or {}).items()):
        idx = spec.get("parameter_index")
        if not isinstance(idx, int) or idx < 0 or idx >= len(params):
            bad.append(f"BINDING_AUTHORITY_INTERNAL_INCONSISTENCY:{role}")
            continue
        if idx in claimed:
            bad.append(f"BINDING_AUTHORITY_AMBIGUOUS:{idx}")
            continue
        claimed.add(idx)
        param_by_name[params[idx].arg] = {
            "root_role": str(role),
            "steps": [],
            "raw_origin": str(role),
        }

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
            bad.append("BINDING_AUTHORITY_INTERNAL_INCONSISTENCY")
            continue
        try:
            env[target.id] = _trace_expr(value, env, param_by_name)
        except ValueError as exc:
            bad.append(str(exc))
    if not found:
        bad.append("BINDING_AUTHORITY_INTERNAL_INCONSISTENCY")
    return env, param_by_name, sorted(set(bad))


def _projection_payload(trace: Mapping[str, Any], operand_index: int) -> dict[str, Any]:
    steps: list[dict[str, str]] = []
    for row in trace.get("steps", ()) or ():
        if not isinstance(row, Mapping):
            raise ValueError("BINDING_AUTHORITY_INTERNAL_INCONSISTENCY")
        kind = row.get("kind")
        token = row.get("token_digest_sha256")
        if kind not in {"ATTRIBUTE", "SUBSCRIPT_LITERAL"}:
            raise ValueError("BINDING_AUTHORITY_PROJECTION_CERTIFICATE_MISMATCH")
        if not isinstance(token, str) or len(token) != 64:
            raise ValueError("BINDING_AUTHORITY_PROJECTION_CERTIFICATE_MISMATCH")
        steps.append({"kind": str(kind), "token_digest_sha256": token})
    return {
        "root_role": str(trace.get("root_role", "")),
        "terminal_guard_operand_index": int(operand_index),
        "steps": steps,
    }


def _valid_authority_rows(rows: Sequence[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    valid: list[Mapping[str, Any]] = []
    for row in rows:
        try:
            payload = _projection_payload(row, int(row.get("terminal_guard_operand_index")))
        except (TypeError, ValueError):
            continue
        if row.get("fingerprint_sha256") == _digest_json(payload):
            valid.append(row)
    return valid


def derive_binding_authority_receipt(
    expr: ast.AST,
    *,
    case_id: str,
    binding_id: str,
    source_sha256: str,
    raw_origin: str,
    binding_slot_identity: Mapping[str, Any],
    env: Mapping[str, Mapping[str, Any]],
    param_by_name: Mapping[str, Mapping[str, Any]],
    authority_rows: Sequence[Mapping[str, Any]] = FROZEN_BINDING_PROJECTION_AUTHORITY,
    authority_provenance: str = FROZEN_AUTHORITY_PROVENANCE,
    derivation_source: str = "C1_RAW_BINDING_AST",
) -> dict[str, Any]:
    """Derive one binding-scoped receipt without consulting allowed_origins."""
    if derivation_source != "C1_RAW_BINDING_AST":
        return _reject("BINDING_AUTHORITY_PRIMARY_DERIVATION_FORBIDDEN")
    if not isinstance(source_sha256, str) or len(source_sha256) != 64:
        return _reject("BINDING_AUTHORITY_SOURCE_MISMATCH")

    operand = binding_slot_identity.get("operand_index")
    if not isinstance(operand, int) or operand < 0:
        return _reject("BINDING_AUTHORITY_SLOT_MISMATCH")

    try:
        trace = _trace_expr(expr, env, param_by_name)
    except ValueError as exc:
        return _reject(str(exc))
    if trace.get("raw_origin") != raw_origin:
        return _reject(
            "BINDING_AUTHORITY_RAW_ORIGIN_MISMATCH",
            derived_raw_origin=trace.get("raw_origin"),
        )

    try:
        projection = _projection_payload(trace, operand)
    except (TypeError, ValueError) as exc:
        return _reject(str(exc))
    fingerprint = _digest_json(projection)

    if projection["steps"]:
        if authority_provenance not in {"FROZEN_GATE2C5", "SYNTHETIC_GATE2C8"}:
            return _reject(
                "BINDING_AUTHORITY_PROJECTION_CERTIFICATE_MISMATCH",
                projection_fingerprint_sha256=fingerprint,
            )
        valid = _valid_authority_rows(authority_rows)
        same_role = [r for r in valid if str(r.get("root_role")) == projection["root_role"]]
        if not same_role:
            return _reject(
                "BINDING_AUTHORITY_CERTIFIED_ROLE_MISMATCH",
                projection_fingerprint_sha256=fingerprint,
            )
        same_operand = [
            r for r in same_role
            if int(r.get("terminal_guard_operand_index")) == operand
        ]
        if not same_operand:
            return _reject(
                "BINDING_AUTHORITY_SLOT_MISMATCH",
                projection_fingerprint_sha256=fingerprint,
            )
        matches = [r for r in same_operand if r.get("fingerprint_sha256") == fingerprint]
        if len(matches) > 1:
            return _reject(
                "BINDING_AUTHORITY_AMBIGUOUS",
                projection_fingerprint_sha256=fingerprint,
            )
        if len(matches) != 1:
            return _reject(
                "BINDING_AUTHORITY_PROJECTION_FINGERPRINT_MISMATCH",
                projection_fingerprint_sha256=fingerprint,
            )
    else:
        if projection["root_role"] != raw_origin:
            return _reject("BINDING_AUTHORITY_RAW_ORIGIN_MISMATCH")
        authority_provenance = "DIRECT_SOURCE_ROLE"

    projection_certificate_digest = _digest_json({
        "projection_certificate": projection,
        "authority_provenance": authority_provenance,
    })
    wrapper = {
        "case_id": str(case_id),
        "binding_id": str(binding_id),
        "source_sha256": source_sha256,
        "raw_origin": raw_origin,
        "binding_slot_identity": dict(binding_slot_identity),
        "certified_role": projection["root_role"],
        "projection_fingerprint_sha256": fingerprint,
        "projection_certificate_digest_sha256": projection_certificate_digest,
    }
    return {
        "decision": "ADMIT",
        "reason": (
            "BINDING_CANONICAL_PROJECTION_AUTHORIZED"
            if projection["steps"]
            else "BINDING_DIRECT_BASE_ROLE_AUTHORIZED"
        ),
        "binding_wrapper": wrapper,
        "binding_wrapper_digest_sha256": _digest_json(wrapper),
        "projection_certificate": projection,
        "authority_provenance": authority_provenance,
        "derivation_source": "C1_RAW_BINDING_AST",
        "world_evaluation_receipt_reused": False,
        "primary_derived": False,
    }


def classify_binding_origin_relation(
    binding: Mapping[str, Any],
    *,
    raw_origin: str,
    case_id: str,
    source_sha256: str,
) -> dict[str, Any]:
    """Classify only after certificate derivation; allowed_origins enters here."""
    allowed = {str(x) for x in (binding.get("allowed_origins", []) or [])}
    if raw_origin in allowed:
        return {
            "raw_origin": raw_origin,
            "relation": EXACT_BASE_MATCH,
            "certified_role": raw_origin,
            "reason": "RAW_ORIGIN_LITERAL_ALLOWED_ROLE",
        }

    candidates = []
    for receipt in binding.get("binding_authority_receipts", []) or []:
        wrapper = receipt.get("binding_wrapper", {}) if isinstance(receipt, Mapping) else {}
        if isinstance(wrapper, Mapping) and wrapper.get("raw_origin") == raw_origin:
            candidates.append(receipt)
    if len(candidates) != 1:
        return {
            "raw_origin": raw_origin,
            "relation": UNRESOLVED_AUTHORITY,
            "certified_role": None,
            "reason": (
                "BINDING_AUTHORITY_MISSING"
                if not candidates else "BINDING_AUTHORITY_AMBIGUOUS"
            ),
        }

    receipt = candidates[0]
    if receipt.get("decision") != "ADMIT":
        return {
            "raw_origin": raw_origin,
            "relation": UNRESOLVED_AUTHORITY,
            "certified_role": None,
            "reason": str(receipt.get("reason") or "BINDING_AUTHORITY_MISSING"),
        }
    if receipt.get("derivation_source") != "C1_RAW_BINDING_AST" or receipt.get("primary_derived") is not False:
        return {
            "raw_origin": raw_origin,
            "relation": UNRESOLVED_AUTHORITY,
            "certified_role": None,
            "reason": "BINDING_AUTHORITY_PRIMARY_DERIVATION_FORBIDDEN",
        }
    if receipt.get("world_evaluation_receipt_reused") is not False:
        return {
            "raw_origin": raw_origin,
            "relation": UNRESOLVED_AUTHORITY,
            "certified_role": None,
            "reason": "BINDING_AUTHORITY_WORLD_RECEIPT_REUSE",
        }

    wrapper = receipt.get("binding_wrapper", {}) or {}
    checks = (
        (wrapper.get("case_id") == case_id, "BINDING_AUTHORITY_CASE_MISMATCH"),
        (wrapper.get("binding_id") == binding.get("binding_id"), "BINDING_AUTHORITY_BINDING_ID_MISMATCH"),
        (wrapper.get("source_sha256") == source_sha256, "BINDING_AUTHORITY_SOURCE_MISMATCH"),
        (wrapper.get("raw_origin") == raw_origin, "BINDING_AUTHORITY_RAW_ORIGIN_MISMATCH"),
        (wrapper.get("binding_slot_identity") == binding.get("slot_identity"), "BINDING_AUTHORITY_SLOT_MISMATCH"),
    )
    for ok, reason in checks:
        if not ok:
            return {
                "raw_origin": raw_origin,
                "relation": UNRESOLVED_AUTHORITY,
                "certified_role": None,
                "reason": reason,
            }

    if receipt.get("binding_wrapper_digest_sha256") != _digest_json(wrapper):
        return {
            "raw_origin": raw_origin,
            "relation": UNRESOLVED_AUTHORITY,
            "certified_role": None,
            "reason": "BINDING_AUTHORITY_WRAPPER_DIGEST_MISMATCH",
        }

    projection = receipt.get("projection_certificate", {}) or {}
    try:
        operand = int(projection.get("terminal_guard_operand_index"))
        normalized = _projection_payload(projection, operand)
    except (TypeError, ValueError):
        return {
            "raw_origin": raw_origin,
            "relation": UNRESOLVED_AUTHORITY,
            "certified_role": None,
            "reason": "BINDING_AUTHORITY_PROJECTION_CERTIFICATE_MISMATCH",
        }
    if normalized != projection:
        return {
            "raw_origin": raw_origin,
            "relation": UNRESOLVED_AUTHORITY,
            "certified_role": None,
            "reason": "BINDING_AUTHORITY_PROJECTION_CERTIFICATE_MISMATCH",
        }

    fp = _digest_json(normalized)
    if wrapper.get("projection_fingerprint_sha256") != fp:
        return {
            "raw_origin": raw_origin,
            "relation": UNRESOLVED_AUTHORITY,
            "certified_role": None,
            "reason": "BINDING_AUTHORITY_PROJECTION_FINGERPRINT_MISMATCH",
        }
    certified = str(wrapper.get("certified_role", ""))
    if certified != str(normalized.get("root_role", "")):
        return {
            "raw_origin": raw_origin,
            "relation": UNRESOLVED_AUTHORITY,
            "certified_role": None,
            "reason": "BINDING_AUTHORITY_CERTIFIED_ROLE_MISMATCH",
        }
    cert_digest = _digest_json({
        "projection_certificate": normalized,
        "authority_provenance": receipt.get("authority_provenance"),
    })
    if wrapper.get("projection_certificate_digest_sha256") != cert_digest:
        return {
            "raw_origin": raw_origin,
            "relation": UNRESOLVED_AUTHORITY,
            "certified_role": None,
            "reason": "BINDING_AUTHORITY_PROJECTION_CERTIFICATE_MISMATCH",
        }

    return {
        "raw_origin": raw_origin,
        "relation": (
            CERTIFIED_PROJECTION_MATCH
            if certified in allowed else CERTIFIED_NONMATCH
        ),
        "certified_role": certified,
        "reason": (
            "CERTIFIED_ROLE_IN_ALLOWED_SET"
            if certified in allowed else "CERTIFIED_ROLE_OUTSIDE_ALLOWED_SET"
        ),
        "binding_wrapper_digest_sha256": receipt.get("binding_wrapper_digest_sha256"),
    }
