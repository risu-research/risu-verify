from __future__ import annotations

"""Independent Python raw-source reconstruction for the C1 minimal fragment."""

import ast
import copy
from typing import Any, Mapping, Sequence

from .common import SLICE_SCHEMA, _digest_bytes, _digest_json

ALLOWED_ASSIGN = (ast.Assign, ast.AnnAssign)
UNSUPPORTED_NODES = (
    ast.For, ast.AsyncFor, ast.While, ast.Try, ast.With, ast.AsyncWith,
    ast.Match, ast.Raise, ast.Await, ast.Yield, ast.YieldFrom,
    ast.Break, ast.Continue, ast.Lambda, ast.NamedExpr, ast.Delete,
    ast.Global, ast.Nonlocal, ast.ClassDef,
)

def _span(n: ast.AST) -> tuple[int, int, int, int]:
    return (int(n.lineno), int(n.col_offset), int(n.end_lineno), int(n.end_col_offset))


def _contains(outer: Sequence[int], inner: Sequence[int]) -> bool:
    a = (int(outer[0]), int(outer[1])); b = (int(outer[2]), int(outer[3]))
    c = (int(inner[0]), int(inner[1])); d = (int(inner[2]), int(inner[3]))
    return a <= c and d <= b


def _find_exact(tree: ast.AST, typ: type[ast.AST], span: Sequence[int]) -> list[ast.AST]:
    target = tuple(map(int, span))
    return [n for n in ast.walk(tree) if isinstance(n, typ) and hasattr(n, "lineno") and _span(n) == target]


def _slice_bytes(source: bytes, span: Sequence[int]) -> bytes:
    sl, sc, el, ec = map(int, span)
    lines = source.splitlines(keepends=True)
    if sl < 1 or el < sl or el > len(lines):
        raise ValueError("bad span")
    if sl == el:
        return lines[sl - 1][sc:ec]
    return b"".join([lines[sl - 1][sc:]] + lines[sl:el - 1] + [lines[el - 1][:ec]])


def _name_targets(stmt: ast.stmt) -> list[str]:
    targets: list[ast.AST] = []
    if isinstance(stmt, ast.Assign): targets = list(stmt.targets)
    elif isinstance(stmt, ast.AnnAssign): targets = [stmt.target]
    out: list[str] = []
    for t in targets:
        if isinstance(t, ast.Name): out.append(t.id)
        elif isinstance(t, (ast.Tuple, ast.List)):
            out.extend(x.id for x in t.elts if isinstance(x, ast.Name))
    return out


def _assignment_value(stmt: ast.stmt) -> ast.expr | None:
    if isinstance(stmt, ast.Assign): return stmt.value
    if isinstance(stmt, ast.AnnAssign): return stmt.value
    return None


def _origins(expr: ast.AST, state: Mapping[str, set[str]]) -> set[str] | None:
    """Return abstract semantic origins; None means outside the admitted fragment."""
    if isinstance(expr, ast.Name):
        return set(state.get(expr.id, set())) or None
    if isinstance(expr, ast.Constant):
        return {"CONST:" + _digest_json(expr.value)[:16]}
    if isinstance(expr, ast.UnaryOp) and isinstance(expr.op, ast.Not):
        return _origins(expr.operand, state)
    if isinstance(expr, ast.Attribute):
        base = _origins(expr.value, state)
        if base is None: return None
        return {f"{x}.slot:{expr.attr}" for x in base}
    if isinstance(expr, ast.Subscript):
        base = _origins(expr.value, state)
        if base is None: return None
        key = ast.literal_eval(expr.slice) if isinstance(expr.slice, ast.Constant) else None
        if key is None: return None
        return {f"{x}.slot:{key}" for x in base}
    # A call result is opaque in C1 v0.1; call-argument carrier checks are done
    # at the effect boundary itself rather than by trusting return semantics.
    return None


def _compare_op_name(op: ast.cmpop) -> str | None:
    if isinstance(op, ast.Eq): return "EQ"
    if isinstance(op, ast.NotEq): return "NE"
    return None


def _eval_compare(node: ast.Compare, state: Mapping[str, set[str]], world: Mapping[str, Any]) -> bool | None:
    if len(node.ops) != 1 or len(node.comparators) != 1:
        return None
    op = _compare_op_name(node.ops[0])
    if op is None: return None
    left_o = _origins(node.left, state); right_o = _origins(node.comparators[0], state)
    if left_o is None or right_o is None or len(left_o) != 1 or len(right_o) != 1:
        return None
    lo = next(iter(left_o)); ro = next(iter(right_o))
    vals = world.get("role_values", {}) or {}
    if lo not in vals or ro not in vals:
        return None
    eq = vals[lo] == vals[ro]
    return eq if op == "EQ" else not eq


def _unsupported_in_function(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    bad = {type(n).__name__ for n in ast.walk(fn) if isinstance(n, UNSUPPORTED_NODES)}
    # C1 v0.1 admits only one semantic branch point: the effective consequence guard.
    if sum(1 for n in ast.walk(fn) if isinstance(n, ast.If)) != 1:
        bad.add("C1_REQUIRES_EXACTLY_ONE_IF")
    return sorted(bad)


def _role_state(fn: ast.FunctionDef | ast.AsyncFunctionDef, signature: Mapping[str, Any]) -> tuple[dict[str, set[str]], list[str]]:
    params = list(fn.args.posonlyargs) + list(fn.args.args) + list(fn.args.kwonlyargs)
    state: dict[str, set[str]] = {}
    bad: list[str] = []
    claimed: set[int] = set()
    for role, spec in sorted((signature.get("source_roles", {}) or {}).items()):
        idx = spec.get("parameter_index")
        if not isinstance(idx, int) or idx < 0 or idx >= len(params):
            bad.append(f"SOURCE_ROLE_PARAMETER_INDEX_INVALID:{role}")
            continue
        if idx in claimed:
            bad.append(f"SOURCE_ROLE_PARAMETER_INDEX_AMBIGUOUS:{idx}")
            continue
        claimed.add(idx)
        state[params[idx].arg] = {str(role)}
    return state, bad


def _apply_assign(stmt: ast.stmt, state: dict[str, set[str]], trace: list[dict[str, Any]]) -> tuple[dict[str, set[str]], str | None]:
    value = _assignment_value(stmt)
    targets = _name_targets(stmt)
    if value is None or len(targets) != 1:
        return state, "ASSIGNMENT_OUTSIDE_MINIMAL_FRAGMENT"
    origins = _origins(value, state)
    if origins is None:
        return state, "ASSIGNMENT_RHS_ORIGIN_UNRESOLVED"
    name = targets[0]
    previous = set(state.get(name, set()))
    next_state = {k: set(v) for k, v in state.items()}
    next_state[name] = set(origins)
    trace.append({
        "kind": "KILL" if previous else "DEF",
        "target_symbol": name,
        "previous_origins": sorted(previous),
        "new_origins": sorted(origins),
        "required_definition_killed": bool(previous and previous != origins),
        "span": list(_span(stmt)),
    })
    return next_state, None


def _dict_field_value(node: ast.Dict, field: str) -> ast.expr | None:
    matches: list[ast.expr] = []
    for k, v in zip(node.keys, node.values):
        if isinstance(k, ast.Constant) and str(k.value) == field:
            matches.append(v)
    return matches[0] if len(matches) == 1 else None


def _effect_expr(return_node: ast.Return, spec: Mapping[str, Any], effect_anchor: ast.AST) -> ast.expr | None:
    kind = spec.get("kind")
    if kind == "effect_call_argument":
        if not isinstance(effect_anchor, ast.Call): return None
        idx = spec.get("arg_index")
        if not isinstance(idx, int) or idx < 0 or idx >= len(effect_anchor.args): return None
        return effect_anchor.args[idx]
    if kind == "effect_return_mapping_field":
        if not isinstance(return_node.value, ast.Dict): return None
        field = spec.get("field_key")
        if not isinstance(field, str) or not field: return None
        return _dict_field_value(return_node.value, field)
    return None


def _anchor_node(tree: ast.AST, role: str, contract: Mapping[str, Any]) -> tuple[ast.AST | None, str | None]:
    row = (contract.get("anchors", {}) or {}).get(role)
    if not isinstance(row, Mapping): return None, f"ANCHOR_MISSING:{role}"
    span = row.get("span", [])
    typ = {
        "guard": ast.Compare,
        "effect": ast.AST,
        "success": ast.Return,
        "rejection": ast.Return,
    }[role]
    candidates = [n for n in ast.walk(tree) if isinstance(n, typ) and hasattr(n, "lineno") and _span(n) == tuple(span)]
    # For effect, require the declared syntax_kind to prevent arbitrary AST-node matching.
    if role == "effect":
        syntax = row.get("syntax_kind")
        candidates = [n for n in candidates if (syntax == "CALL" and isinstance(n, ast.Call)) or (syntax == "RETURN" and isinstance(n, ast.Return))]
    if len(candidates) != 1: return None, f"ANCHOR_NOT_UNIQUE:{role}"
    return candidates[0], None


def _find_target_function(tree: ast.Module, span: Sequence[int]) -> tuple[ast.FunctionDef | ast.AsyncFunctionDef | None, str | None]:
    rows = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and _span(n) == tuple(span)]
    if len(rows) != 1: return None, "TARGET_SCOPE_NOT_UNIQUE"
    return rows[0], None
