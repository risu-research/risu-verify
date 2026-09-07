from __future__ import annotations

import ast
import hashlib
import json
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

SCHEMA = "risu.e2-predicate-polarity-certificate/v0.1"


@dataclass(frozen=True)
class Relation:
    value: str
    flips: int
    steps: tuple[dict[str, Any], ...]
    reason: str | None = None


def _span(node: ast.AST) -> tuple[int, int, int, int]:
    return (
        int(getattr(node, "lineno", -1)),
        int(getattr(node, "col_offset", -1)),
        int(getattr(node, "end_lineno", -1)),
        int(getattr(node, "end_col_offset", -1)),
    )


def _contains(outer: ast.AST, inner: ast.AST) -> bool:
    a = _span(outer)
    b = _span(inner)
    return (a[0], a[1]) <= (b[0], b[1]) and (b[2], b[3]) <= (a[2], a[3])


def _node_key(node: ast.AST) -> tuple[int, int, int, int, str]:
    return (*_span(node), type(node).__name__)


def _step(kind: str, node: ast.AST, relation: str, detail: str | None = None) -> dict[str, Any]:
    out: dict[str, Any] = {"kind": kind, "span": list(_span(node)), "relation": relation}
    if detail is not None:
        out["detail"] = detail
    return out


def _flip(rel: Relation, node: ast.AST, kind: str = "BOOLEAN_NOT_FLIP") -> Relation:
    if rel.value == "UNKNOWN":
        return rel
    value = "INVERTED" if rel.value == "SAME" else "SAME"
    return Relation(value, rel.flips + 1, rel.steps + (_step(kind, node, value),))


def _preserve(rel: Relation, node: ast.AST, kind: str) -> Relation:
    if rel.value == "UNKNOWN":
        return rel
    return Relation(rel.value, rel.flips, rel.steps + (_step(kind, node, rel.value),))


def _unknown(reason: str, node: ast.AST | None = None, steps: Sequence[dict[str, Any]] = ()) -> Relation:
    rows = tuple(steps)
    if node is not None:
        rows = rows + (_step("UNKNOWN", node, "UNKNOWN", reason),)
    return Relation("UNKNOWN", 0, rows, reason)


def _unsupported_reason(node: ast.AST) -> str:
    if isinstance(node, ast.BoolOp):
        return "AND_OR_BOOLEAN_COMPOSITION"
    if isinstance(node, ast.Compare):
        return "BOOLEAN_EQUALITY_OR_IDENTITY_TEST"
    if isinstance(node, ast.IfExp):
        return "CONDITIONAL_EXPRESSION"
    if isinstance(node, (ast.BinOp, ast.NamedExpr)):
        return "ARITHMETIC_OR_BITWISE_TRANSFORM"
    if isinstance(node, ast.Call):
        return "OPAQUE_NONTRANSPARENT_CALL"
    return "UNSUPPORTED_AST_FORM"


def _relation_to_root(expr: ast.AST, root: ast.AST) -> Relation:
    if _node_key(expr) == _node_key(root):
        return Relation("SAME", 0, (_step("TRANSPORTED_COMPARISON_AS_ROOT", root, "SAME"),))
    if isinstance(expr, ast.UnaryOp) and isinstance(expr.op, ast.Not):
        child = _relation_to_root(expr.operand, root)
        return _flip(child, expr)
    if _contains(expr, root):
        return _unknown(_unsupported_reason(expr), expr)
    return _unknown("ROOT_NOT_IN_EXPRESSION", expr)


def _calls_named(node: ast.AST, name: str) -> list[ast.Call]:
    return [
        child for child in ast.walk(node)
        if isinstance(child, ast.Call) and isinstance(child.func, ast.Name) and child.func.id == name
    ]


def _name_assignments(function: ast.FunctionDef | ast.AsyncFunctionDef, name: str, before: ast.AST) -> list[ast.Assign | ast.AnnAssign]:
    out: list[ast.Assign | ast.AnnAssign] = []
    limit = (_span(before)[0], _span(before)[1])
    for node in ast.walk(function):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        if (_span(node)[0], _span(node)[1]) >= limit:
            continue
        targets: list[ast.AST] = list(node.targets) if isinstance(node, ast.Assign) else [node.target]
        if any(isinstance(target, ast.Name) and target.id == name for target in targets):
            out.append(node)
    return sorted(out, key=lambda n: (_span(n)[0], _span(n)[1]))


def _assignment_value(node: ast.Assign | ast.AnnAssign) -> ast.AST | None:
    return node.value


def _relation_to_helper(
    expr: ast.AST,
    helper_name: str,
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    branch: ast.If,
    seen_names: frozenset[str] = frozenset(),
) -> Relation:
    if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Name) and expr.func.id == helper_name:
        return Relation("SAME", 0, (_step("DIRECT_HELPER_CALL_IN_BRANCH_PRESERVE", expr, "SAME", helper_name),))
    if isinstance(expr, ast.UnaryOp) and isinstance(expr.op, ast.Not):
        child = _relation_to_helper(expr.operand, helper_name, function, branch, seen_names)
        return _flip(child, expr)
    if isinstance(expr, ast.Name):
        if expr.id in seen_names:
            return _unknown("UNRESOLVED_ASSIGNMENT_OR_ALIAS", expr)
        assignments = _name_assignments(function, expr.id, branch)
        if len(assignments) != 1:
            return _unknown("UNRESOLVED_ASSIGNMENT_OR_ALIAS", expr)
        value = _assignment_value(assignments[0])
        if value is None:
            return _unknown("UNRESOLVED_ASSIGNMENT_OR_ALIAS", expr)
        if isinstance(value, ast.Name) and value.id == helper_name:
            return _unknown("UNRESOLVED_ASSIGNMENT_OR_ALIAS", value)
        child = _relation_to_helper(value, helper_name, function, branch, seen_names | {expr.id})
        return _preserve(child, assignments[0], "CALL_RESULT_TO_LOCAL_ASSIGNMENT_PRESERVE")
    calls = _calls_named(expr, helper_name)
    if calls:
        return _unknown(_unsupported_reason(expr), expr)
    return _unknown("NO_HELPER_DEPENDENCY", expr)


def _function_nodes(tree: ast.AST) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
    return [node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]


def _smallest_container(nodes: Iterable[ast.AST], target: ast.AST) -> ast.AST | None:
    rows = [node for node in nodes if _contains(node, target)]
    if not rows:
        return None
    rows.sort(key=lambda n: ((_span(n)[2] - _span(n)[0]) * 100000 + (_span(n)[3] - _span(n)[1]), _node_key(n)))
    return rows[0]


def _alias_mentions_helper(function: ast.FunctionDef | ast.AsyncFunctionDef, helper_name: str, branch: ast.If) -> bool:
    aliases: set[str] = set()
    for node in ast.walk(function):
        if not isinstance(node, ast.Assign) or (_span(node)[0], _span(node)[1]) >= (_span(branch)[0], _span(branch)[1]):
            continue
        if isinstance(node.value, ast.Name) and node.value.id == helper_name:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    aliases.add(target.id)
    return any(isinstance(call.func, ast.Name) and call.func.id in aliases for call in ast.walk(branch.test) if isinstance(call, ast.Call))


def prove_python_helper_polarity(
    source: str,
    transported_comparison_span: Sequence[int],
) -> dict[str, Any]:
    tree = ast.parse(source)
    wanted = tuple(map(int, transported_comparison_span))
    roots = [node for node in ast.walk(tree) if isinstance(node, ast.Compare) and _span(node) == wanted]
    if len(roots) != 1:
        return _certificate(source, wanted, None, None, _unknown("TRANSPORTED_COMPARISON_NOT_UNIQUE"))
    root = roots[0]
    helper = _smallest_container(_function_nodes(tree), root)
    if not isinstance(helper, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return _certificate(source, wanted, None, None, _unknown("HELPER_FUNCTION_NOT_FOUND", root))
    returns = [node for node in ast.walk(helper) if isinstance(node, ast.Return) and node.value is not None and _contains(node.value, root)]
    if len(returns) != 1:
        return _certificate(source, wanted, helper.name, None, _unknown("HELPER_RETURN_NOT_UNIQUE", helper))
    helper_relation = _relation_to_root(returns[0].value, root)
    if helper_relation.value == "UNKNOWN":
        return _certificate(source, wanted, helper.name, None, helper_relation)
    helper_relation = _preserve(helper_relation, returns[0], "FUNCTION_RETURN_PRESERVE")

    candidates: list[tuple[ast.FunctionDef | ast.AsyncFunctionDef, ast.If, Relation]] = []
    alias_unknown: list[tuple[ast.FunctionDef | ast.AsyncFunctionDef, ast.If]] = []
    for function in _function_nodes(tree):
        if function is helper:
            continue
        for branch in [node for node in ast.walk(function) if isinstance(node, ast.If)]:
            relation = _relation_to_helper(branch.test, helper.name, function, branch)
            if relation.reason != "NO_HELPER_DEPENDENCY":
                candidates.append((function, branch, relation))
            elif _alias_mentions_helper(function, helper.name, branch):
                alias_unknown.append((function, branch))
    if len(candidates) == 0 and len(alias_unknown) == 1:
        function, branch = alias_unknown[0]
        return _certificate(source, wanted, helper.name, branch, _unknown("UNRESOLVED_ASSIGNMENT_OR_ALIAS", branch.test, helper_relation.steps))
    if len(candidates) != 1:
        reason = "MULTIPLE_DISTINCT_SOURCE_PREDICATES" if len(candidates) > 1 else "BRANCH_CONSUMER_NOT_FOUND"
        return _certificate(source, wanted, helper.name, None, _unknown(reason, helper, helper_relation.steps))
    _, branch, branch_relation = candidates[0]
    if branch_relation.value == "UNKNOWN":
        return _certificate(source, wanted, helper.name, branch, _unknown(branch_relation.reason or "UNSUPPORTED_AST_FORM", branch.test, helper_relation.steps + branch_relation.steps))
    branch_relation = _preserve(branch_relation, branch, "BRANCH_CONSUMER_PRESERVE")
    total_flips = helper_relation.flips + branch_relation.flips
    final = "INVERTED" if total_flips % 2 else "SAME"
    steps = helper_relation.steps + (_step("FUNCTION_RETURN_TO_CALL_RESULT_PRESERVE", branch, helper_relation.value, helper.name),) + branch_relation.steps
    relation = Relation(final, total_flips, steps)
    return _certificate(source, wanted, helper.name, branch, relation)


def _certificate(
    source: str,
    transported_span: Sequence[int],
    helper_name: str | None,
    branch: ast.If | None,
    relation: Relation,
) -> dict[str, Any]:
    status = "PROVED" if relation.value in {"SAME", "INVERTED"} and relation.reason is None else "UNKNOWN"
    body = {
        "schema": SCHEMA,
        "status": status,
        "language": "python",
        "transported_comparison_span": list(map(int, transported_span)),
        "helper_function": helper_name,
        "branch_consumer_span": list(_span(branch.test)) if branch is not None else None,
        "steps": list(relation.steps),
        "flip_count": int(relation.flips) if status == "PROVED" else None,
        "final_relation": relation.value if status == "PROVED" else "UNKNOWN",
        "reason": None if status == "PROVED" else (relation.reason or "UNSUPPORTED_AST_FORM"),
    }
    digest = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {**body, "certificate_sha256": digest}
