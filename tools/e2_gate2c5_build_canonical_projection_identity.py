#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping, Sequence

SCHEMA = "risu.e2-gate2c5-canonical-opaque-projection-identity/v0.1"
SEED_ID = "SYN-PY-01"
ROLES = ("BOUND_VALUE:expected_coordinate", "BOUND_VALUE:current_coordinate")


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def digest_json(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def span(node: ast.AST) -> tuple[int, int, int, int]:
    return (int(node.lineno), int(node.col_offset), int(node.end_lineno), int(node.end_col_offset))


def slice_bytes(source: bytes, wanted: Sequence[int]) -> bytes:
    sl, sc, el, ec = map(int, wanted)
    lines = source.splitlines(keepends=True)
    if sl < 1 or el < sl or el > len(lines):
        raise ValueError("INVALID_FROZEN_SPAN")
    if sl == el:
        return lines[sl - 1][sc:ec]
    return b"".join([lines[sl - 1][sc:]] + lines[sl:el - 1] + [lines[el - 1][:ec]])


def selected_row(rows: Sequence[Mapping[str, Any]], key: str, value: str, error: str) -> Mapping[str, Any]:
    matches = [x for x in rows if str(x.get(key)) == value]
    if len(matches) != 1:
        raise ValueError(error)
    return matches[0]


def exact_guard(tree: ast.Module, guard_span: Sequence[int]) -> ast.Compare:
    target = tuple(map(int, guard_span))
    rows = [n for n in ast.walk(tree) if isinstance(n, ast.Compare) and hasattr(n, "lineno") and span(n) == target]
    if len(rows) != 1:
        raise ValueError("FROZEN_GUARD_NOT_UNIQUE")
    return rows[0]


def containing_function(tree: ast.Module, guard: ast.Compare) -> ast.FunctionDef | ast.AsyncFunctionDef:
    gs, ge = (guard.lineno, guard.col_offset), (guard.end_lineno, guard.end_col_offset)
    rows = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        ns, ne = (node.lineno, node.col_offset), (node.end_lineno, node.end_col_offset)
        if ns <= gs and ge <= ne:
            rows.append(node)
    rows.sort(key=lambda n: ((n.end_lineno - n.lineno), (n.end_col_offset - n.col_offset)))
    if not rows:
        raise ValueError("GUARD_SCOPE_FUNCTION_MISSING")
    narrow = rows[0]
    if len(rows) > 1 and span(rows[0]) == span(rows[1]):
        raise ValueError("GUARD_SCOPE_FUNCTION_AMBIGUOUS")
    return narrow


def containing_if(fn: ast.FunctionDef | ast.AsyncFunctionDef, guard: ast.Compare) -> ast.If:
    rows = []
    for n in ast.walk(fn):
        if isinstance(n, ast.If):
            a, b = span(n.test), span(guard)
            if (a[0], a[1]) <= (b[0], b[1]) and (b[2], b[3]) <= (a[2], a[3]):
                rows.append(n)
    if len(rows) != 1:
        raise ValueError("FROZEN_GUARD_IF_NOT_UNIQUE")
    return rows[0]


def params(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> list[ast.arg]:
    return list(fn.args.posonlyargs) + list(fn.args.args) + list(fn.args.kwonlyargs)


def projection_step(node: ast.AST) -> dict[str, str]:
    if isinstance(node, ast.Attribute):
        return {"kind": "ATTRIBUTE", "token_digest_sha256": digest_bytes(node.attr.encode("utf-8"))}
    if isinstance(node, ast.Subscript):
        try:
            key = ast.literal_eval(node.slice)
        except Exception as exc:
            raise ValueError("UNSUPPORTED_DYNAMIC_SUBSCRIPT") from exc
        try:
            key_bytes = canonical_bytes(key)
        except (TypeError, ValueError) as exc:
            raise ValueError("UNSUPPORTED_SUBSCRIPT_LITERAL") from exc
        return {"kind": "SUBSCRIPT_LITERAL", "token_digest_sha256": digest_bytes(key_bytes)}
    raise ValueError("UNSUPPORTED_PROJECTION_STEP")


def _resolve_expr(expr: ast.AST, env: Mapping[str, tuple[int, tuple[tuple[str, str], ...]]], param_by_name: Mapping[str, int]) -> tuple[int, tuple[tuple[str, str], ...]]:
    if isinstance(expr, ast.Name):
        if expr.id in env:
            return env[expr.id]
        if expr.id in param_by_name:
            return param_by_name[expr.id], ()
        raise ValueError("ORIGIN_NAME_UNRESOLVED")
    if isinstance(expr, ast.Attribute):
        root, steps = _resolve_expr(expr.value, env, param_by_name)
        s = projection_step(expr)
        return root, steps + ((s["kind"], s["token_digest_sha256"]),)
    if isinstance(expr, ast.Subscript):
        root, steps = _resolve_expr(expr.value, env, param_by_name)
        s = projection_step(expr)
        return root, steps + ((s["kind"], s["token_digest_sha256"]),)
    raise ValueError("ORIGIN_EXPRESSION_OUTSIDE_ADMITTED_FRAGMENT")


def prefix_environment(fn: ast.FunctionDef | ast.AsyncFunctionDef, guard_if: ast.If) -> tuple[dict[str, tuple[int, tuple[tuple[str, str], ...]]], dict[str, int]]:
    ps = params(fn)
    param_by_name = {p.arg: i for i, p in enumerate(ps)}
    env: dict[str, tuple[int, tuple[tuple[str, str], ...]]] = {}
    found = False
    for stmt in fn.body:
        if stmt is guard_if:
            found = True
            break
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant):
            continue
        if isinstance(stmt, ast.Assign):
            if len(stmt.targets) != 1 or not isinstance(stmt.targets[0], ast.Name):
                raise ValueError("AMBIGUOUS_ALIAS_OR_ASSIGNMENT")
            value = _resolve_expr(stmt.value, env, param_by_name)
            env[stmt.targets[0].id] = value
            continue
        if isinstance(stmt, ast.AnnAssign):
            if not isinstance(stmt.target, ast.Name) or stmt.value is None:
                raise ValueError("AMBIGUOUS_ALIAS_OR_ASSIGNMENT")
            value = _resolve_expr(stmt.value, env, param_by_name)
            env[stmt.target.id] = value
            continue
        raise ValueError("NON_STRAIGHT_LINE_PREFIX")
    if not found:
        raise ValueError("FROZEN_GUARD_IF_NOT_TOP_LEVEL_IN_FUNCTION")
    return env, param_by_name


def role_config(*, role: str, profile: Mapping[str, Any], signature: Mapping[str, Any], anchor: Mapping[str, Any]) -> tuple[int, int, list[str]]:
    source_roles = profile.get("source_roles", {}) or {}
    srow = source_roles.get(role)
    if not isinstance(srow, Mapping) or srow.get("status") != "RESOLVED":
        raise ValueError(f"SOURCE_ROLE_UNRESOLVED:{role}")
    parameter_index = srow.get("parameter_index")
    if type(parameter_index) is not int:
        raise ValueError(f"SOURCE_ROLE_PARAMETER_INVALID:{role}")
    shapes = srow.get("lineage_edge_shapes", []) or []
    if len(shapes) != 1 or not isinstance(shapes[0], list):
        raise ValueError(f"CANONICAL_PROFILE_SHAPE_UNRESOLVED:{role}")
    shape = [str(x) for x in shapes[0]]
    slot_name = role.split(":", 1)[1]
    sig_slot = (signature.get("required_binding_slot_roles", {}) or {}).get(slot_name)
    anc_slot = (anchor.get("binding_slots", {}) or {}).get(slot_name)
    if not isinstance(sig_slot, Mapping) or not isinstance(anc_slot, Mapping):
        raise ValueError(f"TERMINAL_SLOT_UNRESOLVED:{role}")
    sig_idx, anc_idx = sig_slot.get("operand_index"), anc_slot.get("operand_index")
    if type(sig_idx) is not int or type(anc_idx) is not int or sig_idx != anc_idx:
        raise ValueError(f"TERMINAL_OPERAND_INDEX_MISMATCH:{role}")
    return parameter_index, sig_idx, shape


def derive_authority(*, protocol: Mapping[str, Any], resolution: Mapping[str, Any], anchor_bundle: Mapping[str, Any], seed_catalog: Mapping[str, Any], signatures: Mapping[str, Any], profiles: Mapping[str, Any], source: bytes) -> dict[str, Any]:
    if protocol.get("schema") != "risu.e2-gate2c5-canonical-opaque-projection-identity-protocol/v0.1":
        raise ValueError("PROTOCOL_SCHEMA_MISMATCH")
    if resolution.get("schema") != "risu.e2-gate2c5-canonical-guard-anchor-resolution/v0.1":
        raise ValueError("RESOLUTION_SCHEMA_MISMATCH")
    selected = resolution.get("selected_contract", {}) or {}
    if selected.get("seed_id") != SEED_ID:
        raise ValueError("RESOLUTION_SEED_MISMATCH")
    seed = selected_row(seed_catalog.get("seeds", []) or [], "seed_id", SEED_ID, "SEED_CATALOG_SELECTION_NOT_UNIQUE")
    contract = selected_row(anchor_bundle.get("contracts", []) or [], "seed_id", SEED_ID, "ANCHOR_CONTRACT_SELECTION_NOT_UNIQUE")
    decl = contract.get("declaration", {}) or {}
    profile = selected_row(profiles.get("profiles", []) or [], "seed_id", SEED_ID, "PROFILE_SELECTION_NOT_UNIQUE")
    signature = selected_row(signatures.get("signatures", []) or [], "seed_id", SEED_ID, "SIGNATURE_SELECTION_NOT_UNIQUE")
    if seed.get("program_sha256") != selected.get("source", {}).get("sha256"):
        raise ValueError("SEED_CATALOG_SOURCE_SHA_MISMATCH")
    if decl.get("source", {}).get("sha256") != selected.get("source", {}).get("sha256"):
        raise ValueError("ANCHOR_SOURCE_SHA_MISMATCH")
    if decl.get("source", {}).get("git_blob_sha") != selected.get("source", {}).get("git_blob"):
        raise ValueError("ANCHOR_SOURCE_BLOB_MISMATCH")
    if decl.get("contract_id") != selected.get("contract_id"):
        raise ValueError("ANCHOR_CONTRACT_ID_MISMATCH")
    if contract.get("contract_canonical_sha256") != selected.get("contract_canonical_sha256"):
        raise ValueError("ANCHOR_CONTRACT_DIGEST_MISMATCH")
    if signature.get("anchor_contract_sha256") != selected.get("contract_canonical_sha256"):
        raise ValueError("SIGNATURE_ANCHOR_CONTRACT_MISMATCH")
    if digest_bytes(source) != selected.get("source", {}).get("sha256"):
        raise ValueError("SOURCE_SHA256_MISMATCH")
    guard_row = (decl.get("anchors", {}) or {}).get("guard_comparison", {}) or {}
    resolved_guard = selected.get("guard", {}) or {}
    for key in ("span", "slice_bytes", "slice_sha256", "syntax_kind", "unique_in_source"):
        if guard_row.get(key) != resolved_guard.get(key):
            raise ValueError(f"FROZEN_GUARD_AUTHORITY_MISMATCH:{key}")
    raw_guard = slice_bytes(source, resolved_guard["span"])
    if len(raw_guard) != int(resolved_guard["slice_bytes"]):
        raise ValueError("FROZEN_GUARD_SLICE_LENGTH_MISMATCH")
    if digest_bytes(raw_guard) != resolved_guard["slice_sha256"]:
        raise ValueError("FROZEN_GUARD_SLICE_SHA_MISMATCH")
    try:
        tree = ast.parse(source.decode("utf-8"))
    except (UnicodeDecodeError, SyntaxError) as exc:
        raise ValueError("CANONICAL_SOURCE_PARSE_FAILURE") from exc
    guard = exact_guard(tree, resolved_guard["span"])
    if len(guard.ops) != 1 or len(guard.comparators) != 1:
        raise ValueError("CANONICAL_GUARD_NOT_BINARY_COMPARE")
    fn = containing_function(tree, guard)
    gif = containing_if(fn, guard)
    env, param_by_name = prefix_environment(fn, gif)
    operands = [guard.left] + list(guard.comparators)
    ps = params(fn)
    records = []
    for role in ROLES:
        root_index, operand_index, frozen_shape = role_config(role=role, profile=profile, signature=signature, anchor=decl)
        if root_index < 0 or root_index >= len(ps):
            raise ValueError(f"ROOT_PARAMETER_INDEX_OUT_OF_RANGE:{role}")
        if operand_index < 0 or operand_index >= len(operands):
            raise ValueError(f"OPERAND_INDEX_OUT_OF_RANGE:{role}")
        observed_root, observed_steps = _resolve_expr(operands[operand_index], env, param_by_name)
        if observed_root != root_index:
            raise ValueError(f"ROOT_ROLE_MISMATCH:{role}")
        steps = [{"kind": k, "token_digest_sha256": d} for k, d in observed_steps]
        shape = ["DERIVES" for _ in steps]
        if shape != frozen_shape:
            raise ValueError(f"CANONICAL_PROFILE_SHAPE_MISMATCH:{role}")
        payload = {"root_role": role, "terminal_guard_operand_index": operand_index, "steps": steps}
        records.append({**payload, "root_parameter_index": root_index, "shape": shape, "fingerprint_sha256": digest_json(payload)})
    out = {"schema": SCHEMA, "seed_id": SEED_ID, "role_count": len(records), "roles": records, "authority": {"source_sha256": digest_bytes(source), "anchor_contract_sha256": selected.get("contract_canonical_sha256"), "guard_span": list(map(int, resolved_guard["span"])), "guard_slice_sha256": resolved_guard["slice_sha256"]}, "raw_source_bytes_emitted": False, "raw_projection_tokens_emitted": False, "identifier_spelling_interpreted_as_semantic_role": False, "semantic_scope": "Structural projection identity relative to the frozen canonical SYN-PY-01 source only; does not independently assign domain meaning."}
    body = dict(out)
    out["authority_digest_sha256"] = digest_json(body)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--protocol", required=True); ap.add_argument("--resolution", required=True); ap.add_argument("--anchor-bundle", required=True); ap.add_argument("--seed-catalog", required=True); ap.add_argument("--signatures", required=True); ap.add_argument("--profiles", required=True); ap.add_argument("--source", required=True); ap.add_argument("--output", required=True)
    a = ap.parse_args(); load = lambda p: json.loads(Path(p).read_text(encoding="utf-8"))
    out = derive_authority(protocol=load(a.protocol), resolution=load(a.resolution), anchor_bundle=load(a.anchor_bundle), seed_catalog=load(a.seed_catalog), signatures=load(a.signatures), profiles=load(a.profiles), source=Path(a.source).read_bytes())
    Path(a.output).write_bytes(canonical_bytes(out)); return 0


if __name__ == "__main__":
    raise SystemExit(main())
