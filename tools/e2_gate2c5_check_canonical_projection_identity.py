#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping, Sequence

AUTH_SCHEMA = "risu.e2-gate2c5-canonical-opaque-projection-identity/v0.1"
CHECK_SCHEMA = "risu.e2-gate2c5-independent-projection-identity-check/v0.1"
SEED_ID = "SYN-PY-01"
ROLES = ("BOUND_VALUE:expected_coordinate", "BOUND_VALUE:current_coordinate")


def jbytes(v: Any) -> bytes:
    return (json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def hbytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def hj(v: Any) -> str:
    return hbytes(jbytes(v))


def nspan(n: ast.AST) -> tuple[int, int, int, int]:
    return int(n.lineno), int(n.col_offset), int(n.end_lineno), int(n.end_col_offset)


def source_slice(raw: bytes, coords: Sequence[int]) -> bytes:
    sl, sc, el, ec = [int(x) for x in coords]
    lines = raw.splitlines(keepends=True)
    if not (1 <= sl <= el <= len(lines)):
        raise ValueError("BAD_FROZEN_GUARD_SPAN")
    if sl == el:
        return lines[sl - 1][sc:ec]
    return b"".join([lines[sl - 1][sc:]] + lines[sl:el - 1] + [lines[el - 1][:ec]])


def one(rows: Sequence[Mapping[str, Any]], pred, reason: str) -> Mapping[str, Any]:
    matches = [r for r in rows if pred(r)]
    if len(matches) != 1:
        raise ValueError(reason)
    return matches[0]


def literal_digest(value: Any) -> str:
    try:
        return hbytes(jbytes(value))
    except (TypeError, ValueError) as exc:
        raise ValueError("NON_JSON_SUBSCRIPT_LITERAL") from exc


def step_of(n: ast.AST) -> tuple[str, str]:
    if isinstance(n, ast.Attribute):
        return "ATTRIBUTE", hbytes(n.attr.encode("utf-8"))
    if isinstance(n, ast.Subscript):
        try:
            value = ast.literal_eval(n.slice)
        except Exception as exc:
            raise ValueError("DYNAMIC_SUBSCRIPT_FORBIDDEN") from exc
        return "SUBSCRIPT_LITERAL", literal_digest(value)
    raise ValueError("STEP_OUTSIDE_ADMITTED_PROJECTION")


def params(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> list[ast.arg]:
    return list(fn.args.posonlyargs) + list(fn.args.args) + list(fn.args.kwonlyargs)


def guard_and_scope(tree: ast.Module, coords: Sequence[int]) -> tuple[ast.Compare, ast.FunctionDef | ast.AsyncFunctionDef, ast.If]:
    target = tuple(int(x) for x in coords)
    guards = [n for n in ast.walk(tree) if isinstance(n, ast.Compare) and hasattr(n, "lineno") and nspan(n) == target]
    if len(guards) != 1:
        raise ValueError("CHECKER_GUARD_NOT_UNIQUE")
    g = guards[0]
    funcs = []
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and (n.lineno, n.col_offset) <= (g.lineno, g.col_offset) and (g.end_lineno, g.end_col_offset) <= (n.end_lineno, n.end_col_offset):
            funcs.append(n)
    funcs.sort(key=lambda x: (x.end_lineno - x.lineno, x.end_col_offset - x.col_offset))
    if not funcs:
        raise ValueError("CHECKER_GUARD_SCOPE_MISSING")
    fn = funcs[0]
    ifs = []
    for n in ast.walk(fn):
        if isinstance(n, ast.If):
            s = nspan(n.test)
            if (s[0], s[1]) <= (g.lineno, g.col_offset) and (g.end_lineno, g.end_col_offset) <= (s[2], s[3]):
                ifs.append(n)
    if len(ifs) != 1:
        raise ValueError("CHECKER_GUARD_IF_NOT_UNIQUE")
    return g, fn, ifs[0]


def prefix_assignments(fn: ast.FunctionDef | ast.AsyncFunctionDef, guard_if: ast.If) -> dict[str, ast.AST]:
    out: dict[str, ast.AST] = {}
    for stmt in fn.body:
        if stmt is guard_if:
            return out
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant):
            continue
        if isinstance(stmt, ast.Assign):
            if len(stmt.targets) != 1 or not isinstance(stmt.targets[0], ast.Name):
                raise ValueError("CHECKER_ALIAS_ASSIGNMENT_AMBIGUOUS")
            name = stmt.targets[0].id
            if name in out:
                raise ValueError("CHECKER_ALIAS_REDEFINITION_NOT_ADMITTED")
            out[name] = stmt.value
            continue
        if isinstance(stmt, ast.AnnAssign):
            if not isinstance(stmt.target, ast.Name) or stmt.value is None:
                raise ValueError("CHECKER_ALIAS_ASSIGNMENT_AMBIGUOUS")
            name = stmt.target.id
            if name in out:
                raise ValueError("CHECKER_ALIAS_REDEFINITION_NOT_ADMITTED")
            out[name] = stmt.value
            continue
        raise ValueError("CHECKER_NON_STRAIGHT_LINE_PREFIX")
    raise ValueError("CHECKER_GUARD_IF_NOT_TOP_LEVEL")


def trace_back(node: ast.AST, *, pindex: Mapping[str, int], aliases: Mapping[str, ast.AST], visiting: frozenset[str] = frozenset()) -> tuple[int, list[tuple[str, str]]]:
    if isinstance(node, ast.Name):
        if node.id in pindex:
            return pindex[node.id], []
        if node.id not in aliases or node.id in visiting:
            raise ValueError("CHECKER_ORIGIN_UNRESOLVED")
        return trace_back(aliases[node.id], pindex=pindex, aliases=aliases, visiting=visiting | {node.id})
    if isinstance(node, (ast.Attribute, ast.Subscript)):
        root, prior = trace_back(node.value, pindex=pindex, aliases=aliases, visiting=visiting)
        return root, prior + [step_of(node)]
    raise ValueError("CHECKER_ORIGIN_EXPRESSION_UNSUPPORTED")


def derive_expected(*, resolution: Mapping[str, Any], anchor_bundle: Mapping[str, Any], seed_catalog: Mapping[str, Any], signatures: Mapping[str, Any], profiles: Mapping[str, Any], source: bytes) -> list[dict[str, Any]]:
    selected = resolution.get("selected_contract", {}) or {}
    if selected.get("seed_id") != SEED_ID:
        raise ValueError("CHECKER_RESOLUTION_SEED_MISMATCH")
    seed = one(seed_catalog.get("seeds", []) or [], lambda r: r.get("seed_id") == SEED_ID, "CHECKER_SEED_NOT_UNIQUE")
    contract = one(anchor_bundle.get("contracts", []) or [], lambda r: r.get("seed_id") == SEED_ID, "CHECKER_ANCHOR_NOT_UNIQUE")
    decl = contract.get("declaration", {}) or {}
    sig = one(signatures.get("signatures", []) or [], lambda r: r.get("seed_id") == SEED_ID, "CHECKER_SIGNATURE_NOT_UNIQUE")
    prof = one(profiles.get("profiles", []) or [], lambda r: r.get("seed_id") == SEED_ID, "CHECKER_PROFILE_NOT_UNIQUE")
    if hbytes(source) != selected.get("source", {}).get("sha256"):
        raise ValueError("CHECKER_SOURCE_SHA_MISMATCH")
    if seed.get("program_sha256") != hbytes(source) or decl.get("source", {}).get("sha256") != hbytes(source):
        raise ValueError("CHECKER_SOURCE_AUTHORITY_DISAGREEMENT")
    if contract.get("contract_canonical_sha256") != selected.get("contract_canonical_sha256") or sig.get("anchor_contract_sha256") != selected.get("contract_canonical_sha256"):
        raise ValueError("CHECKER_ANCHOR_CONTRACT_DISAGREEMENT")
    gdecl = (decl.get("anchors", {}) or {}).get("guard_comparison", {}) or {}; gres = selected.get("guard", {}) or {}
    if gdecl.get("span") != gres.get("span") or gdecl.get("slice_sha256") != gres.get("slice_sha256") or gdecl.get("unique_in_source") is not True:
        raise ValueError("CHECKER_GUARD_AUTHORITY_DISAGREEMENT")
    if hbytes(source_slice(source, gres["span"])) != gres.get("slice_sha256"):
        raise ValueError("CHECKER_GUARD_SLICE_SHA_MISMATCH")
    tree = ast.parse(source.decode("utf-8")); guard, fn, guard_if = guard_and_scope(tree, gres["span"])
    if len(guard.ops) != 1 or len(guard.comparators) != 1:
        raise ValueError("CHECKER_GUARD_NOT_BINARY")
    operands = [guard.left] + list(guard.comparators); plist = params(fn); pindex = {p.arg: i for i, p in enumerate(plist)}; aliases = prefix_assignments(fn, guard_if)
    rows = []
    for role in ROLES:
        srow = (prof.get("source_roles", {}) or {}).get(role, {}) or {}
        if srow.get("status") != "RESOLVED" or type(srow.get("parameter_index")) is not int:
            raise ValueError(f"CHECKER_ROLE_PROFILE_INVALID:{role}")
        shapes = srow.get("lineage_edge_shapes", []) or []
        if len(shapes) != 1 or not isinstance(shapes[0], list):
            raise ValueError(f"CHECKER_PROFILE_SHAPE_INVALID:{role}")
        shape = [str(x) for x in shapes[0]]; slot = role.split(":", 1)[1]
        ss = (sig.get("required_binding_slot_roles", {}) or {}).get(slot, {}) or {}; aa = (decl.get("binding_slots", {}) or {}).get(slot, {}) or {}
        if type(ss.get("operand_index")) is not int or ss.get("operand_index") != aa.get("operand_index"):
            raise ValueError(f"CHECKER_TERMINAL_INDEX_DISAGREEMENT:{role}")
        oi = ss["operand_index"]
        if oi < 0 or oi >= len(operands):
            raise ValueError(f"CHECKER_OPERAND_INDEX_RANGE:{role}")
        root, steps0 = trace_back(operands[oi], pindex=pindex, aliases=aliases)
        if root != srow["parameter_index"]:
            raise ValueError(f"CHECKER_ROOT_ROLE_MISMATCH:{role}")
        steps = [{"kind": k, "token_digest_sha256": d} for k, d in steps0]
        if ["DERIVES" for _ in steps] != shape:
            raise ValueError(f"CHECKER_PROFILE_SHAPE_MISMATCH:{role}")
        payload = {"root_role": role, "terminal_guard_operand_index": oi, "steps": steps}
        rows.append({**payload, "fingerprint_sha256": hj(payload)})
    return rows


def check_authority(*, authority: Mapping[str, Any], resolution: Mapping[str, Any], anchor_bundle: Mapping[str, Any], seed_catalog: Mapping[str, Any], signatures: Mapping[str, Any], profiles: Mapping[str, Any], source: bytes) -> dict[str, Any]:
    reasons: list[str] = []
    if authority.get("schema") != AUTH_SCHEMA:
        reasons.append("AUTHORITY_SCHEMA_MISMATCH")
    body = dict(authority); claimed = body.pop("authority_digest_sha256", None)
    if claimed != hj(body):
        reasons.append("AUTHORITY_DIGEST_MISMATCH")
    try:
        expected = derive_expected(resolution=resolution, anchor_bundle=anchor_bundle, seed_catalog=seed_catalog, signatures=signatures, profiles=profiles, source=source)
    except (ValueError, SyntaxError, UnicodeDecodeError) as exc:
        return {"schema": CHECK_SCHEMA, "status": "FAIL_CLOSED", "reasons": [str(exc)]}
    actual = authority.get("roles", []) or []
    if len(actual) != 2:
        reasons.append("AUTHORITY_ROLE_COUNT_MISMATCH")
    by_role = {str(x.get("root_role")): x for x in actual if isinstance(x, Mapping)}
    if len(by_role) != len(actual):
        reasons.append("AUTHORITY_ROLE_DUPLICATE_OR_MALFORMED")
    for row in expected:
        role = row["root_role"]; got = by_role.get(role)
        if not isinstance(got, Mapping):
            reasons.append(f"AUTHORITY_ROLE_MISSING:{role}"); continue
        for key in ("terminal_guard_operand_index", "steps", "fingerprint_sha256"):
            if got.get(key) != row.get(key):
                reasons.append(f"AUTHORITY_REDERIVATION_MISMATCH:{role}:{key}")
    if set(by_role) != set(ROLES):
        reasons.append("AUTHORITY_ROLE_SET_MISMATCH")
    return {"schema": CHECK_SCHEMA, "seed_id": SEED_ID, "status": "PASS" if not reasons else "FAIL_CLOSED", "reasons": sorted(set(reasons)), "rederived_fingerprints": {r["root_role"]: r["fingerprint_sha256"] for r in expected}, "raw_projection_tokens_emitted": False, "identifier_spelling_interpreted_as_semantic_role": False}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--authority", required=True); ap.add_argument("--resolution", required=True); ap.add_argument("--anchor-bundle", required=True); ap.add_argument("--seed-catalog", required=True); ap.add_argument("--signatures", required=True); ap.add_argument("--profiles", required=True); ap.add_argument("--source", required=True); ap.add_argument("--output", required=True)
    a = ap.parse_args(); load = lambda p: json.loads(Path(p).read_text(encoding="utf-8"))
    result = check_authority(authority=load(a.authority), resolution=load(a.resolution), anchor_bundle=load(a.anchor_bundle), seed_catalog=load(a.seed_catalog), signatures=load(a.signatures), profiles=load(a.profiles), source=Path(a.source).read_bytes())
    Path(a.output).write_bytes(jbytes(result)); return 0 if result["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
