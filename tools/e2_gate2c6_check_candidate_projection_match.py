#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping, Sequence

PROTOCOL_SCHEMA = "risu.e2-gate2c6-frozen-candidate-opaque-projection-match-protocol/v0.1"
CANONICAL_SCHEMA = "risu.e2-gate2c5-canonical-opaque-projection-identity/v0.1"
CHECK_SCHEMA = "risu.e2-gate2c6-independent-candidate-projection-check/v0.1"
LEDGER_SCHEMA = "risu.e2-gate2c6-candidate-opaque-projection-match-ledger/v0.1"
ROLES = ("BOUND_VALUE:expected_coordinate", "BOUND_VALUE:current_coordinate")


def jbytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def h(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def hj(value: Any) -> str:
    return h(jbytes(value))


def load(path: Path) -> Any:
    return json.loads(path.read_bytes())


def sp(node: ast.AST) -> tuple[int, int, int, int]:
    return int(node.lineno), int(node.col_offset), int(node.end_lineno), int(node.end_col_offset)


def exact(tree: ast.AST, types: tuple[type[ast.AST], ...], coords: Sequence[int]) -> list[ast.AST]:
    target = tuple(int(x) for x in coords)
    return [n for n in ast.walk(tree) if isinstance(n, types) and hasattr(n, "lineno") and sp(n) == target]


def function_parameters(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> list[ast.arg]:
    return [*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs]


def canonical_map(canonical: Mapping[str, Any], protocol: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    if canonical.get("schema") != CANONICAL_SCHEMA or canonical.get("seed_id") != "SYN-PY-01":
        raise ValueError("CHECK_CANONICAL_SCHEMA_OR_SEED")
    body = dict(canonical); claimed = body.pop("authority_digest_sha256", None)
    if claimed != hj(body):
        raise ValueError("CHECK_CANONICAL_DIGEST")
    lock = protocol.get("canonical_match_authority", {}) or {}
    if claimed != lock.get("authority_digest_sha256"):
        raise ValueError("CHECK_CANONICAL_PROTOCOL_DIGEST")
    rows = canonical.get("roles", []) or []
    by = {str(r.get("root_role")): r for r in rows if isinstance(r, Mapping)}
    if len(rows) != 2 or set(by) != set(ROLES):
        raise ValueError("CHECK_CANONICAL_ROLE_SET")
    expected = {ROLES[0]: lock.get("expected_fingerprint_sha256"), ROLES[1]: lock.get("current_fingerprint_sha256")}
    if any(by[r].get("fingerprint_sha256") != expected[r] for r in ROLES):
        raise ValueError("CHECK_CANONICAL_FINGERPRINT_LOCK")
    return by


def step_identity(node: ast.AST) -> tuple[str, str]:
    if isinstance(node, ast.Attribute):
        return "ATTRIBUTE", h(node.attr.encode("utf-8"))
    if isinstance(node, ast.Subscript):
        try:
            value = ast.literal_eval(node.slice)
        except Exception as exc:
            raise ValueError("CHECK_TOKEN_UNRESOLVED:DYNAMIC_SUBSCRIPT") from exc
        try:
            raw = jbytes(value)
        except (TypeError, ValueError) as exc:
            raise ValueError("CHECK_TOKEN_UNRESOLVED:NON_JSON_LITERAL") from exc
        return "SUBSCRIPT_LITERAL", h(raw)
    raise ValueError("CHECK_PROJECTION_STEP_UNSUPPORTED")


def trace(node: ast.AST, aliases: Mapping[str, ast.AST], pindex: Mapping[str, int], visiting: frozenset[str] = frozenset()) -> tuple[int, list[tuple[str, str]]]:
    if isinstance(node, ast.Name):
        if node.id in pindex:
            return pindex[node.id], []
        if node.id not in aliases or node.id in visiting:
            raise ValueError("CHECK_ROOT_OR_ALIAS_UNRESOLVED")
        return trace(aliases[node.id], aliases, pindex, visiting | {node.id})
    if isinstance(node, (ast.Attribute, ast.Subscript)):
        root, prior = trace(node.value, aliases, pindex, visiting)
        return root, prior + [step_identity(node)]
    raise ValueError("CHECK_ROOT_EXPRESSION_UNSUPPORTED")


def frozen_surface(source: bytes, contract: Mapping[str, Any]) -> tuple[ast.Compare, dict[str, ast.AST], dict[str, int]]:
    try:
        tree = ast.parse(source.decode("utf-8"))
    except (UnicodeDecodeError, SyntaxError) as exc:
        raise ValueError("CHECK_SOURCE_PARSE_FAILURE") from exc
    fspan = contract.get("target_function_span", []) or []
    gspan = (((contract.get("anchors", {}) or {}).get("guard", {}) or {}).get("span", []) or [])
    ispan = contract.get("effective_if_span", []) or []
    fs = exact(tree, (ast.FunctionDef, ast.AsyncFunctionDef), fspan)
    gs = exact(tree, (ast.Compare,), gspan)
    ifs = exact(tree, (ast.If,), ispan)
    if len(fs) != 1 or len(gs) != 1 or len(ifs) != 1:
        raise ValueError("CHECK_EXACT_SURFACE_NOT_UNIQUE")
    fn, guard, target_if = fs[0], gs[0], ifs[0]
    if len(guard.ops) != 1 or len(guard.comparators) != 1:
        raise ValueError("CHECK_GUARD_NOT_BINARY")
    t, g = sp(target_if.test), sp(guard)
    if not ((t[0], t[1]) <= (g[0], g[1]) and (g[2], g[3]) <= (t[2], t[3])):
        raise ValueError("CHECK_GUARD_OUTSIDE_EFFECTIVE_IF")
    pindex = {p.arg: i for i, p in enumerate(function_parameters(fn))}
    aliases: dict[str, ast.AST] = {}
    reached = False
    for stmt in fn.body:
        if stmt is target_if:
            reached = True
            break
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant):
            continue
        if isinstance(stmt, ast.Assign):
            if len(stmt.targets) != 1 or not isinstance(stmt.targets[0], ast.Name):
                raise ValueError("CHECK_ALIAS_ASSIGNMENT_AMBIGUOUS")
            name, value = stmt.targets[0].id, stmt.value
        elif isinstance(stmt, ast.AnnAssign):
            if not isinstance(stmt.target, ast.Name) or stmt.value is None:
                raise ValueError("CHECK_ALIAS_ASSIGNMENT_AMBIGUOUS")
            name, value = stmt.target.id, stmt.value
        else:
            raise ValueError("CHECK_NON_STRAIGHT_LINE_PREFIX")
        if name in aliases or name in pindex:
            raise ValueError("CHECK_ALIAS_REDEFINITION")
        aliases[name] = value
    if not reached:
        raise ValueError("CHECK_EFFECTIVE_IF_NOT_TOP_LEVEL")
    return guard, aliases, pindex


def role_root(signature: Mapping[str, Any], role: str) -> int:
    row = (signature.get("source_roles", {}) or {}).get(role)
    if not isinstance(row, Mapping) or type(row.get("parameter_index")) is not int:
        raise ValueError("CHECK_SOURCE_ROLE_ROOT_UNRESOLVED")
    return int(row["parameter_index"])


def role_operand(signature: Mapping[str, Any], role: str) -> int:
    hits = []
    for row in signature.get("required_bindings", []) or []:
        if isinstance(row, Mapping) and row.get("kind") == "guard_operand" and list(map(str, row.get("allowed_origins", []) or [])) == [role]:
            hits.append(row)
    if len(hits) != 1 or type(hits[0].get("operand_index")) is not int:
        raise ValueError("CHECK_TERMINAL_BINDING_UNRESOLVED")
    return int(hits[0]["operand_index"])


def derive_one(*, role: str, source: bytes, signature: Mapping[str, Any], contract: Mapping[str, Any], canonical_row: Mapping[str, Any], protocol: Mapping[str, Any]) -> dict[str, Any]:
    try:
        guard, aliases, pindex = frozen_surface(source, contract)
    except ValueError as exc:
        return {"taxonomy": "GUARD_OR_SCOPE_RESOLUTION_FAILURE", "reason": str(exc), "fingerprint_sha256": None}
    terminal = (protocol.get("candidate_role_authority", {}) or {}).get("terminal_operand_indices", {}).get(role)
    if type(terminal) is not int:
        return {"taxonomy": "TERMINAL_OPERAND_INDEX_MISMATCH", "reason": "CHECK_PROTOCOL_TERMINAL_MISSING", "fingerprint_sha256": None}
    try:
        frozen_terminal = role_operand(signature, role)
    except ValueError as exc:
        return {"taxonomy": "TERMINAL_OPERAND_INDEX_MISMATCH", "reason": str(exc), "fingerprint_sha256": None}
    if frozen_terminal != terminal:
        return {"taxonomy": "TERMINAL_OPERAND_INDEX_MISMATCH", "reason": "CHECK_SIGNATURE_TERMINAL_DISAGREEMENT", "fingerprint_sha256": None}
    operands = [guard.left, *guard.comparators]
    if terminal < 0 or terminal >= len(operands):
        return {"taxonomy": "TERMINAL_OPERAND_INDEX_MISMATCH", "reason": "CHECK_TERMINAL_RANGE", "fingerprint_sha256": None}
    try:
        authorized_root = role_root(signature, role)
        observed_root, steps0 = trace(operands[terminal], aliases, pindex)
    except ValueError as exc:
        reason = str(exc)
        if "TOKEN_UNRESOLVED" in reason or "PROJECTION_STEP" in reason:
            return {"taxonomy": "PROJECTION_TOKEN_DIGEST_MISMATCH", "reason": reason, "fingerprint_sha256": None}
        return {"taxonomy": "ROOT_PARAMETER_ORIGIN_MISMATCH", "reason": reason, "fingerprint_sha256": None}
    if observed_root != authorized_root:
        return {"taxonomy": "ROOT_PARAMETER_ORIGIN_MISMATCH", "reason": "CHECK_ROOT_PARAMETER_DISAGREEMENT", "fingerprint_sha256": None}
    steps = [{"kind": k, "token_digest_sha256": d} for k, d in steps0]
    shape = ["DERIVES"] * len(steps)
    shape_cfg = (protocol.get("candidate_role_authority", {}) or {}).get("shape_precondition", {}) or {}
    required = list(shape_cfg.get("required_expected_shape", [])) if role == ROLES[0] else list(shape_cfg.get("required_current_shape", []))
    cshape = list(canonical_row.get("shape", []) or [])
    if shape != required or cshape != required or len(steps) != len(canonical_row.get("steps", []) or []):
        return {"taxonomy": "PROJECTION_SHAPE_MISMATCH", "reason": "CHECK_SHAPE_OR_CARDINALITY", "fingerprint_sha256": None}
    csteps = list(canonical_row.get("steps", []) or [])
    if [x["kind"] for x in steps] != [str(x.get("kind")) for x in csteps]:
        return {"taxonomy": "PROJECTION_STEP_KIND_MISMATCH", "reason": "CHECK_KIND_SEQUENCE", "fingerprint_sha256": None}
    if [x["token_digest_sha256"] for x in steps] != [str(x.get("token_digest_sha256")) for x in csteps]:
        return {"taxonomy": "PROJECTION_TOKEN_DIGEST_MISMATCH", "reason": "CHECK_TOKEN_SEQUENCE", "fingerprint_sha256": None}
    payload = {"root_role": role, "terminal_guard_operand_index": terminal, "steps": steps}
    fp = hj(payload)
    if fp != canonical_row.get("fingerprint_sha256"):
        return {"taxonomy": "FULL_FINGERPRINT_MISMATCH", "reason": "CHECK_FULL_FINGERPRINT", "fingerprint_sha256": fp}
    return {"taxonomy": "CANONICAL_OPAQUE_PROJECTION_MATCH", "reason": "", "fingerprint_sha256": fp}


def check(*, protocol: Mapping[str, Any], canonical: Mapping[str, Any], tracer_ledger: Mapping[str, Any], sources_dir: Path, cases_dir: Path) -> dict[str, Any]:
    reasons: list[str] = []
    if protocol.get("schema") != PROTOCOL_SCHEMA:
        reasons.append("PROTOCOL_SCHEMA_MISMATCH")
    population = protocol.get("population", {}) or {}
    ids = sorted(map(str, population.get("case_ids", []) or []))
    if population.get("case_count") != 7 or len(ids) != 7 or len(set(ids)) != 7:
        reasons.append("POPULATION_NOT_EXACT_SEVEN")
    try:
        cmap = canonical_map(canonical, protocol)
    except ValueError as exc:
        reasons.append(str(exc)); cmap = {}
    if tracer_ledger.get("schema") != LEDGER_SCHEMA or tracer_ledger.get("role_observation_count") != 14:
        reasons.append("TRACER_LEDGER_SCHEMA_OR_COUNT_MISMATCH")
    tracer_rows = {(str(r.get("case_id")), str(r.get("role"))): r for r in tracer_ledger.get("observations", []) or [] if isinstance(r, Mapping)}
    if len(tracer_rows) != 14:
        reasons.append("TRACER_LEDGER_ROLE_KEY_SET_MISMATCH")
    observations = []
    if reasons:
        return {"schema": CHECK_SCHEMA, "status": "FAIL_CLOSED", "reasons": sorted(set(reasons)), "observations": []}
    expected_hashes = population.get("source_sha256_by_case", {}) or {}
    for cid in ids:
        spath = sources_dir / f"{cid}.py"; cdir = cases_dir / cid
        if not spath.is_file() or not (cdir / "adapter_receipt.json").is_file() or not (cdir / "semantic_slice.json").is_file():
            reasons.append(f"SELECTED_INPUT_FILE_MISSING:{cid}"); continue
        source = spath.read_bytes()
        if h(source) != expected_hashes.get(cid):
            reasons.append(f"SOURCE_SHA_MISMATCH:{cid}"); continue
        adapter = load(cdir / "adapter_receipt.json"); semantic = load(cdir / "semantic_slice.json")
        signature = adapter.get("execution_signature") if isinstance(adapter, Mapping) else None
        contract = semantic.get("source_contract") if isinstance(semantic, Mapping) else None
        if not isinstance(signature, Mapping) or not isinstance(contract, Mapping):
            reasons.append(f"CHECKER_INPUT_SURFACE_MISSING:{cid}"); continue
        for role in ROLES:
            row = derive_one(role=role, source=source, signature=signature, contract=contract, canonical_row=cmap[role], protocol=protocol)
            tr = tracer_rows.get((cid, role))
            if not isinstance(tr, Mapping):
                reasons.append(f"TRACER_ROW_MISSING:{cid}:{role}"); continue
            fp = row.get("fingerprint_sha256")
            tracer_fp = tr.get("candidate_fingerprint_sha256")
            taxonomy_equal = row["taxonomy"] == tr.get("taxonomy")
            fp_equal = fp == tracer_fp if fp is not None or tracer_fp is not None else True
            if not taxonomy_equal:
                reasons.append(f"TRACER_CHECKER_TAXONOMY_DISAGREEMENT:{cid}:{role}")
            if not fp_equal:
                reasons.append(f"TRACER_CHECKER_FINGERPRINT_DISAGREEMENT:{cid}:{role}")
            observations.append({"case_id": cid, "role": role, "checker_taxonomy": row["taxonomy"], "checker_fingerprint_sha256": fp, "tracer_taxonomy": tr.get("taxonomy"), "tracer_fingerprint_sha256": tracer_fp, "taxonomy_agreement": taxonomy_equal, "fingerprint_agreement": fp_equal})
    if len(observations) != 14:
        reasons.append("CHECKER_OBSERVATION_COUNT_NOT_14")
    return {"schema": CHECK_SCHEMA, "status": "PASS" if not reasons else "FAIL_CLOSED", "reasons": sorted(set(reasons)), "role_observation_count": len(observations), "all_taxonomy_agree": len(observations) == 14 and all(x["taxonomy_agreement"] for x in observations), "all_fingerprints_agree": len(observations) == 14 and all(x["fingerprint_agreement"] for x in observations), "observations": observations, "c1_rerun": False, "truth_used": False, "remediation": False}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--protocol", required=True); ap.add_argument("--canonical", required=True); ap.add_argument("--tracer-ledger", required=True); ap.add_argument("--sources", required=True); ap.add_argument("--case-artifacts", required=True); ap.add_argument("--output", required=True)
    a = ap.parse_args()
    result = check(protocol=load(Path(a.protocol)), canonical=load(Path(a.canonical)), tracer_ledger=load(Path(a.tracer_ledger)), sources_dir=Path(a.sources), cases_dir=Path(a.case_artifacts))
    Path(a.output).write_bytes(jbytes(result))
    return 0 if result["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
