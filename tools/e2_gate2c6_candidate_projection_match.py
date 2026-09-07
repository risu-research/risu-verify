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
LEDGER_SCHEMA = "risu.e2-gate2c6-candidate-opaque-projection-match-ledger/v0.1"
SUMMARY_SCHEMA = "risu.e2-gate2c6-candidate-opaque-projection-match-summary/v0.1"
ROLES = ("BOUND_VALUE:expected_coordinate", "BOUND_VALUE:current_coordinate")
TAXONOMY = (
    "TRACE_INPUT_INTEGRITY_FAILURE",
    "GUARD_OR_SCOPE_RESOLUTION_FAILURE",
    "ROOT_PARAMETER_ORIGIN_MISMATCH",
    "TERMINAL_OPERAND_INDEX_MISMATCH",
    "PROJECTION_SHAPE_MISMATCH",
    "PROJECTION_STEP_KIND_MISMATCH",
    "PROJECTION_TOKEN_DIGEST_MISMATCH",
    "FULL_FINGERPRINT_MISMATCH",
    "CANONICAL_OPAQUE_PROJECTION_MATCH",
)


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def sha_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def digest_json(value: Any) -> str:
    return sha_bytes(canonical_bytes(value))


def read_json(path: Path) -> Any:
    return json.loads(path.read_bytes())


def node_span(node: ast.AST) -> tuple[int, int, int, int]:
    return int(node.lineno), int(node.col_offset), int(node.end_lineno), int(node.end_col_offset)


def exact_nodes(tree: ast.AST, typ: type[ast.AST], coords: Sequence[int]) -> list[ast.AST]:
    wanted = tuple(map(int, coords))
    return [n for n in ast.walk(tree) if isinstance(n, typ) and hasattr(n, "lineno") and node_span(n) == wanted]


def params(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> list[ast.arg]:
    return list(fn.args.posonlyargs) + list(fn.args.args) + list(fn.args.kwonlyargs)


def validate_population(protocol: Mapping[str, Any]) -> list[str]:
    if protocol.get("schema") != PROTOCOL_SCHEMA:
        raise ValueError("PROTOCOL_SCHEMA_MISMATCH")
    population = protocol.get("population", {}) or {}
    ids = [str(x) for x in population.get("case_ids", []) or []]
    if population.get("case_count") != 7 or len(ids) != 7 or len(set(ids)) != 7:
        raise ValueError("POPULATION_NOT_EXACT_SEVEN")
    if population.get("role_observation_count") != 14 or tuple(population.get("roles", []) or []) != ROLES:
        raise ValueError("POPULATION_ROLE_SURFACE_MISMATCH")
    return sorted(ids)


def canonical_roles(canonical: Mapping[str, Any], protocol: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    if canonical.get("schema") != CANONICAL_SCHEMA or canonical.get("seed_id") != "SYN-PY-01":
        raise ValueError("CANONICAL_AUTHORITY_SCHEMA_OR_SEED_MISMATCH")
    body = dict(canonical)
    claimed = body.pop("authority_digest_sha256", None)
    if claimed != digest_json(body):
        raise ValueError("CANONICAL_AUTHORITY_DIGEST_MISMATCH")
    lock = protocol.get("canonical_match_authority", {}) or {}
    if claimed != lock.get("authority_digest_sha256"):
        raise ValueError("CANONICAL_AUTHORITY_PROTOCOL_DIGEST_MISMATCH")
    rows = canonical.get("roles", []) or []
    by_role = {str(x.get("root_role")): x for x in rows if isinstance(x, Mapping)}
    if len(rows) != 2 or set(by_role) != set(ROLES):
        raise ValueError("CANONICAL_AUTHORITY_ROLE_SET_MISMATCH")
    expected = {
        "BOUND_VALUE:expected_coordinate": str(lock.get("expected_fingerprint_sha256")),
        "BOUND_VALUE:current_coordinate": str(lock.get("current_fingerprint_sha256")),
    }
    for role in ROLES:
        if by_role[role].get("fingerprint_sha256") != expected[role]:
            raise ValueError(f"CANONICAL_AUTHORITY_FINGERPRINT_MISMATCH:{role}")
    return by_role


def projection_step(node: ast.AST) -> tuple[str, str]:
    if isinstance(node, ast.Attribute):
        return "ATTRIBUTE", sha_bytes(node.attr.encode("utf-8"))
    if isinstance(node, ast.Subscript):
        try:
            key = ast.literal_eval(node.slice)
        except Exception as exc:
            raise ValueError("PROJECTION_TOKEN_UNRESOLVED:DYNAMIC_SUBSCRIPT") from exc
        try:
            token = canonical_bytes(key)
        except (TypeError, ValueError) as exc:
            raise ValueError("PROJECTION_TOKEN_UNRESOLVED:NON_JSON_LITERAL") from exc
        return "SUBSCRIPT_LITERAL", sha_bytes(token)
    raise ValueError("PROJECTION_STEP_UNSUPPORTED")


def resolve_expr(expr: ast.AST, env: Mapping[str, tuple[int, tuple[tuple[str, str], ...]]], pindex: Mapping[str, int]) -> tuple[int, tuple[tuple[str, str], ...]]:
    if isinstance(expr, ast.Name):
        if expr.id in env:
            return env[expr.id]
        if expr.id in pindex:
            return pindex[expr.id], ()
        raise ValueError("ROOT_OR_ALIAS_UNRESOLVED")
    if isinstance(expr, (ast.Attribute, ast.Subscript)):
        root, prior = resolve_expr(expr.value, env, pindex)
        step = projection_step(expr)
        return root, prior + (step,)
    raise ValueError("ROOT_ORIGIN_EXPRESSION_OUTSIDE_ADMITTED_FRAGMENT")


def prefix_environment(fn: ast.FunctionDef | ast.AsyncFunctionDef, target_if: ast.If) -> tuple[dict[str, tuple[int, tuple[tuple[str, str], ...]]], dict[str, int]]:
    plist = params(fn)
    pindex = {p.arg: i for i, p in enumerate(plist)}
    env: dict[str, tuple[int, tuple[tuple[str, str], ...]]] = {}
    found = False
    for stmt in fn.body:
        if stmt is target_if:
            found = True
            break
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant):
            continue
        if isinstance(stmt, ast.Assign):
            if len(stmt.targets) != 1 or not isinstance(stmt.targets[0], ast.Name):
                raise ValueError("AMBIGUOUS_ALIAS_OR_ASSIGNMENT")
            name, value = stmt.targets[0].id, stmt.value
        elif isinstance(stmt, ast.AnnAssign):
            if not isinstance(stmt.target, ast.Name) or stmt.value is None:
                raise ValueError("AMBIGUOUS_ALIAS_OR_ASSIGNMENT")
            name, value = stmt.target.id, stmt.value
        else:
            raise ValueError("NON_STRAIGHT_LINE_PREFIX")
        if name in env or name in pindex:
            raise ValueError("AMBIGUOUS_ALIAS_OR_ASSIGNMENT")
        env[name] = resolve_expr(value, env, pindex)
    if not found:
        raise ValueError("EFFECTIVE_IF_NOT_TOP_LEVEL_IN_TARGET_FUNCTION")
    return env, pindex


def resolve_surface(source: bytes, contract: Mapping[str, Any]) -> tuple[ast.FunctionDef | ast.AsyncFunctionDef, ast.Compare, ast.If, dict[str, tuple[int, tuple[tuple[str, str], ...]]], dict[str, int]]:
    try:
        tree = ast.parse(source.decode("utf-8"))
    except (UnicodeDecodeError, SyntaxError) as exc:
        raise ValueError("SOURCE_PARSE_FAILURE") from exc
    fspan = contract.get("target_function_span", []) or []
    gspan = (((contract.get("anchors", {}) or {}).get("guard", {}) or {}).get("span", []) or [])
    ifspan = contract.get("effective_if_span", []) or []
    fns = exact_nodes(tree, ast.FunctionDef, fspan) + exact_nodes(tree, ast.AsyncFunctionDef, fspan)
    guards = exact_nodes(tree, ast.Compare, gspan)
    ifs = exact_nodes(tree, ast.If, ifspan)
    if len(fns) != 1 or len(guards) != 1 or len(ifs) != 1:
        raise ValueError("EXACT_GUARD_OR_SCOPE_NOT_UNIQUE")
    fn, guard, target_if = fns[0], guards[0], ifs[0]
    if len(guard.ops) != 1 or len(guard.comparators) != 1:
        raise ValueError("GUARD_NOT_BINARY_COMPARE")
    ts, gs = node_span(target_if.test), node_span(guard)
    if not ((ts[0], ts[1]) <= (gs[0], gs[1]) and (gs[2], gs[3]) <= (ts[2], ts[3])):
        raise ValueError("GUARD_NOT_WITHIN_EFFECTIVE_IF_TEST")
    env, pindex = prefix_environment(fn, target_if)
    return fn, guard, target_if, env, pindex


def source_role_parameter(signature: Mapping[str, Any], role: str) -> int:
    row = (signature.get("source_roles", {}) or {}).get(role)
    if not isinstance(row, Mapping) or type(row.get("parameter_index")) is not int:
        raise ValueError(f"SOURCE_ROLE_PARAMETER_AUTHORITY_MISSING:{role}")
    return int(row["parameter_index"])


def required_binding_operand(signature: Mapping[str, Any], role: str) -> int:
    rows = []
    for row in signature.get("required_bindings", []) or []:
        if not isinstance(row, Mapping):
            continue
        if row.get("kind") != "guard_operand":
            continue
        allowed = row.get("allowed_origins", []) or []
        if list(map(str, allowed)) == [role]:
            rows.append(row)
    if len(rows) != 1 or type(rows[0].get("operand_index")) is not int:
        raise ValueError(f"TERMINAL_BINDING_AUTHORITY_UNRESOLVED:{role}")
    return int(rows[0]["operand_index"])


def observation_failure(case_id: str, role: str, taxonomy: str, reasons: Sequence[str], **extra: Any) -> dict[str, Any]:
    row = {"case_id": case_id, "role": role, "taxonomy": taxonomy, "reasons": sorted(set(map(str, reasons)))}
    row.update(extra)
    return row


def classify_role(*, case_id: str, role: str, guard: ast.Compare, env: Mapping[str, tuple[int, tuple[tuple[str, str], ...]]], pindex: Mapping[str, int], signature: Mapping[str, Any], canonical_row: Mapping[str, Any], protocol: Mapping[str, Any]) -> dict[str, Any]:
    fixed = protocol.get("candidate_role_authority", {}) or {}
    terminal_map = fixed.get("terminal_operand_indices", {}) or {}
    shapes = fixed.get("shape_precondition", {}) or {}
    expected_index = terminal_map.get(role)
    if type(expected_index) is not int:
        return observation_failure(case_id, role, "TERMINAL_OPERAND_INDEX_MISMATCH", ["PROTOCOL_TERMINAL_INDEX_MISSING"])
    try:
        binding_index = required_binding_operand(signature, role)
    except ValueError as exc:
        return observation_failure(case_id, role, "TERMINAL_OPERAND_INDEX_MISMATCH", [str(exc)])
    if binding_index != expected_index:
        return observation_failure(case_id, role, "TERMINAL_OPERAND_INDEX_MISMATCH", [f"SIGNATURE_INDEX:{binding_index}", f"PROTOCOL_INDEX:{expected_index}"])
    operands = [guard.left] + list(guard.comparators)
    if expected_index < 0 or expected_index >= len(operands):
        return observation_failure(case_id, role, "TERMINAL_OPERAND_INDEX_MISMATCH", ["TERMINAL_INDEX_OUT_OF_RANGE"])
    try:
        expected_root = source_role_parameter(signature, role)
    except ValueError as exc:
        return observation_failure(case_id, role, "ROOT_PARAMETER_ORIGIN_MISMATCH", [str(exc)])
    try:
        observed_root, observed_steps = resolve_expr(operands[expected_index], env, pindex)
    except ValueError as exc:
        reason = str(exc)
        if reason.startswith("PROJECTION_TOKEN_UNRESOLVED") or reason == "PROJECTION_STEP_UNSUPPORTED":
            return observation_failure(case_id, role, "PROJECTION_TOKEN_DIGEST_MISMATCH", [reason])
        return observation_failure(case_id, role, "ROOT_PARAMETER_ORIGIN_MISMATCH", [reason])
    if observed_root != expected_root:
        return observation_failure(case_id, role, "ROOT_PARAMETER_ORIGIN_MISMATCH", [f"OBSERVED_ROOT:{observed_root}", f"AUTHORIZED_ROOT:{expected_root}"], observed_root_parameter_index=observed_root, authorized_root_parameter_index=expected_root)
    steps = [{"kind": k, "token_digest_sha256": d} for k, d in observed_steps]
    candidate_shape = ["DERIVES" for _ in steps]
    required_shape = list(shapes.get("required_expected_shape", [])) if role.endswith("expected_coordinate") else list(shapes.get("required_current_shape", []))
    canonical_shape = list(canonical_row.get("shape", []) or [])
    if candidate_shape != required_shape or canonical_shape != required_shape:
        return observation_failure(case_id, role, "PROJECTION_SHAPE_MISMATCH", ["CANDIDATE_OR_CANONICAL_SHAPE_DIFFERS_FROM_FROZEN_SHAPE"], candidate_shape=candidate_shape, canonical_shape=canonical_shape, required_shape=required_shape)
    canonical_steps = list(canonical_row.get("steps", []) or [])
    if len(steps) != len(canonical_steps):
        return observation_failure(case_id, role, "PROJECTION_SHAPE_MISMATCH", ["STEP_CARDINALITY_MISMATCH"], candidate_shape=candidate_shape, canonical_shape=canonical_shape)
    candidate_kinds = [str(x.get("kind")) for x in steps]
    canonical_kinds = [str(x.get("kind")) for x in canonical_steps]
    if candidate_kinds != canonical_kinds:
        return observation_failure(case_id, role, "PROJECTION_STEP_KIND_MISMATCH", ["OPAQUE_STEP_KIND_SEQUENCE_DIFFERS"], candidate_step_kinds=candidate_kinds, canonical_step_kinds=canonical_kinds)
    candidate_tokens = [str(x.get("token_digest_sha256")) for x in steps]
    canonical_tokens = [str(x.get("token_digest_sha256")) for x in canonical_steps]
    if candidate_tokens != canonical_tokens:
        return observation_failure(case_id, role, "PROJECTION_TOKEN_DIGEST_MISMATCH", ["OPAQUE_TOKEN_DIGEST_SEQUENCE_DIFFERS"], candidate_token_digests=candidate_tokens, canonical_token_digests=canonical_tokens)
    payload = {"root_role": role, "terminal_guard_operand_index": expected_index, "steps": steps}
    fp = digest_json(payload)
    if fp != canonical_row.get("fingerprint_sha256"):
        return observation_failure(case_id, role, "FULL_FINGERPRINT_MISMATCH", ["RECOMPUTED_FULL_FINGERPRINT_DIFFERS"], candidate_fingerprint_sha256=fp, canonical_fingerprint_sha256=canonical_row.get("fingerprint_sha256"))
    return {"case_id": case_id, "role": role, "taxonomy": "CANONICAL_OPAQUE_PROJECTION_MATCH", "reasons": [], "authorized_root_parameter_index": expected_root, "terminal_guard_operand_index": expected_index, "shape": candidate_shape, "steps": steps, "candidate_fingerprint_sha256": fp, "canonical_fingerprint_sha256": canonical_row.get("fingerprint_sha256"), "raw_projection_tokens_emitted": False, "identifier_spelling_interpreted_as_semantic_role": False}


def diagnose_case(*, case_id: str, source: bytes, adapter: Mapping[str, Any], semantic_slice: Mapping[str, Any], canonical: Mapping[str, Any], protocol: Mapping[str, Any]) -> list[dict[str, Any]]:
    reasons = []
    expected_hashes = (protocol.get("population", {}) or {}).get("source_sha256_by_case", {}) or {}
    if sha_bytes(source) != expected_hashes.get(case_id):
        reasons.append("SOURCE_SHA256_MISMATCH")
    signature = adapter.get("execution_signature") if isinstance(adapter, Mapping) else None
    contract = semantic_slice.get("source_contract") if isinstance(semantic_slice, Mapping) else None
    if not isinstance(signature, Mapping):
        reasons.append("EXECUTION_SIGNATURE_MISSING")
    if not isinstance(contract, Mapping):
        reasons.append("SOURCE_CONTRACT_MISSING")
    try:
        crows = canonical_roles(canonical, protocol)
    except ValueError as exc:
        reasons.append(str(exc))
        crows = {}
    if reasons:
        return [observation_failure(case_id, role, "TRACE_INPUT_INTEGRITY_FAILURE", reasons) for role in ROLES]
    try:
        _, guard, _, env, pindex = resolve_surface(source, contract)
    except ValueError as exc:
        return [observation_failure(case_id, role, "GUARD_OR_SCOPE_RESOLUTION_FAILURE", [str(exc)]) for role in ROLES]
    return [classify_role(case_id=case_id, role=role, guard=guard, env=env, pindex=pindex, signature=signature, canonical_row=crows[role], protocol=protocol) for role in ROLES]


def run_real(*, protocol: Mapping[str, Any], canonical: Mapping[str, Any], sources_dir: Path, cases_dir: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    ids = validate_population(protocol)
    canonical_roles(canonical, protocol)
    observations = []
    for case_id in ids:
        source_path = sources_dir / f"{case_id}.py"
        case_dir = cases_dir / case_id
        if not source_path.is_file() or not (case_dir / "adapter_receipt.json").is_file() or not (case_dir / "semantic_slice.json").is_file():
            observations.extend([observation_failure(case_id, role, "TRACE_INPUT_INTEGRITY_FAILURE", ["SELECTED_INPUT_FILE_MISSING"]) for role in ROLES])
            continue
        observations.extend(diagnose_case(case_id=case_id, source=source_path.read_bytes(), adapter=read_json(case_dir / "adapter_receipt.json"), semantic_slice=read_json(case_dir / "semantic_slice.json"), canonical=canonical, protocol=protocol))
    if len(observations) != 14:
        raise ValueError("ROLE_OBSERVATION_COUNT_NOT_14")
    counts = {k: 0 for k in TAXONOMY}
    for row in observations:
        if row["taxonomy"] not in counts:
            raise ValueError("UNKNOWN_TAXONOMY")
        counts[row["taxonomy"]] += 1
    ledger = {"schema": LEDGER_SCHEMA, "case_count": 7, "role_observation_count": 14, "observations": observations}
    summary = {"schema": SUMMARY_SCHEMA, "case_count": 7, "role_observation_count": 14, "taxonomy_counts": counts, "taxonomy_case_roles": {k: [{"case_id": r["case_id"], "role": r["role"]} for r in observations if r["taxonomy"] == k] for k in TAXONOMY}, "canonical_match_count": counts["CANONICAL_OPAQUE_PROJECTION_MATCH"], "repair_hypothesis_authorized_by_gate2c6": counts["CANONICAL_OPAQUE_PROJECTION_MATCH"] == 14, "epistemic10_opened": False, "mutation_algebra_opened": False, "c1_rerun": False, "remediation": False, "truth_used": False}
    return ledger, summary


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--protocol", required=True)
    ap.add_argument("--canonical", required=True)
    ap.add_argument("--sources", required=True)
    ap.add_argument("--case-artifacts", required=True)
    ap.add_argument("--output", required=True)
    args = ap.parse_args()
    protocol = read_json(Path(args.protocol))
    canonical = read_json(Path(args.canonical))
    ledger, summary = run_real(protocol=protocol, canonical=canonical, sources_dir=Path(args.sources), cases_dir=Path(args.case_artifacts))
    out = Path(args.output); out.mkdir(parents=True, exist_ok=True)
    (out / "E2_GATE2C6_CANDIDATE_PROJECTION_MATCH_LEDGER.json").write_bytes(canonical_bytes(ledger))
    (out / "E2_GATE2C6_CANDIDATE_PROJECTION_MATCH_SUMMARY.json").write_bytes(canonical_bytes(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
