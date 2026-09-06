#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path
from typing import Any

SCHEMA = "risu.e2-a3-a4-candidate-observability-root-cause-independent-second-pass/v0.1"
PROTOCOL_SCHEMA = "risu.e2-a3-a4-candidate-observability-postfreeze-root-cause-adjudication-protocol/v0.1"
DOSSIER_SCHEMA = "risu.e2-a3-a4-candidate-observability-root-cause-evidence-dossier/v0.1"
DOSSIER_SHA256 = "76f2c895bf5a481e6fa7bf05d349a4e0bb5ac56cc6be2d81dd24a62bb8162da9"


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def canon(v: Any) -> bytes:
    return (json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def python_calls_inside_span(source: str, span: list[int]) -> list[str]:
    tree = ast.parse(source)
    sl, sc, el, ec = map(int, span)
    out: list[str] = []
    for n in ast.walk(tree):
        if not isinstance(n, ast.Call):
            continue
        nsp = (n.lineno, n.col_offset, n.end_lineno, n.end_col_offset)
        if (sl, sc) <= nsp[:2] and nsp[2:] <= (el, ec):
            if isinstance(n.func, ast.Name): out.append(n.func.id)
            elif isinstance(n.func, ast.Attribute): out.append(n.func.attr)
            else: out.append("<dynamic>")
    return sorted(out)


def line_prefix_before_span(source: str, span: list[int]) -> str:
    line = source.splitlines()[int(span[0]) - 1]
    return line[:int(span[1])]


def derive(row: dict[str, Any]) -> dict[str, Any]:
    lang = row["language"]
    loc = row["anchor_locator_evidence"]
    checks: dict[str, bool] = {}

    # Rule I1: JS/TS comparison returned from helper is absent before any downstream layer.
    if lang == "typescript_javascript" and loc["guard_comparison"]["match_count"] == 0:
        checks["source_contains_declared_comparison"] = "expected == current" in row["source"]
        checks["frontend_compare_fact_absent"] = row["frontend_fact_kind_counts"].get("COMPARE", 0) == 0
        checks["pipeline_stopped_at_unresolved_locator"] = row["pipeline_replay_status"] == "NOT_ATTEMPTED_LOCATOR_UNRESOLVED"
        if all(checks.values()):
            return {"primary_cause":"FRONTEND_OBSERVABILITY_GAP","mechanism":"JS_TS_RETURN_COMPARE_NOT_EMITTED","rule_id":"I1_RETURNED_COMPARE_ABSENT","checks":checks}

    # Rule I2: JS/TS CALL extraction admits a function-declaration pseudo-call before the real target call.
    eff = loc["effect_applied"]
    if lang == "typescript_javascript" and eff["locator"]["fact_kind"] == "CALL" and eff["match_count"] > 1:
        first = eff["matches"][0]
        checks["first_match_preceded_by_function_keyword"] = "function" in line_prefix_before_span(row["source"], first["span"])
        checks["first_match_is_not_target_scope"] = row.get("effect_control_context", {}).get("scope") != "target"
        role_nodes = row.get("effect_surface_span_evidence", {}).get("role_nodes", [])
        checks["target_role_nodes_disjoint_from_effect_anchor"] = bool(role_nodes) and all(x["relation_to_effect_anchor"] == "DISJOINT" for x in role_nodes)
        checks["effect_surface_missing"] = row.get("effect_surface_span_evidence", {}).get("path_surface_status", {}).get("status") == "MISSING"
        if all(checks.values()):
            return {"primary_cause":"FRONTEND_OBSERVABILITY_GAP","mechanism":"JS_TS_CALL_REGEX_FALSE_POSITIVE_ON_FUNCTION_DECLARATION","rule_id":"I2_DECLARATION_PSEUDOCALL","checks":checks}

    # Rule I3: a JS/TS frontend RETURN anchor is narrower than the already materialized structured representation statement.
    if lang == "typescript_javascript" and eff["locator"]["fact_kind"] == "RETURN" and row.get("effect_operation_role") == "representation_instance":
        role_nodes = row.get("effect_surface_span_evidence", {}).get("role_nodes", [])
        containing = [x for x in role_nodes if x["relation_to_effect_anchor"] == "OPERATION_CONTAINS_ANCHOR"]
        stmt = row.get("effect_control_context", {}).get("containing_statements", [])
        checks["effect_locator_resolved_once"] = eff["match_count"] == 1
        checks["representation_operation_contains_anchor"] = len(containing) == 1
        checks["effect_surface_missing"] = row.get("effect_surface_span_evidence", {}).get("path_surface_status", {}).get("status") == "MISSING"
        checks["structured_return_contains_anchor"] = len(stmt) == 1 and stmt[0]["kind"] == "RETURN" and stmt[0]["span"][-1] > eff["matches"][0]["span"][-1]
        checks["path_control_complete"] = row.get("path_evidence", {}).get("material_control_complete") is True
        checks["path_dataflow_complete"] = row.get("path_evidence", {}).get("path_dataflow_correlation") == "COMPLETE"
        if all(checks.values()):
            return {"primary_cause":"FRONTEND_OBSERVABILITY_GAP","mechanism":"JS_TS_RETURN_SPAN_NOT_COMPOSABLE_WITH_STRUCTURED_REPRESENTATION_SPAN","rule_id":"I3_RETURN_SPAN_COMPOSITION","checks":checks}

    # Rule I4: Python source contains multiple nested calls inside the effect RETURN, but frozen frontend evidence exposes one call.
    if lang == "python" and row["family_id"] == "CQ_EFFECT_SURFACE_AMBIGUOUS" and eff["match_count"] == 1:
        span = eff["matches"][0]["span"]
        source_calls = python_calls_inside_span(row["source"], span)
        role_nodes = row.get("effect_surface_span_evidence", {}).get("role_nodes", [])
        checks["source_has_multiple_calls_inside_effect_return"] = len(source_calls) >= 3
        checks["frontend_exposes_one_call_fact"] = row["frontend_fact_kind_counts"].get("CALL", 0) == 1
        checks["effect_surface_is_unique"] = row.get("effect_surface_span_evidence", {}).get("path_surface_status", {}).get("status") == "UNIQUE"
        checks["one_materialized_call_role"] = len(role_nodes) == 1
        checks["path_dataflow_complete"] = row.get("path_evidence", {}).get("path_dataflow_correlation") == "COMPLETE"
        if all(checks.values()):
            return {"primary_cause":"FRONTEND_OBSERVABILITY_GAP","mechanism":"PYTHON_RETURN_OUTER_CALL_SUPPRESSES_NESTED_CALL_VISIT","rule_id":"I4_NESTED_CALLS_SUPPRESSED","checks":checks,"source_calls_inside_effect_return":source_calls}

    return {"primary_cause":"UNKNOWN","mechanism":"UNRESOLVED_BY_INDEPENDENT_RULES","rule_id":"I0_UNKNOWN","checks":checks}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--protocol", required=True)
    ap.add_argument("--dossier", required=True)
    ap.add_argument("--output", required=True)
    args = ap.parse_args()
    protocol_raw = Path(args.protocol).read_bytes(); protocol = json.loads(protocol_raw)
    dossier_raw = Path(args.dossier).read_bytes(); dossier = json.loads(dossier_raw)
    if protocol.get("schema") != PROTOCOL_SCHEMA or protocol.get("status") != "POST_FREEZE_DIAGNOSIS_PROTOCOL_FROZEN": raise SystemExit("bad protocol")
    if dossier.get("schema") != DOSSIER_SCHEMA or dossier.get("category_labels_present") is not False or dossier.get("case_count") != 8: raise SystemExit("bad dossier")
    if sha(dossier_raw) != DOSSIER_SHA256: raise SystemExit("dossier sha mismatch")
    allowed = set(protocol["causal_taxonomy"])
    rows=[]
    for row in sorted(dossier["rows"], key=lambda x:x["fixture_id"]):
        result=derive(row)
        if result["primary_cause"] not in allowed: raise SystemExit("derived category outside frozen taxonomy")
        rows.append({"fixture_id":row["fixture_id"],"family_id":row["family_id"],"language":row["language"],**result})
    unresolved=[x["fixture_id"] for x in rows if x["primary_cause"]=="UNKNOWN"]
    out={
      "schema":SCHEMA,"status":"PASS" if not unresolved else "INCOMPLETE","semantic_authority":False,
      "case_count":8,"rows":rows,"unresolved_fixture_ids":unresolved,
      "category_counts":dict(sorted(__import__('collections').Counter(x['primary_cause'] for x in rows).items())),
      "mechanism_counts":dict(sorted(__import__('collections').Counter(x['mechanism'] for x in rows).items())),
      "independence_attestation":{
        "primary_adjudication_file_read":False,"primary_category_labels_read":False,"scientific_pipeline_reexecuted":False,
        "derivation_uses_category_free_dossier_only":True,"uses_stdlib_structural_rechecks":True,"remediation_design_read_or_emitted":False},
      "firewall":{k:False for k in ["candidate_58_bytes","sanitized_58_manifest","raw_blind_58_transport","mutation_truth","operator_metadata","expected_e2_predictions","fresh_target_bytes","scientific_implementation_changes","remediation_code_changes"]}
    }
    out["audit_digest_sha256"]=sha(canon(out))
    Path(args.output).write_bytes(canon(out))
    print(json.dumps({"status":out["status"],"cases":8,"unresolved":len(unresolved),"category_counts":out["category_counts"],"mechanism_counts":out["mechanism_counts"],"sha256":sha(Path(args.output).read_bytes())},sort_keys=True,separators=(",",":")))
    return 0 if not unresolved else 1

if __name__ == "__main__":
    raise SystemExit(main())
