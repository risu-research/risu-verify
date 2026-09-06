#!/usr/bin/env python3
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import tempfile
from pathlib import Path
from typing import Any, Mapping

from risu_e2.acquisition import AcquisitionConfig, acquire
from risu_e2.ir import build_ir
from risu_e2.model import canonical_bytes
from risu_e2.observability_overlay import build_overlay, validate_overlay
from risu_e2.path_observability import build_path_observability
from risu_e2.overlay_control import _control_functions, _function_for_span
from e2_a3_a4_candidate_observability_microqualify import (
    frontend, make_contract, make_signature, source_slice, span_tuple,
)

SCHEMA = "risu.e2-a3-a4-candidate-observability-root-cause-evidence-dossier/v0.1"
DIAG_SCHEMA = "risu.e2-a3-a4-candidate-observability-postfreeze-root-cause-adjudication-protocol/v0.1"


def canon(v: Any) -> bytes:
    return canonical_bytes(v)


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def contains(a: tuple[int, int, int, int], b: tuple[int, int, int, int]) -> bool:
    return (a[0], a[1]) <= (b[0], b[1]) and (b[2], b[3]) <= (a[2], a[3])


def overlaps(a: tuple[int, int, int, int], b: tuple[int, int, int, int]) -> bool:
    return not ((a[2], a[3]) < (b[0], b[1]) or (b[2], b[3]) < (a[0], a[1]))


def node_span(n: Mapping[str, Any]) -> tuple[int, int, int, int]:
    s = n["span"]
    return int(s["start_line"]), int(s["start_col"]), int(s["end_line"]), int(s["end_col"])


def locator_matches(facts: list[Mapping[str, Any]], source: str, locator: Mapping[str, Any]) -> list[dict[str, Any]]:
    out = []
    needle = str(locator["source_contains"])
    for fact in facts:
        if fact.get("kind") != locator["fact_kind"]:
            continue
        sp = span_tuple(fact)
        raw = source_slice(source, sp).decode("utf-8")
        if needle in raw:
            out.append({
                "kind": fact.get("kind"),
                "span": list(sp),
                "slice": raw,
                "fact": {k: v for k, v in fact.items() if k not in {"span", "scope"}},
                "scope": fact.get("scope"),
            })
    out.sort(key=lambda r: (r["span"], json.dumps(r, sort_keys=True, separators=(",", ":"))))
    return out


def reverse_origins(overlay: Mapping[str, Any], start: str) -> list[dict[str, Any]]:
    nodes = {n["id"]: n for n in overlay["nodes"]}
    incoming: dict[str, list[Mapping[str, Any]]] = {}
    for e in overlay["edges"]:
        incoming.setdefault(e["target"], []).append(e)
    seen: set[str] = set()
    stack = [start]
    out: dict[str, dict[str, Any]] = {}
    while stack:
        cur = stack.pop()
        if cur in seen:
            continue
        seen.add(cur)
        n = nodes.get(cur, {})
        if n.get("attrs", {}).get("definition_site_key"):
            out[cur] = {
                "id": cur,
                "kind": n.get("kind"),
                "label": n.get("label"),
                "span": list(node_span(n)),
                "definition_role": n.get("attrs", {}).get("definition_role"),
                "scope": n.get("attrs", {}).get("scope"),
                "parameter_index": n.get("attrs", {}).get("parameter_index"),
            }
        for e in incoming.get(cur, []):
            if e["kind"] in {"DERIVES", "BINDS_TO"}:
                stack.append(e["source"])
    return [out[k] for k in sorted(out)]


def relation(anchor: tuple[int, int, int, int], op: tuple[int, int, int, int]) -> str:
    if anchor == op:
        return "EXACT_SPAN"
    if contains(anchor, op):
        return "ANCHOR_CONTAINS_OPERATION"
    if contains(op, anchor):
        return "OPERATION_CONTAINS_ANCHOR"
    if overlaps(anchor, op):
        return "PARTIAL_OVERLAP"
    return "DISJOINT"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--diagnosis-protocol", required=True)
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--frozen-primary", required=True)
    ap.add_argument("--go-helper", required=True)
    ap.add_argument("--output", required=True)
    args = ap.parse_args()

    diag_raw = Path(args.diagnosis_protocol).read_bytes(); diag = json.loads(diag_raw)
    corpus_raw = Path(args.corpus).read_bytes(); corpus = json.loads(corpus_raw)
    primary_raw = Path(args.frozen_primary).read_bytes(); primary = json.loads(primary_raw)
    if diag.get("schema") != DIAG_SCHEMA or diag.get("status") != "POST_FREEZE_DIAGNOSIS_PROTOCOL_FROZEN":
        raise SystemExit("diagnosis protocol not frozen")
    frozen_ids = list(diag["frozen_failure_ids"])
    if sorted(primary.get("failed_fixture_ids", [])) != sorted(frozen_ids):
        raise SystemExit("frozen failure set mismatch")
    fixtures = {x["fixture_id"]: x for x in corpus["fixtures"]}
    primary_rows = {x["fixture_id"]: x for x in primary["rows"]}
    if any(fid not in fixtures or fid not in primary_rows for fid in frozen_ids):
        raise SystemExit("missing frozen failure fixture or row")

    rows = []
    for fid in sorted(frozen_ids):
        fx = fixtures[fid]; prow = primary_rows[fid]
        source = str(fx["source"]); raw = source.encode("utf-8")
        parsed = frontend(str(fx["language"]), str(fx["filename"]), raw, Path(args.go_helper))
        facts = list(parsed.get("facts", []))
        locators = {}
        for name, loc in sorted(fx["anchor_locators"].items()):
            matches = locator_matches(facts, source, loc)
            locators[name] = {"locator": loc, "match_count": len(matches), "matches": matches}

        row: dict[str, Any] = {
            "fixture_id": fid,
            "family_id": fx["family_id"],
            "language": fx["language"],
            "source_sha256": sha(raw),
            "source": source,
            "expected_observation": fx["expected_observation"],
            "frozen_observed_observation": prow["observed_observation"],
            "frozen_infrastructure_status": prow["infrastructure_status"],
            "frozen_diagnostics": prow.get("diagnostics", []),
            "frozen_diagnostic_type": prow.get("diagnostic_type"),
            "frozen_diagnostic_message": prow.get("diagnostic_message"),
            "frontend_status": parsed.get("status"),
            "frontend_parser": parsed.get("parser"),
            "frontend_fact_kind_counts": dict(sorted(collections.Counter(str(f.get("kind")) for f in facts).items())),
            "anchor_locator_evidence": locators,
            "effect_operation_role": fx["effect_operation_role"],
            "pipeline_replay_status": "NOT_ATTEMPTED_LOCATOR_UNRESOLVED",
        }
        if any(v["match_count"] == 0 for v in locators.values()):
            rows.append(row)
            continue

        contract, contract_sha = make_contract(fx, facts, source, sha(raw))
        signature = make_signature(fx)
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / str(fx["filename"]); p.write_bytes(raw)
            acq, acquired = acquire(Path(td), entrypoints=[p.name], config=AcquisitionConfig())
            base_ir, base_status = build_ir(acquired, acquisition_doc=acq, go_helper_path=Path(args.go_helper))
        if base_status.get("status") != "PASS":
            row["pipeline_replay_status"] = "BASE_IR_INVALID"
            row["base_ir_status"] = base_status
            rows.append(row)
            continue
        overlay = build_overlay(path=str(fx["filename"]), source=source, source_sha256=sha(raw), language=str(fx["language"]), facts=facts, base_ir=base_ir, anchor_contract=contract, anchor_contract_sha256=contract_sha)
        validate_overlay(overlay)
        pathdoc = build_path_observability(path=str(fx["filename"]), source=source, source_sha256=sha(raw), language=str(fx["language"]), facts=facts, overlay=overlay, canonical_signature=signature)
        row["pipeline_replay_status"] = "REPLAYED_EXACT_FROZEN_PIPELINE"
        row["digest_reproduction"] = {
            "base_ir_matches_frozen": base_ir.get("ir_digest_sha256") == prow.get("base_ir_digest_sha256"),
            "overlay_matches_frozen": overlay.get("overlay_digest_sha256") == prow.get("overlay_digest_sha256"),
            "path_matches_frozen": pathdoc.get("path_observability_digest_sha256") == prow.get("path_observability_digest_sha256"),
            "base_ir_digest_sha256": base_ir.get("ir_digest_sha256"),
            "overlay_digest_sha256": overlay.get("overlay_digest_sha256"),
            "path_observability_digest_sha256": pathdoc.get("path_observability_digest_sha256"),
        }
        nodes = {n["id"]: n for n in overlay["nodes"]}
        effect_nodes = [n for n in overlay["nodes"] if n.get("attrs", {}).get("anchor_role") == "EFFECT_BOUNDARY"]
        if len(effect_nodes) != 1:
            raise SystemExit(fid + ": expected exactly one effect anchor node")
        effect_anchor = effect_nodes[0]; esp = node_span(effect_anchor)
        role_nodes = [n for n in overlay["nodes"] if n.get("attrs", {}).get("operation_role") == fx["effect_operation_role"]]
        row["effect_surface_span_evidence"] = {
            "effect_anchor_id": effect_anchor["id"],
            "effect_anchor_span": list(esp),
            "effect_anchor_slice": source_slice(source, esp).decode("utf-8"),
            "declared_operation_role": fx["effect_operation_role"],
            "role_nodes": [
                {"id": n["id"], "label": n["label"], "span": list(node_span(n)), "relation_to_effect_anchor": relation(esp, node_span(n)), "attrs": {k: v for k, v in n.get("attrs", {}).items() if k in {"operation_role", "representation_instance_id", "scope", "callee"}}}
                for n in sorted(role_nodes, key=lambda n: (node_span(n), n["id"]))
            ],
            "path_surface_status": pathdoc["effect_binding_surface"],
        }
        rep_fields = [n for n in overlay["nodes"] if n.get("attrs", {}).get("definition_role") == "representation_field_write"]
        row["representation_evidence"] = {
            "field_writes": [
                {"id": n["id"], "field": n.get("attrs", {}).get("field"), "span": list(node_span(n)), "representation_instance_id": n.get("attrs", {}).get("representation_instance_id"), "label": n.get("label")}
                for n in sorted(rep_fields, key=lambda n: (node_span(n), n["id"]))
            ],
            "guard_field_write_count": sum(1 for n in rep_fields if str(n.get("attrs", {}).get("field", "")).lower() == "guard"),
            "representation_closure_status": pathdoc.get("representation_closure_status"),
        }
        slot_evidence = {}
        for sname, srow in sorted(overlay.get("binding_slots", {}).items()):
            vals = list(srow.get("value_instance_ids", []))
            slot_evidence[sname] = {
                "value_instance_ids": vals,
                "origins": {v: reverse_origins(overlay, v) for v in vals},
            }
        row["binding_slot_evidence"] = slot_evidence
        row["path_evidence"] = {
            "effective_guard_observability": pathdoc["effective_guard_observability"],
            "material_control_complete": pathdoc["material_control_complete"],
            "control_scope_completeness": pathdoc["control_scope_completeness"],
            "path_dataflow_correlation": pathdoc["path_dataflow_correlation"],
            "entry_effect_paths": pathdoc["entry_effect_paths"],
            "rejection_paths": pathdoc["rejection_paths"],
            "success_paths": pathdoc["success_paths"],
            "terminal_reaching_facts": pathdoc["terminal_reaching_facts"],
        }
        controls = _control_functions(source, str(fx["language"]), [f for f in facts if f.get("kind") == "FUNCTION"])
        scope = _function_for_span(controls, esp)
        stmt_rows = []
        if scope:
            def walk(stmts):
                for st in stmts:
                    if contains(st.span, esp):
                        stmt_rows.append({"kind": st.kind, "span": list(st.span), "condition_span": list(st.condition_span) if st.condition_span else None})
                    if st.then_body: walk(st.then_body)
                    if st.else_body: walk(st.else_body)
            walk(controls[scope]["stmts"])
        row["effect_control_context"] = {"scope": scope, "containing_statements": stmt_rows}
        rows.append(row)

    dossier = {
        "schema": SCHEMA,
        "semantic_authority": False,
        "status": "PASS",
        "diagnosis_protocol_sha256": sha(diag_raw),
        "frozen_primary_sha256": sha(primary_raw),
        "corpus_sha256": sha(corpus_raw),
        "case_count": len(rows),
        "failure_ids": sorted(frozen_ids),
        "rows": rows,
        "category_labels_present": False,
        "read_set_attestation": {
            "frozen_48_microfixture_corpus": True,
            "frozen_failed_primary_matrix": True,
            "exact_frozen_frontend_ir_overlay_path_implementation": True,
            "candidate_58_bytes": False,
            "sanitized_58_manifest": False,
            "raw_blind_58_transport": False,
            "mutation_truth": False,
            "operator_metadata": False,
            "expected_e2_predictions": False,
            "fresh_target_bytes": False,
        },
        "claim_boundary": {
            "diagnosis_only": True,
            "scientific_implementation_changed": False,
            "remediation_design_emitted": False,
            "a3_a4_verdicts_emitted": False,
        },
    }
    dossier["dossier_digest_sha256"] = sha(canon(dossier))
    Path(args.output).write_bytes(canon(dossier))
    print(json.dumps({"status":"PASS","cases":len(rows),"unresolved_locators":sum(1 for r in rows if r["pipeline_replay_status"]=="NOT_ATTEMPTED_LOCATOR_UNRESOLVED"),"sha256":sha(Path(args.output).read_bytes())},sort_keys=True,separators=(",",":")))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
