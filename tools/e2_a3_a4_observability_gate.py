#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
import sys
from typing import Any, Dict, List, Mapping, Sequence

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from risu_e2.acquisition import AcquisitionConfig, SUPPORTED_CODE, acquire
from risu_e2.ir import build_ir
from risu_e2.model import validate_ir

CELLS = ROOT / "experiments" / "risu-diff-e2" / "qualification" / "materialized" / "cells"
GO_HELPER = ROOT / "tools" / "e2_go_ir_extract.go"

DATAFLOW = {"DERIVES", "CARRIES", "BINDS_TO"}
CONTROL = {"GUARDS"}
ORDER = {"PRECEDES"}
EFFECT_REL = {"MUTATES"}
OUTCOME_REL = {"REJECTS_AS"}


def _code_files(cell: Path) -> List[Path]:
    return sorted(p for p in cell.iterdir() if p.is_file() and p.suffix.lower() in SUPPORTED_CODE)


def _cell_ir(cell: Path) -> tuple[Dict[str, Any], Dict[str, Any]]:
    meta = json.loads((cell / "CELL.json").read_text(encoding="utf-8"))
    code = _code_files(cell)
    if not code:
        return {}, {"status": "INFRASTRUCTURE_INVALID_BEFORE_PREDICTION", "reason": "NO_CODE_FILE"}
    primary = next((p for p in code if p.name.startswith("SYN-")), code[0])
    budget = (meta.get("evidence_contract") or {}).get("acquisition_budget_files")
    cfg = AcquisitionConfig(max_files=int(budget)) if budget is not None else AcquisitionConfig()

    # Truth-independent acquisition: when a declared budget is smaller than the material
    # code surface, all material code files are requested so the budget ceiling is observable.
    if budget is not None and len(code) > int(budget):
        entrypoints: Sequence[str] = [p.name for p in code]
    else:
        entrypoints = [primary.name]

    acq, rows = acquire(cell, entrypoints=entrypoints, config=cfg)
    ir, status = build_ir(rows, acquisition_doc=acq, go_helper_path=GO_HELPER)
    return ir, status


def _count_kinds(rows: Sequence[Mapping[str, Any]]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for row in rows:
        k = str(row.get("kind"))
        out[k] = out.get(k, 0) + 1
    return dict(sorted(out.items()))


def _multi_definition_coordinates(ir: Mapping[str, Any]) -> List[Dict[str, Any]]:
    nodes = {n["id"]: n for n in ir.get("nodes", [])}
    incoming: Dict[str, List[Mapping[str, Any]]] = {}
    for e in ir.get("edges", []):
        if e.get("kind") != "DERIVES":
            continue
        target = str(e.get("target"))
        if nodes.get(target, {}).get("kind") not in {"SEMANTIC_COORDINATE", "INPUT"}:
            continue
        incoming.setdefault(target, []).append(e)

    out: List[Dict[str, Any]] = []
    for nid, edges in sorted(incoming.items()):
        definition_sites = sorted({
            (e["span"]["path"], e["span"]["start_line"], e["span"]["start_col"], e["span"]["end_line"], e["span"]["end_col"])
            for e in edges
        })
        if len(definition_sites) > 1:
            n = nodes[nid]
            out.append({
                "node_id": nid,
                "label": n.get("label"),
                "symbol_key": (n.get("attrs") or {}).get("symbol_key"),
                "distinct_definition_sites": len(definition_sites),
            })
    return out


def inspect_ir(ir: Mapping[str, Any]) -> Dict[str, Any]:
    validate_ir(ir)
    node_counts = _count_kinds(ir.get("nodes", []))
    edge_counts = _count_kinds(ir.get("edges", []))
    multi_defs = _multi_definition_coordinates(ir)

    dataflow_surface = sum(edge_counts.get(k, 0) for k in DATAFLOW) > 0
    explicit_resource_surface = node_counts.get("RESOURCE", 0) > 0
    explicit_effect_surface = node_counts.get("EFFECT", 0) > 0 or sum(edge_counts.get(k, 0) for k in EFFECT_REL) > 0
    explicit_control_surface = sum(edge_counts.get(k, 0) for k in CONTROL) > 0
    explicit_order_surface = sum(edge_counts.get(k, 0) for k in ORDER) > 0
    explicit_outcome_surface = (
        node_counts.get("OUTCOME", 0) > 0
        or node_counts.get("FAILURE", 0) > 0
        or sum(edge_counts.get(k, 0) for k in OUTCOME_REL) > 0
    )

    # This gate deliberately does not infer semantics from labels, comments, operator ids,
    # target names, or source line order. It reports whether the IR itself exposes enough.
    a3 = {
        "dataflow_surface": dataflow_surface,
        "explicit_resource_surface": explicit_resource_surface,
        "multi_definition_coordinate_count": len(multi_defs),
        "multi_definition_coalescing_observed": bool(multi_defs),
        "status": (
            "BLOCKED_BY_MULTI_DEFINITION_COALESCING"
            if multi_defs
            else "NO_OVERWRITE_COALESCING_BLOCKER_OBSERVED_IN_THIS_CELL"
        ),
    }
    a4 = {
        "explicit_effect_surface": explicit_effect_surface,
        "explicit_control_surface": explicit_control_surface,
        "explicit_order_surface": explicit_order_surface,
        "explicit_outcome_surface": explicit_outcome_surface,
        "status": "SUFFICIENT_CANDIDATE" if explicit_effect_surface and explicit_control_surface and explicit_order_surface else "INSUFFICIENT_FOR_DEFINITIVE_A4",
    }
    return {
        "node_kind_counts": node_counts,
        "edge_kind_counts": edge_counts,
        "multi_definition_coordinates": multi_defs,
        "A3": a3,
        "A4": a4,
    }


def main() -> int:
    rows: List[Dict[str, Any]] = []
    pass_rows = 0
    a3_coalescing_cells = 0
    a4_sufficient = 0

    for cell in sorted(p for p in CELLS.iterdir() if p.is_dir() and p.name.startswith("Q")):
        ir, status = _cell_ir(cell)
        row: Dict[str, Any] = {
            "cell_id": cell.name,
            "a1_a2_status": status.get("status"),
            "a1_a2_reason": status.get("reason"),
        }
        if status.get("status") == "PASS":
            pass_rows += 1
            obs = inspect_ir(ir)
            row["ir_digest_sha256"] = ir.get("ir_digest_sha256")
            row["observability"] = obs
            if obs["A3"]["multi_definition_coalescing_observed"]:
                a3_coalescing_cells += 1
            if obs["A4"]["status"] == "SUFFICIENT_CANDIDATE":
                a4_sufficient += 1
        rows.append(row)

    out = {
        "schema": "risu.diff-e2-a3-a4-observability-audit/v0.1",
        "semantic_authority": False,
        "truth_labels_consumed": False,
        "mutation_operator_names_consumed_as_features": False,
        "cell_count": len(rows),
        "a1_a2_pass_cell_count": pass_rows,
        "a3_multi_definition_coalescing_cell_count": a3_coalescing_cells,
        "a4_sufficient_candidate_count": a4_sufficient,
        "rows": rows,
    }
    out["decision"] = (
        "A3_A4_MAY_PROCEED_ON_FROZEN_A2"
        if pass_rows > 0 and a3_coalescing_cells == 0 and a4_sufficient == pass_rows
        else "DO_NOT_IMPLEMENT_DEFINITIVE_A3_A4_ON_FROZEN_A2_V0_1"
    )
    out["recommended_next"] = (
        "IMPLEMENT_A3_A4_MUST_ANALYSIS"
        if out["decision"] == "A3_A4_MAY_PROCEED_ON_FROZEN_A2"
        else "PRESERVE_V0_1_AND_DESIGN_MINIMAL_VERSIONED_OBSERVABILITY_EXTENSION"
    )
    print(json.dumps(out, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
    # Audit completion is success even when the scientific decision is to block promotion.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
