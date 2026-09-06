#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
import shutil
import tempfile
import sys
from typing import Any, Dict, Iterable, List, Mapping, Sequence

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from risu_e2.acquisition import AcquisitionConfig, SUPPORTED_CODE, acquire
from risu_e2.ir import build_ir
from risu_e2.model import EDGE_KINDS, NODE_KINDS, canonical_bytes, validate_ir

CELLS = ROOT / "experiments" / "risu-diff-e2" / "qualification" / "materialized" / "cells"
SEEDS = ROOT / "experiments" / "risu-diff-e2" / "qualification" / "CANONICAL_SYNTHETIC_SEEDS.json"
DEV_UNIVERSE = ROOT / "protocols" / "RISU_DIFF_E2_DEVELOPMENT_UNIVERSE_v0.1.json"
GO_HELPER = ROOT / "tools" / "e2_go_ir_extract.go"

PRODUCTION_SURFACE = [
    ROOT / "risu_e2",
    ROOT / "tools" / "e2_acquire_ir.py",
    ROOT / "tools" / "e2_go_ir_extract.go",
]

def _repositories(value: Any) -> set[str]:
    out: set[str] = set()
    if isinstance(value, dict):
        for k, v in value.items():
            if k == "repository" and isinstance(v, str):
                out.add(v)
            else:
                out |= _repositories(v)
    elif isinstance(value, list):
        for x in value:
            out |= _repositories(x)
    return out

def _production_text() -> str:
    chunks = []
    for item in PRODUCTION_SURFACE:
        if item.is_dir():
            for p in sorted(item.glob("*.py")):
                chunks.append(p.read_text(encoding="utf-8"))
        else:
            chunks.append(item.read_text(encoding="utf-8"))
    return "\n".join(chunks)

def specialization_lexical_audit() -> Dict[str, Any]:
    repos = sorted(_repositories(json.loads(DEV_UNIVERSE.read_text(encoding="utf-8"))))
    text = _production_text().lower()
    hits = [r for r in repos if r.lower() in text]
    return {"status":"PASS" if not hits else "FAIL","repository_literals_scanned":len(repos),"hits":hits}

def graph_invariants(ir: Mapping[str, Any]) -> List[str]:
    errors: List[str] = []
    try:
        validate_ir(ir)
    except Exception as exc:
        errors.append(f"validate_ir:{type(exc).__name__}:{exc}")
        return errors
    nodes = {n["id"]: n for n in ir["nodes"]}
    evid_by_source = {e["source"] for e in ir["edges"] if e["kind"] == "EVIDENCED_BY"}
    for n in ir["nodes"]:
        if n["kind"] != "EVIDENCE" and n["id"] not in evid_by_source:
            errors.append(f"node_without_evidence:{n['id']}")
    file_sha = {x["path"]: x["sha256"] for x in ir["files"]}
    for n in ir["nodes"]:
        s = n["span"]
        if s["path"] not in file_sha:
            errors.append(f"node_span_unacquired:{n['id']}:{s['path']}")
        elif file_sha[s["path"]] != s["sha256"]:
            errors.append(f"node_span_sha_mismatch:{n['id']}")
    for e in ir["edges"]:
        s = e["span"]
        if s["path"] not in file_sha:
            errors.append(f"edge_span_unacquired:{e['id']}:{s['path']}")
        elif file_sha[s["path"]] != s["sha256"]:
            errors.append(f"edge_span_sha_mismatch:{e['id']}")
        if e["kind"] not in EDGE_KINDS:
            errors.append(f"bad_edge_kind:{e['kind']}")
    return errors

def run_once(case_root: Path, entrypoints: Sequence[str], cfg: AcquisitionConfig) -> Dict[str, Any]:
    acq, rows = acquire(case_root, entrypoints=entrypoints, config=cfg)
    ir, status = build_ir(rows, acquisition_doc=acq, go_helper_path=GO_HELPER)
    return {"acquisition":acq,"ir":ir,"status":status}

def deterministic_pair(case_root: Path, entrypoints: Sequence[str], cfg: AcquisitionConfig) -> tuple[Dict[str,Any], List[str]]:
    a = run_once(case_root, entrypoints, cfg)
    b = run_once(case_root, entrypoints, cfg)
    errors = []
    if canonical_bytes(a) != canonical_bytes(b):
        errors.append("NONDETERMINISTIC_REPLAY")
    errors.extend(graph_invariants(a["ir"]))
    return a, errors

def qualify_frozen_seeds() -> Dict[str, Any]:
    cat = json.loads(SEEDS.read_text(encoding="utf-8"))
    rows, errors = [], []
    for seed in cat["seeds"]:
        p = ROOT / seed["program_path"]
        case_root = p.parent
        result, errs = deterministic_pair(case_root, [p.name], AcquisitionConfig())
        relation_counts = {}
        for e in result["ir"]["edges"]:
            relation_counts[e["kind"]] = relation_counts.get(e["kind"], 0) + 1
        row = {
            "seed_id": seed["seed_id"],
            "status": result["status"]["status"],
            "ir_digest_sha256": result["ir"]["ir_digest_sha256"],
            "node_count": len(result["ir"]["nodes"]),
            "edge_count": len(result["ir"]["edges"]),
            "relation_counts": relation_counts,
            "errors": errs,
        }
        if row["status"] != "PASS":
            errors.append(f"{seed['seed_id']}:status:{row['status']}")
        for needed in ("DERIVES","CARRIES","BINDS_TO","COMPARES","EVIDENCED_BY"):
            if relation_counts.get(needed, 0) == 0:
                errors.append(f"{seed['seed_id']}:missing_relation:{needed}")
        errors.extend(f"{seed['seed_id']}:{x}" for x in errs)
        rows.append(row)
    return {"status":"PASS" if not errors else "FAIL","seed_count":len(rows),"rows":rows,"errors":errors}

def _code_files(cell: Path) -> List[Path]:
    return sorted(p for p in cell.iterdir() if p.is_file() and p.suffix.lower() in SUPPORTED_CODE)

def qualify_58_cells() -> Dict[str, Any]:
    rows, errors = [], []
    cells = sorted(p for p in CELLS.iterdir() if p.is_dir() and p.name.startswith("Q"))
    for cell in cells:
        meta = json.loads((cell/"CELL.json").read_text(encoding="utf-8"))
        code = _code_files(cell)
        if not code:
            errors.append(f"{cell.name}:NO_CODE_FILE")
            continue
        primary = next((p for p in code if p.name.startswith("SYN-")), code[0])
        budget = (meta.get("evidence_contract") or {}).get("acquisition_budget_files")
        cfg = AcquisitionConfig(max_files=int(budget)) if budget is not None else AcquisitionConfig()
        entrypoints = [primary.name]
        if meta.get("operator_id") == "A04_ACQUISITION_BUDGET_CEILING":
            entrypoints = [primary.name] + [p.name for p in code if p != primary]
        result, errs = deterministic_pair(cell, entrypoints, cfg)
        observed = result["status"]["status"]
        op = meta.get("operator_id")
        if op == "A01_MATERIAL_PARSE_FAILURE":
            expected_a1a2 = "INFRASTRUCTURE_INVALID_BEFORE_PREDICTION"
        elif op == "A04_ACQUISITION_BUDGET_CEILING":
            expected_a1a2 = "E2_PREDICTED_ASSURANCE_INCOMPLETE"
        else:
            expected_a1a2 = "PASS"
        if observed != expected_a1a2:
            errors.append(f"{cell.name}:{op}:expected_{expected_a1a2}:observed_{observed}")
        errors.extend(f"{cell.name}:{x}" for x in errs)
        rows.append({
            "cell_id":cell.name,"operator_id":op,"seed_id":meta.get("seed_id"),
            "expected_a1a2":expected_a1a2,"observed_a1a2":observed,
            "selected_file_count":result["acquisition"].get("selected_file_count",0),
            "ir_digest_sha256":result["ir"]["ir_digest_sha256"],
            "node_count":len(result["ir"]["nodes"]),"edge_count":len(result["ir"]["edges"]),
            "errors":errs,
        })
    return {"status":"PASS" if not errors and len(rows)==58 else "FAIL","cell_count":len(rows),"rows":rows,"errors":errors}

def qualify_acquisition_microcases() -> Dict[str, Any]:
    errors, rows = [], []
    with tempfile.TemporaryDirectory(prefix="e2-a1a2-") as td:
        base=Path(td)
        cases = {
            "python_import": {
                "files":{"main.py":"from helper import build\n\ndef run(x): return build(x)\n","helper.py":"def build(x): return {'guard': x}\n"},
                "entry":["main.py"],"expect":"PASS","selected":2,
            },
            "go_unique_callee": {
                "files":{"main.go":"package main\nfunc run(x int) int { return helper(x) }\n","helper.go":"package main\nfunc helper(x int) int { return x }\n"},
                "entry":["main.go"],"expect":"PASS","selected":2,
            },
            "js_relative_import": {
                "files":{"main.mjs":"import { build } from './helper.mjs';\nfunction run(x){ return build(x); }\n","helper.mjs":"export function build(x){ return { guard: x }; }\n"},
                "entry":["main.mjs"],"expect":"PASS","selected":2,
            },
            "ts_structural": {
                "files":{"main.ts":"type Req={guard:string};\nfunction build(x: string): Req { return {guard:x}; }\nfunction run(cur:string, x:string){ const r:Req=build(x); if(r.guard!==cur){return false;} return true; }\n"},
                "entry":["main.ts"],"expect":"PASS","selected":1,
            },
            "unsupported_material": {
                "files":{"main.rs":"fn main() {}\n"},"entry":["main.rs"],"expect":"E2_PREDICTED_ASSURANCE_INCOMPLETE","selected":0,
            },
            "parse_failure": {
                "files":{"main.py":"def broken(:\n  pass\n"},"entry":["main.py"],"expect":"INFRASTRUCTURE_INVALID_BEFORE_PREDICTION","selected":1,
            },
        }
        for name,spec in cases.items():
            case=base/name; case.mkdir()
            for rel,content in spec["files"].items():
                (case/rel).write_text(content,encoding="utf-8")
            result, errs=deterministic_pair(case,spec["entry"],AcquisitionConfig())
            observed=result["status"]["status"]
            selected=result["acquisition"].get("selected_file_count",0)
            if observed!=spec["expect"]: errors.append(f"{name}:status:{observed}")
            if selected!=spec["selected"]: errors.append(f"{name}:selected:{selected}")
            errors.extend(f"{name}:{x}" for x in errs)
            rows.append({"case":name,"status":observed,"selected_file_count":selected,"errors":errs})
        # explicit budget ceiling across two required entrypoints
        case=base/"budget"; case.mkdir()
        (case/"a.go").write_text("package main\nfunc a() int { return b() }\n",encoding="utf-8")
        (case/"b.go").write_text("package main\nfunc b() int { return 1 }\n",encoding="utf-8")
        result,errs=deterministic_pair(case,["a.go","b.go"],AcquisitionConfig(max_files=1))
        if result["status"]["status"]!="E2_PREDICTED_ASSURANCE_INCOMPLETE":
            errors.append("budget:not_incomplete")
        if result["acquisition"].get("reason")!="ACQUISITION_BUDGET_EXHAUSTED":
            errors.append(f"budget:reason:{result['acquisition'].get('reason')}")
        errors.extend(f"budget:{x}" for x in errs)
        rows.append({"case":"budget","status":result["status"]["status"],"selected_file_count":result["acquisition"].get("selected_file_count"),"errors":errs})
    return {"status":"PASS" if not errors else "FAIL","rows":rows,"errors":errors}

def main() -> int:
    out = {
        "schema":"risu.e2-a1-a2-qualification/v0.1",
        "semantic_authority":False,
        "specialization_lexical_audit":specialization_lexical_audit(),
        "frozen_seed_qualification":qualify_frozen_seeds(),
        "mutation_cell_structural_qualification":qualify_58_cells(),
        "acquisition_microcases":qualify_acquisition_microcases(),
    }
    failures = [k for k,v in out.items() if isinstance(v,dict) and v.get("status")=="FAIL"]
    out["status"] = "PASS" if not failures else "FAIL"
    out["failed_sections"] = failures
    print(json.dumps(out,sort_keys=True,separators=(",",":"),ensure_ascii=False))
    return 0 if out["status"]=="PASS" else 1

if __name__=="__main__":
    raise SystemExit(main())
