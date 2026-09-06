#!/usr/bin/env python3
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping, Sequence

from risu_e2.acquisition import AcquiredFile
from risu_e2.frontend_go import extract_many as go_extract
from risu_e2.frontend_js_v3 import extract as js_extract
from risu_e2.frontend_python_v2 import extract as py_extract
from risu_e2.ir_v3 import build_ir as build_v3_ir
from risu_e2.model import canonical_bytes
from risu_e2.observability_overlay import build_overlay, validate_overlay
from risu_e2.path_observability import build_path_observability

OUTPUT_SCHEMA = "risu.e2-a3-a4-frozen48-requalification-independent/v0.1"
PREFLIGHT_SCHEMA = "risu.e2-a3-a4-frozen48-adapter-preflight-independent/v0.1"
LANGS = ("go", "python", "typescript_javascript")
PROJECTION_KEYS = [
    "cell_id", "qualification_status", "sorted_reasons", "base_ir_status",
    "overlay_status", "path_observability_status", "anchor_usability",
    "effective_guard_form", "control_scope_completeness",
    "path_dataflow_correlation", "effect_surface_status",
    "ordering_outcome_observability", "representation_closure_status",
    "witness_precondition_observability",
]


def h256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_doc(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = path.read_bytes()
    obj = json.loads(raw.decode("utf-8"))
    if not isinstance(obj, dict):
        raise ValueError("JSON root must be object")
    return obj, raw


def ext_for(language: str) -> str:
    table = {"go": ".go", "python": ".py", "typescript_javascript": ".mjs"}
    if language not in table:
        raise ValueError("unsupported language")
    return table[language]


def parse_surface(language: str, logical_path: str, raw: bytes, helper: Path) -> dict[str, Any]:
    if language == "go":
        return go_extract([{"path": logical_path, "data": raw}], helper)[logical_path]
    text = raw.decode("utf-8")
    if language == "python":
        return py_extract(text)
    if language == "typescript_javascript":
        return js_extract(text)
    raise ValueError("unsupported language")


def make_ir(logical_path: str, language: str, raw: bytes, helper: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    digest = h256(raw)
    material = AcquiredFile(
        path=logical_path, language=language, sha256=digest, data=raw,
        selection_round=0, selection_reasons=("FROZEN48_INDEPENDENT_EXACT_INPUT",),
    )
    acquisition = {
        "status": "PASS",
        "reason": "FROZEN48_INDEPENDENT_BOUND_SINGLE_FILE",
        "semantic_authority": False,
        "selected_file_count": 1,
        "selected_total_bytes": len(raw),
    }
    return build_v3_ir([material], acquisition_doc=acquisition, go_helper_path=helper)


def extract_span_bytes(text: str, span: Sequence[int]) -> bytes:
    if len(span) != 4:
        raise ValueError("bad span arity")
    sl, sc, el, ec = [int(x) for x in span]
    lines = text.splitlines(keepends=True)
    if sl < 1 or el < sl or el > len(lines):
        raise ValueError("bad span bounds")
    if sl == el:
        return lines[sl - 1].encode()[sc:ec]
    pieces = [lines[sl - 1].encode()[sc:]]
    pieces.extend(line.encode() for line in lines[sl:el - 1])
    pieces.append(lines[el - 1].encode()[:ec])
    return b"".join(pieces)


def bind_transported_contract(seed_contract: Mapping[str, Any], receipt: Mapping[str, Any], logical_path: str, text: str, language: str) -> tuple[dict[str, Any], str]:
    declaration = copy.deepcopy(seed_contract["declaration"])
    receipt_anchors: dict[str, Mapping[str, Any]] = {}
    for item in receipt["anchors"]:
        key = str(item["anchor_key"])
        if key in receipt_anchors:
            raise ValueError("duplicate transported anchor")
        receipt_anchors[key] = item
    declaration["source"] = {
        "git_blob_sha": "OPAQUE_RUNTIME_SOURCE",
        "language": language,
        "path": logical_path,
        "sha256": receipt["candidate_source_sha256"],
    }
    for key in sorted(declaration["anchors"]):
        target = declaration["anchors"][key]
        observed = receipt_anchors.get(key)
        if observed is None or observed.get("realization_status") != "ROLE_COMPATIBLE":
            raise ValueError("transported anchor not role-compatible")
        span = observed.get("candidate_span")
        if not isinstance(span, list) or len(span) != 4:
            raise ValueError("transported anchor span missing")
        target["span"] = [int(x) for x in span]
        target["slice_sha256"] = str(observed["candidate_slice_sha256"])
        actual = extract_span_bytes(text, target["span"])
        if h256(actual) != target["slice_sha256"]:
            raise ValueError("transported slice digest mismatch")
        target["slice_bytes"] = len(actual)
        target["unique_in_source"] = True
    for slot in ("current_coordinate", "expected_coordinate"):
        observed = receipt["binding_slots"][slot]
        declared = declaration["binding_slots"][slot]
        if observed.get("status") != "AVAILABLE" or int(observed["operand_index"]) != int(declared["operand_index"]):
            raise ValueError("binding-slot transport mismatch")
    declaration["transport"] = {
        "mutant_revision_authorized": True,
        "fresh_revision_authorized": False,
        "projection_authority": "SELECTED_48_FROZEN_TRANSPORT_RECEIPT",
    }
    declaration["verdict_authority"] = False
    return declaration, h256(canonical_bytes(declaration))


def independent_admission(pathdoc: Mapping[str, Any]) -> tuple[str, list[str]]:
    failures: set[str] = set()
    if pathdoc["material_control_complete"] is not True:
        failures.add("CONTROL_INCOMPLETE")
    form = pathdoc["effective_guard_observability"]["form"]
    if form not in ("DIRECT_CONTROL", "HELPER_CONTROL"):
        failures.add(str(pathdoc["effective_guard_observability"].get("reason") or "EFFECTIVE_GUARD_UNPROVEN"))
    if pathdoc["path_dataflow_correlation"] != "COMPLETE":
        failures.add("PATH_DATAFLOW_CORRELATION_UNPROVEN")
    if pathdoc["effect_binding_surface"]["status"] != "UNIQUE":
        failures.add("EFFECT_INVOCATION_UNRESOLVED")
    reasons = sorted(failures)
    return ("OBSERVABILITY_INCOMPLETE" if reasons else "OBSERVABILITY_QUALIFIED_FOR_A3_A4_EXECUTION", reasons)


def independent_witness_surface(pathdoc: Mapping[str, Any]) -> dict[str, Any]:
    path_ok = pathdoc["path_dataflow_correlation"] == "COMPLETE" and pathdoc["material_control_complete"] is True
    guard_ok = pathdoc["effective_guard_observability"]["form"] in ("DIRECT_CONTROL", "HELPER_CONTROL")
    effect_ok = pathdoc["effect_binding_surface"]["status"] == "UNIQUE"
    return {
        "A3_R1_WRONG_BINDING_IDENTITY": {"evaluable": bool(path_ok and guard_ok), "reason": None if path_ok and guard_ok else "PATH_OR_GUARD_UNPROVEN"},
        "A3_R2_DEFINITE_OVERWRITE_TO_WRONG_CARRIER": {"evaluable": bool(path_ok), "reason": None if path_ok else "PATH_DATAFLOW_CORRELATION_UNPROVEN"},
        "A3_R3_EXPLICIT_CARRIER_SUBSTITUTION_OR_DROP": {"evaluable": bool(path_ok and effect_ok), "reason": None if path_ok and effect_ok else "EFFECT_OR_PATH_UNPROVEN"},
        "A3_R4_CLOSED_REPRESENTATION_OMISSION": {"evaluable": False, "reason": "REPRESENTATION_CLOSURE_UNPROVEN"},
        "A4_CONTROL_ORDER_OUTCOME_FAMILY": {"evaluable": bool(path_ok and guard_ok and effect_ok), "reason": None if path_ok and guard_ok and effect_ok else "CONTROL_GUARD_OR_EFFECT_UNPROVEN"},
    }


def normalize_json(value: Any) -> Any:
    if value is None or type(value) in (bool, int, float, str):
        return value
    if isinstance(value, list):
        return [normalize_json(item) for item in value]
    if isinstance(value, dict):
        if any(type(key) is not str for key in value):
            raise ValueError("canonical mapping key is not string")
        return {key: normalize_json(value[key]) for key in sorted(value)}
    raise ValueError("canonical value outside JSON domain")


def project_row(row: Mapping[str, Any]) -> dict[str, Any]:
    if any(key not in row for key in PROJECTION_KEYS):
        raise ValueError("canonical projection field absent")
    projection = {key: normalize_json(row[key]) for key in PROJECTION_KEYS}
    reasons = projection["sorted_reasons"]
    if not isinstance(reasons, list) or reasons != sorted(set(reasons)):
        raise ValueError("canonical reasons invalid")
    return projection


def one_heldout_row(cell_id: str, language: str, logical_path: str, raw: bytes, receipt: Mapping[str, Any], seed_contract: Mapping[str, Any], signature: Mapping[str, Any], helper: Path) -> dict[str, Any]:
    if language not in LANGS or receipt.get("transport_case_id") != cell_id:
        raise ValueError("heldout identity invalid")
    digest = h256(raw)
    if receipt.get("candidate_source_sha256") != digest:
        raise ValueError("heldout source digest invalid")
    if receipt.get("case_transport_status") != "COMPLETE":
        return {
            "cell_id": cell_id, "qualification_status": "OBSERVABILITY_INCOMPLETE",
            "sorted_reasons": ["OBSERVABILITY_INCOMPLETE_TRANSPORT"],
            "base_ir_status": "NOT_EVALUATED", "overlay_status": "NOT_EVALUATED",
            "path_observability_status": "NOT_EVALUATED", "anchor_usability": "INCOMPLETE",
            "effective_guard_form": "UNPROVEN", "control_scope_completeness": {},
            "path_dataflow_correlation": "UNPROVEN", "effect_surface_status": "UNPROVEN",
            "ordering_outcome_observability": {}, "representation_closure_status": "REPRESENTATION_CLOSURE_UNPROVEN",
            "witness_precondition_observability": {}, "semantic_authority": False,
        }
    text = raw.decode("utf-8")
    contract, contract_digest = bind_transported_contract(seed_contract, receipt, logical_path, text, language)
    ir, status = make_ir(logical_path, language, raw, helper)
    if status.get("status") != "PASS":
        raise ValueError("heldout IR construction failed")
    parsed = parse_surface(language, logical_path, raw, helper)
    if parsed.get("status") != "PASS":
        raise ValueError("heldout frontend failed")
    overlay = build_overlay(
        path=logical_path, source=text, source_sha256=digest, language=language,
        facts=parsed["facts"], base_ir=ir, anchor_contract=contract,
        anchor_contract_sha256=contract_digest,
    )
    validate_overlay(overlay)
    pathdoc = build_path_observability(
        path=logical_path, source=text, source_sha256=digest, language=language,
        facts=parsed["facts"], overlay=overlay, canonical_signature=signature,
    )
    disposition, reasons = independent_admission(pathdoc)
    return {
        "cell_id": cell_id,
        "qualification_status": disposition,
        "sorted_reasons": reasons,
        "base_ir_status": "PASS",
        "overlay_status": "PASS",
        "path_observability_status": "PASS",
        "anchor_usability": "COMPLETE",
        "effective_guard_form": pathdoc["effective_guard_observability"]["form"],
        "control_scope_completeness": pathdoc["control_scope_completeness"],
        "path_dataflow_correlation": pathdoc["path_dataflow_correlation"],
        "effect_surface_status": pathdoc["effect_binding_surface"]["status"],
        "ordering_outcome_observability": {
            "effect_path_count": len(pathdoc["entry_effect_paths"]),
            "rejection_path_count": len(pathdoc["rejection_paths"]),
            "success_path_count": len(pathdoc["success_paths"]),
        },
        "representation_closure_status": pathdoc["representation_closure_status"],
        "witness_precondition_observability": independent_witness_surface(pathdoc),
        "semantic_authority": False,
        "base_ir_digest_sha256": ir["ir_digest_sha256"],
        "overlay_digest_sha256": overlay["overlay_digest_sha256"],
        "path_observability_digest_sha256": pathdoc["path_observability_digest_sha256"],
    }


def self_checks() -> list[dict[str, Any]]:
    valid = {
        "material_control_complete": True,
        "effective_guard_observability": {"form": "DIRECT_CONTROL", "reason": None},
        "path_dataflow_correlation": "COMPLETE",
        "effect_binding_surface": {"status": "UNIQUE"},
    }
    checks: list[tuple[str, bool]] = [("valid_admitted", independent_admission(valid)[0] == "OBSERVABILITY_QUALIFIED_FOR_A3_A4_EXECUTION")]
    bad = copy.deepcopy(valid); bad["material_control_complete"] = False
    checks.append(("control_incomplete_rejected", independent_admission(bad)[0] == "OBSERVABILITY_INCOMPLETE"))
    bad = copy.deepcopy(valid); bad["effective_guard_observability"] = {"form": "UNPROVEN", "reason": "GUARD_UNPROVEN"}
    checks.append(("guard_unproven_rejected", independent_admission(bad)[0] == "OBSERVABILITY_INCOMPLETE"))
    bad = copy.deepcopy(valid); bad["path_dataflow_correlation"] = "INCOMPLETE"
    checks.append(("path_incomplete_rejected", independent_admission(bad)[0] == "OBSERVABILITY_INCOMPLETE"))
    bad = copy.deepcopy(valid); bad["effect_binding_surface"] = {"status": "AMBIGUOUS"}
    checks.append(("effect_ambiguous_rejected", independent_admission(bad)[0] == "OBSERVABILITY_INCOMPLETE"))
    template = {
        "cell_id": "SELFTEST", "qualification_status": "OBSERVABILITY_QUALIFIED_FOR_A3_A4_EXECUTION",
        "sorted_reasons": [], "base_ir_status": "PASS", "overlay_status": "PASS",
        "path_observability_status": "PASS", "anchor_usability": "COMPLETE",
        "effective_guard_form": "DIRECT_CONTROL", "control_scope_completeness": {"f": "COMPLETE"},
        "path_dataflow_correlation": "COMPLETE", "effect_surface_status": "UNIQUE",
        "ordering_outcome_observability": {"effect_path_count": 1, "rejection_path_count": 1, "success_path_count": 1},
        "representation_closure_status": "REPRESENTATION_CLOSURE_UNPROVEN", "witness_precondition_observability": {},
    }
    checks.append(("canonical_valid", project_row(template)["cell_id"] == "SELFTEST"))
    try:
        x = dict(template); del x["effect_surface_status"]; project_row(x); passed = False
    except ValueError:
        passed = True
    checks.append(("canonical_missing_field_rejected", passed))
    try:
        x = dict(template); x["control_scope_completeness"] = {"x": {1}}; project_row(x); passed = False
    except ValueError:
        passed = True
    checks.append(("canonical_non_json_rejected", passed))
    try:
        x = dict(template); x["sorted_reasons"] = ["B", "A"]; project_row(x); passed = False
    except ValueError:
        passed = True
    checks.append(("canonical_unsorted_reasons_rejected", passed))
    return [{"name": name, "passed": bool(passed)} for name, passed in checks]


def preflight(v3: Path, v2: Path, helper: Path) -> dict[str, Any]:
    result_rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    corpus_records = []
    for role, corpus_path in (("v0.3-prospective-24", v3), ("v0.2-frozen-regression-24", v2)):
        corpus, raw_corpus = read_doc(corpus_path)
        cases = corpus.get("cases")
        if not isinstance(cases, list) or len(cases) != 24:
            raise ValueError("wrong public corpus cardinality")
        corpus_records.append({"role": role, "sha256": h256(raw_corpus), "bytes": len(raw_corpus)})
        for case in cases:
            fixture = str(case["fixture_id"])
            language = str(case["language"])
            raw = str(case["source"]).encode("utf-8")
            declared = str(case["source_sha256"])
            if language not in LANGS or h256(raw) != declared:
                raise ValueError("public source binding failed")
            public_id = role + "::" + fixture
            if public_id in seen:
                raise ValueError("duplicate public identity")
            seen.add(public_id)
            ir, status = make_ir(fixture + ext_for(language), language, raw, helper)
            result_rows.append({
                "public_case_id": public_id,
                "corpus_role": role,
                "fixture_id": fixture,
                "language": language,
                "source_sha256": declared,
                "ir_status": status.get("status"),
                "frontend_surface_version": status.get("frontend_surface_version"),
                "python_frontend_surface_version": status.get("python_frontend_surface_version"),
                "node_count": len(ir.get("nodes", [])),
                "edge_count": len(ir.get("edges", [])),
                "frontend_statuses": [item.get("status") for item in ir.get("frontend_status", [])],
            })
    result_rows.sort(key=lambda item: item["public_case_id"])
    checks = self_checks()
    route_ok = len(result_rows) == 48 and all(row["ir_status"] == "PASS" and row["frontend_statuses"] == ["PASS"] for row in result_rows)
    checks_ok = all(item["passed"] for item in checks)
    output = {
        "schema": PREFLIGHT_SCHEMA,
        "status": "PASS" if route_ok and checks_ok else "FAIL",
        "semantic_authority": False,
        "preflight_scope": "ROUTING_INPUT_NORMALIZATION_IR_AND_FROZEN_GATE_LOGIC_ONLY",
        "public_case_count": len(result_rows),
        "public_cases": result_rows,
        "gate_and_canonicalizer_selftests": checks,
        "gate_and_canonicalizer_selftest_pass_count": sum(bool(item["passed"]) for item in checks),
        "gate_and_canonicalizer_selftest_count": len(checks),
        "heldout_anchor_path_pipeline_executed": False,
        "frozen_48_source_bytes_read": False,
        "candidate_58_bytes_read": False,
        "raw_blind_58_transport_read": False,
        "a3_a4_semantic_verdicts_emitted": False,
        "corpora": corpus_records,
    }
    output["preflight_digest_sha256"] = h256(canonical_bytes(output))
    return output


def heldout(args: argparse.Namespace) -> dict[str, Any]:
    selection, _ = read_doc(Path(args.selection))
    transport, _ = read_doc(Path(args.transport))
    anchors, _ = read_doc(Path(args.anchors))
    signatures, _ = read_doc(Path(args.signatures))
    selected = selection.get("selected_cells")
    if not isinstance(selected, list) or len(selected) != 48:
        raise ValueError("heldout selection cardinality invalid")
    transport_map = {str(item["transport_case_id"]): item for item in transport["receipts"]}
    anchor_map = {str(item["seed_id"]): item for item in anchors["contracts"]}
    signature_map = {str(item["seed_id"]): item for item in signatures["signatures"]}
    output_rows = []
    for meta in selected:
        cell = str(meta["cell_id"])
        paths = list(meta["source_file_path_metadata"])
        if len(paths) != 1 or len(meta["source_git_blob_identity"]) != 1:
            raise ValueError("heldout cell does not have one frozen material source")
        receipt = transport_map.get(cell)
        if receipt is None:
            raise ValueError("heldout transport receipt absent")
        relative = str(paths[0])
        raw = (Path(args.source_root) / relative).read_bytes()
        seed = str(receipt["seed_id"])
        anchor = anchor_map.get(seed)
        signature = signature_map.get(seed)
        if anchor is None or signature is None:
            raise ValueError("canonical seed authority absent")
        language = str(anchor["declaration"]["source"]["language"])
        if not relative.endswith(ext_for(language)):
            raise ValueError("source path/language mismatch")
        output_rows.append(one_heldout_row(cell, language, Path(relative).name, raw, receipt, anchor, signature, Path(args.go_helper)))
    output_rows.sort(key=lambda item: item["cell_id"])
    accepted = sum(item["qualification_status"] == "OBSERVABILITY_QUALIFIED_FOR_A3_A4_EXECUTION" for item in output_rows)
    output = {
        "schema": OUTPUT_SCHEMA,
        "status": "PASS" if len(output_rows) == 48 and accepted == 48 else "FAIL",
        "semantic_authority": False,
        "case_count": len(output_rows),
        "qualified_count": accepted,
        "rows": output_rows,
        "canonical_rows": [project_row(item) for item in output_rows],
        "candidate_58_bytes_read": False,
        "raw_blind_58_transport_read": False,
        "a3_a4_semantic_verdicts_emitted": False,
    }
    output["bundle_digest_sha256"] = h256(canonical_bytes(output))
    return output


def main() -> int:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="mode", required=True)
    p = commands.add_parser("preflight")
    p.add_argument("--v3-corpus", required=True); p.add_argument("--v2-corpus", required=True)
    p.add_argument("--go-helper", required=True); p.add_argument("--output", required=True)
    h = commands.add_parser("heldout")
    h.add_argument("--selection", required=True); h.add_argument("--transport", required=True)
    h.add_argument("--anchors", required=True); h.add_argument("--signatures", required=True)
    h.add_argument("--source-root", required=True); h.add_argument("--go-helper", required=True); h.add_argument("--output", required=True)
    args = parser.parse_args()
    output = preflight(Path(args.v3_corpus), Path(args.v2_corpus), Path(args.go_helper)) if args.mode == "preflight" else heldout(args)
    Path(args.output).write_bytes(canonical_bytes(output))
    print(json.dumps({"status": output["status"], "mode": args.mode, "output_sha256": h256(Path(args.output).read_bytes())}, sort_keys=True, separators=(",", ":")))
    return 0 if output["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
