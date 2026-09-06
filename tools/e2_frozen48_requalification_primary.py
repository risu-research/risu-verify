#!/usr/bin/env python3
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import tempfile
from pathlib import Path
from typing import Any, Mapping, Sequence

from risu_e2.acquisition import AcquiredFile
from risu_e2.frontend_go import extract_many as extract_go_many
from risu_e2.frontend_js_v3 import extract as extract_js
from risu_e2.frontend_python_v2 import extract as extract_python
from risu_e2.ir_v3 import build_ir
from risu_e2.model import canonical_bytes
from risu_e2.observability_overlay import build_overlay, validate_overlay
from risu_e2.path_observability import build_path_observability

SCHEMA = "risu.e2-a3-a4-frozen48-requalification-primary/v0.1"
PREFLIGHT_SCHEMA = "risu.e2-a3-a4-frozen48-adapter-preflight-primary/v0.1"
ALLOWED_LANGUAGES = {"python", "go", "typescript_javascript"}
CANONICAL_ROW_FIELDS = (
    "cell_id",
    "qualification_status",
    "sorted_reasons",
    "base_ir_status",
    "overlay_status",
    "path_observability_status",
    "anchor_usability",
    "effective_guard_form",
    "control_scope_completeness",
    "path_dataflow_correlation",
    "effect_surface_status",
    "ordering_outcome_observability",
    "representation_closure_status",
    "witness_precondition_observability",
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_json(path: Path) -> tuple[Any, bytes]:
    raw = path.read_bytes()
    return json.loads(raw), raw


def suffix(language: str) -> str:
    return {"python": ".py", "go": ".go", "typescript_javascript": ".mjs"}[language]


def frontend(language: str, path: str, data: bytes, go_helper: Path) -> dict[str, Any]:
    text = data.decode("utf-8")
    if language == "python":
        return extract_python(text)
    if language == "typescript_javascript":
        return extract_js(text)
    if language == "go":
        return extract_go_many([{"path": path, "data": data}], go_helper)[path]
    raise ValueError("unsupported language")


def direct_ir(path: str, language: str, data: bytes, go_helper: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    digest = sha256(data)
    acquired = [AcquiredFile(
        path=path,
        language=language,
        sha256=digest,
        data=data,
        selection_round=0,
        selection_reasons=("FROZEN48_ADAPTER_DIRECT_BOUND_INPUT",),
    )]
    acquisition = {
        "status": "PASS",
        "reason": "FROZEN48_ADAPTER_EXACT_BOUND_SINGLE_FILE_INPUT",
        "semantic_authority": False,
        "selected_file_count": 1,
        "selected_total_bytes": len(data),
    }
    return build_ir(acquired, acquisition_doc=acquisition, go_helper_path=go_helper)


def source_slice(source: str, span: Sequence[int]) -> bytes:
    sl, sc, el, ec = map(int, span)
    lines = source.splitlines(keepends=True)
    if sl < 1 or el < sl or el > len(lines):
        raise ValueError("invalid transported span")
    if sl == el:
        return lines[sl - 1].encode("utf-8")[sc:ec]
    out = lines[sl - 1].encode("utf-8")[sc:]
    for line in lines[sl:el - 1]:
        out += line.encode("utf-8")
    out += lines[el - 1].encode("utf-8")[:ec]
    return out


def projected_contract(canonical_entry: Mapping[str, Any], receipt: Mapping[str, Any], candidate_path: str, source: str) -> tuple[dict[str, Any], str]:
    declaration = copy.deepcopy(canonical_entry["declaration"])
    anchors = {row["anchor_key"]: row for row in receipt["anchors"]}
    language = str(receipt["language"])
    declaration["source"] = {
        "git_blob_sha": "OPAQUE_RUNTIME_SOURCE",
        "language": language,
        "path": candidate_path,
        "sha256": receipt["candidate_source_sha256"],
    }
    for key, anchor in declaration["anchors"].items():
        row = anchors.get(key)
        if row is None or row.get("realization_status") != "ROLE_COMPATIBLE" or not row.get("candidate_span"):
            raise ValueError("transport anchor ineligible")
        anchor["span"] = list(row["candidate_span"])
        anchor["slice_sha256"] = row["candidate_slice_sha256"]
        actual = source_slice(source, anchor["span"])
        if sha256(actual) != anchor["slice_sha256"]:
            raise ValueError("candidate anchor slice mismatch")
        anchor["slice_bytes"] = len(actual)
        anchor["unique_in_source"] = True
    for slot in ("expected_coordinate", "current_coordinate"):
        row = receipt["binding_slots"][slot]
        if row.get("status") != "AVAILABLE":
            raise ValueError("transport slot ineligible")
        if int(row["operand_index"]) != int(declaration["binding_slots"][slot]["operand_index"]):
            raise ValueError("transport operand index mismatch")
    declaration["transport"] = {
        "mutant_revision_authorized": True,
        "fresh_revision_authorized": False,
        "projection_authority": "SELECTED_48_FROZEN_TRANSPORT_RECEIPT",
    }
    declaration["verdict_authority"] = False
    return declaration, sha256(canonical_bytes(declaration))


def case_status(pathdoc: Mapping[str, Any]) -> tuple[str, list[str]]:
    reasons: list[str] = []
    if pathdoc["material_control_complete"] is not True:
        reasons.append("CONTROL_INCOMPLETE")
    guard = pathdoc["effective_guard_observability"]
    if guard["form"] not in {"DIRECT_CONTROL", "HELPER_CONTROL"}:
        reasons.append(str(guard.get("reason") or "EFFECTIVE_GUARD_UNPROVEN"))
    if pathdoc["path_dataflow_correlation"] != "COMPLETE":
        reasons.append("PATH_DATAFLOW_CORRELATION_UNPROVEN")
    if pathdoc["effect_binding_surface"]["status"] != "UNIQUE":
        reasons.append("EFFECT_INVOCATION_UNRESOLVED")
    return (
        "OBSERVABILITY_QUALIFIED_FOR_A3_A4_EXECUTION" if not reasons else "OBSERVABILITY_INCOMPLETE",
        sorted(set(reasons)),
    )


def witness_preconditions(pathdoc: Mapping[str, Any]) -> dict[str, Any]:
    complete = pathdoc["path_dataflow_correlation"] == "COMPLETE" and pathdoc["material_control_complete"] is True
    effect = pathdoc["effect_binding_surface"]["status"] == "UNIQUE"
    guard = pathdoc["effective_guard_observability"]["form"] in {"DIRECT_CONTROL", "HELPER_CONTROL"}
    return {
        "A3_R1_WRONG_BINDING_IDENTITY": {"evaluable": complete and guard, "reason": None if complete and guard else "PATH_OR_GUARD_UNPROVEN"},
        "A3_R2_DEFINITE_OVERWRITE_TO_WRONG_CARRIER": {"evaluable": complete, "reason": None if complete else "PATH_DATAFLOW_CORRELATION_UNPROVEN"},
        "A3_R3_EXPLICIT_CARRIER_SUBSTITUTION_OR_DROP": {"evaluable": complete and effect, "reason": None if complete and effect else "EFFECT_OR_PATH_UNPROVEN"},
        "A3_R4_CLOSED_REPRESENTATION_OMISSION": {"evaluable": False, "reason": "REPRESENTATION_CLOSURE_UNPROVEN"},
        "A4_CONTROL_ORDER_OUTCOME_FAMILY": {"evaluable": complete and guard and effect, "reason": None if complete and guard and effect else "CONTROL_GUARD_OR_EFFECT_UNPROVEN"},
    }


def json_value(value: Any) -> Any:
    if value is None or isinstance(value, (str, bool, int, float)):
        return value
    if isinstance(value, list):
        return [json_value(x) for x in value]
    if isinstance(value, dict):
        if any(not isinstance(k, str) for k in value):
            raise ValueError("non-string canonical key")
        return {k: json_value(value[k]) for k in sorted(value)}
    raise ValueError("non-json canonical value")


def canonical_projection(row: Mapping[str, Any]) -> dict[str, Any]:
    missing = [field for field in CANONICAL_ROW_FIELDS if field not in row]
    if missing:
        raise ValueError("missing canonical fields:" + ",".join(missing))
    out = {field: json_value(row[field]) for field in CANONICAL_ROW_FIELDS}
    if not isinstance(out["sorted_reasons"], list) or out["sorted_reasons"] != sorted(set(out["sorted_reasons"])):
        raise ValueError("reasons not canonical")
    return out


def heldout_row(*, cell_id: str, language: str, source_path: str, source: bytes, receipt: Mapping[str, Any], anchor_entry: Mapping[str, Any], signature: Mapping[str, Any], go_helper: Path) -> dict[str, Any]:
    if language not in ALLOWED_LANGUAGES:
        raise ValueError("bad heldout language")
    if receipt.get("transport_case_id") != cell_id:
        raise ValueError("transport identity mismatch")
    source_hash = sha256(source)
    if receipt.get("candidate_source_sha256") != source_hash:
        raise ValueError("transport source hash mismatch")
    if receipt.get("case_transport_status") != "COMPLETE":
        return {
            "cell_id": cell_id,
            "qualification_status": "OBSERVABILITY_INCOMPLETE",
            "sorted_reasons": ["OBSERVABILITY_INCOMPLETE_TRANSPORT"],
            "base_ir_status": "NOT_EVALUATED",
            "overlay_status": "NOT_EVALUATED",
            "path_observability_status": "NOT_EVALUATED",
            "anchor_usability": "INCOMPLETE",
            "effective_guard_form": "UNPROVEN",
            "control_scope_completeness": {},
            "path_dataflow_correlation": "UNPROVEN",
            "effect_surface_status": "UNPROVEN",
            "ordering_outcome_observability": {},
            "representation_closure_status": "REPRESENTATION_CLOSURE_UNPROVEN",
            "witness_precondition_observability": {},
            "semantic_authority": False,
        }
    text = source.decode("utf-8")
    contract, contract_sha = projected_contract(anchor_entry, receipt, source_path, text)
    ir, ir_status = direct_ir(source_path, language, source, go_helper)
    if ir_status.get("status") != "PASS":
        raise ValueError("base IR failed")
    fdoc = frontend(language, source_path, source, go_helper)
    if fdoc.get("status") != "PASS":
        raise ValueError("frontend failed")
    overlay = build_overlay(
        path=source_path,
        source=text,
        source_sha256=source_hash,
        language=language,
        facts=fdoc["facts"],
        base_ir=ir,
        anchor_contract=contract,
        anchor_contract_sha256=contract_sha,
    )
    validate_overlay(overlay)
    pathdoc = build_path_observability(
        path=source_path,
        source=text,
        source_sha256=source_hash,
        language=language,
        facts=fdoc["facts"],
        overlay=overlay,
        canonical_signature=signature,
    )
    status, reasons = case_status(pathdoc)
    return {
        "cell_id": cell_id,
        "qualification_status": status,
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
        "witness_precondition_observability": witness_preconditions(pathdoc),
        "semantic_authority": False,
        "base_ir_digest_sha256": ir["ir_digest_sha256"],
        "overlay_digest_sha256": overlay["overlay_digest_sha256"],
        "path_observability_digest_sha256": pathdoc["path_observability_digest_sha256"],
    }


def gate_selftests() -> list[dict[str, Any]]:
    base = {
        "material_control_complete": True,
        "effective_guard_observability": {"form": "DIRECT_CONTROL", "reason": None},
        "path_dataflow_correlation": "COMPLETE",
        "effect_binding_surface": {"status": "UNIQUE"},
    }
    tests: list[tuple[str, bool]] = []
    tests.append(("valid_admitted", case_status(base)[0] == "OBSERVABILITY_QUALIFIED_FOR_A3_A4_EXECUTION"))
    x = copy.deepcopy(base); x["material_control_complete"] = False
    tests.append(("control_incomplete_rejected", case_status(x)[0] == "OBSERVABILITY_INCOMPLETE"))
    x = copy.deepcopy(base); x["effective_guard_observability"] = {"form": "UNPROVEN", "reason": "GUARD_UNPROVEN"}
    tests.append(("guard_unproven_rejected", case_status(x)[0] == "OBSERVABILITY_INCOMPLETE"))
    x = copy.deepcopy(base); x["path_dataflow_correlation"] = "INCOMPLETE"
    tests.append(("path_incomplete_rejected", case_status(x)[0] == "OBSERVABILITY_INCOMPLETE"))
    x = copy.deepcopy(base); x["effect_binding_surface"] = {"status": "AMBIGUOUS"}
    tests.append(("effect_ambiguous_rejected", case_status(x)[0] == "OBSERVABILITY_INCOMPLETE"))
    valid_row = {
        "cell_id": "SELFTEST",
        "qualification_status": "OBSERVABILITY_QUALIFIED_FOR_A3_A4_EXECUTION",
        "sorted_reasons": [],
        "base_ir_status": "PASS",
        "overlay_status": "PASS",
        "path_observability_status": "PASS",
        "anchor_usability": "COMPLETE",
        "effective_guard_form": "DIRECT_CONTROL",
        "control_scope_completeness": {"f": "COMPLETE"},
        "path_dataflow_correlation": "COMPLETE",
        "effect_surface_status": "UNIQUE",
        "ordering_outcome_observability": {"effect_path_count": 1, "rejection_path_count": 1, "success_path_count": 1},
        "representation_closure_status": "REPRESENTATION_CLOSURE_UNPROVEN",
        "witness_precondition_observability": {},
    }
    tests.append(("canonical_valid", canonical_projection(valid_row)["cell_id"] == "SELFTEST"))
    try:
        bad = dict(valid_row); bad.pop("effect_surface_status"); canonical_projection(bad); ok = False
    except ValueError:
        ok = True
    tests.append(("canonical_missing_field_rejected", ok))
    try:
        bad = dict(valid_row); bad["control_scope_completeness"] = {"x": {1, 2}}; canonical_projection(bad); ok = False
    except ValueError:
        ok = True
    tests.append(("canonical_non_json_rejected", ok))
    try:
        bad = dict(valid_row); bad["sorted_reasons"] = ["B", "A"]; canonical_projection(bad); ok = False
    except ValueError:
        ok = True
    tests.append(("canonical_unsorted_reasons_rejected", ok))
    return [{"name": name, "passed": passed} for name, passed in tests]


def public_preflight(corpora: Sequence[tuple[str, Path]], go_helper: Path) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    identities: set[str] = set()
    for corpus_role, path in corpora:
        corpus, raw = load_json(path)
        cases = corpus.get("cases")
        if not isinstance(cases, list) or len(cases) != 24:
            raise ValueError("public corpus must contain exactly 24 cases")
        for case in cases:
            fixture = str(case["fixture_id"])
            language = str(case["language"])
            source = str(case["source"]).encode("utf-8")
            declared_sha = str(case["source_sha256"])
            if language not in ALLOWED_LANGUAGES or sha256(source) != declared_sha:
                raise ValueError("public corpus source identity invalid")
            identity = corpus_role + "::" + fixture
            if identity in identities:
                raise ValueError("duplicate public preflight identity")
            identities.add(identity)
            logical_path = fixture + suffix(language)
            ir, status = direct_ir(logical_path, language, source, go_helper)
            rows.append({
                "public_case_id": identity,
                "corpus_role": corpus_role,
                "fixture_id": fixture,
                "language": language,
                "source_sha256": declared_sha,
                "ir_status": status.get("status"),
                "frontend_surface_version": status.get("frontend_surface_version"),
                "python_frontend_surface_version": status.get("python_frontend_surface_version"),
                "node_count": len(ir.get("nodes", [])),
                "edge_count": len(ir.get("edges", [])),
                "frontend_statuses": [x.get("status") for x in ir.get("frontend_status", [])],
            })
    rows.sort(key=lambda x: x["public_case_id"])
    tests = gate_selftests()
    all_ir_pass = len(rows) == 48 and all(row["ir_status"] == "PASS" and row["frontend_statuses"] == ["PASS"] for row in rows)
    selftests_pass = all(row["passed"] for row in tests)
    out = {
        "schema": PREFLIGHT_SCHEMA,
        "status": "PASS" if all_ir_pass and selftests_pass else "FAIL",
        "semantic_authority": False,
        "preflight_scope": "ROUTING_INPUT_NORMALIZATION_IR_AND_FROZEN_GATE_LOGIC_ONLY",
        "public_case_count": len(rows),
        "public_cases": rows,
        "gate_and_canonicalizer_selftests": tests,
        "gate_and_canonicalizer_selftest_pass_count": sum(1 for row in tests if row["passed"]),
        "gate_and_canonicalizer_selftest_count": len(tests),
        "heldout_anchor_path_pipeline_executed": False,
        "frozen_48_source_bytes_read": False,
        "candidate_58_bytes_read": False,
        "raw_blind_58_transport_read": False,
        "a3_a4_semantic_verdicts_emitted": False,
        "corpora": [{"role": role, "sha256": sha256(path.read_bytes()), "bytes": len(path.read_bytes())} for role, path in corpora],
    }
    out["preflight_digest_sha256"] = sha256(canonical_bytes(out))
    return out


def run_heldout(args: argparse.Namespace) -> dict[str, Any]:
    selection, _ = load_json(Path(args.selection))
    transport, _ = load_json(Path(args.transport))
    anchors, _ = load_json(Path(args.anchors))
    signatures, _ = load_json(Path(args.signatures))
    selected = selection.get("selected_cells")
    if not isinstance(selected, list) or len(selected) != 48:
        raise ValueError("selection manifest not exact 48")
    by_transport = {row["transport_case_id"]: row for row in transport["receipts"]}
    by_anchor = {row["seed_id"]: row for row in anchors["contracts"]}
    by_signature = {row["seed_id"]: row for row in signatures["signatures"]}
    rows = []
    for meta in selected:
        cell_id = str(meta["cell_id"])
        paths = list(meta["source_file_path_metadata"])
        blobs = list(meta["source_git_blob_identity"])
        if len(paths) != 1 or len(blobs) != 1:
            raise ValueError("selected heldout cell must bind exactly one material source")
        receipt = by_transport.get(cell_id)
        if receipt is None:
            raise ValueError("missing selected transport receipt")
        source_path = paths[0]
        data = (Path(args.source_root) / source_path).read_bytes()
        if receipt.get("candidate_source_sha256") != sha256(data):
            raise ValueError("selected source/transport mismatch")
        seed_id = str(receipt["seed_id"])
        anchor = by_anchor.get(seed_id)
        signature = by_signature.get(seed_id)
        if anchor is None or signature is None:
            raise ValueError("missing canonical seed authority")
        row = heldout_row(
            cell_id=cell_id,
            language=str(receipt["language"]),
            source_path=Path(source_path).name,
            source=data,
            receipt=receipt,
            anchor_entry=anchor,
            signature=signature,
            go_helper=Path(args.go_helper),
        )
        rows.append(row)
    rows.sort(key=lambda x: x["cell_id"])
    qualified = sum(row["qualification_status"] == "OBSERVABILITY_QUALIFIED_FOR_A3_A4_EXECUTION" for row in rows)
    out = {
        "schema": SCHEMA,
        "status": "PASS" if len(rows) == 48 and qualified == 48 else "FAIL",
        "semantic_authority": False,
        "case_count": len(rows),
        "qualified_count": qualified,
        "rows": rows,
        "canonical_rows": [canonical_projection(row) for row in rows],
        "candidate_58_bytes_read": False,
        "raw_blind_58_transport_read": False,
        "a3_a4_semantic_verdicts_emitted": False,
    }
    out["bundle_digest_sha256"] = sha256(canonical_bytes(out))
    return out


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="mode", required=True)
    p = sub.add_parser("preflight")
    p.add_argument("--v3-corpus", required=True)
    p.add_argument("--v2-corpus", required=True)
    p.add_argument("--go-helper", required=True)
    p.add_argument("--output", required=True)
    h = sub.add_parser("heldout")
    h.add_argument("--selection", required=True)
    h.add_argument("--transport", required=True)
    h.add_argument("--anchors", required=True)
    h.add_argument("--signatures", required=True)
    h.add_argument("--source-root", required=True)
    h.add_argument("--go-helper", required=True)
    h.add_argument("--output", required=True)
    args = parser.parse_args()
    if args.mode == "preflight":
        out = public_preflight((("v0.3-prospective-24", Path(args.v3_corpus)), ("v0.2-frozen-regression-24", Path(args.v2_corpus))), Path(args.go_helper))
    else:
        out = run_heldout(args)
    Path(args.output).write_bytes(canonical_bytes(out))
    print(json.dumps({"status": out["status"], "mode": args.mode, "output_sha256": sha256(Path(args.output).read_bytes())}, sort_keys=True, separators=(",", ":")))
    return 0 if out["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
