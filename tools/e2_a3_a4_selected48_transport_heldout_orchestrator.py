#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

AUTHORIZATION = "AUTHORIZE_EXACT_SELECTED48_FIRST_READ"
ADMISSION_SCHEMA = "risu.e2-a3-a4-selected48-runtime-admission/v0.1"
TRANSPORT_SCHEMA = "risu.e2-a3-a4-selected48-only-transport-bundle/v0.1"
CROSSCHECK_SCHEMA = "risu.e2-a3-a4-selected48-heldout-cross-check/v0.1"
EXPECTED_COUNT = 48
LANG_BY_SUFFIX = {
    ".py": "python",
    ".go": "go",
    ".mjs": "typescript_javascript",
}
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
CELL_RE = re.compile(r"^Q[0-9]{3}$")
SEED_FILE_RE = re.compile(r"^(SYN-(?:PY|GO|TS)-0[12])\.(py|go|mjs)$")


def canon(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_blob_id(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()


def read_json(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = path.read_bytes()
    doc = json.loads(raw)
    if not isinstance(doc, dict):
        raise ValueError("top-level JSON must be an object")
    return doc, raw


def require_authorization(value: str) -> None:
    if value != AUTHORIZATION:
        raise ValueError("explicit selected-48 first-read authorization mismatch")


def safe_relpath(value: str) -> PurePosixPath:
    p = PurePosixPath(value)
    if p.is_absolute() or not p.parts or any(part in {"", ".", ".."} for part in p.parts):
        raise ValueError("unsafe selected source path")
    if len(p.parts) != 2 or not CELL_RE.fullmatch(p.parts[0]):
        raise ValueError("selected source path must be exact cell/file metadata shape")
    if not SEED_FILE_RE.fullmatch(p.name):
        raise ValueError("selected source filename is outside frozen seed surface")
    return p


def language_from_path(path: PurePosixPath) -> str:
    language = LANG_BY_SUFFIX.get(path.suffix)
    if language is None:
        raise ValueError("unsupported selected source suffix")
    return language


def seed_from_path(path: PurePosixPath) -> str:
    match = SEED_FILE_RE.fullmatch(path.name)
    if match is None:
        raise ValueError("cannot derive frozen seed identity")
    return match.group(1)


def load_admission(path: Path) -> dict[str, Any]:
    doc, _ = read_json(path)
    if doc.get("schema") != ADMISSION_SCHEMA or doc.get("case_count") != EXPECTED_COUNT:
        raise ValueError("runtime admission authority mismatch")
    rows = doc.get("selected_cells")
    if not isinstance(rows, list) or len(rows) != EXPECTED_COUNT:
        raise ValueError("runtime admission cardinality mismatch")
    expected_fields = {"cell_id", "language", "source_git_blob_identity", "source_file_path_metadata"}
    seen_cells: set[str] = set()
    seen_paths: set[str] = set()
    seen_blobs: set[str] = set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != expected_fields:
            raise ValueError("runtime admission row field allowlist mismatch")
        cell = str(row["cell_id"])
        paths = row["source_file_path_metadata"]
        blobs = row["source_git_blob_identity"]
        if not CELL_RE.fullmatch(cell) or not isinstance(paths, list) or len(paths) != 1 or not isinstance(blobs, list) or len(blobs) != 1:
            raise ValueError("runtime admission row identity shape mismatch")
        p = safe_relpath(str(paths[0]))
        blob = str(blobs[0])
        if p.parts[0] != cell:
            raise ValueError("runtime admission cell/path mismatch")
        if not re.fullmatch(r"[0-9a-f]{40}", blob):
            raise ValueError("runtime admission Git blob identity malformed")
        if row["language"] != language_from_path(p):
            raise ValueError("runtime admission language mismatch")
        if cell in seen_cells or str(p) in seen_paths or blob in seen_blobs:
            raise ValueError("duplicate selected admission identity")
        seen_cells.add(cell); seen_paths.add(str(p)); seen_blobs.add(blob)
    if rows != sorted(rows, key=lambda r: str(r["cell_id"])):
        raise ValueError("runtime admission rows are not canonical identity order")
    return doc


def project_admission(selection_path: Path, output_path: Path) -> None:
    selection, _ = read_json(selection_path)
    selected = selection.get("selected_cells")
    if not isinstance(selected, list) or len(selected) != EXPECTED_COUNT:
        raise ValueError("selection manifest is not exact 48")
    projected: list[dict[str, Any]] = []
    for meta in selected:
        if not isinstance(meta, dict):
            raise ValueError("selection row malformed")
        cell = str(meta["cell_id"])
        paths = meta["source_file_path_metadata"]
        blobs = meta["source_git_blob_identity"]
        if not isinstance(paths, list) or len(paths) != 1 or not isinstance(blobs, list) or len(blobs) != 1:
            raise ValueError("selected cell must bind exactly one path and one blob")
        p = safe_relpath(str(paths[0]))
        if p.parts[0] != cell:
            raise ValueError("selection cell/path mismatch")
        projected.append({
            "cell_id": cell,
            "language": language_from_path(p),
            "source_git_blob_identity": [str(blobs[0])],
            "source_file_path_metadata": [str(p)],
        })
    projected.sort(key=lambda row: row["cell_id"])
    out = {
        "schema": ADMISSION_SCHEMA,
        "semantic_authority": False,
        "case_count": EXPECTED_COUNT,
        "selected_cells": projected,
        "projection_contract": {
            "per_cell_fields": ["cell_id", "language", "source_git_blob_identity", "source_file_path_metadata"],
            "all_other_selection_fields_discarded": True,
            "frozen_mutation_class_propagated": False,
        },
        "firewall": {
            "selected_source_bytes_read": False,
            "epistemic_10_source_bytes_read": False,
            "candidate_58_bytes_read": False,
            "raw_blind_58_transport_read": False,
            "mutation_truth_read": False,
            "mutation_operator_metadata_read": False,
            "expected_e2_prediction_read": False,
            "a3_a4_semantic_verdicts_emitted": False,
        },
    }
    out["admission_digest_sha256"] = sha256(canon(out))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(canon(out))
    load_admission(output_path)


def stage_selected(admission_path: Path, blob_dir: Path, source_root: Path, authorization: str) -> None:
    require_authorization(authorization)
    admission = load_admission(admission_path)
    staged = 0
    for row in admission["selected_cells"]:
        rel = safe_relpath(str(row["source_file_path_metadata"][0]))
        expected_blob = str(row["source_git_blob_identity"][0])
        blob_path = blob_dir / expected_blob
        if not blob_path.is_file():
            raise ValueError("authorized selected Git blob is missing from exact-blob staging")
        data = blob_path.read_bytes()
        if git_blob_id(data) != expected_blob:
            raise ValueError("selected source Git blob identity mismatch")
        dst = source_root.joinpath(*rel.parts)
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(data)
        staged += 1
    if staged != EXPECTED_COUNT:
        raise ValueError("selected source staging count mismatch")
    print(json.dumps({"status": "PASS", "selected_source_files_staged": staged, "raw_source_emitted": False}, sort_keys=True, separators=(",", ":")))


def selected_transport(
    admission_path: Path,
    anchors_path: Path,
    baseline_root: Path,
    source_root: Path,
    output_path: Path,
    authorization: str,
) -> None:
    require_authorization(authorization)
    admission = load_admission(admission_path)
    anchors, _ = read_json(anchors_path)
    contracts = anchors.get("contracts")
    if not isinstance(contracts, list) or len(contracts) != 6:
        raise ValueError("canonical anchor bundle mismatch")
    by_seed = {str(row["seed_id"]): row for row in contracts}
    if len(by_seed) != 6:
        raise ValueError("canonical anchor seed identity mismatch")

    from risu_e2.anchor_transport import transport_case, verify_receipt_digest

    receipts: list[dict[str, Any]] = []
    for row in admission["selected_cells"]:
        cell_id = str(row["cell_id"])
        rel = safe_relpath(str(row["source_file_path_metadata"][0]))
        expected_blob = str(row["source_git_blob_identity"][0])
        language = str(row["language"])
        seed_id = seed_from_path(rel)
        contract = by_seed.get(seed_id)
        if contract is None:
            raise ValueError("selected source seed has no canonical anchor contract")
        declaration = contract.get("declaration")
        if not isinstance(declaration, dict):
            raise ValueError("canonical anchor declaration malformed")
        source_decl = declaration.get("source")
        if not isinstance(source_decl, dict) or source_decl.get("language") != language:
            raise ValueError("selected language/canonical anchor mismatch")
        baseline_rel = PurePosixPath(str(source_decl["path"]))
        baseline = baseline_root.joinpath(*baseline_rel.parts).read_bytes()
        if sha256(baseline) != source_decl.get("sha256"):
            raise ValueError("canonical baseline seed digest mismatch")
        candidate = source_root.joinpath(*rel.parts).read_bytes()
        if git_blob_id(candidate) != expected_blob:
            raise ValueError("selected source Git blob changed after staging")
        engine_receipt = transport_case(
            baseline.decode("utf-8"),
            candidate.decode("utf-8"),
            language,
            seed_id,
            declaration,
            contract["contract_canonical_sha256"],
        )
        if not isinstance(engine_receipt, dict) or not verify_receipt_digest(engine_receipt):
            raise ValueError("frozen transport engine receipt digest invalid")
        candidate_sha = sha256(candidate)
        if engine_receipt.get("candidate_source_sha256") != candidate_sha:
            raise ValueError("transport candidate digest mismatch")
        if engine_receipt.get("anchor_contract_sha256") != contract["contract_canonical_sha256"]:
            raise ValueError("transport anchor contract mismatch")
        engine_transport_case_id = engine_receipt.get("transport_case_id")
        engine_receipt_digest = engine_receipt.get("receipt_digest_sha256")
        wrapped = dict(engine_receipt)
        wrapped.pop("receipt_digest_sha256", None)
        wrapped["transport_case_id"] = cell_id
        wrapped["selected_identity_binding"] = {
            "binding_type": "NONSCIENTIFIC_SELECTED_CELL_IDENTITY_ONLY",
            "engine_transport_case_id": engine_transport_case_id,
            "engine_receipt_digest_sha256": engine_receipt_digest,
            "selected_cell_id": cell_id,
            "selected_source_git_blob_identity": expected_blob,
        }
        wrapped["selected_transport_receipt_digest_sha256"] = sha256(canon(wrapped))
        receipts.append(wrapped)
    receipts.sort(key=lambda receipt: str(receipt["transport_case_id"]))
    if len(receipts) != EXPECTED_COUNT or {r["transport_case_id"] for r in receipts} != {r["cell_id"] for r in admission["selected_cells"]}:
        raise ValueError("selected transport receipt identity set mismatch")
    out = {
        "schema": TRANSPORT_SCHEMA,
        "semantic_authority": False,
        "case_count": EXPECTED_COUNT,
        "receipts": receipts,
        "transport_authority": {
            "frozen_engine_reused_byte_identically": True,
            "selected_identity_binding_is_nonsemantic": True,
            "raw_blind_58_transport_reused": False,
            "transport_recomputed_from_exact_selected48_sources": True,
        },
        "firewall": {
            "selected48_source_bytes_read": True,
            "epistemic_10_source_bytes_read": False,
            "candidate_58_bytes_read": False,
            "raw_blind_58_transport_read": False,
            "mutation_truth_read": False,
            "mutation_operator_metadata_read": False,
            "expected_e2_prediction_read": False,
            "a3_a4_semantic_verdicts_emitted": False,
        },
    }
    out["bundle_digest_sha256"] = sha256(canon(out))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(canon(out))


def canonical_row_map(doc: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    rows = doc.get("canonical_rows")
    if not isinstance(rows, list) or len(rows) != EXPECTED_COUNT:
        raise ValueError("heldout canonical row cardinality mismatch")
    expected = set(CANONICAL_ROW_FIELDS)
    mapped: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict) or set(row) != expected:
            raise ValueError("heldout canonical row field mismatch")
        cell = str(row["cell_id"])
        if not CELL_RE.fullmatch(cell) or cell in mapped:
            raise ValueError("heldout canonical row identity mismatch")
        if row.get("sorted_reasons") != sorted(set(row.get("sorted_reasons", []))):
            raise ValueError("heldout canonical reasons are not normalized")
        mapped[cell] = row
    return mapped


def cross_check(primary_path: Path, independent_path: Path, output_path: Path) -> bool:
    primary, _ = read_json(primary_path)
    independent, _ = read_json(independent_path)
    pmap = canonical_row_map(primary)
    imap = canonical_row_map(independent)
    same_ids = set(pmap) == set(imap) and len(pmap) == EXPECTED_COUNT
    mismatches = []
    if same_ids:
        for cell in sorted(pmap):
            if canon(pmap[cell]) != canon(imap[cell]):
                mismatches.append(cell)
    else:
        mismatches = sorted(set(pmap) ^ set(imap))
    agreement = same_ids and not mismatches
    passed = (
        agreement
        and primary.get("status") == "PASS"
        and independent.get("status") == "PASS"
        and primary.get("case_count") == EXPECTED_COUNT
        and independent.get("case_count") == EXPECTED_COUNT
        and primary.get("qualified_count") == EXPECTED_COUNT
        and independent.get("qualified_count") == EXPECTED_COUNT
    )
    out = {
        "schema": CROSSCHECK_SCHEMA,
        "status": "PASS" if passed else "FAIL",
        "semantic_authority": False,
        "case_count": EXPECTED_COUNT,
        "same_identity_set": same_ids,
        "exact_named_canonical_agreement": agreement,
        "mismatch_cell_ids": mismatches,
        "primary_status": primary.get("status"),
        "independent_status": independent.get("status"),
        "primary_qualified_count": primary.get("qualified_count"),
        "independent_qualified_count": independent.get("qualified_count"),
        "canonical_row_fields": list(CANONICAL_ROW_FIELDS),
        "firewall": {
            "candidate_58_bytes_read": False,
            "raw_blind_58_transport_read": False,
            "a3_a4_semantic_verdicts_emitted": False,
        },
    }
    out["cross_check_digest_sha256"] = sha256(canon(out))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(canon(out))
    return passed


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="mode", required=True)

    p = sub.add_parser("project-admission")
    p.add_argument("--selection", required=True)
    p.add_argument("--output", required=True)

    s = sub.add_parser("stage-selected")
    s.add_argument("--authorization", required=True)
    s.add_argument("--admission", required=True)
    s.add_argument("--blob-dir", required=True)
    s.add_argument("--source-root", required=True)

    t = sub.add_parser("transport")
    t.add_argument("--authorization", required=True)
    t.add_argument("--admission", required=True)
    t.add_argument("--anchors", required=True)
    t.add_argument("--baseline-root", required=True)
    t.add_argument("--source-root", required=True)
    t.add_argument("--output", required=True)

    c = sub.add_parser("cross-check")
    c.add_argument("--primary", required=True)
    c.add_argument("--independent", required=True)
    c.add_argument("--output", required=True)

    args = parser.parse_args()
    if args.mode == "project-admission":
        project_admission(Path(args.selection), Path(args.output))
        return 0
    if args.mode == "stage-selected":
        stage_selected(Path(args.admission), Path(args.blob_dir), Path(args.source_root), args.authorization)
        return 0
    if args.mode == "transport":
        selected_transport(Path(args.admission), Path(args.anchors), Path(args.baseline_root), Path(args.source_root), Path(args.output), args.authorization)
        return 0
    if args.mode == "cross-check":
        return 0 if cross_check(Path(args.primary), Path(args.independent), Path(args.output)) else 1
    raise AssertionError("unreachable")


if __name__ == "__main__":
    raise SystemExit(main())
