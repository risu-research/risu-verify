#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sys
import urllib.request
from collections import Counter
from typing import Any

REPOSITORY = "risu-research/risu-verify"
MATRIX_BLOB = "b6d7d9c4d172a6e38ab59e93ae9748fafefc9fd0"
CELLS_TREE = "34a30574c7420728bff57958c815194979a622ab"
IDENTITY_EXPANSION_REFERENCE_BLOB = "1e5fe69f302df6fdd367797649b17eb3c4ea5950"
EXPECTED_COUNTS = {
    "positive_semantic_loss": 24,
    "semantic_preserving": 24,
    "epistemic_adversarial": 10,
}
CELL_RE = re.compile(r"^Q[0-9]{3}$")
FORBIDDEN_OUTPUT_KEYS = {
    "source_bytes",
    "source_text",
    "expected_truth",
    "operator_id",
    "operator_name",
    "operator_class",
    "expected_e2_prediction",
    "candidate_58_content",
}


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def git_blob_sha(value: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(value)).encode("ascii") + b"\0" + value).hexdigest()


def api_get(path: str) -> dict[str, Any]:
    token = os.environ.get("GITHUB_TOKEN", "")
    req = urllib.request.Request(
        "https://api.github.com" + path,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "risu-e2-frozen48-metadata-selector",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode("utf-8"))


def classify_group_key(key: Any) -> str | None:
    if not isinstance(key, str):
        return None
    normalized = re.sub(r"[^A-Z0-9]+", "_", key.strip().upper()).strip("_")
    if normalized.endswith("_EPISTEMIC_ADVERSARIAL"):
        return "epistemic_adversarial"
    if normalized.endswith("_SEMANTIC_PRESERVING"):
        return "semantic_preserving"
    if normalized.endswith("_SEMANTIC_LOSS"):
        return "positive_semantic_loss"
    return None


def derive_projected_cells(matrix: dict[str, Any]) -> list[dict[str, str]]:
    # Identity derivation is the pre-existing frozen expansion algorithm:
    # seed_order -> class_order -> assignment-list position -> monotonically
    # increasing Q%03d. Assignment element VALUES are deliberately never read.
    contract = matrix.get("expansion_contract")
    assignments = matrix.get("assignments")
    if not isinstance(contract, dict) or not isinstance(assignments, dict):
        raise RuntimeError("MATRIX_IDENTITY_CONTRACT_MISSING")
    seed_order = contract.get("seed_order")
    class_order = contract.get("class_order")
    expanded_count = contract.get("expanded_row_count")
    if not isinstance(seed_order, list) or not all(isinstance(x, str) for x in seed_order):
        raise RuntimeError("SEED_ORDER_INVALID")
    if not isinstance(class_order, list) or not all(isinstance(x, str) for x in class_order):
        raise RuntimeError("CLASS_ORDER_INVALID")
    if expanded_count != 58:
        raise RuntimeError("EXPANDED_ROW_COUNT_NOT_58")

    class_map: dict[str, str] = {}
    for cls_key in class_order:
        cls = classify_group_key(cls_key)
        if cls is None:
            raise RuntimeError("UNRECOGNIZED_CLASSIFICATION_GROUP")
        if cls in class_map.values():
            raise RuntimeError("DUPLICATE_CLASSIFICATION_GROUP")
        class_map[cls_key] = cls
    if set(class_map.values()) != set(EXPECTED_COUNTS):
        raise RuntimeError("CLASSIFICATION_GROUP_SET_MISMATCH")

    out: list[dict[str, str]] = []
    index = 1
    for seed_id in seed_order:
        seed_assignments = assignments.get(seed_id)
        if not isinstance(seed_assignments, dict):
            raise RuntimeError("SEED_ASSIGNMENT_GROUP_MISSING")
        for cls_key in class_order:
            entries = seed_assignments.get(cls_key)
            if not isinstance(entries, list):
                raise RuntimeError("ASSIGNMENT_LIST_MISSING")
            # Critical firewall: only cardinality is consumed. No assignment
            # element value is accessed, compared, emitted, logged, or hashed.
            for _ in range(len(entries)):
                out.append({
                    "cell_id": f"Q{index:03d}",
                    "frozen_mutation_class": class_map[cls_key],
                })
                index += 1
    if len(out) != 58 or index != 59:
        raise RuntimeError("DERIVED_IDENTITY_COUNT_MISMATCH")
    return out


def cell_tree_map(tree_doc: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    if tree_doc.get("sha") != CELLS_TREE or tree_doc.get("truncated"):
        raise RuntimeError("CELLS_TREE_METADATA_INVALID")
    grouped: dict[str, list[dict[str, Any]]] = {}
    for ent in tree_doc.get("tree", []):
        path = str(ent.get("path", ""))
        if "/" not in path:
            continue
        cell, rel = path.split("/", 1)
        if not CELL_RE.fullmatch(cell) or ent.get("type") != "blob" or rel == "CELL.json":
            continue
        grouped.setdefault(cell, []).append({
            "path": path,
            "sha": ent.get("sha"),
            "size": ent.get("size"),
        })
    return {k: sorted(v, key=lambda x: x["path"]) for k, v in sorted(grouped.items())}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", required=True)
    args = ap.parse_args()

    blob_doc = api_get(f"/repos/{REPOSITORY}/git/blobs/{MATRIX_BLOB}")
    matrix_raw = base64.b64decode(blob_doc["content"])
    if blob_doc.get("sha") != MATRIX_BLOB or git_blob_sha(matrix_raw) != MATRIX_BLOB:
        raise SystemExit("MATRIX_BLOB_IDENTITY_MISMATCH")
    matrix_doc = json.loads(matrix_raw.decode("utf-8"))

    projected = derive_projected_cells(matrix_doc)
    ids = [row["cell_id"] for row in projected]
    if len(set(ids)) != 58 or any(not CELL_RE.fullmatch(x) for x in ids):
        raise SystemExit("DERIVED_CELL_IDENTITY_INVALID")
    counts = Counter(row["frozen_mutation_class"] for row in projected)
    if dict(counts) != EXPECTED_COUNTS:
        raise SystemExit("CLASS_PARTITION_MISMATCH:" + json.dumps(dict(sorted(counts.items())), sort_keys=True))

    tree_doc = api_get(f"/repos/{REPOSITORY}/git/trees/{CELLS_TREE}?recursive=1")
    material = cell_tree_map(tree_doc)
    if set(material) != set(ids):
        raise SystemExit("CELL_TREE_IDENTITY_SET_MISMATCH")

    selected_rows: list[dict[str, Any]] = []
    excluded_count = 0
    for projected_row in projected:
        cell_id = projected_row["cell_id"]
        frozen_class = projected_row["frozen_mutation_class"]
        if frozen_class == "epistemic_adversarial":
            excluded_count += 1
            continue
        files = material[cell_id]
        if not files:
            raise SystemExit("SELECTED_CELL_HAS_NO_MATERIAL_BLOB:" + cell_id)
        selected_rows.append({
            "cell_id": cell_id,
            "frozen_mutation_class": frozen_class,
            "cell_directory_path": cell_id,
            "source_file_path_metadata": [f["path"] for f in files],
            "source_git_blob_identity": [f["sha"] for f in files],
            "source_file_size_if_available": [f["size"] for f in files],
        })

    if len(selected_rows) != 48 or excluded_count != 10:
        raise SystemExit("SELECTION_CARDINALITY_MISMATCH")

    selection_identity = [row["cell_id"] for row in selected_rows]
    body: dict[str, Any] = {
        "schema": "risu.e2-a3-a4-frozen-48-selection-manifest/v0.1",
        "status": "FROZEN_48_METADATA_SELECTION_DERIVED_PASS",
        "semantic_authority": False,
        "authority": {
            "repository": REPOSITORY,
            "matrix_git_blob": MATRIX_BLOB,
            "cells_tree_git_sha": CELLS_TREE,
            "identity_expansion_reference_git_blob": IDENTITY_EXPANSION_REFERENCE_BLOB,
            "classification_source": "FROZEN_ASSIGNMENT_GROUP_SUFFIX_ONLY",
        },
        "identity_derivation": {
            "algorithm": "FROZEN_SEED_ORDER_THEN_CLASS_ORDER_THEN_ASSIGNMENT_CARDINALITY_TO_Q_PERCENT_03D",
            "assignment_element_values_consumed": False,
            "cell_id_numeric_range_assumed": False,
            "cell_ids_derived_from_frozen_expansion_order": True,
        },
        "read_set_attestation": {
            "matrix_bytes_read_by_selector": True,
            "matrix_semantic_fields_consumed": [
                "expansion_contract.seed_order",
                "expansion_contract.class_order",
                "expansion_contract.expanded_row_count",
                "assignments.<seed>.<classification>.length",
            ],
            "assignment_element_values_consumed": False,
            "cell_source_blob_contents_read": False,
            "cell_json_contents_read": False,
            "mutation_truth_semantically_consumed": False,
            "mutation_operator_metadata_semantically_consumed": False,
            "expected_e2_prediction_consumed": False,
            "raw_blind_58_transport_consumed": False,
            "candidate_58_bytes_consumed": False,
            "git_tree_metadata_consumed": True,
        },
        "partition_counts": dict(sorted(counts.items())),
        "selected_count": 48,
        "excluded_epistemic_count": 10,
        "selected_identity_sha256": sha256(canonical_bytes(selection_identity)),
        "selected_cells": selected_rows,
    }
    body["manifest_digest_sha256"] = sha256(canonical_bytes(body))

    text = canonical_bytes(body).decode("utf-8")
    parsed = json.loads(text)
    serialized_keys: set[str] = set()

    def collect_keys(v: Any) -> None:
        if isinstance(v, dict):
            serialized_keys.update(map(str, v.keys()))
            for child in v.values():
                collect_keys(child)
        elif isinstance(v, list):
            for child in v:
                collect_keys(child)

    collect_keys(parsed)
    bad = sorted(FORBIDDEN_OUTPUT_KEYS & serialized_keys)
    if bad:
        raise SystemExit("FORBIDDEN_OUTPUT_KEY:" + ",".join(bad))

    with open(args.output, "wb") as f:
        f.write(text.encode("utf-8"))
    print(json.dumps({
        "status": "PASS",
        "selected_count": 48,
        "excluded_epistemic_count": 10,
        "selected_identity_sha256": body["selected_identity_sha256"],
        "manifest_digest_sha256": body["manifest_digest_sha256"],
        "assignment_element_values_consumed": False,
        "source_blob_contents_read": False,
    }, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
