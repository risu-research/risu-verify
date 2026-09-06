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
EXPECTED_COUNTS = {
    "positive_semantic_loss": 24,
    "semantic_preserving": 24,
    "epistemic_adversarial": 10,
}
ALLOWED_CLASS_KEYS = (
    "mutation_classification",
    "frozen_mutation_class",
    "semantic_classification",
    "semantic_class",
    "case_classification",
    "case_class",
    "qualification_class",
    "classification",
)
CLASS_ALIASES = {
    "positive_semantic_loss": "positive_semantic_loss",
    "semantic_loss": "positive_semantic_loss",
    "positive_loss": "positive_semantic_loss",
    "semantic_loss_positive": "positive_semantic_loss",
    "semantic_preserving": "semantic_preserving",
    "semantic_preservation": "semantic_preserving",
    "preserving": "semantic_preserving",
    "no_semantic_loss": "semantic_preserving",
    "epistemic_adversarial": "epistemic_adversarial",
    "adversarial_epistemic": "epistemic_adversarial",
    "epistemic": "epistemic_adversarial",
}
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
CELL_RE = re.compile(r"^Q[0-9]{3}$")


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


def normalize_token(raw: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", raw.strip().lower()).strip("_")


def normalize_class(raw: Any) -> str | None:
    if not isinstance(raw, str):
        return None
    return CLASS_ALIASES.get(normalize_token(raw))


def safe_shape(doc: Any, *, depth: int = 0, path: str = "$", out: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    if out is None:
        out = []
    if depth > 3 or len(out) >= 80:
        return out
    if isinstance(doc, dict):
        keys = sorted(map(str, doc.keys()))
        out.append({"path": path, "type": "dict", "keys": keys})
        for key in keys:
            child = doc[key]
            if isinstance(child, (dict, list)):
                safe_shape(child, depth=depth + 1, path=f"{path}.{key}", out=out)
    elif isinstance(doc, list):
        element_types = sorted({type(x).__name__ for x in doc})
        entry: dict[str, Any] = {"path": path, "type": "list", "length": len(doc), "element_types": element_types}
        dict_items = [x for x in doc if isinstance(x, dict)]
        if dict_items:
            entry["dict_element_keys"] = sorted(set().union(*(x.keys() for x in dict_items)))
        out.append(entry)
        for i, child in enumerate(doc[:4]):
            if isinstance(child, (dict, list)):
                safe_shape(child, depth=depth + 1, path=f"{path}[{i}]", out=out)
    return out


def project_cells(doc: Any) -> list[dict[str, str]]:
    projected: list[dict[str, str]] = []

    def visit(value: Any, inherited_class: str | None = None) -> None:
        if isinstance(value, dict):
            local_class = inherited_class
            class_sources: list[str] = []
            for key in ALLOWED_CLASS_KEYS:
                if key in value:
                    cls = normalize_class(value[key])
                    if cls is not None:
                        class_sources.append(cls)
            if len(set(class_sources)) > 1:
                raise RuntimeError("AMBIGUOUS_ALLOWED_CLASSIFICATION_CONTEXT")
            if class_sources:
                local_class = class_sources[0]

            cid = value.get("cell_id")
            if isinstance(cid, str) and CELL_RE.fullmatch(cid):
                if local_class is None:
                    raise RuntimeError("CELL_WITHOUT_ALLOWED_CLASSIFICATION:" + cid)
                projected.append({"cell_id": cid, "frozen_mutation_class": local_class})

            for key, child in value.items():
                if not isinstance(child, (dict, list)):
                    continue
                child_class = local_class
                key_class = normalize_class(str(key))
                if key_class is not None:
                    child_class = key_class
                visit(child, child_class)
        elif isinstance(value, list):
            for child in value:
                if isinstance(child, (dict, list)):
                    visit(child, inherited_class)

    visit(doc)
    dedup: dict[str, str] = {}
    for row in projected:
        cid = row["cell_id"]
        cls = row["frozen_mutation_class"]
        if cid in dedup and dedup[cid] != cls:
            raise RuntimeError("CONFLICTING_CELL_CLASSIFICATION:" + cid)
        dedup[cid] = cls
    return [{"cell_id": cid, "frozen_mutation_class": dedup[cid]} for cid in sorted(dedup)]


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

    try:
        projected = project_cells(matrix_doc)
    except RuntimeError as exc:
        diagnostic = {"error": str(exc), "structure_only": safe_shape(matrix_doc)}
        print("SAFE_MATRIX_STRUCTURE_DIAGNOSTIC:" + json.dumps(diagnostic, sort_keys=True), file=sys.stderr)
        raise SystemExit(2)

    if len(projected) != 58:
        diagnostic = {"projected_cell_count": len(projected), "structure_only": safe_shape(matrix_doc)}
        print("SAFE_MATRIX_STRUCTURE_DIAGNOSTIC:" + json.dumps(diagnostic, sort_keys=True), file=sys.stderr)
        raise SystemExit(2)

    ids = [row["cell_id"] for row in projected]
    if len(set(ids)) != 58:
        raise SystemExit("DUPLICATE_CELL_IDENTITY")
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
            "classification_source": "ALLOWED_PREEXISTING_MATRIX_CLASSIFICATION_ONLY",
        },
        "read_set_attestation": {
            "matrix_bytes_read_by_selector": True,
            "matrix_semantic_fields_consumed": ["cell_id", "allowed_preexisting_mutation_classification"],
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
        "source_blob_contents_read": False,
    }, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
