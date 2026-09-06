#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import difflib
import hashlib
import json
from pathlib import Path
from typing import Any


ROOT_REL = Path("experiments/risu-diff-e2/qualification")
CATALOG_REL = ROOT_REL / "CANONICAL_SYNTHETIC_SEEDS.json"
MATRIX_REL = ROOT_REL / "MUTATION_QUALIFICATION_MATRIX_EXPANDED.jsonl"
RECIPES_DIR_REL = ROOT_REL / "mutation-recipes"
DEFAULT_CORPUS_REL = ROOT_REL / "materialized/MATERIALIZED_MUTANT_CORPUS.jsonl"

EXPECTED_MATRIX_SHA256 = "afd681d308a6f4ec8c183edd9b139c6b914fe501936cf84e5845a6a1c0d6b7cb"
EXPECTED_TRUTH_FREEZE_COMMIT = "5738a2025457afeb408a44b446019347c1289a80"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json_line(obj: dict[str, Any]) -> bytes:
    return (json.dumps(obj, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_jsonl(path: Path) -> tuple[list[dict[str, Any]], bytes]:
    raw = path.read_bytes()
    rows = [json.loads(line) for line in raw.decode("utf-8").splitlines() if line.strip()]
    return rows, raw


def seed_map(catalog: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {s["seed_id"]: s for s in catalog["seeds"]}


def apply_recipe(seed_text: str, ops: list[dict[str, Any]]) -> str:
    lines = seed_text.splitlines(keepends=True)
    ordered = sorted(ops, key=lambda x: x["seed_start_line_1based"], reverse=True)
    last_start = None
    for op in ordered:
        i1 = op["seed_start_line_1based"] - 1
        i2 = op["seed_end_line_exclusive_1based"] - 1
        if not (0 <= i1 <= i2 <= len(lines)):
            raise ValueError(f"invalid line splice [{i1},{i2})")
        if last_start is not None and i2 > last_start:
            raise ValueError("overlapping primary patch operations")
        before = "".join(lines[i1:i2]).encode("utf-8")
        if sha256(before) != op["before_sha256"]:
            raise ValueError("recipe before_sha256 mismatch")
        declared_before = base64.b64decode(op["before_b64"])
        if before != declared_before:
            raise ValueError("recipe before_b64 mismatch")
        replacement = base64.b64decode(op["after_b64"]).decode("utf-8")
        lines[i1:i2] = replacement.splitlines(keepends=True)
        last_start = i1
    return "".join(lines)


def diff_stats(seed_text: str, mutant_text: str) -> dict[str, Any]:
    a = seed_text.splitlines(keepends=True)
    b = mutant_text.splitlines(keepends=True)
    sm = difflib.SequenceMatcher(a=a, b=b, autojunk=False)
    hunks: list[dict[str, Any]] = []
    old_lines: set[int] = set()
    new_lines: set[int] = set()
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            continue
        hunks.append({
            "tag": tag,
            "seed_lines": [i1 + 1, i2],
            "mutant_lines": [j1 + 1, j2],
        })
        old_lines.update(range(i1 + 1, i2 + 1))
        new_lines.update(range(j1 + 1, j2 + 1))
    return {
        "hunks": hunks,
        "seed_changed_line_count": len(old_lines),
        "mutant_changed_line_count": len(new_lines),
    }


def bundle_hash(files: list[tuple[str, bytes]]) -> str:
    h = hashlib.sha256()
    for name, data in sorted(files):
        h.update(name.encode("utf-8"))
        h.update(b"\0")
        h.update(len(data).to_bytes(8, "big"))
        h.update(data)
    return h.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description="Deterministically materialize the frozen E2 synthetic mutation corpus.")
    ap.add_argument("--repo-root", type=Path, default=Path("."))
    ap.add_argument("--output-corpus", type=Path)
    ap.add_argument("--emit-dir", type=Path)
    ap.add_argument("--stdout-summary", action="store_true")
    args = ap.parse_args()

    root = args.repo_root.resolve()
    catalog = load_json(root / CATALOG_REL)
    matrix_rows, matrix_raw = load_jsonl(root / MATRIX_REL)
    recipes_dir = root / RECIPES_DIR_REL
    recipes_doc = load_json(recipes_dir / "INDEX.json")
    recipe_rows = [load_json(p) for p in sorted(recipes_dir.glob("Q[0-9][0-9][0-9].json"))]

    if sha256(matrix_raw) != EXPECTED_MATRIX_SHA256:
        raise SystemExit("frozen expanded matrix digest mismatch")
    if recipes_doc["authority"]["truth_freeze_commit"] != EXPECTED_TRUTH_FREEZE_COMMIT:
        raise SystemExit("recipe truth-freeze authority mismatch")
    if recipes_doc["authority"]["expanded_matrix_sha256"] != EXPECTED_MATRIX_SHA256:
        raise SystemExit("recipe matrix authority mismatch")
    if recipes_doc["anti_contamination"] != {
        "e2_prediction_consumed": False,
        "expected_truth_modified": False,
        "real_target_bytes_used": False,
    }:
        raise SystemExit("anti-contamination attestation mismatch")

    seeds = seed_map(catalog)
    recipes = {r["cell_id"]: r for r in recipe_rows}
    if len(matrix_rows) != 58 or len(recipes) != 58:
        raise SystemExit("expected exactly 58 matrix rows and recipes")

    out_rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for mrow in matrix_rows:
        cell = mrow["cell_id"]
        if cell in seen:
            raise SystemExit(f"duplicate cell {cell}")
        seen.add(cell)
        rec = recipes.get(cell)
        if rec is None:
            raise SystemExit(f"missing recipe for {cell}")
        for key in ("cell_id", "seed_id", "operator_id", "operator_class"):
            if rec[key] != mrow[key]:
                raise SystemExit(f"{cell}: recipe/matrix mismatch on {key}")

        seed = seeds[rec["seed_id"]]
        seed_path = root / seed["program_path"]
        seed_bytes = seed_path.read_bytes()
        if sha256(seed_bytes) != seed["program_sha256"] or sha256(seed_bytes) != rec["seed_sha256"]:
            raise SystemExit(f"{cell}: seed identity mismatch")
        seed_text = seed_bytes.decode("utf-8")
        mutant_text = apply_recipe(seed_text, rec["primary_patch_ops"])
        primary_name = Path(seed["program_path"]).name

        bundle: list[tuple[str, bytes]] = [(primary_name, mutant_text.encode("utf-8"))]
        for extra in rec.get("extra_files", []):
            data = base64.b64decode(extra["content_b64"])
            if sha256(data) != extra["sha256"]:
                raise SystemExit(f"{cell}: extra file digest mismatch")
            bundle.append((extra["path"], data))
        if len({name for name, _ in bundle}) != len(bundle):
            raise SystemExit(f"{cell}: duplicate bundle path")

        file_records = []
        for name, data in sorted(bundle):
            file_records.append({
                "path": name,
                "bytes": len(data),
                "sha256": sha256(data),
                "content_b64": base64.b64encode(data).decode("ascii"),
            })

        out_rows.append({
            **mrow,
            "schema": "risu.diff-e2-materialized-mutant-cell/v0.1",
            "seed_sha256": sha256(seed_bytes),
            "bundle_sha256": bundle_hash(bundle),
            "files": file_records,
            "primary_diff": diff_stats(seed_text, mutant_text),
            "evidence_fault": rec.get("evidence_fault"),
            "evidence_contract": rec.get("evidence_contract", {}),
            "truth_source": "FROZEN_MUTATION_MATRIX_NOT_E2_OUTPUT",
        })

    corpus = b"".join(canonical_json_line(row) for row in out_rows)
    output = args.output_corpus or (root / DEFAULT_CORPUS_REL)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(corpus)

    if args.emit_dir:
        emit = args.emit_dir.resolve()
        emit.mkdir(parents=True, exist_ok=True)
        for row in out_rows:
            cell_dir = emit / row["cell_id"]
            cell_dir.mkdir(parents=True, exist_ok=True)
            for f in row["files"]:
                (cell_dir / f["path"]).write_bytes(base64.b64decode(f["content_b64"]))
            metadata = {k: v for k, v in row.items() if k != "files"}
            (cell_dir / "CELL.json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    if args.stdout_summary:
        print(json.dumps({
            "status": "PASS",
            "cells": len(out_rows),
            "corpus_sha256": sha256(corpus),
            "e2_prediction_consumed": False,
            "fresh_target_bytes_consumed": False,
        }, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
