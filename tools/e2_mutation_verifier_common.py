#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from typing import Any


ROOT_REL = Path("experiments/risu-diff-e2/qualification")
CATALOG_REL = ROOT_REL / "CANONICAL_SYNTHETIC_SEEDS.json"
MATRIX_REL = ROOT_REL / "MUTATION_QUALIFICATION_MATRIX_EXPANDED.jsonl"
CORPUS_REL = ROOT_REL / "materialized/MATERIALIZED_MUTANT_CORPUS.jsonl"
CONTRACT_REL = Path("protocols/RISU_DIFF_E2_MUTATION_MATERIALIZATION_CONTRACT_v0.1.json")
MATERIALIZER_REL = Path("tools/e2_mutation_materializer.py")

EXPECTED_MATRIX_SHA256 = "afd681d308a6f4ec8c183edd9b139c6b914fe501936cf84e5845a6a1c0d6b7cb"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_jsonl(path: Path) -> tuple[list[dict[str, Any]], bytes]:
    raw = path.read_bytes()
    return [json.loads(x) for x in raw.decode("utf-8").splitlines() if x.strip()], raw


def bundle_hash(files: list[tuple[str, bytes]]) -> str:
    h = hashlib.sha256()
    for name, data in sorted(files):
        h.update(name.encode("utf-8"))
        h.update(b"\0")
        h.update(len(data).to_bytes(8, "big"))
        h.update(data)
    return h.hexdigest()


def tree_digest(root: Path) -> str:
    h = hashlib.sha256()
    for p in sorted(x for x in root.rglob("*") if x.is_file()):
        rel = p.relative_to(root).as_posix()
        data = p.read_bytes()
        h.update(rel.encode("utf-8"))
        h.update(b"\0")
        h.update(len(data).to_bytes(8, "big"))
        h.update(data)
    return h.hexdigest()


def world_lines(text: str) -> list[str]:
    return [line for line in text.splitlines() if "W_MATCH" in line or "W_STALE" in line]


def parse_last_json(stdout: str) -> dict[str, Any]:
    lines = [x for x in stdout.splitlines() if x.strip()]
    if not lines:
        raise ValueError("no runtime output")
    value = json.loads(lines[-1])
    if not isinstance(value, dict):
        raise ValueError("runtime output is not an object")
    return value


def run_program(language: str, files: list[tuple[str, bytes]], timeout: int) -> tuple[int, dict[str, Any] | None, str]:
    with tempfile.TemporaryDirectory(prefix="risu-e2-cell-") as td_s:
        td = Path(td_s)
        for name, data in files:
            p = td / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data)
        primary = td / files[0][0]
        if language == "python":
            source = primary.read_text(encoding="utf-8")
            try:
                ast.parse(source, filename=str(primary))
            except SyntaxError as exc:
                return 65, None, f"PYTHON_SYNTAX_ERROR:{exc.msg}"
            cmd = [sys.executable, "-I", "-S", str(primary)]
        elif language == "go":
            go_files = [str(td / name) for name, _ in files if name.endswith(".go")]
            cmd = ["go", "run", *go_files]
        elif language == "typescript_javascript":
            check = subprocess.run(["node", "--check", str(primary)], capture_output=True, text=True, timeout=timeout)
            if check.returncode != 0:
                return check.returncode, None, "NODE_SYNTAX_ERROR:" + check.stderr[-1000:]
            cmd = ["node", str(primary)]
        else:
            raise ValueError(f"unsupported language {language}")

        cp = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if cp.returncode != 0:
            return cp.returncode, None, cp.stderr[-2000:]
        return 0, parse_last_json(cp.stdout), cp.stderr[-1000:]


def compare_matrix_row(m: dict[str, Any], c: dict[str, Any]) -> None:
    for key in ("cell_id", "seed_id", "operator_id", "operator_class", "expected_truth", "expected_e2_primary"):
        if m[key] != c[key]:
            raise AssertionError(f"{m['cell_id']}: corpus/matrix mismatch on {key}")


