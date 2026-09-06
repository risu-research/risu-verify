from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

SCHEMA = "risu.e2-sanitized-opaque-58-admission-manifest/v0.1"
CASE_DOMAIN = b"risu-e2-transport-case/v0.1\0"
FROZEN_CELLS_TREE = "34a30574c7420728bff57958c815194979a622ab"
SEED_RE = re.compile(r"^(SYN-(?:PY|GO|TS)-0[12])\.(py|go|mjs|js|ts)$")
LANG = {
    "py": "python",
    "go": "go",
    "mjs": "typescript_javascript",
    "js": "typescript_javascript",
    "ts": "typescript_javascript",
}
FORBIDDEN_KEYS = {
    "expected_truth", "expected_e2_primary", "expected_e2_secondary",
    "mutation_operator", "operator", "operator_id", "operator_name",
    "operator_class", "repair", "verdict", "label", "cell_id",
    "cell_path", "source_path", "original_path", "q_id",
}

def canonical(obj: object) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def git_tree(root: Path, rel: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", f"HEAD:{rel}"],
        text=True,
    ).strip()

def manifest_digest(obj: dict) -> str:
    tmp = dict(obj)
    tmp.pop("manifest_digest_sha256", None)
    return sha256(canonical(tmp))

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--audit-output", required=True)
    args = ap.parse_args()

    root = Path(args.root).resolve()
    cells_rel = "experiments/risu-diff-e2/qualification/materialized/cells"
    cells = root / cells_rel

    observed_tree = git_tree(root, cells_rel)
    if observed_tree != FROZEN_CELLS_TREE:
        raise SystemExit(f"materialized cells tree mismatch: {observed_tree}")

    source_files = []
    for p in cells.rglob("*"):
        if not p.is_file():
            continue
        m = SEED_RE.fullmatch(p.name)
        if m:
            source_files.append((p, m.group(1), m.group(2)))

    if len(source_files) != 58:
        raise SystemExit(f"expected exactly 58 candidate source files, got {len(source_files)}")

    cases = []
    seen_ids = set()
    for p, seed_id, ext in source_files:
        data = p.read_bytes()
        source_hash = sha256(data)
        case_id = sha256(CASE_DOMAIN + seed_id.encode("ascii") + b"\0" + source_hash.encode("ascii"))
        if case_id in seen_ids:
            raise SystemExit("duplicate transport_case_id")
        seen_ids.add(case_id)
        cases.append({
            "candidate_source_sha256": source_hash,
            "language": LANG[ext],
            "seed_id": seed_id,
            "transport_case_id": case_id,
        })

    cases.sort(key=lambda row: row["transport_case_id"])
    manifest = {
        "case_count": 58,
        "cases": cases,
        "schema": SCHEMA,
        "semantic_authority": False,
    }
    manifest["manifest_digest_sha256"] = manifest_digest(manifest)

    allowed_top = {"schema", "semantic_authority", "case_count", "cases", "manifest_digest_sha256"}
    allowed_case = {"transport_case_id", "seed_id", "language", "candidate_source_sha256"}
    if set(manifest) != allowed_top:
        raise SystemExit("top-level allowlist violation")
    for row in cases:
        if set(row) != allowed_case:
            raise SystemExit("case allowlist violation")
        if set(row) & FORBIDDEN_KEYS:
            raise SystemExit("forbidden key emitted")

    emitted = canonical(manifest)
    if re.search(rb'"Q[0-9]{3}"', emitted) or b"/materialized/" in emitted or b"CELL.json" in emitted:
        raise SystemExit("original cell/path metadata leaked into manifest")

    Path(args.output).write_bytes(emitted)
    audit = {
        "case_count": len(cases),
        "cells_tree_git_sha": observed_tree,
        "forbidden_metadata_files_opened": False,
        "manifest_sha256": sha256(emitted),
        "only_candidate_source_bytes_hashed": True,
        "original_cell_identifier_emitted": False,
        "original_path_emitted": False,
        "path_projection_rule": "enumerate source files; capture only seed_id from basename and language from extension; ignore all other path components",
        "schema": "risu.e2-sanitized-opaque-admission-build-audit/v0.1",
        "status": "PASS",
        "truth_matrix_json_opened": False,
    }
    Path(args.audit_output).write_bytes(canonical(audit))
    print(json.dumps({"status":"PASS","case_count":58,"manifest_sha256":sha256(emitted)}, separators=(",",":")))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
