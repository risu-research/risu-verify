#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterable, List, Sequence

from risu_e1.acquisition import (
    MAX_TOTAL_FILES,
    acquisition_plan_digest,
    dependency_tokens_from_text,
    expansion_select,
    round0_select,
)
from risu_e1.engine import verify_output_dir, write_outputs
from tools.risu_e1_machine_first import engine_identity

ROOT = Path(__file__).resolve().parents[1]
FIXED_RUN_ID = "unit004-e1-first-prediction"
INPUT_SCHEMA = "risu.diff-e0-machine-input/v0.1"
SELECTION_SCHEMA = "risu.unit004-e1-round0-selection/v0.1alpha1"
ACQUISITION_SCHEMA = "risu.unit004-e1-acquisition/v0.1alpha1"
RECORD_SCHEMA = "risu.unit004-e1-first-seal-record/v0.1alpha1"


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_json(path: Path) -> Dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"expected JSON object: {path}")
    return data


def read_tree_paths(path: Path) -> List[str]:
    rows = sorted({line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()})
    for row in rows:
        p = PurePosixPath(row)
        if p.is_absolute() or ".." in p.parts:
            raise ValueError(f"unsafe tree path: {row}")
    return rows


def binding_target(binding: Dict[str, Any]) -> Dict[str, Any]:
    if binding.get("status") != "BOUND_BEFORE_TARGET_TREE_OR_CONTENT_ACCESS":
        raise ValueError("target binding is not in the required frozen state")
    if binding.get("selection", {}).get("substitution_used") is not False:
        raise ValueError("this harness accepts only the already-bound non-substituted target")
    target = binding.get("target")
    if not isinstance(target, dict) or not target.get("materializable"):
        raise ValueError("bound target is not materializable")
    frozen = binding.get("frozen_e1", {})
    if frozen.get("engine_identity_digest") != engine_identity()["engine_identity_digest"]:
        raise ValueError("frozen E1 identity does not match target binding")
    return target


def make_round0(binding_path: Path, tree_paths_path: Path, out_path: Path) -> Dict[str, Any]:
    binding = load_json(binding_path)
    target = binding_target(binding)
    tree_paths = read_tree_paths(tree_paths_path)
    rows = round0_select(tree_paths, target["screened_operation"], [])
    result = {
        "schema": SELECTION_SCHEMA,
        "binding_id": binding["binding_id"],
        "target_revision": target["revision"],
        "target_tree_sha": target["tree_sha"],
        "screened_operation": target["screened_operation"],
        "surface_arguments": [],
        "tree_path_count": len(tree_paths),
        "round0": rows,
        "round0_selected_count": len(rows),
        "round0_plan_digest": acquisition_plan_digest([rows]),
        "selector": "FROZEN_RISU_E1_ROUND0",
        "human_selection": False,
        "target_content_bytes_consumed": 0,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(canonical_bytes(result))
    return result


def git_show_bytes(target_git: Path, revision: str, relpath: str) -> bytes:
    proc = subprocess.run(
        ["git", "-C", str(target_git), "show", f"{revision}:{relpath}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"selected blob materialization failed for {relpath}: {proc.stderr.decode(errors='replace')}")
    return proc.stdout


def language_for(path: str) -> str:
    suffix = PurePosixPath(path).suffix.lower()
    return {
        ".py": "python",
        ".go": "go",
        ".md": "markdown",
        ".yaml": "yaml",
        ".yml": "yaml",
        ".json": "json",
        ".txt": "text",
    }.get(suffix, "unknown")


def materialize_rows(
    rows: Sequence[Dict[str, Any]],
    target_git: Path,
    revision: str,
    evidence_dir: Path,
    already: Dict[str, Dict[str, Any]],
) -> List[str]:
    texts: List[str] = []
    for row in rows:
        path = row["path"]
        if path in already:
            continue
        raw = git_show_bytes(target_git, revision, path)
        evidence_path = PurePosixPath("evidence") / PurePosixPath(path)
        disk_path = evidence_dir.parent / evidence_path
        disk_path.parent.mkdir(parents=True, exist_ok=True)
        disk_path.write_bytes(raw)
        rec = {
            "path": evidence_path.as_posix(),
            "sha256": sha256_bytes(raw),
            "kind": "TARGET_TEXT",
            "language": language_for(path),
            "target_path": path,
            "bytes": len(raw),
        }
        already[path] = rec
        texts.append(raw.decode("utf-8", errors="replace"))
    return texts


def execute(
    binding_path: Path,
    round0_path: Path,
    tree_paths_path: Path,
    target_git: Path,
    artifact_dir: Path,
) -> Dict[str, Any]:
    binding = load_json(binding_path)
    target = binding_target(binding)
    selection = load_json(round0_path)
    if selection.get("binding_id") != binding.get("binding_id"):
        raise ValueError("round0 selection is not bound to this target")
    if selection.get("target_revision") != target["revision"] or selection.get("target_tree_sha") != target["tree_sha"]:
        raise ValueError("round0 selection target identity mismatch")
    tree_paths = read_tree_paths(tree_paths_path)
    recomputed = make_round0(binding_path, tree_paths_path, artifact_dir / "_round0_recomputed.json")
    if canonical_bytes(recomputed) != canonical_bytes(selection):
        raise ValueError("round0 selection failed deterministic replay")
    (artifact_dir / "_round0_recomputed.json").unlink()

    packet_dir = artifact_dir / "packet"
    evidence_dir = packet_dir / "evidence"
    output_dir = artifact_dir / "output"
    packet_dir.mkdir(parents=True, exist_ok=True)
    selected: Dict[str, Dict[str, Any]] = {}
    rounds: List[List[Dict[str, Any]]] = [list(selection["round0"])]

    texts = materialize_rows(rounds[0], target_git, target["revision"], evidence_dir, selected)
    dependency_tokens = set()
    for text in texts:
        dependency_tokens |= dependency_tokens_from_text(text, "machine-selected")

    for round_number in (1, 2):
        already_paths = sorted(selected)
        remaining = max(0, MAX_TOTAL_FILES - len(already_paths))
        rows = expansion_select(tree_paths, dependency_tokens, already_paths, round_number, remaining)
        rounds.append(rows)
        new_texts = materialize_rows(rows, target_git, target["revision"], evidence_dir, selected)
        for text in new_texts:
            dependency_tokens |= dependency_tokens_from_text(text, "machine-selected")

    evidence_files = [
        {k: rec[k] for k in ("path", "sha256", "kind", "language")}
        for _, rec in sorted(selected.items())
    ]
    machine_input = {
        "schema": INPUT_SCHEMA,
        "run_id": FIXED_RUN_ID,
        "unit_id": binding["enrollment"]["unit_id"],
        "target_revision": target["revision"],
        "screened_operation": target["screened_operation"],
        "surface": {"name": target["screened_operation"], "arguments": []},
        "evidence_files": evidence_files,
        "acquisition": {
            "selector": "FROZEN_RISU_E1_ADAPTIVE",
            "plan_digest": acquisition_plan_digest(rounds),
            "round_counts": [len(x) for x in rounds],
            "selected_target_paths": sorted(selected),
            "human_selection": False,
            "human_semantic_reranking": False,
        },
    }
    machine_bytes = canonical_bytes(machine_input)
    (packet_dir / "MACHINE_INPUT.json").write_bytes(machine_bytes)

    acquisition = {
        "schema": ACQUISITION_SCHEMA,
        "binding_id": binding["binding_id"],
        "target_revision": target["revision"],
        "target_tree_sha": target["tree_sha"],
        "rounds": rounds,
        "round_counts": [len(x) for x in rounds],
        "selected_target_paths": sorted(selected),
        "evidence_count": len(selected),
        "evidence": [
            {k: rec[k] for k in ("target_path", "path", "sha256", "language", "bytes")}
            for _, rec in sorted(selected.items())
        ],
        "dependency_token_count": len(dependency_tokens),
        "plan_digest": acquisition_plan_digest(rounds),
        "human_selection": False,
        "human_semantic_reranking": False,
    }
    (artifact_dir / "ACQUISITION_MANIFEST.json").write_bytes(canonical_bytes(acquisition))
    shutil.copy2(binding_path, artifact_dir / "TARGET_BINDING.json")
    shutil.copy2(round0_path, artifact_dir / "ROUND0_SELECTION.json")

    write_outputs(packet_dir, output_dir, engine_identity(), ROOT / "tools" / "risu_e1_go_extract.go")
    verified = verify_output_dir(output_dir)
    seal_bytes = (output_dir / "E1_OUTPUT_SEAL.json").read_bytes()
    record = {
        "schema": RECORD_SCHEMA,
        "status": "FIRST_VALID_E1_SEAL_EMITTED",
        "run_id": FIXED_RUN_ID,
        "binding_id": binding["binding_id"],
        "target_revision": target["revision"],
        "target_tree_sha": target["tree_sha"],
        "engine_identity_digest": engine_identity()["engine_identity_digest"],
        "round0_plan_digest": selection["round0_plan_digest"],
        "acquisition_plan_digest": acquisition["plan_digest"],
        "evidence_count": acquisition["evidence_count"],
        "machine_input_sha256": sha256_bytes(machine_bytes),
        "e1_output_seal_sha256": sha256_bytes(seal_bytes),
        "seal_digest": verified["seal_digest"],
        "prediction_value_intentionally_not_copied_into_record": True,
        "canonical_scientific_authority": False,
    }
    (artifact_dir / "FIRST_SEAL_RECORD.json").write_bytes(canonical_bytes(record))
    return record


def main() -> int:
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("select")
    s.add_argument("--binding", type=Path, required=True)
    s.add_argument("--tree-paths", type=Path, required=True)
    s.add_argument("--out", type=Path, required=True)
    e = sub.add_parser("execute")
    e.add_argument("--binding", type=Path, required=True)
    e.add_argument("--round0", type=Path, required=True)
    e.add_argument("--tree-paths", type=Path, required=True)
    e.add_argument("--target-git", type=Path, required=True)
    e.add_argument("--artifact-dir", type=Path, required=True)
    args = p.parse_args()
    if args.cmd == "select":
        out = make_round0(args.binding, args.tree_paths, args.out)
        print(json.dumps({"status": "PASS", "tree_path_count": out["tree_path_count"], "round0_selected_count": out["round0_selected_count"], "round0_plan_digest": out["round0_plan_digest"]}, sort_keys=True))
        return 0
    record = execute(args.binding, args.round0, args.tree_paths, args.target_git, args.artifact_dir)
    print(json.dumps({"status": "PASS", "seal_digest": record["seal_digest"], "evidence_count": record["evidence_count"], "machine_input_sha256": record["machine_input_sha256"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
