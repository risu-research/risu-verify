#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import unit002_mutation_control as base

CORRECTION_ID = "UNIT002_M_IMPLEMENTATION_CORRECTION_001"
CORRECTION_RECORD = ROOT / "experiments" / "unit002-m" / "IMPLEMENTATION_CORRECTION_001.json"
COLLAPSED_FROZEN_SURFACES = {
    "target.derivation.program.mechanism.expr",
    "target.derivation.program.discriminator.expr",
    "target.derivation.program.interpreter.expr",
}


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, obj: Any) -> None:
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def surface_aware_diff_paths(before: Any, after: Any, prefix: str = "") -> set[str]:
    """Represent a changed predeclared JSON subtree by its frozen parent surface.

    Outside the three already-frozen positive mutation surfaces, preserve the base
    executor's recursive diff semantics exactly. This changes no mutation bytes and
    no semantic detector predicate; it only fixes locality representation.
    """
    if prefix in COLLAPSED_FROZEN_SURFACES:
        return set() if before == after else {prefix}
    if type(before) is not type(after):
        return {prefix or "$"}
    if isinstance(before, dict):
        out: set[str] = set()
        for key in sorted(set(before) | set(after)):
            p = f"{prefix}.{key}" if prefix else str(key)
            if key not in before or key not in after:
                out.add(p)
            else:
                out |= surface_aware_diff_paths(before[key], after[key], p)
        return out
    if isinstance(before, list):
        return set() if before == after else {prefix or "$"}
    return set() if before == after else {prefix or "$"}


def output_root_from_argv() -> Path:
    args = sys.argv[1:]
    if "--output" in args:
        i = args.index("--output")
        if i + 1 >= len(args):
            raise RuntimeError("--output lacks value")
        p = Path(args[i + 1])
    else:
        p = Path(".risu/unit002-m")
    return p.resolve() if p.is_absolute() else (ROOT / p).resolve()


def annotate_effective_runner(work: Path) -> None:
    result_path = work / "MATRIX_RESULT.json"
    md_path = work / "MATRIX_RESULT.md"
    manifest_path = work / "ARTIFACT_MANIFEST.json"
    if not result_path.is_file() or not manifest_path.is_file():
        return
    result = json.loads(result_path.read_text(encoding="utf-8"))
    execution = result.setdefault("execution", {})
    execution["implementation_correction"] = {
        "id": CORRECTION_ID,
        "record_sha256": sha256_file(CORRECTION_RECORD),
        "base_executor_sha256": sha256_file(ROOT / "tools" / "unit002_mutation_control.py"),
        "correction_wrapper_sha256": sha256_file(Path(__file__)),
        "scope": "MUTATION_LOCALITY_DIFF_REPRESENTATION_ONLY",
        "frozen_plan_changed": False,
        "mutation_bytes_changed": False,
        "semantic_scoring_predicates_changed": False,
    }
    write_json(result_path, result)
    if md_path.is_file():
        with md_path.open("a", encoding="utf-8") as f:
            f.write(
                "\n## Implementation correction\n\n"
                "This eligible execution uses `UNIT002_M_IMPLEMENTATION_CORRECTION_001`, "
                "which changes only how a predeclared parent JSON mutation surface is "
                "represented by the locality checker. The frozen matrix, mutation bytes, "
                "and semantic scoring predicates are unchanged.\n"
            )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["result_sha256"] = sha256_file(result_path)
    if md_path.is_file():
        manifest["result_md_sha256"] = sha256_file(md_path)
    manifest["effective_runner"] = {
        "base_executor_sha256": sha256_file(ROOT / "tools" / "unit002_mutation_control.py"),
        "correction_wrapper_sha256": sha256_file(Path(__file__)),
        "correction_record_sha256": sha256_file(CORRECTION_RECORD),
    }
    write_json(manifest_path, manifest)


def main() -> int:
    correction = json.loads(CORRECTION_RECORD.read_text(encoding="utf-8"))
    if correction.get("correction_id") != CORRECTION_ID:
        raise RuntimeError("implementation correction identity mismatch")
    if correction.get("frozen_plan_unchanged", {}).get("git_blob_sha1") != "958bf01dbf89d338aa0f59a5d892127d65704222":
        raise RuntimeError("correction record does not bind the frozen PLAN identity")

    base.diff_paths = surface_aware_diff_paths
    rc = base.main()
    annotate_effective_runner(output_root_from_argv())
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
