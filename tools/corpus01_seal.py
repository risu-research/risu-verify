#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))

import corpus01_unit_harness as h
from corpus01_bound_evidence import apply_bound_evidence
from corpus01_primary_v08 import sanitize_report_metadata

SCHEMA = "risu.corpus-unit-seal/v0.8alpha1"


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def sha256_file(path: Path) -> str:
    x = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            x.update(chunk)
    return x.hexdigest()


def run(cmd: list[str], *, binary: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd, cwd=str(ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=not binary,
    )


def repo_rel(path: Path) -> str:
    return str(path.resolve().relative_to(ROOT)).replace("\\", "/")


def require_clean_authoring_head(manifest_path: Path, seal_path: Path, freeze_ref: str) -> str:
    rev = run(["git", "rev-parse", "--verify", f"{freeze_ref}^{{commit}}"])
    if rev.returncode != 0:
        raise RuntimeError(f"freeze ref is not a commit: {freeze_ref}")
    freeze = (rev.stdout or "").strip()
    head = run(["git", "rev-parse", "HEAD"])
    if head.returncode != 0:
        raise RuntimeError("cannot resolve HEAD")
    head_sha = (head.stdout or "").strip()
    if freeze != head_sha:
        raise RuntimeError("v0.8 seal requires the scientific freeze commit to equal current HEAD")

    if manifest_path.exists() or seal_path.exists():
        raise RuntimeError("seal outputs already exist; remove them before a fresh deterministic seal")
    status = run(["git", "status", "--porcelain"])
    if status.returncode != 0:
        raise RuntimeError("cannot inspect git working tree")
    dirty = [x for x in (status.stdout or "").splitlines() if x.strip()]
    if dirty:
        raise RuntimeError("authoring tree must be clean and committed before seal: " + "; ".join(dirty))
    return freeze


def seal_unit(unit_dir: Path, freeze_ref: str, manifest_path: Path, seal_path: Path) -> dict:
    unit_dir = unit_dir.resolve()
    unit_dir.relative_to(ROOT)
    manifest_path = manifest_path.resolve()
    seal_path = seal_path.resolve()
    manifest_path.relative_to(ROOT)
    seal_path.relative_to(ROOT)

    freeze = require_clean_authoring_head(manifest_path, seal_path, freeze_ref)
    audit = h.audit_unit(unit_dir, include_compile_probe=True)
    if audit.get("status") != "PASS":
        raise RuntimeError("read-only audit blocked seal: " + ", ".join(audit.get("blocker_keys") or []))

    manifest = h.build_primary_manifest(unit_dir, freeze, manifest_path)
    manifest["post_freeze_allowed_paths"] = sorted({repo_rel(manifest_path), repo_rel(seal_path)})
    manifest["seal_record_path"] = repo_rel(seal_path)
    manifest["execution_infrastructure"] = {
        "name": "RISU Corpus protocol-preserving infrastructure",
        "version": "0.8",
        "primary_runner": "tools/corpus01_primary_v08.py",
        "bound_evidence_compiler": "tools/corpus01_bound_evidence.py",
        "zero_hand_edited_hash_scope": "PRIMARY_SEALING_AND_EXECUTION_METADATA",
    }
    write_json(manifest_path, manifest)

    gate = run([sys.executable, str(TOOLS / "corpus01_primary_gate.py"), repo_rel(manifest_path), "--json"])
    if gate.returncode != 0:
        manifest_path.unlink(missing_ok=True)
        raise RuntimeError("freeze gate rejected generated manifest:\n" + (gate.stdout or ""))

    mat = run([sys.executable, str(TOOLS / "materialize_case_bundles.py")])
    if mat.returncode != 0:
        manifest_path.unlink(missing_ok=True)
        raise RuntimeError("retained case materialization failed:\n" + (mat.stdout or ""))

    instance_path = ROOT / manifest["instance_path"]
    with tempfile.TemporaryDirectory(prefix="risu-corpus-v08-seal-") as td:
        case_dir = Path(td) / "compiled-case"
        compile_cmd = [
            sys.executable, str(TOOLS / "corpus01_compile.py"), str(instance_path), "--output", str(case_dir)
        ]
        overlay = manifest.get("provenance_overlay")
        if overlay:
            compile_cmd.extend(["--provenance-overlay", str(ROOT / overlay["path"])])
        comp = run(compile_cmd)
        if comp.returncode != 0:
            manifest_path.unlink(missing_ok=True)
            raise RuntimeError("prospective compile probe failed:\n" + (comp.stdout or ""))

        target = read_json(unit_dir / "TARGET_LANE.json")
        boundary = read_json(unit_dir / "BOUNDARY_MODEL.json")
        sanitation = sanitize_report_metadata(case_dir, target, boundary)
        bound = apply_bound_evidence(case_dir, unit_dir, manifest)
        pre = run([
            sys.executable, str(TOOLS / "corpus01_provenance_preflight.py"),
            str(case_dir / "assurance" / "adapter.json"), "--json"
        ])
        if pre.returncode != 0:
            manifest_path.unlink(missing_ok=True)
            raise RuntimeError("provenance preflight failed during seal:\n" + (pre.stdout or ""))

        compile_manifest = case_dir / "VBE_COMPILE_MANIFEST.json"
        bound_manifest = case_dir / "BOUND_EVIDENCE_MANIFEST.json"
        sanitation_manifest = case_dir / "REPORT_METADATA_SANITIZATION.json"
        probe = {
            "compiled_adapter_sha256": sha256_file(case_dir / "assurance" / "adapter.json"),
            "compiled_source_contract_sha256": sha256_file(case_dir / "assurance" / "source-contract.json"),
            "compile_manifest_sha256": sha256_file(compile_manifest),
            "bound_evidence_manifest_sha256": sha256_file(bound_manifest),
            "report_metadata_sanitization_sha256": sha256_file(sanitation_manifest),
            "bound_binding_count": bound["binding_count"],
            "removed_unbound_path_count": len(bound["removed_unbound_paths"]),
            "provenance_preflight_output_sha256": hashlib.sha256((pre.stdout or "").encode("utf-8")).hexdigest(),
            "adapter_and_source_unchanged_by_bound_compiler": True,
            "semantic_assurance_unchanged_by_report_sanitation": sanitation["semantic_assurance_inputs_unchanged"],
        }

    seal = {
        "schema": SCHEMA,
        "status": "READY_FOR_PRIMARY",
        "unit_id": manifest["unit_id"],
        "instance_id": manifest["instance_id"],
        "authoring_freeze_commit": freeze,
        "manifest_path": repo_rel(manifest_path),
        "manifest_sha256": sha256_file(manifest_path),
        "gates": {
            "read_only_audit": "PASS",
            "freeze_gate": "PASS",
            "bound_evidence_compile": "PASS",
            "provenance_preflight": "PASS",
        },
        "compile_probe": probe,
        "controls": {
            "primary_verifier_executed_during_seal": False,
            "scientific_input_bytes_modified": False,
            "semantic_outcome_observed_during_seal": False,
            "hashes_in_primary_manifest_generated_from_frozen_bytes": True,
            "manual_primary_manifest_hash_entry_required": False,
            "seal_is_mechanical_readiness_record_not_scientific_result": True,
        },
        "next_action": "Commit PRIMARY_RUN_MANIFEST.json and UNIT_SEAL.json, require CI, then explicitly dispatch the generic v0.8 primary workflow. Do not edit generated hashes by hand.",
    }
    write_json(seal_path, seal)
    return seal


def main() -> int:
    ap = argparse.ArgumentParser(description="One-command mechanical seal for a prospective Corpus 0.1 unit")
    ap.add_argument("unit_dir")
    ap.add_argument("--freeze-ref", default="HEAD")
    ap.add_argument("--manifest", default="PRIMARY_RUN_MANIFEST.json")
    ap.add_argument("--seal", default="UNIT_SEAL.json")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    manifest_path: Path | None = None
    seal_path: Path | None = None
    try:
        unit_dir = Path(args.unit_dir)
        if not unit_dir.is_absolute():
            unit_dir = (ROOT / unit_dir).resolve()
        manifest_path = Path(args.manifest)
        if not manifest_path.is_absolute():
            manifest_path = unit_dir / manifest_path
        seal_path = Path(args.seal)
        if not seal_path.is_absolute():
            seal_path = unit_dir / seal_path
        result = seal_unit(unit_dir, args.freeze_ref, manifest_path, seal_path)
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print("CORPUS UNIT SEAL v0.8: READY_FOR_PRIMARY")
            print(f"  manifest={repo_rel(manifest_path)}")
            print(f"  seal={repo_rel(seal_path)}")
            print(f"  freeze={result['authoring_freeze_commit']}")
        return 0
    except Exception as exc:
        # Never leave a partial seal record. A generated manifest may remain only if the
        # failure occurred after its integrity checks; remove it to force a fresh seal.
        if seal_path is not None and seal_path.exists():
            seal_path.unlink()
        if manifest_path is not None and manifest_path.exists():
            manifest_path.unlink()
        print(f"CORPUS UNIT SEAL v0.8: FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
