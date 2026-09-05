#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))

import corpus01_unit_harness as h
from corpus01_bound_evidence import apply_bound_evidence

SCHEMA = "risu.corpus-primary-runner/v0.8alpha1"
VALID_SEMANTIC = h.VALID_SEMANTIC


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


def run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=str(ROOT), text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)


def repo_rel(path: Path) -> str:
    return str(path.resolve().relative_to(ROOT)).replace("\\", "/")


def verify_seal(manifest_path: Path, manifest: dict) -> dict:
    rel = str(manifest.get("seal_record_path") or "")
    if not rel:
        raise RuntimeError("v0.8 primary requires manifest.seal_record_path")
    seal_path = (ROOT / rel).resolve()
    seal_path.relative_to(ROOT)
    if not seal_path.is_file():
        raise RuntimeError(f"seal record missing: {rel}")
    seal = read_json(seal_path)
    if seal.get("schema") != "risu.corpus-unit-seal/v0.8alpha1":
        raise RuntimeError("unsupported seal schema")
    if seal.get("status") != "READY_FOR_PRIMARY":
        raise RuntimeError("seal is not READY_FOR_PRIMARY")
    if seal.get("unit_id") != manifest.get("unit_id"):
        raise RuntimeError("seal unit_id mismatch")
    if seal.get("authoring_freeze_commit") != manifest.get("authoring_freeze_commit"):
        raise RuntimeError("seal freeze commit mismatch")
    if seal.get("manifest_sha256") != sha256_file(manifest_path):
        raise RuntimeError("seal does not pin current primary manifest bytes")
    controls = seal.get("controls") or {}
    if controls.get("primary_verifier_executed_during_seal") is not False:
        raise RuntimeError("seal does not prove non-execution of the primary verifier")
    if controls.get("scientific_input_bytes_modified") is not False:
        raise RuntimeError("seal does not prove frozen scientific bytes were untouched")
    gates = seal.get("gates") or {}
    for name in ("read_only_audit", "freeze_gate", "bound_evidence_compile", "provenance_preflight"):
        if gates.get(name) != "PASS":
            raise RuntimeError(f"seal gate did not PASS: {name}")
    return {"path": rel, "sha256": sha256_file(seal_path), "status": "PASS"}


def sanitize_report_metadata(case_dir: Path, target_lane: dict, boundary: dict) -> dict:
    """Replace all inherited human-report identity/scope metadata from frozen unit records only."""
    case_path = case_dir / "case.json"
    adapter_path = case_dir / "assurance" / "adapter.json"
    source_path = case_dir / "assurance" / "source-contract.json"
    adapter_sha = sha256_file(adapter_path)
    source_sha = sha256_file(source_path)
    before_case_sha = sha256_file(case_path)

    case = read_json(case_path)
    before = {
        "display": case.get("display"),
        "external_system": case.get("external_system"),
        "claim_boundary": case.get("claim_boundary"),
    }
    target = target_lane.get("target") or {}
    case.pop("display", None)
    case["external_system"] = {
        "project": target.get("repository"),
        "projection": target.get("operation"),
        "pinned_projection_ref": target.get("revision"),
    }
    if target.get("source_library_pin"):
        case["external_system"]["source_library_pin"] = target.get("source_library_pin")
    case["claim_boundary"] = {
        "source": "FROZEN_BOUNDARY_MODEL",
        "claim_scope": boundary.get("claim_scope") or {},
        "effect_cut": boundary.get("effect_cut") or {},
    }
    write_json(case_path, case)

    if sha256_file(adapter_path) != adapter_sha:
        raise RuntimeError("report metadata sanitation changed adapter.json")
    if sha256_file(source_path) != source_sha:
        raise RuntimeError("report metadata sanitation changed source-contract.json")

    record = {
        "schema": "risu.corpus-report-metadata-sanitization/v0.8alpha1",
        "mode": "FROZEN_TARGET_AND_BOUNDARY_ONLY",
        "before_case_sha256": before_case_sha,
        "after_case_sha256": sha256_file(case_path),
        "before": before,
        "after_external_system": case["external_system"],
        "after_claim_boundary": case["claim_boundary"],
        "adapter_sha256_unchanged": adapter_sha,
        "source_contract_sha256_unchanged": source_sha,
        "semantic_assurance_inputs_unchanged": True,
    }
    write_json(case_dir / "REPORT_METADATA_SANITIZATION.json", record)
    return record


def execute(manifest_path: Path, work_root: Path) -> dict:
    manifest_path = manifest_path.resolve()
    manifest_path.relative_to(ROOT)
    manifest = read_json(manifest_path)
    if manifest.get("schema") != "risu.corpus-primary-run-manifest/v0.1alpha1":
        raise RuntimeError("unsupported primary-run manifest schema")
    if manifest.get("status") != "READY_FOR_FIRST_PRIMARY_EXECUTION":
        raise RuntimeError("manifest is not READY_FOR_FIRST_PRIMARY_EXECUTION")

    seal_status = verify_seal(manifest_path, manifest)
    unit_dir = manifest_path.parent
    audit = h.audit_unit(unit_dir, include_compile_probe=True)
    if audit.get("status") != "PASS":
        raise RuntimeError("pre-primary audit blocked execution: " + ", ".join(audit.get("blocker_keys") or []))

    telemetry: dict[str, float] = {}
    t = time.monotonic()
    corpus = run([sys.executable, str(TOOLS / "corpus01_validate.py"), "--json"])
    telemetry["corpus_validate_seconds"] = round(time.monotonic() - t, 6)
    if corpus.returncode != 0:
        raise RuntimeError("Corpus procedural validator failed:\n" + (corpus.stdout or ""))

    t = time.monotonic()
    gate = run([sys.executable, str(TOOLS / "corpus01_primary_gate.py"), repo_rel(manifest_path), "--json"])
    telemetry["freeze_gate_seconds"] = round(time.monotonic() - t, 6)
    if gate.returncode != 0:
        raise RuntimeError("AUTHOR_ACCEPTED freeze gate failed:\n" + (gate.stdout or ""))

    t = time.monotonic()
    mat = run([sys.executable, str(TOOLS / "materialize_case_bundles.py")])
    telemetry["materialize_seconds"] = round(time.monotonic() - t, 6)
    if mat.returncode != 0:
        raise RuntimeError("retained case materialization failed:\n" + (mat.stdout or ""))

    if work_root.exists():
        shutil.rmtree(work_root)
    case_dir = work_root / "compiled-case"
    output_dir = work_root / "verifier-output"
    console = work_root / "console.json"
    exit_file = work_root / "semantic-exit-code.txt"
    observation_file = work_root / "primary-observation.json"
    bundle_dir = work_root / "bundle"
    work_root.mkdir(parents=True, exist_ok=True)

    instance_path = ROOT / manifest["instance_path"]
    compile_cmd = [sys.executable, str(TOOLS / "corpus01_compile.py"), str(instance_path), "--output", str(case_dir)]
    overlay = manifest.get("provenance_overlay")
    if overlay:
        compile_cmd.extend(["--provenance-overlay", str(ROOT / overlay["path"])])
    t = time.monotonic()
    comp = run(compile_cmd)
    telemetry["compile_seconds"] = round(time.monotonic() - t, 6)
    if comp.returncode != 0:
        raise RuntimeError("prospective compilation failed:\n" + (comp.stdout or ""))

    target_lane = read_json(unit_dir / "TARGET_LANE.json")
    boundary = read_json(unit_dir / "BOUNDARY_MODEL.json")
    sanitation = sanitize_report_metadata(case_dir, target_lane, boundary)

    t = time.monotonic()
    bound = apply_bound_evidence(case_dir, unit_dir, manifest)
    telemetry["bound_evidence_seconds"] = round(time.monotonic() - t, 6)

    t = time.monotonic()
    pre = run([sys.executable, str(TOOLS / "corpus01_provenance_preflight.py"), str(case_dir / "assurance" / "adapter.json"), "--json"])
    telemetry["provenance_preflight_seconds"] = round(time.monotonic() - t, 6)
    if pre.returncode != 0:
        raise RuntimeError("compiled provenance preflight failed:\n" + (pre.stdout or ""))

    t = time.monotonic()
    verify = subprocess.run(
        [str(ROOT / "risu-verify"), "verify", str(case_dir), "--output", str(output_dir), "--json"],
        cwd=str(ROOT), text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    telemetry["verifier_seconds"] = round(time.monotonic() - t, 6)
    console.write_text(verify.stdout or "", encoding="utf-8")
    exit_file.write_text(f"{verify.returncode}\n", encoding="utf-8")
    if verify.returncode not in VALID_SEMANTIC:
        detail = verify.stdout or ""
        failure = output_dir / "failure.log"
        if failure.is_file():
            detail += "\n--- failure.log ---\n" + failure.read_text(encoding="utf-8", errors="replace")
        raise RuntimeError(f"invalid verifier/toolchain exit {verify.returncode}:\n{detail}")

    report = read_json(output_dir / "report.json")
    if report.get("product_status") not in VALID_SEMANTIC[verify.returncode]:
        raise RuntimeError("semantic exit/status mismatch")
    compile_manifest = read_json(case_dir / "VBE_COMPILE_MANIFEST.json")
    observation = h._write_observation(
        manifest, report, compile_manifest, verify.returncode,
        {"case": case_dir, "output": output_dir},
    )
    observation["runner_schema"] = SCHEMA
    observation["seal_record_sha256"] = seal_status["sha256"]
    observation["bound_evidence_manifest_sha256"] = sha256_file(case_dir / "BOUND_EVIDENCE_MANIFEST.json")
    observation["report_metadata_sanitization_sha256"] = sha256_file(case_dir / "REPORT_METADATA_SANITIZATION.json")
    write_json(observation_file, observation)

    checksum_targets = (
        [p for p in case_dir.rglob("*") if p.is_file()]
        + [p for p in output_dir.rglob("*") if p.is_file()]
        + [console, exit_file, observation_file]
    )
    write_json(
        work_root / "ARTIFACT_MANIFEST.json",
        {
            "schema": "risu.corpus-primary-artifact-manifest/v0.8alpha1",
            "unit_id": manifest["unit_id"],
            "entries": h._checksum_entries(work_root, checksum_targets),
        },
    )

    t = time.monotonic()
    zip_path, bundle = h.build_self_contained_bundle(
        manifest, case_dir, output_dir, console, exit_file, observation_file, bundle_dir
    )
    telemetry["package_seconds"] = round(time.monotonic() - t, 6)
    telemetry["total_mechanical_seconds"] = round(sum(telemetry.values()), 6)
    write_json(
        work_root / "HARNESS_TELEMETRY.json",
        {
            "schema": "risu.corpus-harness-telemetry/v0.8alpha1",
            "unit_id": manifest["unit_id"],
            "measured": telemetry,
            "scope": "MECHANICAL_PRIMARY_HARNESS_ONLY",
            "authoring_time_not_inferred": True,
        },
    )

    result = {
        "schema": SCHEMA,
        "status": "VALID_SEMANTIC_OUTCOME",
        "unit_id": manifest["unit_id"],
        "product_status": report.get("product_status"),
        "semantic_exit_code": verify.returncode,
        "seal": seal_status,
        "bound_evidence": {
            "binding_count": bound["binding_count"],
            "removed_unbound_paths": bound["removed_unbound_paths"],
            "manifest_sha256": sha256_file(case_dir / "BOUND_EVIDENCE_MANIFEST.json"),
        },
        "report_metadata_sanitization": sanitation,
        "self_contained_bundle": bundle,
        "telemetry": telemetry,
        "scientific_outcome_not_mapped_to_ci_failure": True,
    }
    write_json(work_root / "HARNESS_RESULT.json", result)
    return result


def main() -> int:
    ap = argparse.ArgumentParser(description="Execute one sealed Corpus 0.1 primary under infrastructure v0.8")
    ap.add_argument("manifest")
    ap.add_argument("--work-root")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    try:
        manifest_path = Path(args.manifest)
        if not manifest_path.is_absolute():
            manifest_path = (ROOT / manifest_path).resolve()
        manifest = read_json(manifest_path)
        work_root = Path(args.work_root).resolve() if args.work_root else ROOT / ".risu" / "corpus01-v08" / str(manifest.get("unit_id") or "unknown")
        result = execute(manifest_path, work_root)
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print(f"CORPUS PRIMARY v0.8: {result['status']} product={result['product_status']} rc={result['semantic_exit_code']}")
        return 0
    except Exception as exc:
        print(f"CORPUS PRIMARY v0.8: FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
