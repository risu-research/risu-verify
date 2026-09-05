#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
from collections import deque
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
VALID_SEMANTIC = {
    0: {"PRESERVED", "PRESERVED_IN_DECLARED_SCOPE"},
    10: {"CONSEQUENCE_REGRESSION"},
    20: {"INCOMPLETE_ASSURANCE"},
}
HARNESS_SCHEMA = "risu.corpus-unit-harness/v0.1alpha1"
BUNDLE_SCHEMA = "risu.corpus-primary-self-contained-bundle/v0.1alpha1"
FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def repo_rel(path: Path) -> str:
    return str(path.resolve().relative_to(ROOT)).replace("\\", "/")


def run(cmd: list[str], *, cwd: Path = ROOT, capture: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        cwd=str(cwd),
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.STDOUT if capture else None,
    )


def finding(code: str, subject: str, message: str, *, severity: str = "BLOCKER", detail: Any = None) -> dict:
    out = {
        "code": code,
        "subject": subject,
        "key": f"{code}:{subject}" if subject else code,
        "severity": severity,
        "message": message,
    }
    if detail is not None:
        out["detail"] = detail
    return out


def _reachable(start: str, targets: set[str], adjacency: dict[str, set[str]]) -> bool:
    q = deque([start])
    seen = {start}
    while q:
        cur = q.popleft()
        if cur in targets:
            return True
        for nxt in adjacency.get(cur, set()):
            if nxt not in seen:
                seen.add(nxt)
                q.append(nxt)
    return False


def provenance_findings(envelope_or_adapter: dict) -> list[dict]:
    provenance = envelope_or_adapter.get("provenance") or {}
    if not provenance and "adapter_base" in envelope_or_adapter:
        provenance = (envelope_or_adapter.get("adapter_base") or {}).get("provenance") or {}
    derivation_facts = envelope_or_adapter.get("derivation_facts")
    if derivation_facts is None:
        derivation_facts = (((envelope_or_adapter.get("target") or {}).get("derivation") or {}).get("facts") or [])

    nodes = {n.get("id") for n in provenance.get("nodes") or [] if n.get("id")}
    exact_roots = set((provenance.get("claim_roots") or {}).get("EXACT") or [])
    out: list[dict] = []
    if not exact_roots or not exact_roots.issubset(nodes):
        out.append(finding("EXACT_CLAIM_ROOT_INVALID", "", "EXACT claim root is missing or references a missing node"))
        return out

    adjacency: dict[str, set[str]] = {}
    for edge in provenance.get("edges") or []:
        src, dst = edge.get("from"), edge.get("to")
        if src not in nodes or dst not in nodes:
            out.append(
                finding(
                    "PROVENANCE_EDGE_NODE_MISSING",
                    f"{src}->{dst}",
                    "provenance edge references a missing node",
                    detail=edge,
                )
            )
            continue
        adjacency.setdefault(src, set()).add(dst)

    for fact in derivation_facts or []:
        if fact.get("status") != "ESTABLISHED":
            continue
        fact_id = str(fact.get("id") or "")
        node = fact.get("provenance_node")
        if node not in nodes:
            out.append(
                finding(
                    "PROVENANCE_NODE_MISSING",
                    fact_id,
                    "ESTABLISHED derivation fact has no valid provenance node",
                    detail={"provenance_node": node},
                )
            )
            continue
        if not _reachable(str(node), exact_roots, adjacency):
            out.append(
                finding(
                    "PROVENANCE_NOT_UPSTREAM_OF_EXACT",
                    fact_id,
                    "ESTABLISHED derivation fact is not upstream of the EXACT claim",
                    detail={"provenance_node": node, "exact_roots": sorted(exact_roots)},
                )
            )
    return out


def _require_json(unit_dir: Path, name: str, findings: list[dict]) -> dict | None:
    p = unit_dir / name
    if not p.is_file():
        findings.append(finding("REQUIRED_FILE_MISSING", name, f"required unit file is missing: {repo_rel(p)}"))
        return None
    try:
        return read_json(p)
    except Exception as exc:
        findings.append(finding("INVALID_JSON", name, f"cannot parse {repo_rel(p)}: {exc}"))
        return None


def _world_map_source(source: dict) -> dict[str, dict]:
    out = {}
    for w in source.get("bounded_worlds") or []:
        wid = w.get("world")
        if wid:
            out[str(wid)] = {
                "coordinates": {k: v for k, v in w.items() if k not in {"world", "required_consequence"}},
                "required_consequence": w.get("required_consequence"),
            }
    return out


def _world_map_boundary(boundary: dict) -> dict[str, dict]:
    out = {}
    for w in boundary.get("worlds") or []:
        wid = w.get("id")
        if wid:
            out[str(wid)] = {
                "coordinates": w.get("coordinates") or {},
                "required_consequence": w.get("required_source_consequence"),
            }
    return out


def _evidence_records(source: dict | None, target: dict | None) -> list[dict]:
    records: list[dict] = []
    for lane_name, lane in (("SOURCE", source), ("TARGET", target)):
        if not lane:
            continue
        for item in lane.get("evidence") or []:
            records.append(
                {
                    "lane": lane_name,
                    "path": item.get("path"),
                    "sha256": item.get("sha256"),
                }
            )
    return records


def static_preflight(unit_dir: Path) -> tuple[list[dict], dict]:
    findings: list[dict] = []
    source = _require_json(unit_dir, "SOURCE_LANE.json", findings)
    target = _require_json(unit_dir, "TARGET_LANE.json", findings)
    boundary = _require_json(unit_dir, "BOUNDARY_MODEL.json", findings)
    envelope = _require_json(unit_dir, "vbe.envelope.json", findings)

    accepted_instance = unit_dir / "vbe.instance.json"
    draft_instance = unit_dir / "vbe.instance.draft.json"
    instance_path = accepted_instance if accepted_instance.is_file() else draft_instance
    instance = None
    if instance_path.is_file():
        try:
            instance = read_json(instance_path)
        except Exception as exc:
            findings.append(finding("INVALID_JSON", instance_path.name, f"cannot parse {repo_rel(instance_path)}: {exc}"))
    else:
        findings.append(
            finding(
                "REQUIRED_FILE_MISSING",
                "vbe.instance(.draft).json",
                "unit needs either vbe.instance.draft.json or vbe.instance.json",
            )
        )

    acceptance = None
    acceptance_path = unit_dir / "AUTHOR_ACCEPTANCE.json"
    if acceptance_path.is_file():
        try:
            acceptance = read_json(acceptance_path)
        except Exception as exc:
            findings.append(finding("INVALID_JSON", "AUTHOR_ACCEPTANCE.json", f"cannot parse acceptance: {exc}"))

    docs = [x for x in (source, target, boundary, instance, acceptance) if x]
    unit_ids = sorted({str(x.get("unit_id")) for x in docs if x.get("unit_id")})
    if instance and (instance.get("corpus") or {}).get("unit_id"):
        unit_ids.append(str(instance["corpus"]["unit_id"]))
        unit_ids = sorted(set(unit_ids))
    if len(unit_ids) != 1:
        findings.append(
            finding(
                "UNIT_ID_MISMATCH",
                ",".join(unit_ids),
                "unit-scoped authoring records do not agree on one unit_id",
                detail={"unit_ids": unit_ids},
            )
        )

    candidate_ids = sorted(
        {
            str(x.get("candidate_id"))
            for x in (source, target, acceptance)
            if x and x.get("candidate_id")
        }
    )
    if len(candidate_ids) > 1:
        findings.append(
            finding(
                "CANDIDATE_ID_MISMATCH",
                ",".join(candidate_ids),
                "SOURCE, TARGET, and acceptance records disagree on candidate_id",
                detail={"candidate_ids": candidate_ids},
            )
        )

    if source and boundary:
        sw = _world_map_source(source)
        bw = _world_map_boundary(boundary)
        if sw != bw:
            findings.append(
                finding(
                    "WORLD_MODEL_MISMATCH",
                    "SOURCE_vs_BOUNDARY",
                    "SOURCE bounded worlds and BOUNDARY world model are not byte-level equivalent after normalization",
                    detail={"source": sw, "boundary": bw},
                )
            )
        contract = source.get("consequence_contract") or {}
        coord_names = set((boundary.get("coordinates") or {}).keys())
        for role, name in (
            ("current", (contract.get("current_coordinate") or {}).get("name")),
            ("reviewed", (contract.get("reviewed_coordinate") or {}).get("name")),
        ):
            if name and name not in coord_names:
                findings.append(
                    finding(
                        "BOUNDARY_COORDINATE_MISSING",
                        str(name),
                        f"{role} source-contract coordinate is missing from BOUNDARY_MODEL.coordinates",
                    )
                )

    if target:
        callable_surface = target.get("callable_surface") or {}
        mechanism = target.get("mechanism_model") or {}
        binding_input = callable_surface.get("reviewed_binding_input")
        carrier = mechanism.get("reviewed_version_carrier")
        if binding_input and carrier and binding_input != carrier:
            findings.append(
                finding(
                    "TARGET_BINDING_MISMATCH",
                    f"{binding_input}!={carrier}",
                    "TARGET callable surface and mechanism model disagree on reviewed-version carrier",
                )
            )

    if target and boundary:
        revision = str(((target.get("target") or {}).get("revision") or ""))
        operation_text = str(((boundary.get("claim_scope") or {}).get("operation") or ""))
        if revision and revision not in operation_text:
            findings.append(
                finding(
                    "BOUNDARY_TARGET_REVISION_MISMATCH",
                    revision,
                    "BOUNDARY claim_scope operation does not contain the pinned TARGET revision",
                    detail={"boundary_operation": operation_text},
                )
            )

    evidence = _evidence_records(source, target)
    for rec in evidence:
        path = rec.get("path")
        expected = rec.get("sha256")
        if not path or not expected:
            findings.append(
                finding(
                    "EVIDENCE_PIN_INCOMPLETE",
                    f"{rec['lane']}:{path}",
                    "evidence record requires path and sha256",
                )
            )
            continue
        p = ROOT / str(path)
        if not p.is_file():
            findings.append(finding("EVIDENCE_FILE_MISSING", str(path), "pinned evidence file is missing"))
            continue
        actual = sha256_file(p)
        if actual != expected:
            findings.append(
                finding(
                    "EVIDENCE_SHA_MISMATCH",
                    str(path),
                    "pinned evidence bytes do not match declared SHA-256",
                    detail={"expected": expected, "actual": actual},
                )
            )

    if envelope:
        bindings = ((envelope.get("adapter_base") or {}).get("bindings") or [])
        empirical_binding_shas = {
            b.get("sha256") for b in bindings if b.get("kind") == "EVIDENCE" and b.get("sha256")
        }
        qualification_binding_shas = {
            b.get("sha256") for b in bindings if b.get("kind") == "QUALIFICATION" and b.get("sha256")
        }
        empirical_lane_shas = {x.get("sha256") for x in evidence if x.get("sha256")}
        missing = sorted(empirical_lane_shas - empirical_binding_shas)
        if missing:
            findings.append(
                finding(
                    "EMPIRICAL_EVIDENCE_NOT_BOUND",
                    ",".join(missing),
                    "SOURCE/TARGET empirical evidence is not fully represented by EVIDENCE bindings",
                    detail={"missing_sha256": missing},
                )
            )
        overlap = sorted(empirical_binding_shas & qualification_binding_shas)
        if overlap:
            findings.append(
                finding(
                    "EMPIRICAL_QUALIFICATION_ALIAS",
                    ",".join(overlap),
                    "the same binding digest is classified as both empirical EVIDENCE and reusable QUALIFICATION",
                )
            )
        for b in bindings:
            if b.get("kind") == "QUALIFICATION" and not str(b.get("role") or "").startswith("SEALED_"):
                findings.append(
                    finding(
                        "QUALIFICATION_ROLE_NOT_EXPLICITLY_SEALED",
                        str(b.get("id") or ""),
                        "QUALIFICATION binding role must make sealed methodological status explicit",
                    )
                )
        findings.extend(provenance_findings(envelope))

    if instance:
        inputs = instance.get("authoring_inputs") or {}
        for name, expected_file in (
            ("source_lane", "SOURCE_LANE.json"),
            ("target_lane", "TARGET_LANE.json"),
            ("boundary_model", "BOUNDARY_MODEL.json"),
            ("carrier_envelope", "vbe.envelope.json"),
        ):
            meta = inputs.get(name) or {}
            rel = meta.get("path")
            expected_sha = meta.get("sha256")
            if not rel or not expected_sha:
                findings.append(
                    finding(
                        "INSTANCE_AUTHORING_PIN_MISSING",
                        name,
                        "instance authoring_inputs entry requires path and sha256",
                    )
                )
                continue
            p = unit_dir / str(rel)
            if p.name != expected_file:
                findings.append(
                    finding(
                        "INSTANCE_AUTHORING_PATH_UNEXPECTED",
                        name,
                        f"instance {name} points to {p.name}, expected {expected_file}",
                    )
                )
            if p.is_file() and sha256_file(p) != expected_sha:
                findings.append(
                    finding(
                        "INSTANCE_AUTHORING_SHA_MISMATCH",
                        name,
                        "instance authoring_inputs SHA-256 does not match current bytes",
                        detail={"path": repo_rel(p), "expected": expected_sha, "actual": sha256_file(p)},
                    )
                )

    context = {
        "unit_dir": repo_rel(unit_dir),
        "unit_id": unit_ids[0] if len(unit_ids) == 1 else None,
        "instance_path": repo_rel(instance_path) if instance_path.is_file() else None,
        "target_revision": ((target or {}).get("target") or {}).get("revision"),
        "finding_count": len(findings),
    }
    return dedupe_findings(findings), context


def dedupe_findings(findings: list[dict]) -> list[dict]:
    out = {}
    for f in findings:
        out[f["key"]] = f
    return [out[k] for k in sorted(out)]


def sanitize_compiled_case_metadata(case_dir: Path, target_lane: dict) -> dict:
    """Replace inherited scaffold-only report metadata from frozen TARGET facts.

    The core adapter and source contract are asserted byte-identical across this operation.
    """
    case_path = case_dir / "case.json"
    adapter_path = case_dir / "assurance" / "adapter.json"
    source_path = case_dir / "assurance" / "source-contract.json"
    before_case_sha = sha256_file(case_path)
    adapter_sha = sha256_file(adapter_path)
    source_sha = sha256_file(source_path)

    case = read_json(case_path)
    target = target_lane.get("target") or {}
    before = {
        "display": case.get("display"),
        "external_system": case.get("external_system"),
    }
    case.pop("display", None)
    case["external_system"] = {
        "project": target.get("repository"),
        "projection": target.get("operation"),
        "pinned_projection_ref": target.get("revision"),
    }
    if target.get("source_library_pin"):
        case["external_system"]["source_library_pin"] = target.get("source_library_pin")
    write_json(case_path, case)

    if sha256_file(adapter_path) != adapter_sha:
        raise RuntimeError("metadata sanitation changed assurance/adapter.json")
    if sha256_file(source_path) != source_sha:
        raise RuntimeError("metadata sanitation changed assurance/source-contract.json")

    record = {
        "schema": "risu.corpus-compiled-metadata-sanitization/v0.1alpha1",
        "mode": "REMOVE_HISTORICAL_SCAFFOLD_DISPLAY_AND_BIND_CURRENT_TARGET_IDENTITY",
        "before_case_sha256": before_case_sha,
        "after_case_sha256": sha256_file(case_path),
        "before": before,
        "after_external_system": case["external_system"],
        "adapter_sha256_unchanged": adapter_sha,
        "source_contract_sha256_unchanged": source_sha,
        "semantic_assurance_inputs_unchanged": True,
    }
    write_json(case_dir / "CORPUS_METADATA_SANITIZATION.json", record)
    return record


def compile_probe(unit_dir: Path) -> tuple[list[dict], dict]:
    findings: list[dict] = []
    instance_path = unit_dir / "vbe.instance.json"
    if not instance_path.is_file():
        return [
            finding(
                "COMPILE_PROBE_REQUIRES_ACCEPTED_INSTANCE",
                "vbe.instance.json",
                "compile probe requires an AUTHOR_ACCEPTED or CALIBRATION_ONLY vbe.instance.json",
                severity="INFO",
            )
        ], {}

    materialize = run([sys.executable, str(TOOLS / "materialize_case_bundles.py")])
    if materialize.returncode != 0:
        return [
            finding(
                "MATERIALIZATION_FAILED",
                "",
                "retained case infrastructure could not be materialized for compile probe",
                detail=materialize.stdout,
            )
        ], {}

    with tempfile.TemporaryDirectory(prefix="risu-corpus-preflight-") as td:
        out = Path(td) / "case"
        proc = run(
            [
                sys.executable,
                str(TOOLS / "vbe_compile.py"),
                str(instance_path),
                "--output",
                str(out),
            ]
        )
        if proc.returncode != 0:
            return [
                finding(
                    "COMPILE_PROBE_FAILED",
                    repo_rel(instance_path),
                    "frozen VBE compiler could not compile the accepted instance",
                    detail=proc.stdout,
                )
            ], {}

        adapter = read_json(out / "assurance" / "adapter.json")
        findings.extend(provenance_findings(adapter))

        target = read_json(unit_dir / "TARGET_LANE.json")
        target_revision = str(((target.get("target") or {}).get("revision") or ""))
        case = read_json(out / "case.json")
        external = case.get("external_system") or {}
        inherited = external.get("pinned_projection_ref")
        sanitation = None
        if inherited and target_revision and inherited != target_revision:
            findings.append(
                finding(
                    "SCAFFOLD_METADATA_SANITIZATION_REQUIRED",
                    str(inherited),
                    "compiled case inherited a historical projection ref; generic harness will replace report-only scaffold metadata from frozen TARGET identity before verification",
                    severity="INFO",
                    detail={"compiled": inherited, "target_revision": target_revision},
                )
            )
        sanitation = sanitize_compiled_case_metadata(out, target)
        sanitized = read_json(out / "case.json")
        if (sanitized.get("external_system") or {}).get("pinned_projection_ref") != target_revision:
            findings.append(
                finding(
                    "CURRENT_TARGET_METADATA_SANITIZATION_FAILED",
                    target_revision,
                    "generic metadata sanitation did not bind current TARGET revision",
                )
            )

        return dedupe_findings(findings), {
            "compiled_case_sha256": sha256_file(out / "case.json"),
            "compiled_adapter_sha256": sha256_file(out / "assurance" / "adapter.json"),
            "metadata_sanitization": sanitation,
        }


def audit_unit(unit_dir: Path, include_compile_probe: bool = True) -> dict:
    findings, context = static_preflight(unit_dir)
    probe = {}
    if include_compile_probe:
        extra, probe = compile_probe(unit_dir)
        findings = dedupe_findings(findings + extra)
    blockers = [f for f in findings if f["severity"] == "BLOCKER"]
    return {
        "schema": HARNESS_SCHEMA,
        "mode": "AUDIT",
        "status": "PASS" if not blockers else "BLOCKED",
        "context": context,
        "compile_probe": probe,
        "findings": findings,
        "blocker_keys": [f["key"] for f in blockers],
    }


def git_bytes(ref: str, path: str) -> bytes:
    proc = subprocess.run(
        ["git", "show", f"{ref}:{path}"],
        cwd=str(ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"cannot read frozen path at {ref}: {path}: "
            + proc.stderr.decode("utf-8", errors="replace")
        )
    return proc.stdout


def build_primary_manifest(unit_dir: Path, freeze_commit: str, output_path: Path) -> dict:
    """Deterministically derive a v0.1 primary-run manifest from accepted frozen bytes.

    This intentionally does not infer or repair scientific semantics.
    """
    audit = audit_unit(unit_dir, include_compile_probe=True)
    blockers = [f for f in audit["findings"] if f["severity"] == "BLOCKER"]
    if blockers:
        raise RuntimeError(
            "cannot build primary manifest while protocol preflight is blocked: "
            + ", ".join(f["key"] for f in blockers)
        )

    acceptance_path = unit_dir / "AUTHOR_ACCEPTANCE.json"
    instance_path = unit_dir / "vbe.instance.json"
    if not acceptance_path.is_file() or not instance_path.is_file():
        raise RuntimeError("manifest build requires AUTHOR_ACCEPTANCE.json and vbe.instance.json")
    acceptance = read_json(acceptance_path)
    instance = read_json(instance_path)
    if acceptance.get("status") != "AUTHOR_ACCEPTED" or instance.get("status") != "AUTHOR_ACCEPTED":
        raise RuntimeError("manifest build requires AUTHOR_ACCEPTED acceptance and instance")
    if acceptance.get("primary_verdict_observed_before_acceptance") is not False:
        raise RuntimeError("acceptance does not record verdict blindness")

    rev = run(["git", "rev-parse", "--verify", f"{freeze_commit}^{{commit}}"])
    if rev.returncode != 0:
        raise RuntimeError(f"freeze commit is not available: {freeze_commit}")
    freeze = (rev.stdout or "").strip()

    source = read_json(unit_dir / "SOURCE_LANE.json")
    target = read_json(unit_dir / "TARGET_LANE.json")
    paths = []
    for rec in _evidence_records(source, target):
        if rec.get("path"):
            paths.append(str(rec["path"]))
    paths.extend(
        [
            repo_rel(unit_dir / "SOURCE_LANE.json"),
            repo_rel(unit_dir / "TARGET_LANE.json"),
            repo_rel(unit_dir / "BOUNDARY_MODEL.json"),
            repo_rel(unit_dir / "vbe.envelope.json"),
            repo_rel(acceptance_path),
            repo_rel(instance_path),
        ]
    )
    unique_paths = sorted(set(paths))
    frozen_paths = []
    for rel in unique_paths:
        current = ROOT / rel
        if not current.is_file():
            raise RuntimeError(f"frozen manifest path missing: {rel}")
        current_bytes = current.read_bytes()
        frozen_bytes = git_bytes(freeze, rel)
        if current_bytes != frozen_bytes:
            raise RuntimeError(f"current bytes differ from freeze commit for {rel}")
        frozen_paths.append({"path": rel, "sha256": sha256_bytes(current_bytes)})

    unit_id = (instance.get("corpus") or {}).get("unit_id") or acceptance.get("unit_id")
    if not unit_id:
        raise RuntimeError("unit_id missing")
    output_rel = repo_rel(output_path)
    manifest = {
        "schema": "risu.corpus-primary-run-manifest/v0.1alpha1",
        "status": "READY_FOR_FIRST_PRIMARY_EXECUTION",
        "unit_id": unit_id,
        "instance_id": instance["instance_id"],
        "instance_path": repo_rel(instance_path),
        "author_acceptance_path": repo_rel(acceptance_path),
        "authoring_freeze_commit": freeze,
        "frozen_paths": frozen_paths,
        "post_freeze_allowed_paths": [output_rel],
        "primary_verdict_observed_before_manifest": False,
        "tracked_primary_result_path": repo_rel(unit_dir / "primary-result" / "PRIMARY_RESULT.json"),
        "generated_by": "tools/corpus01_unit_harness.py build-manifest",
        "protocol_preserving_generation": {
            "semantic_fields_inferred": False,
            "scientific_input_bytes_modified": False,
            "hashes_computed_from_frozen_bytes": True,
        },
    }
    write_json(output_path, manifest)
    return manifest


def _copy_empirical_evidence(manifest: dict, instance_path: Path, case_dir: Path) -> list[dict]:
    envelope = read_json(instance_path.parent / read_json(instance_path)["carrier_envelope"])
    bindings = ((envelope.get("adapter_base") or {}).get("bindings") or [])
    frozen = manifest.get("frozen_paths") or []
    by_sha = {}
    for x in frozen:
        if x.get("path") and x.get("sha256"):
            by_sha.setdefault(x["sha256"], []).append(x["path"])

    copied = []
    for b in bindings:
        if b.get("kind") != "EVIDENCE":
            continue
        digest = b.get("sha256")
        candidates = by_sha.get(digest) or []
        if len(candidates) != 1:
            raise RuntimeError(
                f"EVIDENCE binding {b.get('id')} must map to exactly one frozen path by SHA-256; got {candidates}"
            )
        source = ROOT / candidates[0]
        dest = case_dir / "assurance" / str(b["path"])
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, dest)
        if sha256_file(dest) != digest:
            raise RuntimeError(f"evidence copy digest mismatch for {b.get('id')}")
        copied.append({"binding_id": b.get("id"), "source": candidates[0], "dest": str(dest), "sha256": digest})
    return copied


def _write_observation(
    manifest: dict,
    report: dict,
    compile_manifest: dict,
    rc: int,
    paths: dict[str, Path],
) -> dict:
    expected = VALID_SEMANTIC.get(rc)
    if expected is None or report.get("product_status") not in expected:
        raise RuntimeError(f"semantic exit/status mismatch: rc={rc} status={report.get('product_status')}")

    observation = {
        "schema": "risu.corpus-primary-observation/v0.2alpha1",
        "harness_schema": HARNESS_SCHEMA,
        "unit_id": manifest["unit_id"],
        "instance_id": manifest["instance_id"],
        "authoring_freeze_commit": manifest["authoring_freeze_commit"],
        "workflow_head_sha": os.environ.get("GITHUB_SHA"),
        "github_run_id": os.environ.get("GITHUB_RUN_ID"),
        "github_run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "semantic_exit_code": rc,
        "product_status": report["product_status"],
        "report_json_sha256": sha256_file(paths["output"] / "report.json"),
        "report_md_sha256": sha256_file(paths["output"] / "report.md"),
        "certificate_sha256": report["certificate"]["sha256"],
        "compile_manifest_sha256": sha256_file(paths["case"] / "VBE_COMPILE_MANIFEST.json"),
        "result_is_observation_only": True,
        "input_rewrite_after_result": "PROHIBITED",
        "self_contained_bundle_required": True,
    }
    overlay = manifest.get("provenance_overlay")
    if overlay:
        observation["provenance_overlay_sha256"] = overlay.get("sha256")
        application = paths["case"] / "PROVENANCE_OVERLAY_APPLICATION.json"
        if application.is_file():
            observation["provenance_overlay_application_sha256"] = sha256_file(application)
    return observation


def _checksum_entries(base: Path, relative_paths: list[Path]) -> list[dict]:
    entries = []
    for p in sorted(relative_paths, key=lambda x: str(x).replace("\\", "/")):
        if p.is_file():
            entries.append(
                {
                    "path": str(p.relative_to(base)).replace("\\", "/"),
                    "bytes": p.stat().st_size,
                    "sha256": sha256_file(p),
                }
            )
    return entries


def _deterministic_zip(staging: Path, zip_path: Path) -> str:
    zip_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for path in sorted((p for p in staging.rglob("*") if p.is_file()), key=lambda p: str(p.relative_to(staging))):
            rel = str(path.relative_to(staging)).replace("\\", "/")
            info = zipfile.ZipInfo(rel, FIXED_ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            zf.writestr(info, path.read_bytes())
    return sha256_file(zip_path)


def build_self_contained_bundle(
    manifest: dict,
    case_dir: Path,
    output_dir: Path,
    console: Path,
    exit_code_file: Path,
    observation_file: Path,
    bundle_dir: Path,
) -> tuple[Path, dict]:
    if bundle_dir.exists():
        shutil.rmtree(bundle_dir)
    staging = bundle_dir / "staging"
    shutil.copytree(case_dir, staging / "compiled-case")
    shutil.copytree(output_dir, staging / "verifier-output")
    shutil.copyfile(console, staging / "console.json")
    shutil.copyfile(exit_code_file, staging / "semantic-exit-code.txt")
    shutil.copyfile(observation_file, staging / "primary-observation.json")

    payload_files = [p for p in staging.rglob("*") if p.is_file()]
    entries = _checksum_entries(staging, payload_files)
    bundle_meta = {
        "schema": BUNDLE_SCHEMA,
        "unit_id": manifest["unit_id"],
        "instance_id": manifest["instance_id"],
        "authoring_freeze_commit": manifest["authoring_freeze_commit"],
        "contains_full_compiled_case_tree": True,
        "contains_verifier_output_tree": True,
        "entry_count_before_manifest": len(entries),
        "entries": entries,
    }
    write_json(staging / "BUNDLE.json", bundle_meta)
    all_files = [p for p in staging.rglob("*") if p.is_file()]
    lines = []
    for p in sorted(all_files, key=lambda x: str(x.relative_to(staging)).replace("\\", "/")):
        rel = str(p.relative_to(staging)).replace("\\", "/")
        lines.append(f"{sha256_file(p)}  {rel}")
    (staging / "MANIFEST.sha256").write_text("\n".join(lines) + "\n", encoding="utf-8")

    zip_path = bundle_dir / f"{manifest['unit_id']}-self-contained-primary.zip"
    zip_sha = _deterministic_zip(staging, zip_path)
    result = {
        "schema": BUNDLE_SCHEMA,
        "zip_path": str(zip_path),
        "zip_sha256": zip_sha,
        "compiled_case_file_count": sum(1 for p in (staging / "compiled-case").rglob("*") if p.is_file()),
        "verifier_output_file_count": sum(1 for p in (staging / "verifier-output").rglob("*") if p.is_file()),
    }
    write_json(bundle_dir / "BUNDLE_RESULT.json", result)
    return zip_path, result


def run_primary(manifest_path: Path, work_root: Path) -> dict:
    manifest = read_json(manifest_path)
    if manifest.get("schema") != "risu.corpus-primary-run-manifest/v0.1alpha1":
        raise RuntimeError("unsupported primary-run manifest schema")

    unit_dir = manifest_path.parent
    audit = audit_unit(unit_dir, include_compile_probe=True)
    if audit["status"] != "PASS":
        raise RuntimeError(
            "protocol-preserving preflight blocked primary execution: "
            + ", ".join(audit["blocker_keys"])
        )

    telemetry: dict[str, float] = {}
    t0 = time.monotonic()
    corpus = run([sys.executable, str(TOOLS / "corpus01_validate.py"), "--json"])
    telemetry["corpus_validate_seconds"] = round(time.monotonic() - t0, 6)
    if corpus.returncode != 0:
        raise RuntimeError("Corpus 0.1 procedural integrity failed:\n" + (corpus.stdout or ""))

    t0 = time.monotonic()
    gate = run(
        [
            sys.executable,
            str(TOOLS / "corpus01_primary_gate.py"),
            repo_rel(manifest_path),
            "--json",
        ]
    )
    telemetry["primary_gate_seconds"] = round(time.monotonic() - t0, 6)
    if gate.returncode != 0:
        raise RuntimeError("AUTHOR_ACCEPTED freeze gate failed:\n" + (gate.stdout or ""))

    t0 = time.monotonic()
    mat = run([sys.executable, str(TOOLS / "materialize_case_bundles.py")])
    telemetry["materialize_seconds"] = round(time.monotonic() - t0, 6)
    if mat.returncode != 0:
        raise RuntimeError("case materialization failed:\n" + (mat.stdout or ""))

    if work_root.exists():
        shutil.rmtree(work_root)
    case_dir = work_root / "compiled-case"
    output_dir = work_root / "verifier-output"
    console = work_root / "console.json"
    exit_code_file = work_root / "semantic-exit-code.txt"
    observation_file = work_root / "primary-observation.json"
    bundle_dir = work_root / "bundle"
    work_root.mkdir(parents=True, exist_ok=True)

    instance_path = ROOT / manifest["instance_path"]
    compile_cmd = [
        sys.executable,
        str(TOOLS / "corpus01_compile.py"),
        str(instance_path),
        "--output",
        str(case_dir),
    ]
    overlay = manifest.get("provenance_overlay")
    if overlay:
        compile_cmd.extend(["--provenance-overlay", str(ROOT / overlay["path"])])
    t0 = time.monotonic()
    comp = run(compile_cmd)
    telemetry["compile_seconds"] = round(time.monotonic() - t0, 6)
    if comp.returncode != 0:
        raise RuntimeError("prospective compilation failed:\n" + (comp.stdout or ""))

    target_lane = read_json(unit_dir / "TARGET_LANE.json")
    sanitation = sanitize_compiled_case_metadata(case_dir, target_lane)
    copied = _copy_empirical_evidence(manifest, instance_path, case_dir)

    t0 = time.monotonic()
    preflight = run(
        [
            sys.executable,
            str(TOOLS / "corpus01_provenance_preflight.py"),
            str(case_dir / "assurance" / "adapter.json"),
            "--json",
        ]
    )
    telemetry["provenance_preflight_seconds"] = round(time.monotonic() - t0, 6)
    if preflight.returncode != 0:
        raise RuntimeError("compiled provenance preflight failed:\n" + (preflight.stdout or ""))

    t0 = time.monotonic()
    verify = subprocess.run(
        [
            str(ROOT / "risu-verify"),
            "verify",
            str(case_dir),
            "--output",
            str(output_dir),
            "--json",
        ],
        cwd=str(ROOT),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    telemetry["verifier_seconds"] = round(time.monotonic() - t0, 6)
    console.write_text(verify.stdout or "", encoding="utf-8")
    exit_code_file.write_text(f"{verify.returncode}\n", encoding="utf-8")
    if verify.returncode not in VALID_SEMANTIC:
        failure = output_dir / "failure.log"
        detail = verify.stdout or ""
        if failure.is_file():
            detail += "\n--- failure.log ---\n" + failure.read_text(encoding="utf-8", errors="replace")
        raise RuntimeError(f"invalid verifier/toolchain exit code {verify.returncode}:\n{detail}")

    report = read_json(output_dir / "report.json")
    compile_manifest = read_json(case_dir / "VBE_COMPILE_MANIFEST.json")
    observation = _write_observation(
        manifest,
        report,
        compile_manifest,
        verify.returncode,
        {
            "case": case_dir,
            "output": output_dir,
        },
    )
    write_json(observation_file, observation)

    checksum_targets = (
        [p for p in case_dir.rglob("*") if p.is_file()]
        + [p for p in output_dir.rglob("*") if p.is_file()]
        + [console, exit_code_file, observation_file]
    )
    checksum_root = work_root
    checksum_entries = _checksum_entries(checksum_root, checksum_targets)
    write_json(
        work_root / "ARTIFACT_MANIFEST.json",
        {
            "schema": "risu.corpus-primary-artifact-manifest/v0.2alpha1",
            "unit_id": manifest["unit_id"],
            "entries": checksum_entries,
        },
    )

    t0 = time.monotonic()
    zip_path, bundle = build_self_contained_bundle(
        manifest,
        case_dir,
        output_dir,
        console,
        exit_code_file,
        observation_file,
        bundle_dir,
    )

    telemetry["package_seconds"] = round(time.monotonic() - t0, 6)
    telemetry["total_mechanical_seconds"] = round(sum(telemetry.values()), 6)
    write_json(
        work_root / "HARNESS_TELEMETRY.json",
        {
            "schema": "risu.corpus-harness-telemetry/v0.1alpha1",
            "unit_id": manifest["unit_id"],
            "measured": telemetry,
            "scope": "MECHANICAL_PRIMARY_HARNESS_ONLY",
            "authoring_time_not_inferred": True,
        },
    )

    summary = {
        "schema": HARNESS_SCHEMA,
        "mode": "PRIMARY",
        "status": "VALID_SEMANTIC_OUTCOME",
        "unit_id": manifest["unit_id"],
        "semantic_exit_code": verify.returncode,
        "product_status": report.get("product_status"),
        "copied_empirical_evidence": copied,
        "compiled_metadata_sanitization": sanitation,
        "self_contained_bundle": bundle,
        "telemetry": telemetry,
        "bundle_path": str(zip_path),
        "scientific_outcome_not_mapped_to_ci_failure": True,
    }
    write_json(work_root / "HARNESS_RESULT.json", summary)
    return summary


def _parse_expected(values: list[str]) -> set[str]:
    return {x.strip() for x in values if x.strip()}


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Protocol-preserving infrastructure for Prospective Corpus 0.1 units"
    )
    sub = ap.add_subparsers(dest="command", required=True)

    audit = sub.add_parser("audit", help="read-only preflight/audit; never executes a primary verifier")
    audit.add_argument("unit_dir")
    audit.add_argument("--no-compile-probe", action="store_true")
    audit.add_argument("--expect-finding", action="append", default=[])
    audit.add_argument("--json", action="store_true")

    manifest_cmd = sub.add_parser(
        "build-manifest",
        help="derive frozen-path SHA-256 values mechanically after AUTHOR_ACCEPTED freeze",
    )
    manifest_cmd.add_argument("unit_dir")
    manifest_cmd.add_argument("--freeze-commit", default="HEAD")
    manifest_cmd.add_argument("--output", default="PRIMARY_RUN_MANIFEST.json")
    manifest_cmd.add_argument("--json", action="store_true")

    primary = sub.add_parser("run", help="execute one manifest-driven primary with no unit-specific workflow logic")
    primary.add_argument("manifest")
    primary.add_argument("--work-root")
    primary.add_argument("--json", action="store_true")

    args = ap.parse_args()
    try:
        if args.command == "audit":
            unit_dir = (ROOT / args.unit_dir).resolve() if not Path(args.unit_dir).is_absolute() else Path(args.unit_dir).resolve()
            unit_dir.relative_to(ROOT)
            result = audit_unit(unit_dir, include_compile_probe=not args.no_compile_probe)
            expected = _parse_expected(args.expect_finding)
            if expected:
                actual = set(result["blocker_keys"])
                result["expected_finding_keys"] = sorted(expected)
                result["calibration_match"] = actual == expected
                rc = 0 if result["calibration_match"] else 1
            else:
                rc = 0 if result["status"] == "PASS" else 1
            if args.json:
                print(json.dumps(result, indent=2, sort_keys=True))
            else:
                print(f"Corpus unit audit: {result['status']}")
                for f in result["findings"]:
                    print(f"  {f['severity']} {f['key']}: {f['message']}")
                if expected:
                    print(f"  calibration_match={result['calibration_match']}")
            return rc

        if args.command == "build-manifest":
            unit_dir = (ROOT / args.unit_dir).resolve() if not Path(args.unit_dir).is_absolute() else Path(args.unit_dir).resolve()
            unit_dir.relative_to(ROOT)
            output_path = Path(args.output)
            if not output_path.is_absolute():
                output_path = unit_dir / output_path
            output_path = output_path.resolve()
            output_path.relative_to(ROOT)
            result = build_primary_manifest(unit_dir, args.freeze_commit, output_path)
            if args.json:
                print(json.dumps(result, indent=2, sort_keys=True))
            else:
                print(f"Primary manifest generated: {repo_rel(output_path)}")
                print(f"  frozen_paths={len(result['frozen_paths'])} freeze={result['authoring_freeze_commit']}")
            return 0

        manifest_path = (ROOT / args.manifest).resolve() if not Path(args.manifest).is_absolute() else Path(args.manifest).resolve()
        manifest_path.relative_to(ROOT)
        unit_id = read_json(manifest_path).get("unit_id") or "unknown-unit"
        work_root = (
            Path(args.work_root).resolve()
            if args.work_root
            else ROOT / ".risu" / "corpus01-harness" / str(unit_id)
        )
        result = run_primary(manifest_path, work_root)
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print(f"Corpus primary harness: {result['status']}")
            print(f"  product_status={result['product_status']} semantic_exit_code={result['semantic_exit_code']}")
            print(f"  bundle={result['bundle_path']}")
        return 0
    except Exception as exc:
        print(f"Corpus unit harness: FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
