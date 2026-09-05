from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterable, List, Tuple

from .baselines import b0_surface, b1_name_shape, b2_flow_only, require_non_authoritative
from .cegar import refinement_requests
from .engine import evaluate_vbe, vbe_obligations
from .extractor import extract_coordinate_candidates
from .graph import ConsequenceGraph

INPUT_SCHEMA = "risu.diff-e0-machine-input/v0.1"
CIR_SCHEMA = "risu.diff-e0-cir-candidate/v0.1"
REFINEMENT_SCHEMA = "risu.diff-e0-refinement-map-candidate/v0.1"
OBLIGATION_SCHEMA = "risu.diff-e0-vbe-obligations/v0.1"
PREDICTION_SCHEMA = "risu.diff-e0-prediction/v0.1"
PROBE_SCHEMA = "risu.diff-e0-probe-plan/v0.1"
REQUEST_SCHEMA = "risu.diff-e0-refinement-requests/v0.1"
BASELINE_SCHEMA = "risu.diff-e0-baseline-results/v0.1"
MANIFEST_SCHEMA = "risu.diff-e0-run-manifest/v0.1"
SEAL_SCHEMA = "risu.diff-e0-output-seal/v0.1"
OBSERVATION_SCHEMA = "risu.diff-e0-execution-observation/v0.1"

REQUIRED_ARTIFACTS = (
    "CIR_CANDIDATE.json",
    "REFINEMENT_MAP_CANDIDATE.json",
    "VBE_OBLIGATIONS.json",
    "E0_PREDICTION.json",
    "PROBE_PLAN.json",
    "REFINEMENT_REQUESTS.json",
    "BASELINE_RESULTS.json",
    "E0_RUN_MANIFEST.json",
)
CONTROL_ARTIFACT = "E0_OUTPUT_SEAL.json"
OBSERVATION_ARTIFACT = "E0_EXECUTION_OBSERVATION.json"

MAX_EVIDENCE_FILE_BYTES = 5 * 1024 * 1024
MAX_PACKET_BYTES = 20 * 1024 * 1024

_FORBIDDEN_INPUT_KEYS = {
    "canonical_verdict",
    "canonical_result",
    "gold",
    "human_gold",
    "human_gold_semantics",
    "established_semantics",
    "consequence_authority",
    "authoritative_prediction",
    "e0_prediction",
}
_ALLOWED_ROOT_KEYS = {
    "schema",
    "run_id",
    "unit_id",
    "target_revision",
    "screened_operation",
    "surface",
    "evidence_files",
    "acquisition",
}
_ALLOWED_EVIDENCE_KEYS = {"path", "sha256", "kind", "language"}
_ALLOWED_EVIDENCE_KINDS = {"SOURCE_TEXT", "TARGET_TEXT", "TOOL_SURFACE", "MACHINE_OBSERVATION"}


class MachineInputError(ValueError):
    pass


class OutputSealError(ValueError):
    pass


def canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
    ).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_relpath(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise MachineInputError("evidence path must be a nonempty string")
    p = PurePosixPath(value)
    if p.is_absolute() or ".." in p.parts or "." in p.parts or "\\" in value:
        raise MachineInputError(f"unsafe evidence path: {value!r}")
    normalized = p.as_posix()
    if normalized == "MACHINE_INPUT.json":
        raise MachineInputError("MACHINE_INPUT.json cannot be listed as evidence")
    return normalized


def _scan_forbidden_keys(value: Any, at: str = "$") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if str(key).lower() in _FORBIDDEN_INPUT_KEYS:
                raise MachineInputError(f"forbidden semantic-injection key at {at}: {key}")
            _scan_forbidden_keys(child, f"{at}.{key}")
    elif isinstance(value, list):
        for i, child in enumerate(value):
            _scan_forbidden_keys(child, f"{at}[{i}]")


def _validate_surface(surface: Any) -> Dict[str, Any]:
    if not isinstance(surface, dict):
        raise MachineInputError("surface must be an object")
    if set(surface) - {"name", "arguments"}:
        raise MachineInputError("surface contains unknown fields")
    name = surface.get("name")
    arguments = surface.get("arguments")
    if not isinstance(name, str) or not name:
        raise MachineInputError("surface.name must be nonempty")
    if not isinstance(arguments, list) or any(not isinstance(x, str) or not x for x in arguments):
        raise MachineInputError("surface.arguments must be a list of nonempty strings")
    if len(set(arguments)) != len(arguments):
        raise MachineInputError("surface.arguments must be unique")
    return {"name": name, "arguments": list(arguments)}


def load_machine_packet(packet_dir: Path) -> Dict[str, Any]:
    packet_dir = packet_dir.resolve()
    root_file = packet_dir / "MACHINE_INPUT.json"
    if not root_file.is_file():
        raise MachineInputError("MACHINE_INPUT.json missing")
    root_bytes = root_file.read_bytes()
    try:
        data = json.loads(root_bytes.decode("utf-8"))
    except Exception as exc:
        raise MachineInputError(f"invalid MACHINE_INPUT.json: {exc}") from exc
    if not isinstance(data, dict):
        raise MachineInputError("machine input root must be an object")
    _scan_forbidden_keys(data)
    if set(data) - _ALLOWED_ROOT_KEYS:
        raise MachineInputError(f"unknown machine-input fields: {sorted(set(data) - _ALLOWED_ROOT_KEYS)}")
    required = {
        "schema", "run_id", "unit_id", "target_revision",
        "screened_operation", "surface", "evidence_files",
    }
    missing = sorted(required - set(data))
    if missing:
        raise MachineInputError(f"missing required fields: {missing}")
    if data["schema"] != INPUT_SCHEMA:
        raise MachineInputError(f"unsupported schema: {data['schema']!r}")
    for key in ("run_id", "unit_id", "target_revision", "screened_operation"):
        if not isinstance(data[key], str) or not data[key]:
            raise MachineInputError(f"{key} must be a nonempty string")
    surface = _validate_surface(data["surface"])
    evidence_files = data["evidence_files"]
    if not isinstance(evidence_files, list):
        raise MachineInputError("evidence_files must be a list")

    declared: Dict[str, Dict[str, Any]] = {}
    total = len(root_bytes)
    materialized: List[Dict[str, Any]] = []
    for row in evidence_files:
        if not isinstance(row, dict) or set(row) - _ALLOWED_EVIDENCE_KEYS:
            raise MachineInputError("each evidence entry must use only path/sha256/kind/language")
        if not {"path", "sha256", "kind"} <= set(row):
            raise MachineInputError("evidence entry missing path/sha256/kind")
        rel = _safe_relpath(row["path"])
        if rel in declared:
            raise MachineInputError(f"duplicate evidence path: {rel}")
        if row["kind"] not in _ALLOWED_EVIDENCE_KINDS:
            raise MachineInputError(f"unsupported evidence kind: {row['kind']!r}")
        expected = row["sha256"]
        if not isinstance(expected, str) or len(expected) != 64 or any(c not in "0123456789abcdef" for c in expected):
            raise MachineInputError(f"invalid SHA-256 for {rel}")
        path = packet_dir / rel
        if not path.is_file():
            raise MachineInputError(f"declared evidence missing: {rel}")
        raw = path.read_bytes()
        if len(raw) > MAX_EVIDENCE_FILE_BYTES:
            raise MachineInputError(f"evidence file exceeds size limit: {rel}")
        total += len(raw)
        if total > MAX_PACKET_BYTES:
            raise MachineInputError("packet exceeds total size limit")
        actual = sha256_bytes(raw)
        if actual != expected:
            raise MachineInputError(f"evidence hash mismatch for {rel}")
        clean = {
            "path": rel,
            "sha256": actual,
            "kind": row["kind"],
            "language": row.get("language"),
            "bytes": raw,
        }
        declared[rel] = clean
        materialized.append(clean)

    actual_files = sorted(
        p.relative_to(packet_dir).as_posix()
        for p in packet_dir.rglob("*")
        if p.is_file()
    )
    expected_files = sorted(["MACHINE_INPUT.json", *declared.keys()])
    if actual_files != expected_files:
        extras = sorted(set(actual_files) - set(expected_files))
        missing_actual = sorted(set(expected_files) - set(actual_files))
        raise MachineInputError(f"packet file closure mismatch extras={extras} missing={missing_actual}")

    packet_identity = {
        "machine_input_sha256": sha256_bytes(root_bytes),
        "evidence_sha256": {row["path"]: row["sha256"] for row in sorted(materialized, key=lambda x: x["path"])},
    }
    packet_digest = sha256_bytes(canonical_bytes(packet_identity))
    return {
        "input": data,
        "surface": surface,
        "evidence": materialized,
        "packet_identity": packet_identity,
        "packet_digest": packet_digest,
    }


def _extract(packet: Dict[str, Any]) -> Dict[str, Any]:
    per_file: List[Dict[str, Any]] = []
    aggregate_coordinates: List[Dict[str, Any]] = []
    aggregate_comparisons: List[Dict[str, Any]] = []
    for row in sorted(packet["evidence"], key=lambda x: x["path"]):
        language = (row.get("language") or "").lower()
        if row["kind"] in {"SOURCE_TEXT", "TARGET_TEXT"} and language in {"py", "python"}:
            try:
                text = row["bytes"].decode("utf-8")
                extracted = extract_coordinate_candidates(text)
                error = None
            except Exception as exc:
                extracted = {
                    "coordinate_candidates": [],
                    "comparison_candidates": [],
                    "semantic_authority": False,
                }
                error = f"{type(exc).__name__}:{exc}"
            decorated_coords = [
                {**x, "evidence_path": row["path"]} for x in extracted["coordinate_candidates"]
            ]
            decorated_comps = [
                {**x, "evidence_path": row["path"]} for x in extracted["comparison_candidates"]
            ]
            aggregate_coordinates.extend(decorated_coords)
            aggregate_comparisons.extend(decorated_comps)
            per_file.append({
                "path": row["path"],
                "sha256": row["sha256"],
                "coordinate_candidates": decorated_coords,
                "comparison_candidates": decorated_comps,
                "semantic_authority": False,
                "parse_error": error,
            })
    aggregate_coordinates.sort(key=lambda x: (x["evidence_path"], x.get("line") or -1, x["name"]))
    aggregate_comparisons.sort(key=lambda x: (x["evidence_path"], x.get("line") or -1, x["names"]))
    return {
        "files": per_file,
        "coordinate_candidates": aggregate_coordinates,
        "comparison_candidates": aggregate_comparisons,
        "semantic_authority": False,
    }


def _candidate_graph(packet: Dict[str, Any], extraction: Dict[str, Any]) -> Tuple[ConsequenceGraph, Dict[str, str], Dict[str, Any]]:
    roles = {
        "authoritative_coordinate": "role.authoritative_version_coordinate",
        "current_coordinate": "role.current_version_at_effect_coordinate",
        "guard": "role.binding_or_compare_guard",
        "effect": "role.declared_effect",
        "stale_outcome": "role.stale_mismatch_outcome_or_interpreter",
    }
    nodes = [
        {"id": roles["authoritative_coordinate"], "kind": "SEMANTIC_COORDINATE", "status": "UNRESOLVED"},
        {"id": roles["current_coordinate"], "kind": "SEMANTIC_COORDINATE", "status": "UNRESOLVED"},
        {"id": roles["guard"], "kind": "GUARD", "status": "UNRESOLVED"},
        {"id": roles["effect"], "kind": "EFFECT", "status": "UNRESOLVED"},
        {"id": roles["stale_outcome"], "kind": "INTERPRETER", "status": "UNRESOLVED"},
    ]
    graph = ConsequenceGraph.from_dict({
        "ir_id": f"e0-machine-first:{packet['input']['run_id']}",
        "evidence_boundary": "machine-first-untrusted-candidate",
        "nodes": nodes,
        "edges": [],
    })
    out = graph.canonical_dict()
    out.update({
        "artifact_schema": CIR_SCHEMA,
        "graph_digest": graph.digest(),
        "candidate_extraction": extraction,
        "semantic_authority": False,
        "material_roles": {
            "authoritative_version_coordinate": roles["authoritative_coordinate"],
            "current_version_at_effect_coordinate": roles["current_coordinate"],
            "binding_or_compare_guard": roles["guard"],
            "declared_effect": roles["effect"],
            "stale_mismatch_outcome_or_interpreter": roles["stale_outcome"],
        },
    })
    return graph, roles, out


def _refinement_map(packet: Dict[str, Any], roles: Dict[str, str]) -> Dict[str, Any]:
    relations = [
        {
            "material_role": material_role,
            "candidate_node_id": node_id,
            "status": "UNRESOLVED",
            "evidence_refs": [],
            "semantic_authority": False,
        }
        for material_role, node_id in sorted({
            "authoritative_version_coordinate": roles["authoritative_coordinate"],
            "current_version_at_effect_coordinate": roles["current_coordinate"],
            "binding_or_compare_guard": roles["guard"],
            "declared_effect": roles["effect"],
            "stale_mismatch_outcome_or_interpreter": roles["stale_outcome"],
        }.items())
    ]
    return {
        "artifact_schema": REFINEMENT_SCHEMA,
        "run_id": packet["input"]["run_id"],
        "relations": relations,
        "refinement_complete": False,
        "semantic_authority": False,
    }


def _all_text(packet: Dict[str, Any]) -> str:
    parts = []
    for row in sorted(packet["evidence"], key=lambda x: x["path"]):
        if row["kind"] in {"SOURCE_TEXT", "TARGET_TEXT", "TOOL_SURFACE", "MACHINE_OBSERVATION"}:
            parts.append(row["bytes"].decode("utf-8", errors="replace"))
    return "\n".join(parts)


def _baseline_results(packet: Dict[str, Any], extraction: Dict[str, Any]) -> Dict[str, Any]:
    aggregate = {
        "coordinate_candidates": extraction["coordinate_candidates"],
        "comparison_candidates": extraction["comparison_candidates"],
    }
    results = [
        b0_surface({"name": packet["surface"]["name"], "arguments": packet["surface"]["arguments"]}),
        b1_name_shape(_all_text(packet)),
        b2_flow_only(aggregate),
    ]
    for result in results:
        require_non_authoritative(result)
    return {
        "artifact_schema": BASELINE_SCHEMA,
        "run_id": packet["input"]["run_id"],
        "results": results,
        "consequence_authority": False,
    }


def build_semantic_outputs(packet_dir: Path, engine_identity: Dict[str, Any]) -> Dict[str, bytes]:
    packet = load_machine_packet(packet_dir)
    extraction = _extract(packet)
    graph, roles, cir = _candidate_graph(packet, extraction)
    refinement = _refinement_map(packet, roles)
    obligations = vbe_obligations(graph, roles)
    obligation_artifact = {
        "artifact_schema": OBLIGATION_SCHEMA,
        "run_id": packet["input"]["run_id"],
        "obligations": obligations,
        "unresolved": sorted(k for k, value in obligations.items() if not value),
        "all_satisfied": all(obligations.values()),
    }
    prediction = evaluate_vbe(
        graph,
        roles,
        refinement_complete=False,
        material_interpretation_nonempty=True,
        collapse_witness=None,
        relational_witness=None,
    )
    if prediction["prediction"] != "E0_PREDICTED_ASSURANCE_INCOMPLETE":
        raise RuntimeError("machine-first discovery core must fail closed on unresolved material semantics")
    prediction_artifact = {
        "artifact_schema": PREDICTION_SCHEMA,
        "run_id": packet["input"]["run_id"],
        **prediction,
        "canonical_scientific_authority": False,
    }
    requests = refinement_requests(obligations)
    request_artifact = {
        "artifact_schema": REQUEST_SCHEMA,
        "run_id": packet["input"]["run_id"],
        "requests": requests,
        "source_science_mutation_allowed": False,
        "evaluation_metric_mutation_allowed": False,
    }
    probe_artifact = {
        "artifact_schema": PROBE_SCHEMA,
        "run_id": packet["input"]["run_id"],
        "probes": [
            {
                "sequence": i + 1,
                "obligation": request["obligation"],
                "probe": request["request"],
                "target_only": True,
            }
            for i, request in enumerate(requests)
        ],
        "deterministic_order": True,
        "semantic_authority": False,
    }
    baseline_artifact = _baseline_results(packet, extraction)

    first = {
        "CIR_CANDIDATE.json": canonical_bytes(cir),
        "REFINEMENT_MAP_CANDIDATE.json": canonical_bytes(refinement),
        "VBE_OBLIGATIONS.json": canonical_bytes(obligation_artifact),
        "E0_PREDICTION.json": canonical_bytes(prediction_artifact),
        "PROBE_PLAN.json": canonical_bytes(probe_artifact),
        "REFINEMENT_REQUESTS.json": canonical_bytes(request_artifact),
        "BASELINE_RESULTS.json": canonical_bytes(baseline_artifact),
    }
    first_hashes = {path: sha256_bytes(data) for path, data in sorted(first.items())}
    manifest = {
        "artifact_schema": MANIFEST_SCHEMA,
        "run_id": packet["input"]["run_id"],
        "unit_id": packet["input"]["unit_id"],
        "target_revision": packet["input"]["target_revision"],
        "screened_operation": packet["input"]["screened_operation"],
        "input_packet_digest": packet["packet_digest"],
        "input_packet_identity": packet["packet_identity"],
        "engine_identity": engine_identity,
        "pre_manifest_semantic_artifact_sha256": first_hashes,
        "required_artifacts": list(REQUIRED_ARTIFACTS),
        "prediction_namespace_noncanonical": True,
        "canonical_scientific_authority": False,
        "wall_clock_fields_present": False,
    }
    outputs = {**first, "E0_RUN_MANIFEST.json": canonical_bytes(manifest)}
    artifact_hashes = {path: sha256_bytes(data) for path, data in sorted(outputs.items())}
    seal_payload = {
        "artifact_schema": SEAL_SCHEMA,
        "run_id": packet["input"]["run_id"],
        "input_packet_digest": packet["packet_digest"],
        "engine_identity_digest": engine_identity["engine_identity_digest"],
        "semantic_artifact_sha256": artifact_hashes,
        "required_artifacts": list(REQUIRED_ARTIFACTS),
        "observation_sidecar_excluded": True,
    }
    seal_digest = sha256_bytes(canonical_bytes(seal_payload))
    seal = {**seal_payload, "seal_digest": seal_digest}
    outputs[CONTROL_ARTIFACT] = canonical_bytes(seal)
    return outputs


def write_semantic_outputs(packet_dir: Path, output_dir: Path, engine_identity: Dict[str, Any]) -> Dict[str, str]:
    outputs = build_semantic_outputs(packet_dir, engine_identity)
    output_dir.mkdir(parents=True, exist_ok=True)
    for name, data in outputs.items():
        (output_dir / name).write_bytes(data)
    return {name: sha256_bytes(data) for name, data in sorted(outputs.items())}


def verify_output_dir(output_dir: Path) -> Dict[str, Any]:
    missing = [name for name in (*REQUIRED_ARTIFACTS, CONTROL_ARTIFACT) if not (output_dir / name).is_file()]
    if missing:
        raise OutputSealError(f"missing output artifacts: {missing}")
    actual_files = sorted(p.name for p in output_dir.iterdir() if p.is_file())
    allowed_files = sorted([*REQUIRED_ARTIFACTS, CONTROL_ARTIFACT, OBSERVATION_ARTIFACT])
    extras = sorted(set(actual_files) - set(allowed_files))
    if extras:
        raise OutputSealError(f"unsealed output artifacts present: {extras}")
    seal = json.loads((output_dir / CONTROL_ARTIFACT).read_text(encoding="utf-8"))
    if seal.get("artifact_schema") != SEAL_SCHEMA:
        raise OutputSealError("output seal schema mismatch")
    expected_hashes = seal.get("semantic_artifact_sha256")
    if not isinstance(expected_hashes, dict) or sorted(expected_hashes) != sorted(REQUIRED_ARTIFACTS):
        raise OutputSealError("output seal artifact closure mismatch")
    actual_hashes = {
        name: sha256_bytes((output_dir / name).read_bytes())
        for name in sorted(REQUIRED_ARTIFACTS)
    }
    if actual_hashes != expected_hashes:
        raise OutputSealError("semantic artifact hash mismatch")
    payload = {k: v for k, v in seal.items() if k != "seal_digest"}
    actual_seal_digest = sha256_bytes(canonical_bytes(payload))
    if actual_seal_digest != seal.get("seal_digest"):
        raise OutputSealError("seal digest mismatch")
    manifest = json.loads((output_dir / "E0_RUN_MANIFEST.json").read_text(encoding="utf-8"))
    if manifest.get("wall_clock_fields_present") is not False:
        raise OutputSealError("wall clock leaked into semantic manifest")
    return {
        "status": "PASS",
        "seal_digest": seal["seal_digest"],
        "semantic_artifact_sha256": actual_hashes,
        "observation_sidecar_excluded": seal.get("observation_sidecar_excluded") is True,
    }


def execution_observation(*, run_id: str, elapsed_seconds: float, host: str = "UNSPECIFIED") -> bytes:
    return canonical_bytes({
        "artifact_schema": OBSERVATION_SCHEMA,
        "run_id": run_id,
        "elapsed_seconds": float(elapsed_seconds),
        "host": host,
        "semantic_authority": False,
        "included_in_semantic_seal": False,
    })
