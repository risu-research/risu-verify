#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

SCHEMA = "risu.ctv-finite-primary/v0.1alpha1"
VALID_VERDICTS = {
    "CONSEQUENCE_STABLE_IN_DECLARED_SCOPE",
    "CONSEQUENCE_REGRESSION",
    "ASSURANCE_INCOMPLETE",
}


class ModelError(RuntimeError):
    pass


def read_json(path: Path) -> dict[str, Any]:
    obj = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(obj, dict):
        raise ModelError(f"JSON object required: {path}")
    return obj


def canonical_json_bytes(obj: Any) -> bytes:
    return (json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def git_blob_sha1_bytes(data: bytes) -> str:
    header = f"blob {len(data)}\0".encode("ascii")
    return hashlib.sha1(header + data).hexdigest()


def git_blob_sha1_file(path: Path) -> str:
    return git_blob_sha1_bytes(path.read_bytes())


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ModelError(message)


def verify_author_acceptance(
    author_path: Path,
    boundary_path: Path,
    source_path: Path,
    target_path: Path,
) -> dict[str, Any]:
    author = read_json(author_path)
    require(
        author.get("status") == "AUTHOR_ACCEPTED_BEFORE_PRIMARY_GOLD_VALIDATION",
        "author acceptance is not in the pre-primary accepted state",
    )
    require(
        (author.get("acceptance") or {}).get("all_primary_outcomes_equally_admissible") is True,
        "author acceptance does not admit all primary outcomes",
    )
    require(
        (author.get("acceptance") or {}).get("expected_primary_outcome_recorded") is False,
        "author acceptance records an expected primary outcome",
    )

    accepted = author.get("accepted_normative_git_blobs") or {}
    paths = {
        "BOUNDARY_MODEL.json": boundary_path,
        "SOURCE_LANE.json": source_path,
        "TARGET_LANE.json": target_path,
    }
    verified: dict[str, str] = {}
    for name, path in paths.items():
        expected = accepted.get(name)
        require(isinstance(expected, str) and expected, f"author acceptance does not pin {name}")
        actual = git_blob_sha1_file(path)
        require(actual == expected, f"accepted blob mismatch for {name}: {actual} != {expected}")
        verified[name] = actual

    return {
        "acceptance_id": author.get("acceptance_id"),
        "author_acceptance_sha256": sha256_file(author_path),
        "verified_normative_git_blobs": verified,
    }


def normalize_finite_model(
    boundary: dict[str, Any],
    source: dict[str, Any],
    target: dict[str, Any],
) -> dict[str, Any]:
    unit_ids = {boundary.get("unit_id"), source.get("unit_id"), target.get("unit_id")}
    require(len(unit_ids) == 1 and None not in unit_ids, "unit_id mismatch across frozen lanes")
    unit_id = next(iter(unit_ids))

    b_worlds = boundary.get("worlds")
    s_worlds = source.get("bounded_worlds")
    require(isinstance(b_worlds, list) and b_worlds, "boundary worlds must be a non-empty list")
    require(isinstance(s_worlds, list) and s_worlds, "source bounded_worlds must be a non-empty list")

    source_by_id: dict[str, str] = {}
    for row in s_worlds:
        require(isinstance(row, dict), "source world row must be an object")
        wid = row.get("world")
        consequence = row.get("required_consequence")
        require(isinstance(wid, str) and wid, "source world id missing")
        require(isinstance(consequence, str) and consequence, f"source consequence missing for {wid}")
        require(wid not in source_by_id, f"duplicate source world id: {wid}")
        source_by_id[wid] = consequence

    obs = boundary.get("target_observation_model") or {}
    explicit_realizations = obs.get("world_realizations")
    global_realization = obs.get("target_realization_label")
    if explicit_realizations is not None:
        require(isinstance(explicit_realizations, dict), "world_realizations must be an object")
    else:
        require(
            isinstance(global_realization, str) and global_realization,
            "target realization is absent; cannot evaluate factorization",
        )

    world_target_consequences = obs.get("world_consequences")
    if world_target_consequences is not None:
        require(isinstance(world_target_consequences, dict), "world_consequences must be an object")

    interpretation_map = obs.get("target_to_source_consequence_map")
    if interpretation_map is not None:
        require(isinstance(interpretation_map, dict), "target_to_source_consequence_map must be an object")

    normalized_worlds: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in b_worlds:
        require(isinstance(row, dict), "boundary world row must be an object")
        wid = row.get("id")
        source_consequence = row.get("required_source_consequence")
        require(isinstance(wid, str) and wid, "boundary world id missing")
        require(wid not in seen, f"duplicate boundary world id: {wid}")
        seen.add(wid)
        require(wid in source_by_id, f"boundary world absent from source lane: {wid}")
        require(
            source_by_id[wid] == source_consequence,
            f"source consequence disagreement for {wid}",
        )
        realization = (
            explicit_realizations.get(wid)
            if explicit_realizations is not None
            else global_realization
        )
        require(isinstance(realization, str) and realization, f"target realization missing for {wid}")
        target_consequence = (
            world_target_consequences.get(wid)
            if world_target_consequences is not None
            else None
        )
        if target_consequence is not None:
            require(
                isinstance(target_consequence, str) and target_consequence,
                f"target consequence must be a non-empty string for {wid}",
            )
        normalized_worlds.append(
            {
                "id": wid,
                "source_consequence": source_consequence,
                "target_realization": realization,
                "target_consequence": target_consequence,
            }
        )

    require(set(source_by_id) == seen, "source/boundary admitted-world sets differ")
    normalized_worlds.sort(key=lambda row: row["id"])

    return {
        "schema": "risu.ctv-finite-model/v0.1alpha1",
        "unit_id": unit_id,
        "worlds": normalized_worlds,
        "target_to_source_consequence_map": interpretation_map,
        "claim_scope": boundary.get("claim_scope") or {},
        "effect_cut": boundary.get("effect_cut") or {},
    }


def evaluate_finite_model(model: dict[str, Any]) -> dict[str, Any]:
    worlds = model.get("worlds")
    require(isinstance(worlds, list) and worlds, "finite model has no worlds")

    partitions: dict[str, list[dict[str, Any]]] = {}
    for row in worlds:
        realization = row["target_realization"]
        partitions.setdefault(realization, []).append(row)

    partition_rows: list[dict[str, Any]] = []
    collapse_witnesses: list[dict[str, Any]] = []
    for realization in sorted(partitions):
        rows = sorted(partitions[realization], key=lambda r: r["id"])
        consequences = sorted({r["source_consequence"] for r in rows})
        partition_rows.append(
            {
                "target_realization": realization,
                "world_ids": [r["id"] for r in rows],
                "source_consequences": consequences,
                "factorization_consistent": len(consequences) == 1,
            }
        )
        for i, left in enumerate(rows):
            for right in rows[i + 1 :]:
                if left["source_consequence"] != right["source_consequence"]:
                    collapse_witnesses.append(
                        {
                            "world_1": left["id"],
                            "world_2": right["id"],
                            "shared_target_realization": realization,
                            "source_consequence_1": left["source_consequence"],
                            "source_consequence_2": right["source_consequence"],
                        }
                    )

    collapse_witnesses.sort(
        key=lambda w: (
            w["world_1"],
            w["world_2"],
            w["shared_target_realization"],
            w["source_consequence_1"],
            w["source_consequence_2"],
        )
    )
    if collapse_witnesses:
        return {
            "verdict": "CONSEQUENCE_REGRESSION",
            "reason": "DETERMINISTIC_FACTORIZATION_VIOLATION",
            "deterministic_factorization_exists": False,
            "kernel_inclusion_holds": False,
            "partitions": partition_rows,
            "witness": collapse_witnesses[0],
            "all_collapse_witnesses": collapse_witnesses,
            "refinement_checked": False,
            "unresolved": [],
        }

    interpretation_map = model.get("target_to_source_consequence_map")
    missing_target_consequence = [r["id"] for r in worlds if r.get("target_consequence") is None]
    if missing_target_consequence or interpretation_map is None:
        unresolved = []
        if missing_target_consequence:
            unresolved.append(
                {
                    "kind": "TARGET_CONSEQUENCE_INTERPRETATION_MISSING",
                    "world_ids": missing_target_consequence,
                }
            )
        if interpretation_map is None:
            unresolved.append({"kind": "TARGET_TO_SOURCE_REFINEMENT_MAPPING_MISSING"})
        return {
            "verdict": "ASSURANCE_INCOMPLETE",
            "reason": "FACTORING_ESTABLISHED_BUT_REFINEMENT_NOT_ESTABLISHED",
            "deterministic_factorization_exists": True,
            "kernel_inclusion_holds": True,
            "partitions": partition_rows,
            "witness": None,
            "all_collapse_witnesses": [],
            "refinement_checked": False,
            "unresolved": unresolved,
        }

    mismatches: list[dict[str, Any]] = []
    for row in worlds:
        target_consequence = row["target_consequence"]
        mapped = interpretation_map.get(target_consequence)
        if mapped != row["source_consequence"]:
            mismatches.append(
                {
                    "world": row["id"],
                    "target_consequence": target_consequence,
                    "mapped_source_consequence": mapped,
                    "required_source_consequence": row["source_consequence"],
                }
            )

    if mismatches:
        mismatches.sort(key=lambda x: x["world"])
        return {
            "verdict": "CONSEQUENCE_REGRESSION",
            "reason": "CONSEQUENCE_REFINEMENT_VIOLATION",
            "deterministic_factorization_exists": True,
            "kernel_inclusion_holds": True,
            "partitions": partition_rows,
            "witness": mismatches[0],
            "all_collapse_witnesses": [],
            "refinement_checked": True,
            "unresolved": [],
        }

    return {
        "verdict": "CONSEQUENCE_STABLE_IN_DECLARED_SCOPE",
        "reason": "FINITE_DECLARED_SCOPE_FACTORIZATION_AND_REFINEMENT_ESTABLISHED",
        "deterministic_factorization_exists": True,
        "kernel_inclusion_holds": True,
        "partitions": partition_rows,
        "witness": None,
        "all_collapse_witnesses": [],
        "refinement_checked": True,
        "unresolved": [],
    }


def run_primary(
    author_path: Path,
    boundary_path: Path,
    source_path: Path,
    target_path: Path,
) -> dict[str, Any]:
    acceptance = verify_author_acceptance(author_path, boundary_path, source_path, target_path)
    boundary = read_json(boundary_path)
    source = read_json(source_path)
    target = read_json(target_path)
    model = normalize_finite_model(boundary, source, target)
    evaluation = evaluate_finite_model(model)
    require(evaluation["verdict"] in VALID_VERDICTS, "invalid semantic verdict")
    return {
        "schema": SCHEMA,
        "status": "VALID_SEMANTIC_OUTCOME",
        "unit_id": model["unit_id"],
        "verdict": evaluation["verdict"],
        "reason": evaluation["reason"],
        "meta_theory": {
            "deterministic_factorization": "exists g such that kappa_S = g o rho_T",
            "kernel_rule": "ker(rho_T) subseteq ker(kappa_S)",
            "regression_witness_rule": "same target realization and different source consequences",
        },
        "evaluation": evaluation,
        "finite_model": model,
        "provenance": {
            **acceptance,
            "input_sha256": {
                "AUTHOR_ACCEPTANCE.json": sha256_file(author_path),
                "BOUNDARY_MODEL.json": sha256_file(boundary_path),
                "SOURCE_LANE.json": sha256_file(source_path),
                "TARGET_LANE.json": sha256_file(target_path),
            },
        },
        "coverage": {
            "admitted_world_count": len(model["worlds"]),
            "all_frozen_admitted_worlds_evaluated": True,
            "population_prevalence_claimed": False,
            "live_deployment_claimed": False,
        },
        "scientific_outcome_is_not_infrastructure_failure": True,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Generic finite deterministic CTV primary checker")
    ap.add_argument("--author-acceptance", required=True)
    ap.add_argument("--boundary", required=True)
    ap.add_argument("--source-lane", required=True)
    ap.add_argument("--target-lane", required=True)
    ap.add_argument("--output")
    args = ap.parse_args()
    try:
        result = run_primary(
            Path(args.author_acceptance),
            Path(args.boundary),
            Path(args.source_lane),
            Path(args.target_lane),
        )
        text = json.dumps(result, indent=2, sort_keys=True) + "\n"
        if args.output:
            Path(args.output).write_text(text, encoding="utf-8")
        print(text, end="")
        return 0
    except Exception as exc:
        payload = {
            "schema": SCHEMA,
            "status": "INFRASTRUCTURE_FAILURE",
            "reason": str(exc),
        }
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
