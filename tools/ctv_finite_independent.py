#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

SCHEMA = "risu.ctv-finite-independent-check/v0.1alpha1"


class CheckError(RuntimeError):
    pass


def load(path: Path) -> dict[str, Any]:
    obj = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(obj, dict):
        raise CheckError(f"object required: {path}")
    return obj


def require(ok: bool, message: str) -> None:
    if not ok:
        raise CheckError(message)


def git_blob_sha1(path: Path) -> str:
    data = path.read_bytes()
    return hashlib.sha1(f"blob {len(data)}\0".encode("ascii") + data).hexdigest()


def independent_compute(
    author: dict[str, Any],
    boundary: dict[str, Any],
    source: dict[str, Any],
    target: dict[str, Any],
) -> dict[str, Any]:
    unit = boundary.get("unit_id")
    require(unit and source.get("unit_id") == unit and target.get("unit_id") == unit, "unit mismatch")

    sw = source.get("bounded_worlds")
    bw = boundary.get("worlds")
    require(isinstance(sw, list) and isinstance(bw, list) and sw and bw, "worlds absent")

    source_map = {}
    for row in sw:
        wid = row.get("world")
        c = row.get("required_consequence")
        require(isinstance(wid, str) and wid and isinstance(c, str) and c, "bad source world")
        require(wid not in source_map, "duplicate source world")
        source_map[wid] = c

    obs = boundary.get("target_observation_model") or {}
    per_world_real = obs.get("world_realizations")
    common_real = obs.get("target_realization_label")
    require(per_world_real is None or isinstance(per_world_real, dict), "bad world_realizations")
    require(per_world_real is not None or (isinstance(common_real, str) and common_real), "no realization")

    target_world_consequences = obs.get("world_consequences")
    if target_world_consequences is not None:
        require(isinstance(target_world_consequences, dict), "bad world_consequences")
    refinement_map = obs.get("target_to_source_consequence_map")
    if refinement_map is not None:
        require(isinstance(refinement_map, dict), "bad refinement map")

    rows = []
    for row in bw:
        wid = row.get("id")
        required = row.get("required_source_consequence")
        require(wid in source_map and source_map[wid] == required, f"source mismatch {wid}")
        realization = per_world_real.get(wid) if per_world_real is not None else common_real
        require(isinstance(realization, str) and realization, f"realization missing {wid}")
        target_consequence = (
            target_world_consequences.get(wid)
            if target_world_consequences is not None
            else None
        )
        rows.append((wid, required, realization, target_consequence))
    require({r[0] for r in rows} == set(source_map), "admitted world set mismatch")
    rows.sort()

    pair_witnesses = []
    for i, left in enumerate(rows):
        for right in rows[i + 1 :]:
            if left[2] == right[2] and left[1] != right[1]:
                pair_witnesses.append(
                    {
                        "world_1": left[0],
                        "world_2": right[0],
                        "shared_target_realization": left[2],
                        "source_consequence_1": left[1],
                        "source_consequence_2": right[1],
                    }
                )

    if pair_witnesses:
        return {
            "unit_id": unit,
            "verdict": "CONSEQUENCE_REGRESSION",
            "reason": "DETERMINISTIC_FACTORIZATION_VIOLATION",
            "witness": pair_witnesses[0],
            "pair_witness_count": len(pair_witnesses),
        }

    if target_world_consequences is None or refinement_map is None or any(r[3] is None for r in rows):
        return {
            "unit_id": unit,
            "verdict": "ASSURANCE_INCOMPLETE",
            "reason": "FACTORING_ESTABLISHED_BUT_REFINEMENT_NOT_ESTABLISHED",
            "witness": None,
            "pair_witness_count": 0,
        }

    for wid, required, _, target_consequence in rows:
        mapped = refinement_map.get(target_consequence)
        if mapped != required:
            return {
                "unit_id": unit,
                "verdict": "CONSEQUENCE_REGRESSION",
                "reason": "CONSEQUENCE_REFINEMENT_VIOLATION",
                "witness": {
                    "world": wid,
                    "target_consequence": target_consequence,
                    "mapped_source_consequence": mapped,
                    "required_source_consequence": required,
                },
                "pair_witness_count": 0,
            }

    return {
        "unit_id": unit,
        "verdict": "CONSEQUENCE_STABLE_IN_DECLARED_SCOPE",
        "reason": "FINITE_DECLARED_SCOPE_FACTORIZATION_AND_REFINEMENT_ESTABLISHED",
        "witness": None,
        "pair_witness_count": 0,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Independent stdlib-only finite CTV checker")
    ap.add_argument("--author-acceptance", required=True)
    ap.add_argument("--boundary", required=True)
    ap.add_argument("--source-lane", required=True)
    ap.add_argument("--target-lane", required=True)
    ap.add_argument("--primary-result", required=True)
    ap.add_argument("--output")
    args = ap.parse_args()

    try:
        paths = {
            "AUTHOR_ACCEPTANCE.json": Path(args.author_acceptance),
            "BOUNDARY_MODEL.json": Path(args.boundary),
            "SOURCE_LANE.json": Path(args.source_lane),
            "TARGET_LANE.json": Path(args.target_lane),
        }
        author = load(paths["AUTHOR_ACCEPTANCE.json"])
        accepted = author.get("accepted_normative_git_blobs") or {}
        for name in ("BOUNDARY_MODEL.json", "SOURCE_LANE.json", "TARGET_LANE.json"):
            require(git_blob_sha1(paths[name]) == accepted.get(name), f"accepted blob mismatch {name}")

        computed = independent_compute(
            author,
            load(paths["BOUNDARY_MODEL.json"]),
            load(paths["SOURCE_LANE.json"]),
            load(paths["TARGET_LANE.json"]),
        )
        primary = load(Path(args.primary_result))
        require(primary.get("status") == "VALID_SEMANTIC_OUTCOME", "primary is not a semantic outcome")
        require(primary.get("unit_id") == computed["unit_id"], "primary unit mismatch")
        agreement = primary.get("verdict") == computed["verdict"]
        require(agreement, f"independent verdict disagreement: {computed['verdict']} != {primary.get('verdict')}")
        primary_witness = (primary.get("evaluation") or {}).get("witness")
        if computed["reason"] == "DETERMINISTIC_FACTORIZATION_VIOLATION":
            require(primary_witness == computed["witness"], "constructive witness disagreement")

        result = {
            "schema": SCHEMA,
            "status": "PASS",
            "unit_id": computed["unit_id"],
            "computed_verdict": computed["verdict"],
            "computed_reason": computed["reason"],
            "primary_verdict": primary.get("verdict"),
            "agreement": True,
            "witness": computed["witness"],
            "pair_witness_count": computed["pair_witness_count"],
            "implementation_independence": {
                "imports_primary_checker": False,
                "stdlib_only": True,
                "algorithm": "independent pair enumeration followed by independent refinement check",
            },
        }
        text = json.dumps(result, indent=2, sort_keys=True) + "\n"
        if args.output:
            Path(args.output).write_text(text, encoding="utf-8")
        print(text, end="")
        return 0
    except Exception as exc:
        print(json.dumps({"schema": SCHEMA, "status": "FAIL", "reason": str(exc)}, indent=2, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
