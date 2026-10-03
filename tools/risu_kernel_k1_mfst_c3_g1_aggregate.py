#!/usr/bin/env python3
"""Aggregate all eight precommitted C3 G1 shard summaries."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL = ROOT / "protocols" / "RISU_KERNEL_K1_MFST_C3_GENERATIVE_G1.json"
G1 = json.loads(PROTOCOL.read_text(encoding="utf-8"))

COVERAGE_MAP = {
    "profiles_with_zero_user_slots": "zero_user_slots",
    "profiles_with_at_least_two_user_slots": "at_least_two_user_slots",
    "profiles_with_domain_size_at_least_three": "domain_size_at_least_three",
    "profiles_with_at_least_three_state_cells": "at_least_three_state_cells",
    "profiles_with_at_least_two_tables": "at_least_two_tables",
    "profiles_with_table_arity_at_least_two": "table_arity_at_least_two",
    "profiles_using_SET_CONST": "uses_SET_CONST",
    "profiles_using_SET_FROM": "uses_SET_FROM",
    "profiles_using_APPLY_TABLE": "uses_APPLY_TABLE",
    "profiles_using_IF_EQ": "uses_IF_EQ",
    "profiles_using_GOTO": "uses_GOTO",
    "profiles_with_multi_effect_trace": "multi_effect",
    "profiles_with_duplicate_effect_occurrence": "duplicate_effect_occurrence",
    "profiles_with_valid_unreachable_block": "valid_unreachable_block",
    "profiles_with_state_progress_loop": "state_progress_loop",
    "profiles_using_world_as_explicit_source": "world_explicit_source",
}

STRESS_MAP = {
    "minimum_boundary_points_observed": "max_boundary_points",
    "minimum_state_cells_observed": "max_state_cells",
    "minimum_tables_observed": "max_tables",
    "minimum_table_arity_observed": "max_table_arity",
    "minimum_blocks_observed": "max_blocks",
    "minimum_ordered_effects_in_one_trace_observed": "max_ordered_effects_one_trace",
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    files = sorted(args.input.rglob("g1-shard-*.json"))
    expected_shards = G1["campaign_shape"]["shards"]
    if len(files) != expected_shards:
        raise AssertionError(("missing-or-surplus-shard-files", len(files), expected_shards, [str(x) for x in files]))

    summaries = []
    raw_by_shard = {}
    for path in files:
        raw = path.read_bytes()
        s = json.loads(raw)
        shard = s["shard"]
        if shard in raw_by_shard:
            raise AssertionError(("duplicate-shard", shard))
        raw_by_shard[shard] = raw
        summaries.append(s)
    if set(raw_by_shard) != set(range(expected_shards)):
        raise AssertionError(("wrong-shard-set", sorted(raw_by_shard)))

    expected_classes = {"structured": 192, "metamorphic": 256, "negative": 64, "stress": 24}
    seeds = G1["campaign_shape"]["seeds"]
    total = 0
    coverage = {v: 0 for v in COVERAGE_MAP.values()}
    stress = {v: 0 for v in STRESS_MAP.values()}
    shard_digests = []
    support = 0
    for s in sorted(summaries, key=lambda x: x["shard"]):
        shard = s["shard"]
        if s["campaign_id"] != G1["campaign_id"] or s["seed"] != seeds[shard]:
            raise AssertionError(("shard-binding", shard, s.get("campaign_id"), s.get("seed")))
        if s["scenario_count"] != 536 or s["classes"] != expected_classes:
            raise AssertionError(("shard-count", shard, s["scenario_count"], s["classes"]))
        if s.get("support_control_evaluations") != 128:
            raise AssertionError(("support-count", shard, s.get("support_control_evaluations")))
        if s.get("authority_created") is not False:
            raise AssertionError(("unexpected-authority", shard))
        total += s["scenario_count"]
        support += s["support_control_evaluations"]
        for key in coverage:
            coverage[key] += s["coverage"][key]
        for key in stress:
            stress[key] = max(stress[key], s["stress"][key])
        shard_digests.append([shard, s["shard_digest"]])

    if total != G1["campaign_shape"]["totals"]["generated_scenarios"]:
        raise AssertionError(("total-scenario-count", total))
    for protocol_key, summary_key in COVERAGE_MAP.items():
        minimum = G1["minimum_coverage_over_1536_structured_valid_profiles"][protocol_key]
        if coverage[summary_key] < minimum:
            raise AssertionError(("aggregate-coverage-underflow", protocol_key, coverage[summary_key], minimum))
    for protocol_key, summary_key in STRESS_MAP.items():
        minimum = G1["stress_requirements_over_192_profiles"][protocol_key]
        if stress[summary_key] < minimum:
            raise AssertionError(("aggregate-stress-underflow", protocol_key, stress[summary_key], minimum))

    h = hashlib.sha256(b"RISU-K1-C3-G1-AGGREGATE-V1\0")
    for shard in range(expected_shards):
        raw = raw_by_shard[shard]
        h.update(str(len(raw)).encode("ascii") + b":" + raw + b",")
    out = {
        "campaign_id": G1["campaign_id"],
        "shards": expected_shards,
        "generated_scenarios": total,
        "support_control_evaluations": support,
        "coverage": coverage,
        "stress": stress,
        "shard_digests": shard_digests,
        "aggregate_digest": h.hexdigest(),
        "authority_created": False,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(out, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    print("C3_G1_GENERATIVE_PASS", total)
    print("C3_G1_SUPPORT_CONTROLS", support)
    print("C3_G1_SHARDS", expected_shards)
    print("C3_G1_AGGREGATE_DIGEST", out["aggregate_digest"])
    print("C3_G1_COVERAGE", json.dumps(coverage, sort_keys=True, separators=(",", ":")))
    print("C3_G1_STRESS", json.dumps(stress, sort_keys=True, separators=(",", ":")))
    print("AUTHORITY_CREATED false")


if __name__ == "__main__":
    main()
