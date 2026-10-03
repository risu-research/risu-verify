#!/usr/bin/env python3
"""Run one frozen C3 G1 shard against the full crossed square."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
PROTOCOL = ROOT / "protocols" / "RISU_KERNEL_K1_MFST_C3_GENERATIVE_G1.json"

sys.path.insert(0, str(TOOLS))
import risu_kernel_k1_mfst_c3_g1_generator as gen

spec = importlib.util.spec_from_file_location("c3cross", TOOLS / "risu_kernel_k1_mfst_c3_crossed_gate.py")
cross = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(cross)

G1 = json.loads(PROTOCOL.read_text(encoding="utf-8"))


def _net(raw: bytes) -> bytes:
    return str(len(raw)).encode("ascii") + b":" + raw + b","


class Campaign:
    def __init__(self, shard, seed):
        self.shard = shard
        self.seed = seed
        self.digest = hashlib.sha256()
        self.digest.update(b"RISU-K1-C3-G1-SHARD-V1\0")
        self.digest.update(_net(str(shard).encode()))
        self.digest.update(_net(str(seed).encode()))
        self.scenarios = 0
        self.support_evaluations = 0
        self.classes = {"structured": 0, "metamorphic": 0, "negative": 0, "stress": 0}
        self.coverage = {
            "zero_user_slots": 0,
            "at_least_two_user_slots": 0,
            "domain_size_at_least_three": 0,
            "at_least_three_state_cells": 0,
            "at_least_two_tables": 0,
            "table_arity_at_least_two": 0,
            "uses_SET_CONST": 0,
            "uses_SET_FROM": 0,
            "uses_APPLY_TABLE": 0,
            "uses_IF_EQ": 0,
            "uses_GOTO": 0,
            "multi_effect": 0,
            "duplicate_effect_occurrence": 0,
            "valid_unreachable_block": 0,
            "state_progress_loop": 0,
            "world_explicit_source": 0,
        }
        self.stress = {
            "max_boundary_points": 0,
            "max_state_cells": 0,
            "max_tables": 0,
            "max_table_arity": 0,
            "max_blocks": 0,
            "max_ordered_effects_one_trace": 0,
            "max_c2_program_bytes": 0,
            "max_c2_gas": 0,
        }

    def record(self, case_id, cls, raw, outcome, extras=()):
        self.scenarios += 1
        self.classes[cls] += 1
        for x in (case_id.encode(), cls.encode(), raw, outcome.encode(), *extras):
            self.digest.update(_net(x if isinstance(x, bytes) else str(x).encode()))


def _ops(profile):
    return [op for block in profile["blocks"] for op in block["ops"]]


def _has_world_source(v):
    if isinstance(v, dict):
        if v.get("kind") == "input" and v.get("name") == "@world":
            return True
        return any(_has_world_source(x) for x in v.values())
    if isinstance(v, list):
        return any(_has_world_source(x) for x in v)
    return False


def add_coverage(camp, p, meta):
    slots = p["boundary"]["slots"]
    states = p["state"]
    tables = p["tables"]
    ops = _ops(p)
    domains = list(slots.values()) + [s["domain"] for s in states]
    domains += [a["domain"] for t in tables for a in t["arguments"]]
    c = camp.coverage
    c["zero_user_slots"] += len(slots) == 0
    c["at_least_two_user_slots"] += len(slots) >= 2
    c["domain_size_at_least_three"] += any(len(d) >= 3 for d in domains)
    c["at_least_three_state_cells"] += len(states) >= 3
    c["at_least_two_tables"] += len(tables) >= 2
    c["table_arity_at_least_two"] += any(len(t["arguments"]) >= 2 for t in tables)
    for name in ("SET_CONST", "SET_FROM", "APPLY_TABLE"):
        c["uses_" + name] += any(op["op"] == name for op in ops)
    c["uses_IF_EQ"] += any(b["term"]["op"] == "IF_EQ" for b in p["blocks"])
    c["uses_GOTO"] += any(b["term"]["op"] == "GOTO" for b in p["blocks"])
    effect_lists = [[op["payload"] for op in b["ops"] if op["op"] == "EMIT_HEX"] for b in p["blocks"]]
    c["multi_effect"] += any(len(xs) >= 2 for xs in effect_lists)
    c["duplicate_effect_occurrence"] += any(len(xs) != len(set(xs)) for xs in effect_lists)
    c["valid_unreachable_block"] += bool(meta.get("unreachable_block"))
    c["state_progress_loop"] += bool(meta.get("state_progress_loop"))
    c["world_explicit_source"] += _has_world_source(p)


def safe_structured(seed, i):
    # G1 distribution caps structured profiles at four state cells.  The raw
    # constructor can append a dedicated loop cell, so indices that would make
    # five cells are deterministically moved to a disjoint high index before
    # any checker is run.  This rule is independent of checker outcomes.
    j = i
    while True:
        p, m = gen.make_structured(seed, j)
        if len(p["state"]) <= 4:
            return p, m, j
        j += 997


def check_per_shard_coverage(camp):
    required = {
        "zero_user_slots": 15,
        "at_least_two_user_slots": 44,
        "domain_size_at_least_three": 57,
        "at_least_three_state_cells": 38,
        "at_least_two_tables": 32,
        "table_arity_at_least_two": 44,
        "uses_SET_CONST": 63,
        "uses_SET_FROM": 63,
        "uses_APPLY_TABLE": 63,
        "uses_IF_EQ": 88,
        "uses_GOTO": 44,
        "multi_effect": 88,
        "duplicate_effect_occurrence": 23,
        "valid_unreachable_block": 23,
        "state_progress_loop": 23,
        "world_explicit_source": 15,
    }
    bad = {k: (camp.coverage[k], v) for k, v in required.items() if camp.coverage[k] < v}
    if bad:
        raise AssertionError(("coverage-underflow", bad, camp.coverage))


def full(case_id, raw):
    return cross.full_chain(case_id, raw, require_allowed=True)


def same(a, b, field, case):
    if a["r7"].get(field) != b["r7"].get(field):
        raise AssertionError((case, field, a["r7"].get(field), b["r7"].get(field)))


def different(a, b, field, case):
    if a["r7"].get(field) == b["r7"].get(field):
        raise AssertionError((case, "expected-different", field, a["r7"].get(field)))


def metamorphic_check(case, relation, base, changed):
    if relation == "G1-META-KEY-DECL-PERMUTE":
        for f in ("c3_semantic_id", "graph_id", "trace_map_id", "projected_realize"):
            same(base, changed, f, case)
        if base["program"] != changed["program"]:
            raise AssertionError((case, "C2 bytes changed under representation permutation"))
    elif relation == "G1-META-FORMAL-RENAME":
        different(base, changed, "c3_semantic_id", case)
        for f in ("trace_map_id", "projected_realize"):
            same(base, changed, f, case)
        if base["program"] != changed["program"]:
            raise AssertionError((case, "C2 bytes changed under formal rename"))
    elif relation == "G1-META-UNREACHABLE-BLOCK":
        different(base, changed, "c3_source_id", case)
        different(base, changed, "c3_semantic_id", case)
        for f in ("trace_map_id", "projected_realize"):
            same(base, changed, f, case)
        if base["program"] != changed["program"]:
            raise AssertionError((case, "C2 bytes changed under unreachable block insertion"))
    elif relation == "G1-META-EFFECT-ORDER-MULTIPLICITY":
        different(base, changed, "trace_map_id", case)
        same(base, changed, "projected_realize", case)
        if base["program"] == changed["program"]:
            raise AssertionError((case, "C2 bytes failed to bind ordered effect trace"))
    else:
        raise AssertionError((case, "unknown metamorphic relation", relation))


def _downstream_status(program, artifact, target, realize, case, suffix):
    with tempfile.TemporaryDirectory() as s:
        return cross.downstream(case, program, artifact, target, realize, Path(s), suffix)[:2]


def negative_check(case, base_obj, family, control):
    mutant, name = gen.mutate_negative_profile(base_obj, family)
    raw = gen.encode(mutant)
    if family in range(0, 7):
        r7, r8 = cross.direct_status(raw)
        if r7.get("proof_status") != "REJECTED" or r8.get("proof_status") != "REJECTED":
            raise AssertionError((case, name, "direct did not fail closed", r7, r8))
        return raw, name, (json.dumps(r7, sort_keys=True).encode(), json.dumps(r8, sort_keys=True).encode())
    if family == 10:
        out = cross.faithful_forbidden(case, raw)
        if out.get("k1_subset_allowed") or not out.get("forbidden_projected_pairs"):
            raise AssertionError((case, name, "forbidden effect lost"))
        return raw, name, (json.dumps(out, sort_keys=True).encode(),)

    program = control["program"]
    artifact = control["artifact"]
    target = control["r7"]["c2_target_id"]
    realize = control["realize"]
    art = json.loads(artifact)

    if family == 7:
        slots = art["boundary"]["slots"]
        if not slots:
            raise AssertionError((case, "negative control unexpectedly has no slot"))
        slot = sorted(slots)[0]
        original_values = list(slots[slot])
        if len(original_values) < 2:
            raise AssertionError((case, "negative control slot not shrinkable"))
        slots[slot] = [sorted(original_values)[0]]
        mutated_artifact = gen.encode(art)
        aid = "p:sha256:" + hashlib.sha256(mutated_artifact).hexdigest()
        _, derived, tid = cross.w5wire.check_artifact(mutated_artifact, aid, cross.CLAIM_OBJ, program)
        shrunk_realize = [list(x) for x in sorted(derived)]
        r5, r6 = _downstream_status(program, mutated_artifact, tid, shrunk_realize, case, "shrink")
        for tag, out in (("W5", r5), ("W6", r6)):
            if out.get("proof_status") != "ACCEPTED" or out.get("derived_realize") != shrunk_realize:
                raise AssertionError((case, name, tag, out))
        source_values = base_obj["boundary"]["slots"][slot]
        if len(source_values) <= len(slots[slot]):
            raise AssertionError((case, name, "scope did not shrink"))
        return raw, name, (mutated_artifact, json.dumps(r5, sort_keys=True).encode(), json.dumps(r6, sort_keys=True).encode())

    if family == 8:
        gas = art["boundary"]["gas"]
        if gas <= 1:
            raise AssertionError((case, name, "gas not shrinkable", gas))
        art["boundary"]["gas"] = gas - 1
        mutated_artifact = gen.encode(art)
        r5, r6 = _downstream_status(program, mutated_artifact, target, realize, case, "undergas")
        for tag, out in (("W5", r5), ("W6", r6)):
            if out.get("proof_status") != "REJECTED" or "gas" not in out.get("reason", "").lower():
                raise AssertionError((case, name, tag, out))
        return raw, name, (mutated_artifact, json.dumps(r5, sort_keys=True).encode(), json.dumps(r6, sort_keys=True).encode())

    if family == 9:
        mutated_program = program + b"\n"
        r5, r6 = _downstream_status(mutated_program, artifact, target, realize, case, "stale-program")
        for tag, out in (("W5", r5), ("W6", r6)):
            reason = out.get("reason", "").lower()
            if out.get("proof_status") != "REJECTED" or "program" not in reason or "digest" not in reason:
                raise AssertionError((case, name, tag, out))
        return raw, name, (mutated_program, json.dumps(r5, sort_keys=True).encode(), json.dumps(r6, sort_keys=True).encode())

    if family == 11:
        art["complete"] = "true"
        art["producer_realize"] = [list(x) for x in realize]
        art["producer_target_id"] = target
        mutated_artifact = gen.encode(art)
        r5, r6 = _downstream_status(program, mutated_artifact, target, realize, case, "self-assert")
        for tag, out in (("W5", r5), ("W6", r6)):
            if out.get("proof_status") != "REJECTED" or "malformed" not in out.get("reason", "").lower():
                raise AssertionError((case, name, tag, out))
        return raw, name, (mutated_artifact, json.dumps(r5, sort_keys=True).encode(), json.dumps(r6, sort_keys=True).encode())

    raise AssertionError((case, family))


def run_shard(shard, summary_path):
    shape = G1["campaign_shape"]
    seeds = shape["seeds"]
    if shard < 0 or shard >= shape["shards"]:
        raise ValueError("bad shard")
    seed = seeds[shard]
    camp = Campaign(shard, seed)
    per = shape["per_shard"]

    print("G1_SHARD_BEGIN", shard, "SEED", seed)

    # 1. Ordinary generated profiles.  No expected trace is computed here.
    for i in range(per["structured_valid_full_square"]):
        p, meta, source_index = safe_structured(seed, i)
        raw = gen.encode(p)
        add_coverage(camp, p, meta)
        case = f"G1-S{shard}-V{i:03d}"
        out = full(case, raw)
        camp.record(case, "structured", raw, "FULL_CROSSED_ACCEPT", (str(source_index).encode(), out["program"]))
        if (i + 1) % 48 == 0:
            print("G1_PROGRESS", shard, "structured", i + 1)
    check_per_shard_coverage(camp)

    # 2. Four independently precommitted metamorphic relations per base.
    for i in range(per["metamorphic_base_profiles"]):
        base_obj, _ = gen.make_meta_base(seed, i)
        base_raw = gen.encode(base_obj)
        base_case = f"G1-S{shard}-MB{i:03d}"
        base = full(base_case, base_raw)
        camp.support_evaluations += 1
        for t in range(per["metamorphic_transformations_per_base"]):
            _, raw, relation = gen.transform_meta(base_obj, t)
            case = f"G1-S{shard}-M{i:03d}-{t}"
            changed = full(case, raw)
            metamorphic_check(case, relation, base, changed)
            camp.record(case, "metamorphic", raw, relation + ":PASS", (base_raw, changed["program"]))
        if (i + 1) % 16 == 0:
            print("G1_PROGRESS", shard, "metamorphic-bases", i + 1)

    # 3. Negative lane.  Every mutant gets an accepted full-square control first.
    for i in range(per["negative_fail_closed_mutations"]):
        base_obj, _ = gen.make_negative_base(seed, i)
        base_raw = gen.encode(base_obj)
        control_case = f"G1-S{shard}-NC{i:03d}"
        control = full(control_case, base_raw)
        camp.support_evaluations += 1
        family = i % len(G1["negative_mutation_families"])
        case = f"G1-S{shard}-N{i:03d}-F{family:02d}"
        raw, name, extras = negative_check(case, base_obj, family, control)
        camp.record(case, "negative", raw, name + ":FAIL_CLOSED", extras)
        if (i + 1) % 16 == 0:
            print("G1_PROGRESS", shard, "negative", i + 1)

    # 4. High-complexity but still qualified-C2-bounded profiles.
    for i in range(per["high_complexity_stress_full_square"]):
        p, meta = gen.make_stress(seed, i)
        raw = gen.encode(p)
        case = f"G1-S{shard}-X{i:03d}"
        out = full(case, raw)
        s = camp.stress
        s["max_boundary_points"] = max(s["max_boundary_points"], meta["boundary_points"])
        s["max_state_cells"] = max(s["max_state_cells"], meta["state_count"])
        s["max_tables"] = max(s["max_tables"], meta["table_count"])
        s["max_table_arity"] = max(s["max_table_arity"], meta["max_table_arity"])
        s["max_blocks"] = max(s["max_blocks"], meta["block_count"])
        s["max_ordered_effects_one_trace"] = max(s["max_ordered_effects_one_trace"], meta["max_effects_one_trace"])
        s["max_c2_program_bytes"] = max(s["max_c2_program_bytes"], out["r7"]["c2_program_bytes"])
        s["max_c2_gas"] = max(s["max_c2_gas"], out["r7"]["c2_derived_gas"])
        camp.record(case, "stress", raw, "FULL_CROSSED_ACCEPT", (out["program"],))
        if (i + 1) % 8 == 0:
            print("G1_PROGRESS", shard, "stress", i + 1)

    sr = G1["stress_requirements_over_192_profiles"]
    stress_checks = {
        "minimum_boundary_points_observed": camp.stress["max_boundary_points"],
        "minimum_state_cells_observed": camp.stress["max_state_cells"],
        "minimum_tables_observed": camp.stress["max_tables"],
        "minimum_table_arity_observed": camp.stress["max_table_arity"],
        "minimum_blocks_observed": camp.stress["max_blocks"],
        "minimum_ordered_effects_in_one_trace_observed": camp.stress["max_ordered_effects_one_trace"],
    }
    for key, actual in stress_checks.items():
        if actual < sr[key]:
            raise AssertionError(("stress-underflow", key, actual, sr[key]))

    expected = (
        per["structured_valid_full_square"]
        + per["metamorphic_base_profiles"] * per["metamorphic_transformations_per_base"]
        + per["negative_fail_closed_mutations"]
        + per["high_complexity_stress_full_square"]
    )
    if camp.scenarios != expected or expected != 536:
        raise AssertionError(("scenario-count", camp.scenarios, expected))
    expected_classes = {"structured": 192, "metamorphic": 256, "negative": 64, "stress": 24}
    if camp.classes != expected_classes:
        raise AssertionError(("class-counts", camp.classes, expected_classes))

    summary = {
        "campaign_id": G1["campaign_id"],
        "shard": shard,
        "seed": seed,
        "scenario_count": camp.scenarios,
        "support_control_evaluations": camp.support_evaluations,
        "classes": camp.classes,
        "coverage": camp.coverage,
        "stress": camp.stress,
        "shard_digest": camp.digest.hexdigest(),
        "authority_created": False,
    }
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps(summary, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    print("G1_SHARD_PASS", shard, "SCENARIOS", camp.scenarios, "SUPPORT", camp.support_evaluations, "DIGEST", summary["shard_digest"])
    print("G1_COVERAGE", json.dumps(camp.coverage, sort_keys=True, separators=(",", ":")))
    print("G1_STRESS", json.dumps(camp.stress, sort_keys=True, separators=(",", ":")))
    print("AUTHORITY_CREATED false")
    return summary


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--shard", type=int, required=True)
    ap.add_argument("--summary", type=Path, required=True)
    args = ap.parse_args()
    run_shard(args.shard, args.summary)


if __name__ == "__main__":
    main()
