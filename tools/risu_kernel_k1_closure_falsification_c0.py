#!/usr/bin/env python3
"""Falsification-first laboratory for prospective K1 implementation closure.

C0 does NOT create a production closure proof kind.  A hidden synthetic oracle
knows the complete bounded behavior of each challenge machine and is used only
to kill plausible-but-unsound closure producer strategies.
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
from copy import deepcopy
from pathlib import Path


def hid(prefix: str, label: str) -> str:
    digest = hashlib.sha256(("RISU-K1-C0-" + prefix.upper() + "\0" + label).encode()).hexdigest()
    return f"{prefix}:sha256:{digest}"


W0 = hid("w", "world-0")
W1 = hid("w", "world-1")
C_ALLOW = hid("c", "allowed-effect")
C_FORBID = hid("c", "forbidden-effect")
C_NATIVE = hid("c", "target-native-forbidden-effect")
IMPL_GOOD = "impl:sha256:" + hashlib.sha256(b"RISU-C0-IMPL-GOOD\0").hexdigest()
IMPL_DRIFT = "impl:sha256:" + hashlib.sha256(b"RISU-C0-IMPL-DRIFT\0").hexdigest()
SOURCE_LABEL = "source-label:demo-v1"


def case(case_id, rule, dimensions, worlds=None, impl=IMPL_GOOD, oracle_complete=True):
    return {
        "id": case_id,
        "rule": rule,
        "dimensions": dimensions,
        "worlds": worlds or [W0],
        "implementation_id": impl,
        "oracle_complete": oracle_complete,
    }


CASES = {
    "self": case("self", "safe", {"environment": ["safe", "alt"]}),
    "repeat": case("repeat", "environment", {"environment": ["safe", "alt"]}),
    "branch": case("branch", "data", {"datum": ["representative", "edge"]}),
    "env": case("env", "environment", {"environment": ["safe", "alt"]}),
    "state": case("state", "state", {"state": ["cold", "warm"]}),
    "random": case("random", "random", {"random": ["0", "1"]}),
    "time": case("time", "time", {"time": ["before", "after"]}),
    "schedule": case("schedule", "schedule", {"schedule": ["A", "B"]}),
    "multi": case("multi", "multi", {"mode": ["only"]}),
    "native": case("native", "native", {"mode": ["only"]}),
    "timeout": case("timeout", "timeout", {"completion": ["fast", "late"]}),
    "drift": case("drift", "drift", {"mode": ["only"]}, impl=IMPL_DRIFT),
    "world": case("world", "world", {"mode": ["only"]}, worlds=[W0, W1]),
    "malformed": case("malformed", "safe", {"mode": ["only"]}, oracle_complete=False),
    "closed": case("closed", "closed", {"environment": ["safe", "alt"], "state": ["cold", "warm"]}, worlds=[W0, W1]),
}


def points(c):
    names = list(c["dimensions"])
    values = [c["dimensions"][n] for n in names]
    for w in c["worlds"]:
        for combo in itertools.product(*values):
            yield w, dict(zip(names, combo))


def effects(c, world, d):
    rule = c["rule"]
    if rule in {"safe", "closed"}:
        return [C_ALLOW]
    if rule == "environment":
        return [C_FORBID if d["environment"] == "alt" else C_ALLOW]
    if rule == "state":
        return [C_FORBID if d["state"] == "warm" else C_ALLOW]
    if rule == "random":
        return [C_FORBID if d["random"] == "1" else C_ALLOW]
    if rule == "time":
        return [C_FORBID if d["time"] == "after" else C_ALLOW]
    if rule == "schedule":
        return [C_FORBID if d["schedule"] == "B" else C_ALLOW]
    if rule == "multi":
        return [C_ALLOW, C_FORBID]
    if rule == "native":
        return [C_NATIVE]
    if rule == "timeout":
        return [C_FORBID if d["completion"] == "late" else C_ALLOW]
    if rule == "drift":
        return [C_FORBID]
    if rule == "world":
        return [C_FORBID if world == W1 else C_ALLOW]
    if rule == "data":
        # Same coarse control-flow branch; consequence differs by data value.
        return [C_FORBID if d["datum"] == "edge" else C_ALLOW]
    raise AssertionError(rule)


def oracle(c, reverse=False):
    pts = list(points(c))
    if reverse:
        pts.reverse()
    rel = set()
    traces = []
    for w, d in pts:
        seq = effects(c, w, d)
        traces.append({"world": w, "dimensions": d, "effects": seq})
        rel.update((w, x) for x in seq)
    return {
        "relation": sorted([list(x) for x in rel]),
        "points": traces,
        "complete": bool(c["oracle_complete"]),
    }


def candidate(c, sampled_points, relation, *, implementation_id=None, worlds=None,
              proof_basis="producer-assertion", observation_complete=True,
              claims_closed=True):
    return {
        "claims_closed": claims_closed,
        "implementation_id": implementation_id or c["implementation_id"],
        "worlds": list(c["worlds"] if worlds is None else worlds),
        "proof_basis": proof_basis,
        "sampled_points": deepcopy(sampled_points),
        "relation": sorted([list(x) for x in set(tuple(x) for x in relation)]),
        "observation_complete": observation_complete,
    }


def sample(c, selector):
    chosen = []
    rel = []
    for w, d in points(c):
        if selector(w, d):
            seq = effects(c, w, d)
            chosen.append({"world": w, "dimensions": d, "effects": seq})
            rel.extend((w, x) for x in seq)
    return chosen, rel


def full_enumerator(c, reverse=False):
    o = oracle(c, reverse=reverse)
    return candidate(
        c,
        o["points"],
        [tuple(x) for x in o["relation"]],
        proof_basis="explicit-cartesian-enumeration/v0",
        observation_complete=o["complete"],
    )


def mutant(name, c):
    if name == "self_declared":
        pts, rel = sample(c, lambda _w, d: d.get("environment") == "safe")
        return candidate(c, pts, rel, proof_basis="producer-closed-boolean")
    if name == "repeated_clean":
        pts, rel = sample(c, lambda _w, d: d.get("environment") == "safe")
        pts = pts * 1000
        rel = rel * 1000
        return candidate(c, pts, rel, proof_basis="1000-clean-replays")
    if name == "branch_coverage":
        pts, rel = sample(c, lambda _w, d: d.get("datum") == "representative")
        return candidate(c, pts, rel, proof_basis="100-percent-control-flow-coverage")
    if name == "omit_environment":
        pts, rel = sample(c, lambda _w, d: d.get("environment") == "safe")
        return candidate(c, pts, rel, proof_basis="enumeration-with-fixed-environment")
    if name == "omit_state":
        pts, rel = sample(c, lambda _w, d: d.get("state") == "cold")
        return candidate(c, pts, rel, proof_basis="enumeration-with-reset-state")
    if name == "assume_determinism":
        pts, rel = sample(c, lambda _w, d: d.get("random") == "0")
        return candidate(c, pts, rel, proof_basis="single-run-determinism-assumption")
    if name == "omit_time":
        pts, rel = sample(c, lambda _w, d: d.get("time") == "before")
        return candidate(c, pts, rel, proof_basis="enumeration-with-fixed-time")
    if name == "omit_schedule":
        pts, rel = sample(c, lambda _w, d: d.get("schedule") == "A")
        return candidate(c, pts, rel, proof_basis="enumeration-with-one-schedule")
    if name == "first_effect_only":
        pts = []
        rel = []
        for w, d in points(c):
            seq = effects(c, w, d)
            pts.append({"world": w, "dimensions": d, "effects": seq[:1]})
            rel.append((w, seq[0]))
        return candidate(c, pts, rel, proof_basis="first-effect-projection")
    if name == "drop_unknown":
        pts = []
        rel = []
        for w, d in points(c):
            seq = effects(c, w, d)
            kept = [x for x in seq if x != C_NATIVE]
            pts.append({"world": w, "dimensions": d, "effects": kept})
            rel.extend((w, x) for x in kept)
        return candidate(c, pts, rel, proof_basis="closed-known-consequence-enum")
    if name == "timeout_empty":
        pts, rel = sample(c, lambda _w, d: d.get("completion") == "fast")
        pts.append({"world": W0, "dimensions": {"completion": "late"}, "effects": [], "laundered_timeout": True})
        return candidate(c, pts, rel, proof_basis="timeout-counted-as-empty-safe-run")
    if name == "source_label_binding":
        # Model the old/good behavior but bind only a source label while target bytes drifted.
        pts = [{"world": W0, "dimensions": {"mode": "only"}, "effects": [C_ALLOW]}]
        return candidate(c, pts, [(W0, C_ALLOW)], implementation_id=SOURCE_LABEL, proof_basis="source-label-only")
    if name == "world_shrink":
        pts, rel = sample(c, lambda w, _d: w == W0)
        return candidate(c, pts, rel, worlds=[W0], proof_basis="producer-selected-world-subset")
    if name == "malformed_launder":
        o = oracle(c)
        return candidate(c, o["points"], [tuple(x) for x in o["relation"]], proof_basis="malformed-observation-dropped", observation_complete=True)
    raise AssertionError(name)


def canonical_point(p):
    return (
        p["world"],
        tuple(sorted(p["dimensions"].items())),
        tuple(p.get("effects", [])),
    )


def judge(c, prod):
    o = oracle(c)
    expected_points = {canonical_point(p) for p in o["points"]}
    got_points = {canonical_point(p) for p in prod["sampled_points"] if "laundered_timeout" not in p}
    checks = {
        "claims_closed": prod["claims_closed"] is True,
        "implementation_exact": prod["implementation_id"] == c["implementation_id"],
        "world_domain_exact": set(prod["worlds"]) == set(c["worlds"]) and len(prod["worlds"]) == len(c["worlds"]),
        "oracle_has_no_unresolved_state": o["complete"] is True,
        "producer_observation_complete": prod["observation_complete"] is True,
        "proof_basis_is_explicit_bounded_enumeration": prod["proof_basis"] == "explicit-cartesian-enumeration/v0",
        "all_operational_points_accounted_for": got_points == expected_points,
        "realized_relation_exact": prod["relation"] == o["relation"],
    }
    eligible = all(checks.values())
    return eligible, checks, o


ATTACKS = [
    ("C0-01", "self", "self_declared"),
    ("C0-02", "repeat", "repeated_clean"),
    ("C0-03", "branch", "branch_coverage"),
    ("C0-04", "env", "omit_environment"),
    ("C0-05", "state", "omit_state"),
    ("C0-06", "random", "assume_determinism"),
    ("C0-07", "time", "omit_time"),
    ("C0-08", "schedule", "omit_schedule"),
    ("C0-09", "multi", "first_effect_only"),
    ("C0-10", "native", "drop_unknown"),
    ("C0-11", "timeout", "timeout_empty"),
    ("C0-12", "drift", "source_label_binding"),
    ("C0-13", "world", "world_shrink"),
    ("C0-14", "malformed", "malformed_launder"),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", required=True)
    args = ap.parse_args()

    rows = []
    for vid, cname, mname in ATTACKS:
        c = CASES[cname]
        prod = mutant(mname, c)
        eligible, checks, o = judge(c, prod)
        killed = prod["claims_closed"] and not eligible
        failed_checks = sorted(k for k, v in checks.items() if not v)
        rows.append({
            "id": vid,
            "case": cname,
            "mutant": mname,
            "producer_claimed_closed": prod["claims_closed"],
            "actual_relation": o["relation"],
            "producer_relation": prod["relation"],
            "failed_soundness_checks": failed_checks,
            "killed": killed,
        })

    closed = CASES["closed"]
    p1 = full_enumerator(closed)
    p1_ok, p1_checks, p1_oracle = judge(closed, p1)
    p2 = full_enumerator(closed, reverse=True)
    p2_ok, p2_checks, p2_oracle = judge(closed, p2)
    representation_invariant = p1_oracle["relation"] == p2_oracle["relation"] and p1["relation"] == p2["relation"]

    killed = sum(r["killed"] for r in rows)
    positive = int(p1_ok) + int(p2_ok and representation_invariant)
    result = {
        "gate": "RISU_KERNEL_K1_CLOSURE_FALSIFICATION_C0",
        "status": "PASS" if killed == 14 and positive == 2 else "FAIL",
        "frozen_base": "581ab6c1596751242a312b72d743d7595a43b327",
        "unsound_mutants_total": 14,
        "unsound_mutants_killed": killed,
        "positive_controls_total": 2,
        "positive_controls_passed": positive,
        "semantic_kernel_changed": False,
        "preservation_authority_created": False,
        "oracle_scope": "SYNTHETIC_FALSIFICATION_ONLY_NOT_PRODUCTION_AUTHORITY",
        "rows": rows,
        "positive_controls": [
            {"id": "C0-P1", "eligible": p1_ok, "checks": p1_checks},
            {"id": "C0-P2", "eligible": p2_ok and representation_invariant, "checks": p2_checks, "representation_invariant": representation_invariant},
        ],
        "derived_minimum_obligations": [
            "bind exact implementation bytes or an equivalently strong independently checkable implementation identity",
            "bind exactly the W0 admitted-world domain",
            "justify completeness over every consequence-relevant operational dimension rather than merely sample it",
            "account for persistent state, nondeterminism/randomness, time, and scheduling whenever they can affect consequences",
            "observe the entire declared consequential cut, including multiple effects",
            "keep the consequence universe open to target-native outcomes",
            "treat timeout, unresolved execution, malformed observation, or parser uncertainty as incompleteness rather than safety",
            "treat replay counts and coverage metrics as diagnostics, not closure proofs",
            "make closure evidence independently checkable rather than producer-self-certified",
        ],
        "next_if_pass": "Design C1 bounded implementation-adequacy proof lane around independently checkable boundary completeness; do not modify K1 ALLOW/REALIZE semantics.",
    }
    Path(args.output).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
