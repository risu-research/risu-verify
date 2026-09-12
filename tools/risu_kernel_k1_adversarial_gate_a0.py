#!/usr/bin/env python3
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
PROTOCOL = ROOT / "protocols" / "RISU_KERNEL_K1_ADVERSARIAL_GATE_A0.json"


def pairs(rows):
    return frozenset((str(w), str(c)) for w, c in rows)


def normalize(case):
    return {
        "id": case["id"],
        "worlds": tuple(str(x) for x in case["worlds"]),
        "allow": pairs(case["allow"]),
        "actual_possible": pairs(case["actual_possible"]),
        "realize": pairs(case["realize"]),
        "grounded": pairs(case["grounded"]),
        "expected": case["expected"],
        "diagnostic_only": case.get("diagnostic_only", {}),
    }


def well_formed(c, *, allow_empty_allow=False, allow_empty_world=False):
    W = set(c["worlds"])
    if not W and not allow_empty_world:
        return False
    if not allow_empty_allow:
        for w in W:
            if not any(pw == w for pw, _ in c["allow"]):
                return False
    for key in ("allow", "actual_possible", "realize", "grounded"):
        if any(w not in W for w, _ in c[key]):
            return False
    if not c["grounded"] <= c["realize"]:
        return False
    return True


def total_at_cut(c):
    W = set(c["worlds"])
    return all(any(pw == w for pw, _ in c["actual_possible"]) for w in W)


def reference_verdict(c):
    if not well_formed(c):
        return "MALFORMED"

    # BREAKING is deliberately local and asymmetric. A single grounded forbidden
    # realization is sufficient even when unrelated target scope is incomplete.
    grounded_realize = c["realize"] & c["grounded"]
    if grounded_realize - c["allow"]:
        return "BREAKING"

    # actual_possible is an A0-only adversarial oracle. Future K1 MUST replace
    # this equality test with an independently checkable closure certificate;
    # it MUST NOT trust an asserted "closed": true bit.
    closed = c["realize"] == c["actual_possible"]
    fully_grounded = c["realize"] <= c["grounded"]

    if (
        closed
        and fully_grounded
        and total_at_cut(c)
        and c["realize"] <= c["allow"]
    ):
        return "PRESERVED"
    return "UNKNOWN"


# --- Deliberately wrong kernels. A0 is only strong if its cases kill them. ---

def M1_NO_CLOSURE(c):
    if not well_formed(c):
        return "MALFORMED"
    if (c["realize"] & c["grounded"]) - c["allow"]:
        return "BREAKING"
    if c["realize"] <= c["grounded"] and total_at_cut(c) and c["realize"] <= c["allow"]:
        return "PRESERVED"
    return "UNKNOWN"


def M2_MASK_NONDET_BAD_BRANCH(c):
    if not well_formed(c):
        return "MALFORMED"
    W = set(c["worlds"])
    for w in W:
        gr = {p for p in c["realize"] & c["grounded"] if p[0] == w}
        forbidden = gr - c["allow"]
        allowed = gr & c["allow"]
        if forbidden and not allowed:
            return "BREAKING"
    closed = c["realize"] == c["actual_possible"]
    fully_grounded = c["realize"] <= c["grounded"]
    if not (closed and fully_grounded and total_at_cut(c)):
        return "UNKNOWN"
    # BUG: one allowed branch is treated as sanitizing forbidden siblings.
    if all(({p for p in c["realize"] if p[0] == w} & c["allow"]) for w in W):
        return "PRESERVED"
    return "UNKNOWN"


def M3_UNGROUNDED_COUNTS_AS_BREAK(c):
    if not well_formed(c):
        return "MALFORMED"
    if c["realize"] - c["allow"]:
        return "BREAKING"
    if c["realize"] == c["actual_possible"] and c["realize"] <= c["grounded"] and total_at_cut(c):
        return "PRESERVED"
    return "UNKNOWN"


def M4_REQUIRE_EQUALITY_NOT_SUBSET(c):
    if not well_formed(c):
        return "MALFORMED"
    if (c["realize"] & c["grounded"]) - c["allow"]:
        return "BREAKING"
    if (
        c["realize"] == c["actual_possible"]
        and c["realize"] <= c["grounded"]
        and total_at_cut(c)
        and c["realize"] == c["allow"]
    ):
        return "PRESERVED"
    return "UNKNOWN"


def M5_GLOBAL_COMPLETENESS_BEFORE_LOCAL_BREAK(c):
    if not well_formed(c):
        return "MALFORMED"
    if not (
        c["realize"] == c["actual_possible"]
        and c["realize"] <= c["grounded"]
        and total_at_cut(c)
    ):
        return "UNKNOWN"
    return "BREAKING" if c["realize"] - c["allow"] else "PRESERVED"


def M6_ALLOW_EMPTY_ALLOW(c):
    if not well_formed(c, allow_empty_allow=True):
        return "MALFORMED"
    if (c["realize"] & c["grounded"]) - c["allow"]:
        return "BREAKING"
    if (
        c["realize"] == c["actual_possible"]
        and c["realize"] <= c["grounded"]
        and total_at_cut(c)
        and c["realize"] <= c["allow"]
    ):
        return "PRESERVED"
    return "UNKNOWN"


def M7_ALLOW_EMPTY_WORLD(c):
    if not well_formed(c, allow_empty_world=True):
        return "MALFORMED"
    if (c["realize"] & c["grounded"]) - c["allow"]:
        return "BREAKING"
    if (
        c["realize"] == c["actual_possible"]
        and c["realize"] <= c["grounded"]
        and total_at_cut(c)
        and c["realize"] <= c["allow"]
    ):
        return "PRESERVED"
    return "UNKNOWN"


def M8_NO_TOTALITY(c):
    if not well_formed(c):
        return "MALFORMED"
    if (c["realize"] & c["grounded"]) - c["allow"]:
        return "BREAKING"
    if c["realize"] == c["actual_possible"] and c["realize"] <= c["grounded"] and c["realize"] <= c["allow"]:
        return "PRESERVED"
    return "UNKNOWN"


def M9_CLOSED_CONSEQUENCE_UNIVERSE(c):
    if not well_formed(c):
        return "MALFORMED"
    # BUG: target-native consequences not already named by ALLOW are silently
    # dropped as "outside the vocabulary."
    realize = frozenset(p for p in c["realize"] if p in c["allow"])
    grounded = frozenset(p for p in c["grounded"] if p in realize)
    actual = frozenset(p for p in c["actual_possible"] if p in c["allow"])
    if (realize & grounded) - c["allow"]:
        return "BREAKING"
    W = set(c["worlds"])
    total = all(any(pw == w for pw, _ in actual) for w in W)
    if realize == actual and realize <= grounded and total and realize <= c["allow"]:
        return "PRESERVED"
    return "UNKNOWN"


def M10_FACTORIZATION_ONLY(c):
    obs_rows = c["diagnostic_only"].get("legacy_observation")
    if not obs_rows:
        return reference_verdict(c)
    if not well_formed(c):
        return "MALFORMED"
    obs = dict((str(w), str(v)) for w, v in obs_rows)
    W = list(c["worlds"])

    def allowset(w):
        return {u for pw, u in c["allow"] if pw == w}

    for i, w1 in enumerate(W):
        for w2 in W[i + 1:]:
            if obs.get(w1) == obs.get(w2) and allowset(w1) != allowset(w2):
                return "BREAKING"
    # BUG: target distinguishes the worlds, so this mutant declares success
    # even though it can realize the wrong consequence.
    return "PRESERVED"


MUTANTS = {
    "M1_NO_CLOSURE": M1_NO_CLOSURE,
    "M2_MASK_NONDET_BAD_BRANCH": M2_MASK_NONDET_BAD_BRANCH,
    "M3_UNGROUNDED_COUNTS_AS_BREAK": M3_UNGROUNDED_COUNTS_AS_BREAK,
    "M4_REQUIRE_EQUALITY_NOT_SUBSET": M4_REQUIRE_EQUALITY_NOT_SUBSET,
    "M5_GLOBAL_COMPLETENESS_BEFORE_LOCAL_BREAK": M5_GLOBAL_COMPLETENESS_BEFORE_LOCAL_BREAK,
    "M6_ALLOW_EMPTY_ALLOW": M6_ALLOW_EMPTY_ALLOW,
    "M7_ALLOW_EMPTY_WORLD": M7_ALLOW_EMPTY_WORLD,
    "M8_NO_TOTALITY": M8_NO_TOTALITY,
    "M9_CLOSED_CONSEQUENCE_UNIVERSE": M9_CLOSED_CONSEQUENCE_UNIVERSE,
    "M10_FACTORIZATION_ONLY": M10_FACTORIZATION_ONLY,
}


def fail(reason, **extra):
    print(json.dumps({"status": "FAIL", "reason": reason, **extra}, indent=2, sort_keys=True))
    raise SystemExit(1)


def kernel_fingerprint(c):
    # A0-only oracle data and diagnostic metadata are intentionally excluded.
    return (
        c["worlds"],
        tuple(sorted(c["allow"])),
        tuple(sorted(c["realize"])),
        tuple(sorted(c["grounded"])),
    )


def run_boundary_metamorphics(cases_by_id):
    # B1 representation invariance.
    base = dict(cases_by_id["K0_BASELINE"])
    altered = dict(base)
    altered["diagnostic_only"] = {"carrier": "totally-different-representation"}
    if kernel_fingerprint(base) != kernel_fingerprint(altered):
        fail("representation-invariance fixture changed kernel fields")
    if reference_verdict(base) != reference_verdict(altered):
        fail("diagnostic-only representation changed semantic verdict")

    # B2 evidence ablation.
    source = dict(cases_by_id["K1_WRONG_LABEL_DISTINGUISHABLE"])
    ablated = dict(source)
    forbidden = next(iter((source["realize"] & source["grounded"]) - source["allow"]))
    ablated["grounded"] = frozenset(p for p in source["grounded"] if p != forbidden)
    if reference_verdict(source) != "BREAKING":
        fail("evidence-ablation source was not BREAKING")
    if reference_verdict(ablated) != "UNKNOWN":
        fail("evidence ablation did not downgrade sole forbidden witness to UNKNOWN")

    # B3 post-check material transition. W may name a trajectory; grounding is
    # at the consequential cut, so no temporal primitive is required in K1.
    trace = {
        "id": "B3_POST_CHECK_TRANSITION_TRACE",
        "worlds": ("reviewed=H0|check=H0|effect=H1",),
        "allow": frozenset({("reviewed=H0|check=H0|effect=H1", "STALE_REJECT")}),
        "actual_possible": frozenset({("reviewed=H0|check=H0|effect=H1", "COMMIT_H1")}),
        "realize": frozenset({("reviewed=H0|check=H0|effect=H1", "COMMIT_H1")}),
        "grounded": frozenset({("reviewed=H0|check=H0|effect=H1", "COMMIT_H1")}),
        "expected": "BREAKING",
        "diagnostic_only": {"precheck": "PASS_AT_H0"},
    }
    if reference_verdict(trace) != "BREAKING":
        fail("post-check transition trace was not detected as BREAKING")

    # B4 claim-scope binding premise. W and ALLOW must be future claim identity.
    widened = dict(source)
    widened["allow"] = source["allow"] | frozenset({forbidden})
    if reference_verdict(widened) != "PRESERVED":
        fail("contract-widening probe did not demonstrate claim-changing attack")

    return {
        "representation_invariance": "PASS",
        "evidence_ablation": "PASS",
        "post_check_transition": "PASS",
        "contract_scope_binding_requirement": "PASS",
    }


def main():
    protocol = json.loads(PROTOCOL.read_text())
    raw_cases = protocol["kernel_basis"]
    cases = [normalize(x) for x in raw_cases]
    cases_by_id = {c["id"]: c for c in cases}

    expected_mutants = set(protocol["mutants"])
    if expected_mutants != set(MUTANTS):
        fail("protocol/tool mutant set mismatch", protocol=sorted(expected_mutants), tool=sorted(MUTANTS))

    verdict_rows = []
    for c in cases:
        actual = reference_verdict(c)
        verdict_rows.append({"case": c["id"], "expected": c["expected"], "actual": actual})
        if actual != c["expected"]:
            fail("reference verdict mismatch", case=c["id"], expected=c["expected"], actual=actual)

    mutation_killers = [c for c, raw in zip(cases, raw_cases) if raw.get("role") == "mutation_killer"]
    kill_map = {}
    for c in mutation_killers:
        killed = sorted(name for name, fn in MUTANTS.items() if fn(c) != c["expected"])
        kill_map[c["id"]] = killed

    killed_all = set().union(*(set(v) for v in kill_map.values()))
    survivors = sorted(set(MUTANTS) - killed_all)
    if survivors:
        fail("mutants survived A0 basis", survivors=survivors, kill_map=kill_map)

    # Deletion-minimality: every mutation-killer is indispensable against this
    # explicitly declared mutant class.
    indispensability = {}
    for removed in mutation_killers:
        kept = [c for c in mutation_killers if c["id"] != removed["id"]]
        killed = set()
        for c in kept:
            killed.update(name for name, fn in MUTANTS.items() if fn(c) != c["expected"])
        survivors_if_removed = sorted(set(MUTANTS) - killed)
        indispensability[removed["id"]] = survivors_if_removed
        if not survivors_if_removed:
            fail("mutation basis is not deletion-minimal", redundant_case=removed["id"])

    boundary = run_boundary_metamorphics(cases_by_id)

    print(json.dumps({
        "status": "PASS",
        "protocol_id": protocol["protocol_id"],
        "parent_sha": protocol["parent_sha"],
        "reference_cases": len(cases),
        "mutation_killers": len(mutation_killers),
        "mutants": len(MUTANTS),
        "mutation_score": "10/10",
        "basis_deletion_minimal": True,
        "verdicts": verdict_rows,
        "kill_map": kill_map,
        "indispensability": indispensability,
        "boundary_metamorphics": boundary,
        "constitutional_findings": [
            "ALLOW/REALIZE remains sufficient for the tested safety-refinement semantics.",
            "Factorization is not a fundamental K1 judgment.",
            "The consequence universe must remain open to target-native outcomes.",
            "PRESERVED requires checkable closure, pair grounding, and per-world outcome totality; closure cannot be a trusted boolean.",
            "BREAKING is local/asymmetric: one grounded forbidden realization dominates unrelated incompleteness.",
            "W must be nonempty and ALLOW must be nonempty per admitted world as claim well-formedness.",
            "A strict safe subset remains PRESERVED under the pure safety profile; stronger availability/liveness obligations belong to an explicit stronger profile unless future falsification proves otherwise.",
            "W and ALLOW must be cryptographically bound into future claim identity."
        ]
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
