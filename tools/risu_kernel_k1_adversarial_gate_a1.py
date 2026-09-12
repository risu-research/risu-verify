#!/usr/bin/env python3
"""K1 Adversarial Gate A1 — cross-domain constitutional falsification.

The gate asks whether heterogeneous obligations require a new K1 semantic
primitive under a prospective, target-independent lowering.  It deliberately
separates semantic-kernel counterexamples from elaboration defects and proof-
kind limitations.

Synthetic semantic descriptors are prospective test inputs only.  They are not
claims about external implementations.
"""

import argparse
import copy
import hashlib
import importlib.util
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
PROTOCOL_PATH = ROOT / "protocols" / "RISU_KERNEL_K1_ADVERSARIAL_GATE_A1.json"
CHECKER_PATH = ROOT / "kernel" / "k1_checker_w1.py"

spec = importlib.util.spec_from_file_location("k1_checker_w1", CHECKER_PATH)
K = importlib.util.module_from_spec(spec)
spec.loader.exec_module(K)


class GateFailure(Exception):
    pass


class LoweringReject(Exception):
    pass


def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def htoken(prefix, domain, obj):
    raw = (domain + "\0" + canon(obj)).encode("utf-8")
    return prefix + hashlib.sha256(raw).hexdigest()


def require_fields(desc, required, where):
    if not isinstance(desc, dict):
        raise LoweringReject(where + ": semantic descriptor must be an object")
    missing = sorted(set(required) - set(desc))
    if missing:
        raise LoweringReject(where + ": missing material fields " + ",".join(missing))
    for key in required:
        if desc[key] is None:
            raise LoweringReject(where + f": null material field {key}")


def world_id(case, desc):
    require_fields(desc, case["material_world_fields"], case["id"] + ".world")
    return htoken("w:sha256:", "RISU-K1-A1-WORLD", desc)


def consequence_id(case, desc):
    require_fields(desc, case["material_consequence_fields"], case["id"] + ".consequence")
    return htoken("c:sha256:", "RISU-K1-A1-CONSEQUENCE", desc)


def lowering_commitment(case):
    source = {
        "case_id": case["id"],
        "family": case["family"],
        "material_world_fields": case["material_world_fields"],
        "material_consequence_fields": case["material_consequence_fields"],
        "worlds": [
            {"key": w["key"], "descriptor": w["descriptor"], "allow": w["allow"]}
            for w in case["worlds"]
        ],
    }
    return htoken("e:sha256:", "RISU-K1-A1-SOURCE-LOWERING", source)


def build_claim(case):
    worlds = []
    allow = []
    key_to_world = {}
    seen_keys = set()
    for entry in case["worlds"]:
        key = entry["key"]
        if key in seen_keys:
            raise LoweringReject(case["id"] + ": duplicate source world key")
        seen_keys.add(key)
        w = world_id(case, entry["descriptor"])
        if w in worlds:
            raise LoweringReject(case["id"] + ": semantic world alias after lowering")
        key_to_world[key] = w
        worlds.append(w)
        if not isinstance(entry["allow"], list) or not entry["allow"]:
            raise LoweringReject(case["id"] + ": source world without ALLOW consequence")
        for desc in entry["allow"]:
            allow.append([w, consequence_id(case, desc)])

    claim = {
        "wire": "risu.k1.w0",
        "kind": "claim",
        "semantics": "safety-subset-v1",
        "worlds": worlds,
        "allow": allow,
        "claim_id": "claim:sha256:" + "0" * 64,
    }
    claim["claim_id"] = K.claim_id(claim)
    K.check_claim(claim)
    return claim, key_to_world, lowering_commitment(case)


def target_pairs(case, target_rows, key_to_world):
    if not isinstance(target_rows, list):
        raise LoweringReject(case["id"] + ": target rows must be an array")
    out = []
    for i, row in enumerate(target_rows):
        if not isinstance(row, list) or len(row) != 2:
            raise LoweringReject(case["id"] + f": target[{i}] malformed")
        key, desc = row
        if key not in key_to_world:
            raise LoweringReject(case["id"] + f": target[{i}] references undeclared world key")
        out.append([key_to_world[key], consequence_id(case, desc)])
    if len({tuple(x) for x in out}) != len(out):
        raise LoweringReject(case["id"] + ": duplicate target consequence pair")
    return out


def make_artifact(claim, possible):
    W = frozenset(claim["worlds"])
    R = frozenset((p[0], p[1]) for p in possible)
    target = K.target_id(W, R)
    obj = {
        "proof_format": K.PROOF_KIND,
        "claim_id": claim["claim_id"],
        "target_id": target,
        "worlds": list(claim["worlds"]),
        "possible": possible,
    }
    raw = (canon(obj) + "\n").encode("utf-8")
    artifact_id = "p:sha256:" + hashlib.sha256(raw).hexdigest()
    return obj, raw, artifact_id


def make_certificate(claim, possible, artifact, artifact_id):
    proof = {"kind": K.PROOF_KIND, "artifact": artifact_id}
    cert = {
        "wire": "risu.k1.w0",
        "kind": "preservation_certificate",
        "claim_id": claim["claim_id"],
        "target_id": artifact["target_id"],
        "realize": copy.deepcopy(possible),
        "closure_proof": copy.deepcopy(proof),
        "grounding_proofs": [
            {"pair": copy.deepcopy(pair), "proof": copy.deepcopy(proof)} for pair in possible
        ],
        "evidence_roots": [],
        "certificate_id": "cert:sha256:" + "0" * 64,
    }
    cert["certificate_id"] = K.cert_id(cert)
    return cert


def make_witness(claim, pair, artifact, artifact_id):
    wit = {
        "wire": "risu.k1.w0",
        "kind": "regression_witness",
        "claim_id": claim["claim_id"],
        "target_id": artifact["target_id"],
        "pair": list(pair),
        "grounding_proof": {"kind": K.PROOF_KIND, "artifact": artifact_id},
        "evidence_roots": [],
        "witness_id": "wit:sha256:" + "0" * 64,
    }
    wit["witness_id"] = K.witness_id(wit)
    return wit


def evaluate_target(case, target_name):
    claim, key_to_world, source_commitment = build_claim(case)
    possible = target_pairs(case, case["targets"][target_name], key_to_world)
    artifact, raw, artifact_id = make_artifact(claim, possible)
    allow = frozenset((x[0], x[1]) for x in claim["allow"])
    realize = frozenset((x[0], x[1]) for x in possible)
    forbidden = sorted(realize - allow)

    try:
        if forbidden:
            witness = make_witness(claim, forbidden[0], artifact, artifact_id)
            checked = K.check_witness(witness, claim, raw)
            if checked["semantic_claim"] != "REGRESSION":
                raise GateFailure(case["id"] + ": W1 accepted witness without REGRESSION")
            verdict = "REGRESSION"
            proof_id = witness["witness_id"]
        else:
            cert = make_certificate(claim, possible, artifact, artifact_id)
            checked = K.check_certificate(cert, claim, raw)
            if checked["semantic_claim"] != "PRESERVATION":
                raise GateFailure(case["id"] + ": W1 accepted certificate without PRESERVATION")
            verdict = "PRESERVATION"
            proof_id = cert["certificate_id"]
    except (K.Reject, K.Unsupported) as exc:
        return {
            "case_id": case["id"],
            "family": case["family"],
            "target": target_name,
            "verdict": "ASSURANCE_INCOMPLETE",
            "reason": str(exc),
            "claim_id": claim["claim_id"],
            "target_id": artifact["target_id"],
            "source_lowering_commitment": source_commitment,
            "forbidden_pair_count": len(forbidden),
        }

    return {
        "case_id": case["id"],
        "family": case["family"],
        "target": target_name,
        "verdict": verdict,
        "claim_id": claim["claim_id"],
        "target_id": artifact["target_id"],
        "source_lowering_commitment": source_commitment,
        "forbidden_pair_count": len(forbidden),
        "proof_object_id": proof_id,
        "proof_scope": checked["assurance_scope"],
        "implementation_binding": checked["implementation_binding"],
    }


def protocol_case(protocol, case_id):
    return next(c for c in protocol["cases"] if c["id"] == case_id)


def projected(desc, ignored):
    return {k: copy.deepcopy(v) for k, v in desc.items() if k not in set(ignored)}


def mutant_world_id(case, desc, ignored):
    # The mutant retains all fields syntactically but incorrectly omits selected
    # material fields from identity.
    require_fields(desc, case["material_world_fields"], case["id"] + ".mutant_world")
    return htoken("w:sha256:", "RISU-K1-A1-WORLD", projected(desc, ignored))


def mutant_consequence_id(case, desc, ignored):
    require_fields(desc, case["material_consequence_fields"], case["id"] + ".mutant_consequence")
    return htoken("c:sha256:", "RISU-K1-A1-CONSEQUENCE", projected(desc, ignored))


def mutant_relation_verdict(case, target_name, ignore_world=(), ignore_consequence=()):
    key_to_world = {}
    allow = set()
    for entry in case["worlds"]:
        w = mutant_world_id(case, entry["descriptor"], ignore_world)
        key_to_world[entry["key"]] = w
        for desc in entry["allow"]:
            allow.add((w, mutant_consequence_id(case, desc, ignore_consequence)))

    realize = set()
    for key, desc in case["targets"][target_name]:
        realize.add((key_to_world[key], mutant_consequence_id(case, desc, ignore_consequence)))
    return "PRESERVATION" if realize.issubset(allow) else "REGRESSION"


def run_mutations(protocol):
    results = []

    auth = protocol_case(protocol, "A1-AUTH-REVOCATION")
    sealed_claim, _, sealed_commit = build_claim(auth)

    # 1. A bad target may not retroactively enlarge ALLOW.
    amended = copy.deepcopy(auth)
    bad_desc = amended["targets"]["bad"][1][1]
    amended["worlds"][1]["allow"].append(copy.deepcopy(bad_desc))
    amended_claim, _, amended_commit = build_claim(amended)
    if amended_claim["claim_id"] == sealed_claim["claim_id"] or amended_commit == sealed_commit:
        raise GateFailure("LATE_ALLOW_AMNESTY: source mutation failed to move identity")
    results.append({"mutation": "LATE_ALLOW_AMNESTY", "killed": True, "mechanism": "CLAIM_AND_SOURCE_COMMITMENT_DRIFT"})

    # 2. A target outcome may not create a new source-world distinction post hoc.
    split = copy.deepcopy(auth)
    split["worlds"][1]["descriptor"]["observed_target_outcome"] = "executed_after_revocation"
    split["worlds"][1]["allow"].append(copy.deepcopy(bad_desc))
    split_claim, _, split_commit = build_claim(split)
    if split_claim["claim_id"] == sealed_claim["claim_id"] or split_commit == sealed_commit:
        raise GateFailure("POSTHOC_WORLD_SPLIT: target-dependent rewrite did not move identity")
    results.append({"mutation": "POSTHOC_WORLD_SPLIT", "killed": True, "mechanism": "CLAIM_AND_SOURCE_COMMITMENT_DRIFT"})

    # 3. Realistic identity bug: fields remain present but the world hash ignores
    # revocation state and epoch.  The nonredundant BAD target then falsely
    # becomes a subset because ACTIVE and REVOKED worlds alias.
    if mutant_relation_verdict(auth, "bad", ignore_world=("authorization", "epoch")) != "PRESERVATION":
        raise GateFailure("AUTH_DROP_REVOCATION_STATE: mutant was not exposed by A1 pair")
    if evaluate_target(auth, "bad")["verdict"] != "REGRESSION":
        raise GateFailure("AUTH_DROP_REVOCATION_STATE: correct lowering lost regression")
    results.append({"mutation": "AUTH_DROP_REVOCATION_STATE", "killed": True, "mechanism": "BAD_FALSELY_PRESERVED_IF_WORLD_FIELDS_IGNORED"})

    # 4-5. Recipient and amount are independently necessary consequence identity
    # fields.  Dedicated single-fault targets prevent one mismatch masking the
    # other.
    money = protocol_case(protocol, "A1-MONEY-BINDING")
    if mutant_relation_verdict(money, "bad_recipient", ignore_consequence=("recipient",)) != "PRESERVATION":
        raise GateFailure("MONEY_DROP_RECIPIENT: mutant was not exposed")
    if evaluate_target(money, "bad_recipient")["verdict"] != "REGRESSION":
        raise GateFailure("MONEY_DROP_RECIPIENT: correct lowering lost regression")
    results.append({"mutation": "MONEY_DROP_RECIPIENT", "killed": True, "mechanism": "BAD_FALSELY_PRESERVED_IF_RECIPIENT_IGNORED"})

    if mutant_relation_verdict(money, "bad_amount", ignore_consequence=("amount_minor",)) != "PRESERVATION":
        raise GateFailure("MONEY_DROP_AMOUNT: mutant was not exposed")
    if evaluate_target(money, "bad_amount")["verdict"] != "REGRESSION":
        raise GateFailure("MONEY_DROP_AMOUNT: correct lowering lost regression")
    results.append({"mutation": "MONEY_DROP_AMOUNT", "killed": True, "mechanism": "BAD_FALSELY_PRESERVED_IF_AMOUNT_IGNORED"})

    # 6. Idempotence BAD intentionally uses the same consequence as the first
    # invocation.  Only history/multiplicity in W separates it.
    idem = protocol_case(protocol, "A1-IDEMPOTENCE")
    if mutant_relation_verdict(idem, "bad", ignore_world=("invocation_index", "prior_effects")) != "PRESERVATION":
        raise GateFailure("IDEMPOTENCE_DROP_HISTORY: mutant was not exposed")
    if evaluate_target(idem, "bad")["verdict"] != "REGRESSION":
        raise GateFailure("IDEMPOTENCE_DROP_HISTORY: correct lowering lost regression")
    results.append({"mutation": "IDEMPOTENCE_DROP_HISTORY", "killed": True, "mechanism": "BAD_FALSELY_PRESERVED_IF_HISTORY_IGNORED"})

    # 7. Audience identity is consequential, not metadata.
    comm = protocol_case(protocol, "A1-COMM-AUDIENCE")
    if mutant_relation_verdict(comm, "bad", ignore_consequence=("audience",)) != "PRESERVATION":
        raise GateFailure("COMM_DROP_AUDIENCE: mutant was not exposed")
    if evaluate_target(comm, "bad")["verdict"] != "REGRESSION":
        raise GateFailure("COMM_DROP_AUDIENCE: correct lowering lost regression")
    results.append({"mutation": "COMM_DROP_AUDIENCE", "killed": True, "mechanism": "BAD_FALSELY_PRESERVED_IF_AUDIENCE_IGNORED"})

    # 8. Bounded progress is terminalized at the declared deadline cut.  If the
    # terminal status is ignored, deadline miss aliases completion.
    deadline = protocol_case(protocol, "A1-BOUNDED-DEADLINE")
    if mutant_relation_verdict(deadline, "bad", ignore_consequence=("terminal_status",)) != "PRESERVATION":
        raise GateFailure("DEADLINE_DROP_TERMINAL_STATUS: mutant was not exposed")
    if evaluate_target(deadline, "bad")["verdict"] != "REGRESSION":
        raise GateFailure("DEADLINE_DROP_TERMINAL_STATUS: correct lowering lost regression")
    results.append({"mutation": "DEADLINE_DROP_TERMINAL_STATUS", "killed": True, "mechanism": "BAD_FALSELY_PRESERVED_IF_TERMINAL_STATUS_IGNORED"})

    # 9. No consequence at a bounded cut is incompleteness, never vacuous safety.
    deadline_silent = evaluate_target(deadline, "silent")
    if deadline_silent["verdict"] != "ASSURANCE_INCOMPLETE":
        raise GateFailure("DEADLINE_SILENCE_AS_PRESERVED: silent target was not incomplete")
    results.append({"mutation": "DEADLINE_SILENCE_AS_PRESERVED", "killed": True, "mechanism": "W1_TOTALITY_OR_EMPTY_RELATION_REJECT"})

    # 10. Arbitrarily choosing a finite deadline changes an unbounded liveness
    # obligation; a finite-model proof cannot be laundered as the original claim.
    s = next(x for x in protocol["scope_sentinels"] if x["probe"] == "unbounded_liveness_scope")
    unbounded = {"obligation": s["obligation"], "deadline": None, "scope": s["required_semantic_scope"]}
    bounded_surrogate = {"obligation": s["obligation"], "deadline": 10, "scope": "BOUNDED_DEADLINE_CUT"}
    u = htoken("e:sha256:", "RISU-K1-A1-LIVENESS-SOURCE", unbounded)
    b = htoken("e:sha256:", "RISU-K1-A1-LIVENESS-SOURCE", bounded_surrogate)
    if u == b:
        raise GateFailure("UNBOUNDED_LIVENESS_AS_FINITE_MODEL_PRESERVED: bounded surrogate did not change source identity")
    results.append({"mutation": "UNBOUNDED_LIVENESS_AS_FINITE_MODEL_PRESERVED", "killed": True, "mechanism": "BOUNDED_SURROGATE_SOURCE_IDENTITY_DRIFT"})

    expected = set(protocol["mutation_requirements"])
    got = {x["mutation"] for x in results}
    if expected != got:
        raise GateFailure("mutation suite mismatch: expected=" + repr(sorted(expected)) + " got=" + repr(sorted(got)))
    if not all(x["killed"] for x in results):
        raise GateFailure("not all declared A1 mutations were killed")
    return results


def probe_unbounded_liveness(sentinel):
    # This is an honesty test, not a theorem prover.  A finite deadline surrogate
    # is a different source obligation, and W1 explicitly claims only a finite
    # declared-model scope.  Therefore A1 must not call this preservation.
    if sentinel["required_semantic_scope"] == sentinel["current_proof_scope"]:
        raise GateFailure(sentinel["id"] + ": required scope unexpectedly equals W1 scope")
    return {
        "id": sentinel["id"],
        "classification": "PROOF_KIND_GAP",
        "kernel_implication": sentinel["kernel_implication"],
        "reason": "unbounded liveness is not discharged by k1.finite-model/v1; choosing a finite deadline changes source identity",
    }


def probe_local_witness_partial_model(protocol, sentinel):
    # Construct exactly the asymmetry A0 says K1 should support: one concrete
    # forbidden pair, while an unrelated world has no global finite-model row.
    # W1 finite-model/v1 rejects because check_artifact requires per-world
    # totality.  That exposes a proof-kind gap without changing the K1 rule.
    case = protocol_case(protocol, "A1-AUTH-REVOCATION")
    claim, key_to_world, _ = build_claim(case)
    partial_rows = [case["targets"]["bad"][1]]  # revoked forbidden row only
    possible = target_pairs(case, partial_rows, key_to_world)
    allow = frozenset((x[0], x[1]) for x in claim["allow"])
    pair = tuple(possible[0])
    if pair in allow:
        raise GateFailure(sentinel["id"] + ": constructed pair is not forbidden")
    artifact, raw, artifact_id = make_artifact(claim, possible)
    witness = make_witness(claim, pair, artifact, artifact_id)
    try:
        K.check_witness(witness, claim, raw)
    except K.Reject as exc:
        if "non-total consequential cut" not in str(exc):
            raise GateFailure(sentinel["id"] + ": unexpected W1 rejection: " + str(exc))
        return {
            "id": sentinel["id"],
            "classification": "PROOF_KIND_GAP",
            "kernel_implication": sentinel["kernel_implication"],
            "reason": "abstract K1 has a concrete forbidden pair, but W1 finite-model/v1 requires unrelated-world totality",
        }
    raise GateFailure(sentinel["id"] + ": W1 unexpectedly discharged partial-model local witness")


def classify_sentinels(protocol):
    out = []
    for s in protocol["scope_sentinels"]:
        probe = s.get("probe")
        if probe == "unbounded_liveness_scope":
            row = probe_unbounded_liveness(s)
        elif probe == "local_witness_partial_model":
            row = probe_local_witness_partial_model(protocol, s)
        else:
            raise GateFailure(s["id"] + ": unknown sentinel probe")
        if row["classification"] != s["expected_classification"]:
            raise GateFailure(s["id"] + ": scope classification mismatch")
        row["required_semantic_scope"] = s["required_semantic_scope"]
        row["current_proof_scope"] = s["current_proof_scope"]
        out.append(row)
    return out


def validate_protocol(protocol):
    if protocol.get("gate_id") != "RISU_KERNEL_K1_ADVERSARIAL_GATE_A1":
        raise GateFailure("unexpected gate id")
    cases = protocol.get("cases")
    if not isinstance(cases, list) or not cases:
        raise GateFailure("no A1 cases")
    ids = [c["id"] for c in cases]
    if len(ids) != len(set(ids)):
        raise GateFailure("duplicate A1 case id")
    families = {c["family"] for c in cases}
    if families != set(protocol["required_pressure_classes"]):
        raise GateFailure("pressure class coverage mismatch")
    for c in cases:
        if set(c["expected"]) - set(c["targets"]):
            raise GateFailure(c["id"] + ": expected target missing")
        if "good" not in c["expected"] or "bad" not in c["expected"]:
            raise GateFailure(c["id"] + ": GOOD/BAD pair required")


def run(protocol):
    validate_protocol(protocol)
    rows = []
    for case in protocol["cases"]:
        per_target = {}
        for target_name, expected in case["expected"].items():
            result = evaluate_target(case, target_name)
            if result["verdict"] != expected:
                raise GateFailure(f"{case['id']}:{target_name}: expected {expected}, got {result['verdict']}")
            per_target[target_name] = result
            rows.append(result)

        good = per_target["good"]
        bad = per_target["bad"]
        if good["claim_id"] != bad["claim_id"]:
            raise GateFailure(case["id"] + ": GOOD/BAD did not share claim identity")
        if good["source_lowering_commitment"] != bad["source_lowering_commitment"]:
            raise GateFailure(case["id"] + ": GOOD/BAD did not share source lowering commitment")
        if good["target_id"] == bad["target_id"]:
            raise GateFailure(case["id"] + ": GOOD/BAD target identity failed to separate")
        if bad["forbidden_pair_count"] < 1:
            raise GateFailure(case["id"] + ": BAD target lacked a concrete forbidden realization")

    sentinels = classify_sentinels(protocol)
    mutations = run_mutations(protocol)

    return {
        "status": "PASS",
        "gate": protocol["gate_id"],
        "protocol_version": protocol["version"],
        "kernel_verdict": "SURVIVES_A1_DECLARED_CLASS",
        "release_candidate_eligibility": "ELIGIBLE_FOR_SCOPED_K1_RC1",
        "semantic_scope": "CONSEQUENCE_CUT_SAFETY_INCLUDING_BOUNDED_DEADLINE_VIOLATIONS",
        "pressure_classes": protocol["required_pressure_classes"],
        "case_count": len(protocol["cases"]),
        "good_bad_same_claim": f"{len(protocol['cases'])}/{len(protocol['cases'])}",
        "good_preservation": f"{len(protocol['cases'])}/{len(protocol['cases'])}",
        "bad_regression": f"{len(protocol['cases'])}/{len(protocol['cases'])}",
        "declared_mutations_killed": f"{len(mutations)}/{len(mutations)}",
        "kernel_counterexamples": 0,
        "proof_kind_gaps": sum(1 for x in sentinels if x["classification"] == "PROOF_KIND_GAP"),
        "new_kernel_primitives_justified": [],
        "rows": rows,
        "scope_sentinels": sentinels,
        "mutations": mutations,
        "interpretation": (
            "Within the declared A1 class, heterogeneous obligations lower prospectively to the existing K1 relation. "
            "A1 also exposes two proof-ecosystem gaps: unbounded liveness is outside W1 finite-model scope, and W1 "
            "over-requires global finite-model totality for a semantically local forbidden witness. Neither is evidence "
            "for a new K1 semantic primitive. This result does not prove universal completeness."
        ),
    }


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--protocol", default=str(PROTOCOL_PATH))
    parser.add_argument("--output")
    args = parser.parse_args(argv)
    with open(args.protocol, "r", encoding="utf-8") as handle:
        protocol = json.load(handle)
    try:
        result = run(protocol)
    except (GateFailure, LoweringReject, K.Reject, K.Unsupported) as exc:
        print(json.dumps({"status": "FAIL", "reason": str(exc)}, indent=2, sort_keys=True))
        return 1
    text = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        pathlib.Path(args.output).write_text(text, encoding="utf-8")
    print(text, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
