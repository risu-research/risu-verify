#!/usr/bin/env python3
"""K1 Adversarial Gate A1 — cross-domain constitutional falsification.

A1 does not try to make K1 pass.  It asks whether heterogeneous obligations can
be lowered prospectively into the existing W + ALLOW/REALIZE narrow waist
without target-dependent rewriting, and whether current proof limitations are
kept separate from semantic-kernel limitations.

The gate intentionally reuses the tiny W1 checker for finite-model proof
objects.  Source semantic descriptors used here are synthetic and prospective;
they are not claims about external implementations.
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
            {
                "key": w["key"],
                "descriptor": w["descriptor"],
                "allow": w["allow"],
            }
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
            # W1 finite-model/v1 currently grounds a witness through the full
            # declared finite model.  That is a proof-kind limitation, not a
            # requirement of the abstract K1 regression rule.
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


def mutate_drop_fields(desc, fields):
    x = copy.deepcopy(desc)
    for field in fields:
        x.pop(field, None)
    return x


def assert_lowering_rejects(mutated_case, label):
    try:
        build_claim(mutated_case)
    except LoweringReject:
        return {"mutation": label, "killed": True, "mechanism": "LOWERING_REJECT"}
    except K.Reject:
        return {"mutation": label, "killed": True, "mechanism": "K1_WELL_FORMEDNESS_REJECT"}
    raise GateFailure(label + ": malformed source lowering survived")


def run_mutations(protocol):
    results = []

    # 1. Late amnesty: a target violation can be made to look preserved only by
    # changing the already-sealed source claim.  Claim drift must expose it.
    auth = protocol_case(protocol, "A1-AUTH-REVOCATION")
    sealed_claim, _, sealed_commit = build_claim(auth)
    amended = copy.deepcopy(auth)
    bad_desc = amended["targets"]["bad"][1][1]
    amended["worlds"][1]["allow"].append(copy.deepcopy(bad_desc))
    amended_claim, _, amended_commit = build_claim(amended)
    if amended_claim["claim_id"] == sealed_claim["claim_id"] or amended_commit == sealed_commit:
        raise GateFailure("LATE_ALLOW_AMNESTY: source mutation failed to move source identity")
    results.append({"mutation": "LATE_ALLOW_AMNESTY", "killed": True, "mechanism": "CLAIM_AND_SOURCE_COMMITMENT_DRIFT"})

    # 2. Post-hoc world splitting is likewise visible in claim identity.
    split = copy.deepcopy(auth)
    split["worlds"][1]["descriptor"]["observed_target_outcome"] = "executed_under_stale_grant"
    split["worlds"][1]["allow"].append(copy.deepcopy(bad_desc))
    split_claim, _, split_commit = build_claim(split)
    if split_claim["claim_id"] == sealed_claim["claim_id"] or split_commit == sealed_commit:
        raise GateFailure("POSTHOC_WORLD_SPLIT: target-dependent source rewrite did not move identity")
    results.append({"mutation": "POSTHOC_WORLD_SPLIT", "killed": True, "mechanism": "CLAIM_AND_SOURCE_COMMITMENT_DRIFT"})

    # 3. Authorization lowering that drops revocation state/epoch is rejected.
    auth_drop = copy.deepcopy(auth)
    for w in auth_drop["worlds"]:
        w["descriptor"] = mutate_drop_fields(w["descriptor"], ["authorization", "epoch"])
    results.append(assert_lowering_rejects(auth_drop, "AUTH_DROP_REVOCATION_STATE"))

    # Consequence field-drop mutants must be rejected before hashing, including
    # target-native outcomes.  This prevents a lossy lowerer from making a bad
    # target consequence alias an allowed one.
    field_mutants = [
        ("MONEY_DROP_RECIPIENT", "A1-MONEY-BINDING", ["recipient"]),
        ("MONEY_DROP_AMOUNT", "A1-MONEY-BINDING", ["amount_minor"]),
        ("COMM_DROP_AUDIENCE", "A1-COMM-AUDIENCE", ["audience"]),
        ("DEADLINE_DROP_TERMINAL_STATUS", "A1-BOUNDED-DEADLINE", ["terminal_status"]),
    ]
    for label, cid, fields in field_mutants:
        case = protocol_case(protocol, cid)
        mutated = copy.deepcopy(case)
        # Mutate both source and target semantic encoder inputs to simulate a
        # lowerer that silently omits a declared material field.
        for w in mutated["worlds"]:
            w["allow"] = [mutate_drop_fields(x, fields) for x in w["allow"]]
        for tname, rows in mutated["targets"].items():
            mutated["targets"][tname] = [[r[0], mutate_drop_fields(r[1], fields)] for r in rows]
        try:
            build_claim(mutated)
        except LoweringReject:
            results.append({"mutation": label, "killed": True, "mechanism": "MATERIAL_FIELD_REJECT"})
        else:
            raise GateFailure(label + ": lossy consequence lowering survived")

    # 7. Idempotency requires history/multiplicity to remain material in W.
    idem = protocol_case(protocol, "A1-IDEMPOTENCE")
    idem_drop = copy.deepcopy(idem)
    for w in idem_drop["worlds"]:
        w["descriptor"] = mutate_drop_fields(w["descriptor"], ["invocation_index", "prior_effects"])
    results.append(assert_lowering_rejects(idem_drop, "IDEMPOTENCE_DROP_HISTORY"))

    # 9. Silence at a bounded consequential cut is not preservation.
    deadline_silent = evaluate_target(protocol_case(protocol, "A1-BOUNDED-DEADLINE"), "silent")
    if deadline_silent["verdict"] != "ASSURANCE_INCOMPLETE":
        raise GateFailure("DEADLINE_SILENCE_AS_PRESERVED: silent target was not incomplete")
    results.append({"mutation": "DEADLINE_SILENCE_AS_PRESERVED", "killed": True, "mechanism": "W1_TOTALITY_OR_EMPTY_RELATION_REJECT"})

    # 10. Unbounded liveness cannot be laundered through the finite-model proof
    # scope merely by naming an EVENTUALLY consequence atom.
    sentinel = protocol["scope_sentinels"][0]
    if sentinel["required_semantic_scope"] == sentinel["current_proof_scope"]:
        raise GateFailure("UNBOUNDED_LIVENESS_AS_FINITE_MODEL_PRESERVED: scope sentinel collapsed")
    results.append({"mutation": "UNBOUNDED_LIVENESS_AS_FINITE_MODEL_PRESERVED", "killed": True, "mechanism": "PROOF_SCOPE_MISMATCH"})

    expected = set(protocol["mutation_requirements"])
    got = {x["mutation"] for x in results}
    if expected != got:
        raise GateFailure("mutation suite mismatch: expected=" + repr(sorted(expected)) + " got=" + repr(sorted(got)))
    if not all(x["killed"] for x in results):
        raise GateFailure("not all declared A1 mutations were killed")
    return results


def classify_sentinels(protocol):
    out = []
    for s in protocol["scope_sentinels"]:
        if s["required_semantic_scope"] != s["current_proof_scope"]:
            classification = "PROOF_KIND_GAP"
        else:
            classification = "DISCHARGEABLE_BY_CURRENT_PROOF_SCOPE"
        if classification != s["expected_classification"]:
            raise GateFailure(s["id"] + ": scope classification mismatch")
        out.append({
            "id": s["id"],
            "classification": classification,
            "kernel_implication": s["kernel_implication"],
            "required_semantic_scope": s["required_semantic_scope"],
            "current_proof_scope": s["current_proof_scope"],
        })
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
    required = set(protocol["required_pressure_classes"])
    if families != required:
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
                raise GateFailure(
                    f"{case['id']}:{target_name}: expected {expected}, got {result['verdict']}"
                )
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
            "Within the declared A1 class, heterogeneous obligations were lowered prospectively "
            "without target-dependent source rewriting and judged by the existing K1 relation. "
            "The unbounded-eventuality sentinel remains a proof-scope gap, not evidence for a new "
            "semantic kernel primitive. This result does not prove universal completeness."
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
