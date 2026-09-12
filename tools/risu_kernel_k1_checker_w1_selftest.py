#!/usr/bin/env python3
import hashlib
import importlib.util
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
CHECKER_PATH = ROOT / "kernel" / "k1_checker_w1.py"
spec = importlib.util.spec_from_file_location("k1_checker_w1", CHECKER_PATH)
K = importlib.util.module_from_spec(spec)
spec.loader.exec_module(K)


def token(prefix, text):
    return prefix + hashlib.sha256(text.encode("utf-8")).hexdigest()


def make_claim(world_names, allowed):
    world_ids = {name: token("w:sha256:", name) for name in world_names}
    doc = {
        "wire": "risu.k1.w0",
        "kind": "claim",
        "semantics": "safety-subset-v1",
        "worlds": [world_ids[name] for name in world_names],
        "allow": [[world_ids[w], token("c:sha256:", c)] for w, c in allowed],
        "claim_id": "claim:sha256:" + "0" * 64,
    }
    doc["claim_id"] = K.claim_id(doc)
    return doc, world_ids


def make_artifact(claim, possible):
    possible_set = frozenset((row[0], row[1]) for row in possible)
    target = K.target_id(frozenset(claim["worlds"]), possible_set)
    obj = {
        "proof_format": K.PROOF_KIND,
        "claim_id": claim["claim_id"],
        "target_id": target,
        "worlds": list(claim["worlds"]),
        "possible": [list(row) for row in possible],
    }
    raw = (json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")
    artifact_id = "p:sha256:" + hashlib.sha256(raw).hexdigest()
    return obj, raw, artifact_id


def make_certificate(claim, target_id, realize, artifact_id, proof_kind=None):
    proof_kind = proof_kind or K.PROOF_KIND
    doc = {
        "wire": "risu.k1.w0",
        "kind": "preservation_certificate",
        "claim_id": claim["claim_id"],
        "target_id": target_id,
        "realize": [list(row) for row in realize],
        "closure_proof": {"kind": proof_kind, "artifact": artifact_id},
        "grounding_proofs": [
            {
                "pair": list(row),
                "proof": {"kind": proof_kind, "artifact": artifact_id},
            }
            for row in realize
        ],
        "evidence_roots": [],
        "certificate_id": "cert:sha256:" + "0" * 64,
    }
    doc["certificate_id"] = K.cert_id(doc)
    return doc


def make_witness(claim, target_id, pair, artifact_id, proof_kind=None):
    proof_kind = proof_kind or K.PROOF_KIND
    doc = {
        "wire": "risu.k1.w0",
        "kind": "regression_witness",
        "claim_id": claim["claim_id"],
        "target_id": target_id,
        "pair": list(pair),
        "grounding_proof": {"kind": proof_kind, "artifact": artifact_id},
        "evidence_roots": [],
        "witness_id": "wit:sha256:" + "0" * 64,
    }
    doc["witness_id"] = K.witness_id(doc)
    return doc


def expect(exc_type, fn, *args):
    try:
        fn(*args)
    except exc_type:
        return True
    raise AssertionError(f"expected {exc_type.__name__}")


def main():
    rows = []

    # 1. Complete, grounded, total subset -> accepted preservation.
    claim, W = make_claim(["fresh", "stale"], [("fresh", "commit"), ("stale", "reject")])
    possible = [
        (W["fresh"], token("c:sha256:", "commit")),
        (W["stale"], token("c:sha256:", "reject")),
    ]
    artifact, raw, artifact_id = make_artifact(claim, possible)
    cert = make_certificate(claim, artifact["target_id"], possible, artifact_id)
    result = K.check_certificate(cert, claim, raw)
    assert result["proof_status"] == "ACCEPTED" and result["semantic_claim"] == "PRESERVATION"
    assert result["implementation_binding"] is False
    rows.append(["complete_preservation", "PASS"])

    # 2. A target-native forbidden realized consequence is a valid local regression witness.
    bad = token("c:sha256:", "native-bad")
    bad_possible = [possible[0], (W["stale"], bad)]
    bad_artifact, bad_raw, bad_artifact_id = make_artifact(claim, bad_possible)
    witness = make_witness(claim, bad_artifact["target_id"], bad_possible[1], bad_artifact_id)
    result = K.check_witness(witness, claim, bad_raw)
    assert result["proof_status"] == "ACCEPTED" and result["semantic_claim"] == "REGRESSION"
    rows.append(["target_native_regression", "PASS"])

    # 3. Partial REALIZE cannot masquerade as a closed preservation proof.
    partial = make_certificate(claim, bad_artifact["target_id"], [bad_possible[0]], bad_artifact_id)
    assert expect(K.Reject, K.check_certificate, partial, claim, bad_raw)
    rows.append(["partial_realize_rejected", "PASS"])

    # 4. Every realized pair must be grounded in the recognized finite-model lane.
    ungrounded = make_certificate(claim, artifact["target_id"], possible, artifact_id)
    ungrounded["grounding_proofs"] = ungrounded["grounding_proofs"][:-1]
    ungrounded["certificate_id"] = K.cert_id(ungrounded)
    assert expect(K.Reject, K.check_certificate, ungrounded, claim, raw)
    rows.append(["missing_grounding_rejected", "PASS"])

    # 5. Unknown proof kinds are unsupported, never silently authoritative.
    unknown = make_certificate(claim, artifact["target_id"], possible, artifact_id, "future.solver/v99")
    assert expect(K.Unsupported, K.check_certificate, unknown, claim, raw)
    rows.append(["unknown_proof_kind_unknown", "PASS"])

    # 6. Proof artifact bytes are content-bound.
    tampered = raw + b" "
    assert expect(K.Reject, K.check_certificate, cert, claim, tampered)
    rows.append(["artifact_tamper_rejected", "PASS"])

    # 7. Nondeterminism: one allowed branch does not sanitize a forbidden sibling.
    one, O = make_claim(["w"], [("w", "ok")])
    ok = token("c:sha256:", "ok")
    poison = token("c:sha256:", "poison")
    nondet = [(O["w"], ok), (O["w"], poison)]
    nondet_artifact, nondet_raw, nondet_artifact_id = make_artifact(one, nondet)
    nondet_cert = make_certificate(one, nondet_artifact["target_id"], nondet, nondet_artifact_id)
    assert expect(K.Reject, K.check_certificate, nondet_cert, one, nondet_raw)
    poison_witness = make_witness(one, nondet_artifact["target_id"], nondet[1], nondet_artifact_id)
    assert K.check_witness(poison_witness, one, nondet_raw)["semantic_claim"] == "REGRESSION"
    rows.append(["nondeterministic_poison_detected", "PASS"])

    # 8. Pure safety refinement permits a strict safe subset.
    subset_claim, S = make_claim(["w"], [("w", "commit"), ("w", "reject")])
    reject = token("c:sha256:", "reject")
    subset_possible = [(S["w"], reject)]
    subset_artifact, subset_raw, subset_artifact_id = make_artifact(subset_claim, subset_possible)
    subset_cert = make_certificate(subset_claim, subset_artifact["target_id"], subset_possible, subset_artifact_id)
    assert K.check_certificate(subset_cert, subset_claim, subset_raw)["semantic_claim"] == "PRESERVATION"
    rows.append(["strict_safe_subset_preserved", "PASS"])

    print(json.dumps({
        "status": "PASS",
        "checker": "risu-k1-checker-w1",
        "recognized_proof_kind": K.PROOF_KIND,
        "assurance_scope": "DECLARED_FINITE_TARGET_MODEL",
        "implementation_binding": False,
        "tests": rows,
        "count": len(rows)
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
