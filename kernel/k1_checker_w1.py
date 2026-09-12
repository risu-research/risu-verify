#!/usr/bin/env python3
"""Tiny independent reference checker for the first K1 proof fragment.

W1 deliberately supports exactly one proof kind: k1.finite-model/v1.
It proves claims only relative to an explicit finite target model artifact.
It does not parse source code, call a solver, use the network, or establish
that the finite model faithfully represents an external implementation.
"""

import argparse
import hashlib
import json
import re
import sys

ID = {
    "w": re.compile(r"^w:sha256:[0-9a-f]{64}$"),
    "c": re.compile(r"^c:sha256:[0-9a-f]{64}$"),
    "t": re.compile(r"^t:sha256:[0-9a-f]{64}$"),
    "p": re.compile(r"^p:sha256:[0-9a-f]{64}$"),
    "e": re.compile(r"^e:sha256:[0-9a-f]{64}$"),
    "claim": re.compile(r"^claim:sha256:[0-9a-f]{64}$"),
    "cert": re.compile(r"^cert:sha256:[0-9a-f]{64}$"),
    "wit": re.compile(r"^wit:sha256:[0-9a-f]{64}$"),
}
PROOF_KIND = "k1.finite-model/v1"


class Reject(Exception):
    pass


class Unsupported(Exception):
    pass


def net(s):
    b = s.encode("utf-8")
    return str(len(b)).encode("ascii") + b":" + b + b","


def vals(tag, xs):
    out = tag.encode("ascii") + net(str(len(xs)))
    for x in xs:
        out += b"V" + net(x)
    return out


def pairs(tag, xs):
    out = tag.encode("ascii") + net(str(len(xs)))
    for a, b in xs:
        out += b"P" + net(a) + net(b)
    return out


def exact(obj, keys, where):
    if not isinstance(obj, dict) or set(obj) != set(keys):
        raise Reject(where + ": malformed object")


def ident(kind, value, where):
    if not isinstance(value, str) or ID[kind].fullmatch(value) is None:
        raise Reject(where + ": noncanonical identifier")


def relation(rows, where):
    if not isinstance(rows, list):
        raise Reject(where + ": expected array")
    out = []
    for i, row in enumerate(rows):
        if not isinstance(row, list) or len(row) != 2:
            raise Reject(f"{where}[{i}]: expected pair")
        ident("w", row[0], f"{where}[{i}].world")
        ident("c", row[1], f"{where}[{i}].consequence")
        out.append((row[0], row[1]))
    if len(set(out)) != len(out):
        raise Reject(where + ": duplicate pair")
    return frozenset(out)


def proof_ref(obj, where):
    exact(obj, ["kind", "artifact"], where)
    if not isinstance(obj["kind"], str):
        raise Reject(where + ".kind: expected string")
    ident("p", obj["artifact"], where + ".artifact")


def claim_id(doc):
    ws = sorted(doc["worlds"])
    allow = sorted((x[0], x[1]) for x in doc["allow"])
    pre = b"RISU-K1-CLAIM-W0\0" + b"S" + net(doc["semantics"]) + vals("W", ws) + pairs("A", allow)
    return "claim:sha256:" + hashlib.sha256(pre).hexdigest()


def cert_id(doc):
    realize = sorted((x[0], x[1]) for x in doc["realize"])
    ground = sorted(
        (x["pair"][0], x["pair"][1], x["proof"]["kind"], x["proof"]["artifact"])
        for x in doc["grounding_proofs"]
    )
    roots = sorted(doc["evidence_roots"])
    q = doc["closure_proof"]
    pre = b"RISU-K1-CERT-W0\0" + b"C" + net(doc["claim_id"]) + b"T" + net(doc["target_id"])
    pre += pairs("R", realize) + b"Q" + net(q["kind"]) + net(q["artifact"])
    pre += b"G" + net(str(len(ground)))
    for w, c, k, a in ground:
        pre += b"g" + net(w) + net(c) + net(k) + net(a)
    pre += vals("E", roots)
    return "cert:sha256:" + hashlib.sha256(pre).hexdigest()


def witness_id(doc):
    roots = sorted(doc["evidence_roots"])
    q = doc["grounding_proof"]
    pre = b"RISU-K1-WIT-W0\0" + b"C" + net(doc["claim_id"]) + b"T" + net(doc["target_id"])
    pre += b"P" + net(doc["pair"][0]) + net(doc["pair"][1])
    pre += b"G" + net(q["kind"]) + net(q["artifact"]) + vals("E", roots)
    return "wit:sha256:" + hashlib.sha256(pre).hexdigest()


def target_id(worlds, possible):
    pre = b"RISU-K1-TARGET-FINITE-V1\0" + vals("W", sorted(worlds)) + pairs("R", sorted(possible))
    return "t:sha256:" + hashlib.sha256(pre).hexdigest()


def check_claim(doc):
    exact(doc, ["wire", "kind", "semantics", "worlds", "allow", "claim_id"], "claim")
    if (doc["wire"], doc["kind"], doc["semantics"]) != ("risu.k1.w0", "claim", "safety-subset-v1"):
        raise Reject("claim: unsupported wire/semantics")
    if not isinstance(doc["worlds"], list) or not doc["worlds"]:
        raise Reject("claim.worlds: empty")
    for w in doc["worlds"]:
        ident("w", w, "claim.world")
    if len(set(doc["worlds"])) != len(doc["worlds"]):
        raise Reject("claim.worlds: duplicate")
    allow = relation(doc["allow"], "claim.allow")
    if not allow:
        raise Reject("claim.allow: empty")
    W = frozenset(doc["worlds"])
    if any(w not in W for w, _ in allow):
        raise Reject("claim.allow: undeclared world")
    if any(not any(pw == w for pw, _ in allow) for w in W):
        raise Reject("claim.allow: world without allowed consequence")
    ident("claim", doc["claim_id"], "claim.claim_id")
    if doc["claim_id"] != claim_id(doc):
        raise Reject("claim.claim_id: mismatch")
    return W, allow


def check_artifact(raw, expected_artifact_id, claim):
    actual = "p:sha256:" + hashlib.sha256(raw).hexdigest()
    if actual != expected_artifact_id:
        raise Reject("proof artifact: byte digest mismatch")
    try:
        obj = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise Reject("proof artifact: invalid UTF-8 JSON") from exc
    exact(obj, ["proof_format", "claim_id", "target_id", "worlds", "possible"], "finite-model proof")
    if obj["proof_format"] != PROOF_KIND:
        raise Unsupported("unsupported proof artifact format")
    if obj["claim_id"] != claim["claim_id"]:
        raise Reject("finite-model proof: claim mismatch")
    W, _ = check_claim(claim)
    if not isinstance(obj["worlds"], list) or frozenset(obj["worlds"]) != W or len(obj["worlds"]) != len(W):
        raise Reject("finite-model proof: world domain mismatch")
    possible = relation(obj["possible"], "finite-model proof.possible")
    if not possible:
        raise Reject("finite-model proof: empty target relation")
    if any(w not in W for w, _ in possible):
        raise Reject("finite-model proof: undeclared world")
    if any(not any(pw == w for pw, _ in possible) for w in W):
        raise Reject("finite-model proof: non-total consequential cut")
    expected_target = target_id(W, possible)
    ident("t", obj["target_id"], "finite-model proof.target_id")
    if obj["target_id"] != expected_target:
        raise Reject("finite-model proof: target commitment mismatch")
    return obj, possible


def check_certificate(doc, claim, artifact_raw):
    exact(doc, ["wire", "kind", "claim_id", "target_id", "realize", "closure_proof", "grounding_proofs", "evidence_roots", "certificate_id"], "certificate")
    W, allow = check_claim(claim)
    if (doc["wire"], doc["kind"], doc["claim_id"]) != ("risu.k1.w0", "preservation_certificate", claim["claim_id"]):
        raise Reject("certificate: wire/kind/claim mismatch")
    ident("t", doc["target_id"], "certificate.target_id")
    realize = relation(doc["realize"], "certificate.realize")
    if not realize or any(w not in W for w, _ in realize):
        raise Reject("certificate.realize: empty or undeclared world")
    proof_ref(doc["closure_proof"], "certificate.closure_proof")
    if doc["closure_proof"]["kind"] != PROOF_KIND:
        raise Unsupported("unsupported closure proof kind")

    if not isinstance(doc["grounding_proofs"], list):
        raise Reject("certificate.grounding_proofs: malformed")
    grounded = {}
    for item in doc["grounding_proofs"]:
        exact(item, ["pair", "proof"], "certificate.grounding_entry")
        pair = next(iter(relation([item["pair"]], "certificate.grounding_entry.pair")))
        proof_ref(item["proof"], "certificate.grounding_entry.proof")
        if pair in grounded:
            raise Reject("certificate.grounding_proofs: duplicate pair")
        grounded[pair] = item["proof"]

    if not isinstance(doc["evidence_roots"], list) or len(set(doc["evidence_roots"])) != len(doc["evidence_roots"]):
        raise Reject("certificate.evidence_roots: malformed")
    for root in doc["evidence_roots"]:
        ident("e", root, "certificate.evidence_root")
    ident("cert", doc["certificate_id"], "certificate.certificate_id")
    if doc["certificate_id"] != cert_id(doc):
        raise Reject("certificate.certificate_id: mismatch")

    artifact, possible = check_artifact(artifact_raw, doc["closure_proof"]["artifact"], claim)
    if doc["target_id"] != artifact["target_id"]:
        raise Reject("certificate: target/proof mismatch")
    if realize != possible:
        raise Reject("certificate: closure proof does not establish submitted REALIZE as exhaustive")

    for pair in realize:
        ref = grounded.get(pair)
        if ref is None:
            raise Reject("certificate: REALIZE pair lacks grounding proof")
        if ref["kind"] != PROOF_KIND:
            raise Unsupported("unsupported grounding proof kind")
        if ref["artifact"] != doc["closure_proof"]["artifact"]:
            raise Reject("certificate: grounding artifact differs from finite closure model")
    if set(grounded) != set(realize):
        raise Reject("certificate: grounding set is not exactly REALIZE")

    forbidden = sorted(realize - allow)
    if forbidden:
        raise Reject("certificate: forbidden realized consequence present")

    return {
        "checker": "risu-k1-checker-w1",
        "proof_status": "ACCEPTED",
        "semantic_claim": "PRESERVATION",
        "assurance_scope": "DECLARED_FINITE_TARGET_MODEL",
        "implementation_binding": False,
        "claim_id": claim["claim_id"],
        "target_id": doc["target_id"],
        "certificate_id": doc["certificate_id"],
        "world_count": len(W),
        "realize_pair_count": len(realize),
    }


def check_witness(doc, claim, artifact_raw):
    exact(doc, ["wire", "kind", "claim_id", "target_id", "pair", "grounding_proof", "evidence_roots", "witness_id"], "witness")
    W, allow = check_claim(claim)
    if (doc["wire"], doc["kind"], doc["claim_id"]) != ("risu.k1.w0", "regression_witness", claim["claim_id"]):
        raise Reject("witness: wire/kind/claim mismatch")
    ident("t", doc["target_id"], "witness.target_id")
    pair = next(iter(relation([doc["pair"]], "witness.pair")))
    if pair[0] not in W:
        raise Reject("witness: undeclared world")
    proof_ref(doc["grounding_proof"], "witness.grounding_proof")
    if doc["grounding_proof"]["kind"] != PROOF_KIND:
        raise Unsupported("unsupported grounding proof kind")
    if not isinstance(doc["evidence_roots"], list) or len(set(doc["evidence_roots"])) != len(doc["evidence_roots"]):
        raise Reject("witness.evidence_roots: malformed")
    for root in doc["evidence_roots"]:
        ident("e", root, "witness.evidence_root")
    ident("wit", doc["witness_id"], "witness.witness_id")
    if doc["witness_id"] != witness_id(doc):
        raise Reject("witness.witness_id: mismatch")

    artifact, possible = check_artifact(artifact_raw, doc["grounding_proof"]["artifact"], claim)
    if doc["target_id"] != artifact["target_id"]:
        raise Reject("witness: target/proof mismatch")
    if pair not in possible:
        raise Reject("witness: pair not grounded by finite target model")
    if pair in allow:
        raise Reject("witness: realized consequence is allowed")

    return {
        "checker": "risu-k1-checker-w1",
        "proof_status": "ACCEPTED",
        "semantic_claim": "REGRESSION",
        "assurance_scope": "DECLARED_FINITE_TARGET_MODEL",
        "implementation_binding": False,
        "claim_id": claim["claim_id"],
        "target_id": doc["target_id"],
        "witness_id": doc["witness_id"],
        "witness_pair": list(pair),
    }


def load_json(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--claim", required=True)
    parser.add_argument("--proof-object", required=True, help="W0 preservation certificate or regression witness JSON")
    parser.add_argument("--artifact", required=True, help="exact finite-model proof artifact bytes")
    args = parser.parse_args(argv)

    claim = load_json(args.claim)
    obj = load_json(args.proof_object)
    with open(args.artifact, "rb") as handle:
        artifact = handle.read()

    try:
        if obj.get("kind") == "preservation_certificate":
            result = check_certificate(obj, claim, artifact)
        elif obj.get("kind") == "regression_witness":
            result = check_witness(obj, claim, artifact)
        else:
            raise Reject("proof object: unsupported kind")
    except Unsupported as exc:
        result = {
            "checker": "risu-k1-checker-w1",
            "proof_status": "UNSUPPORTED",
            "semantic_claim": "UNKNOWN",
            "reason": str(exc),
        }
        print(json.dumps(result, indent=2, sort_keys=True))
        return 2
    except Reject as exc:
        result = {
            "checker": "risu-k1-checker-w1",
            "proof_status": "REJECTED",
            "semantic_claim": "NONE",
            "reason": str(exc),
        }
        print(json.dumps(result, indent=2, sort_keys=True))
        return 1

    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
