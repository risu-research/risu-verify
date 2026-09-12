#!/usr/bin/env python3
import copy
import hashlib
import json
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
PROTOCOL = ROOT / "protocols" / "RISU_KERNEL_K1_WIRE_W0.json"
SCHEMA = ROOT / "schemas" / "RISU_KERNEL_K1_WIRE_W0.schema.json"

PATTERNS = {
    "world": re.compile(r"^w:sha256:[0-9a-f]{64}$"),
    "consequence": re.compile(r"^c:sha256:[0-9a-f]{64}$"),
    "target": re.compile(r"^t:sha256:[0-9a-f]{64}$"),
    "proof": re.compile(r"^p:sha256:[0-9a-f]{64}$"),
    "evidence": re.compile(r"^e:sha256:[0-9a-f]{64}$"),
    "claim": re.compile(r"^claim:sha256:[0-9a-f]{64}$"),
    "certificate": re.compile(r"^cert:sha256:[0-9a-f]{64}$"),
    "witness": re.compile(r"^wit:sha256:[0-9a-f]{64}$"),
}
PROOF_KIND = re.compile(r"^[a-z0-9][a-z0-9._/-]{0,127}$")


class WireError(Exception):
    pass


def fail(reason, **extra):
    print(json.dumps({"status": "FAIL", "reason": reason, **extra}, indent=2, sort_keys=True))
    raise SystemExit(1)


def sha_token(prefix, text):
    return prefix + hashlib.sha256(text.encode("utf-8")).hexdigest()


def netstring(text):
    raw = text.encode("utf-8")
    return str(len(raw)).encode("ascii") + b":" + raw + b","


def value_section(tag, values):
    out = tag.encode("ascii") + netstring(str(len(values)))
    for value in values:
        out += b"V" + netstring(value)
    return out


def pair_section(tag, pairs):
    out = tag.encode("ascii") + netstring(str(len(pairs)))
    for left, right in pairs:
        out += b"P" + netstring(left) + netstring(right)
    return out


def claim_preimage(doc):
    worlds = sorted(doc["worlds"])
    allow = sorted((row[0], row[1]) for row in doc["allow"])
    return (
        b"RISU-K1-CLAIM-W0\0"
        + b"S" + netstring(doc["semantics"])
        + value_section("W", worlds)
        + pair_section("A", allow)
    )


def compute_claim_id(doc):
    return "claim:sha256:" + hashlib.sha256(claim_preimage(doc)).hexdigest()


def compute_certificate_id(doc):
    realize = sorted((row[0], row[1]) for row in doc["realize"])
    grounding = sorted(
        (
            item["pair"][0],
            item["pair"][1],
            item["proof"]["kind"],
            item["proof"]["artifact"],
        )
        for item in doc["grounding_proofs"]
    )
    roots = sorted(doc["evidence_roots"])
    closure = doc["closure_proof"]

    preimage = b"RISU-K1-CERT-W0\0"
    preimage += b"C" + netstring(doc["claim_id"])
    preimage += b"T" + netstring(doc["target_id"])
    preimage += pair_section("R", realize)
    preimage += b"Q" + netstring(closure["kind"]) + netstring(closure["artifact"])
    preimage += b"G" + netstring(str(len(grounding)))
    for world, consequence, kind, artifact in grounding:
        preimage += (
            b"g"
            + netstring(world)
            + netstring(consequence)
            + netstring(kind)
            + netstring(artifact)
        )
    preimage += value_section("E", roots)
    return "cert:sha256:" + hashlib.sha256(preimage).hexdigest()


def compute_witness_id(doc):
    roots = sorted(doc["evidence_roots"])
    proof = doc["grounding_proof"]
    preimage = b"RISU-K1-WIT-W0\0"
    preimage += b"C" + netstring(doc["claim_id"])
    preimage += b"T" + netstring(doc["target_id"])
    preimage += b"P" + netstring(doc["pair"][0]) + netstring(doc["pair"][1])
    preimage += b"G" + netstring(proof["kind"]) + netstring(proof["artifact"])
    preimage += value_section("E", roots)
    return "wit:sha256:" + hashlib.sha256(preimage).hexdigest()


def exact_keys(obj, required, where):
    if not isinstance(obj, dict):
        raise WireError(f"{where}: expected object")
    actual = set(obj)
    expected = set(required)
    if actual != expected:
        raise WireError(
            f"{where}: key mismatch; extra={sorted(actual - expected)} missing={sorted(expected - actual)}"
        )


def validate_id(kind, value, where):
    if not isinstance(value, str) or PATTERNS[kind].fullmatch(value) is None:
        raise WireError(f"{where}: invalid {kind} identifier")


def validate_pair(row, where):
    if not isinstance(row, list) or len(row) != 2:
        raise WireError(f"{where}: relation pair must be a two-element array")
    validate_id("world", row[0], where + ".world")
    validate_id("consequence", row[1], where + ".consequence")
    return (row[0], row[1])


def validate_proof_ref(obj, where):
    exact_keys(obj, ["kind", "artifact"], where)
    if not isinstance(obj["kind"], str) or PROOF_KIND.fullmatch(obj["kind"]) is None:
        raise WireError(f"{where}.kind: invalid proof-kind token")
    validate_id("proof", obj["artifact"], where + ".artifact")


def validate_claim(doc):
    exact_keys(doc, ["wire", "kind", "semantics", "worlds", "allow", "claim_id"], "claim")
    if doc["wire"] != "risu.k1.w0":
        raise WireError("claim.wire: unsupported wire version")
    if doc["kind"] != "claim":
        raise WireError("claim.kind: expected claim")
    if doc["semantics"] != "safety-subset-v1":
        raise WireError("claim.semantics: unsupported semantics")

    worlds = doc["worlds"]
    if not isinstance(worlds, list) or not worlds:
        raise WireError("claim.worlds: nonempty array required")
    for index, world in enumerate(worlds):
        validate_id("world", world, f"claim.worlds[{index}]")
    if len(set(worlds)) != len(worlds):
        raise WireError("claim.worlds: duplicate world")

    allow = doc["allow"]
    if not isinstance(allow, list) or not allow:
        raise WireError("claim.allow: nonempty array required")
    allow_pairs = [validate_pair(row, f"claim.allow[{index}]") for index, row in enumerate(allow)]
    if len(set(allow_pairs)) != len(allow_pairs):
        raise WireError("claim.allow: duplicate relation pair")

    world_set = set(worlds)
    if any(world not in world_set for world, _ in allow_pairs):
        raise WireError("claim.allow: relation references undeclared world")
    for world in world_set:
        if not any(pair_world == world for pair_world, _ in allow_pairs):
            raise WireError("claim.allow: every admitted world must have at least one allowed consequence")

    validate_id("claim", doc["claim_id"], "claim.claim_id")
    expected = compute_claim_id(doc)
    if doc["claim_id"] != expected:
        raise WireError("claim.claim_id: commitment mismatch")
    return True


def validate_certificate(doc, claim):
    exact_keys(
        doc,
        [
            "wire",
            "kind",
            "claim_id",
            "target_id",
            "realize",
            "closure_proof",
            "grounding_proofs",
            "evidence_roots",
            "certificate_id",
        ],
        "certificate",
    )
    validate_claim(claim)
    if doc["wire"] != "risu.k1.w0" or doc["kind"] != "preservation_certificate":
        raise WireError("certificate: wire/kind mismatch")
    validate_id("claim", doc["claim_id"], "certificate.claim_id")
    if doc["claim_id"] != claim["claim_id"]:
        raise WireError("certificate.claim_id: supplied claim mismatch")
    validate_id("target", doc["target_id"], "certificate.target_id")

    realize = doc["realize"]
    if not isinstance(realize, list) or not realize:
        raise WireError("certificate.realize: nonempty array required")
    realize_pairs = [validate_pair(row, f"certificate.realize[{index}]") for index, row in enumerate(realize)]
    if len(set(realize_pairs)) != len(realize_pairs):
        raise WireError("certificate.realize: duplicate relation pair")
    admitted = set(claim["worlds"])
    if any(world not in admitted for world, _ in realize_pairs):
        raise WireError("certificate.realize: undeclared world")

    validate_proof_ref(doc["closure_proof"], "certificate.closure_proof")

    grounding = doc["grounding_proofs"]
    if not isinstance(grounding, list):
        raise WireError("certificate.grounding_proofs: array required")
    grounding_pairs = []
    realize_set = set(realize_pairs)
    for index, item in enumerate(grounding):
        where = f"certificate.grounding_proofs[{index}]"
        exact_keys(item, ["pair", "proof"], where)
        pair = validate_pair(item["pair"], where + ".pair")
        validate_proof_ref(item["proof"], where + ".proof")
        if pair not in realize_set:
            raise WireError("certificate.grounding_proofs: proof refers to non-REALIZE pair")
        grounding_pairs.append(pair)
    if len(set(grounding_pairs)) != len(grounding_pairs):
        raise WireError("certificate.grounding_proofs: duplicate grounded pair")

    roots = doc["evidence_roots"]
    if not isinstance(roots, list):
        raise WireError("certificate.evidence_roots: array required")
    for index, root in enumerate(roots):
        validate_id("evidence", root, f"certificate.evidence_roots[{index}]")
    if len(set(roots)) != len(roots):
        raise WireError("certificate.evidence_roots: duplicate root")

    validate_id("certificate", doc["certificate_id"], "certificate.certificate_id")
    expected = compute_certificate_id(doc)
    if doc["certificate_id"] != expected:
        raise WireError("certificate.certificate_id: commitment mismatch")
    return True


def validate_witness(doc, claim):
    exact_keys(
        doc,
        [
            "wire",
            "kind",
            "claim_id",
            "target_id",
            "pair",
            "grounding_proof",
            "evidence_roots",
            "witness_id",
        ],
        "witness",
    )
    validate_claim(claim)
    if doc["wire"] != "risu.k1.w0" or doc["kind"] != "regression_witness":
        raise WireError("witness: wire/kind mismatch")
    validate_id("claim", doc["claim_id"], "witness.claim_id")
    if doc["claim_id"] != claim["claim_id"]:
        raise WireError("witness.claim_id: supplied claim mismatch")
    validate_id("target", doc["target_id"], "witness.target_id")
    pair = validate_pair(doc["pair"], "witness.pair")
    if pair[0] not in set(claim["worlds"]):
        raise WireError("witness.pair: undeclared world")
    validate_proof_ref(doc["grounding_proof"], "witness.grounding_proof")

    roots = doc["evidence_roots"]
    if not isinstance(roots, list):
        raise WireError("witness.evidence_roots: array required")
    for index, root in enumerate(roots):
        validate_id("evidence", root, f"witness.evidence_roots[{index}]")
    if len(set(roots)) != len(roots):
        raise WireError("witness.evidence_roots: duplicate root")

    validate_id("witness", doc["witness_id"], "witness.witness_id")
    expected = compute_witness_id(doc)
    if doc["witness_id"] != expected:
        raise WireError("witness.witness_id: commitment mismatch")
    return True


def expect_invalid(label, fn, *args):
    try:
        fn(*args)
    except WireError:
        return {"vector": label, "result": "PASS"}
    raise WireError(f"{label}: malformed vector was accepted")


def make_claim():
    fresh = sha_token("w:sha256:", "fresh")
    stale = sha_token("w:sha256:", "stale")
    commit = sha_token("c:sha256:", "commit")
    reject = sha_token("c:sha256:", "reject")
    doc = {
        "wire": "risu.k1.w0",
        "kind": "claim",
        "semantics": "safety-subset-v1",
        "worlds": [fresh, stale],
        "allow": [[fresh, commit], [stale, reject]],
        "claim_id": "claim:sha256:" + "0" * 64,
    }
    doc["claim_id"] = compute_claim_id(doc)
    return doc


def make_certificate(claim):
    native = sha_token("c:sha256:", "target-native")
    doc = {
        "wire": "risu.k1.w0",
        "kind": "preservation_certificate",
        "claim_id": claim["claim_id"],
        "target_id": sha_token("t:sha256:", "target"),
        "realize": [
            [claim["worlds"][0], native],
            [claim["worlds"][1], claim["allow"][1][1]],
        ],
        "closure_proof": {
            "kind": "future.closure/v0",
            "artifact": sha_token("p:sha256:", "closure"),
        },
        "grounding_proofs": [],
        "evidence_roots": [sha_token("e:sha256:", "root")],
        "certificate_id": "cert:sha256:" + "0" * 64,
    }
    doc["certificate_id"] = compute_certificate_id(doc)
    return doc


def make_witness(claim):
    native = sha_token("c:sha256:", "native-forbidden")
    doc = {
        "wire": "risu.k1.w0",
        "kind": "regression_witness",
        "claim_id": claim["claim_id"],
        "target_id": sha_token("t:sha256:", "target"),
        "pair": [claim["worlds"][1], native],
        "grounding_proof": {
            "kind": "future.grounding/v0",
            "artifact": sha_token("p:sha256:", "witness-ground"),
        },
        "evidence_roots": [sha_token("e:sha256:", "root")],
        "witness_id": "wit:sha256:" + "0" * 64,
    }
    doc["witness_id"] = compute_witness_id(doc)
    return doc


def main():
    protocol = json.loads(PROTOCOL.read_text())
    schema = json.loads(SCHEMA.read_text())
    if protocol["wire_version"] != "risu.k1.w0":
        fail("protocol wire version changed")
    if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        fail("schema dialect changed")
    for definition in ("claim", "proof_ref", "preservation_certificate", "regression_witness"):
        if schema["$defs"][definition].get("additionalProperties") is not False:
            fail("schema definition is not fail-closed on unknown fields", definition=definition)

    claim = make_claim()
    certificate = make_certificate(claim)
    witness = make_witness(claim)
    validate_claim(claim)
    validate_certificate(certificate, claim)
    validate_witness(witness, claim)

    vectors = []

    # Identity must be independent of transport ordering.
    reordered = copy.deepcopy(claim)
    reordered["worlds"].reverse()
    reordered["allow"].reverse()
    reordered["claim_id"] = compute_claim_id(reordered)
    validate_claim(reordered)
    if reordered["claim_id"] != claim["claim_id"]:
        fail("claim identity depends on JSON array ordering")
    vectors.append({"vector": "order_invariant_claim_identity", "result": "PASS"})

    widened = copy.deepcopy(claim)
    widened["allow"].append([claim["worlds"][0], sha_token("c:sha256:", "posthoc-extra")])
    widened["claim_id"] = compute_claim_id(widened)
    if widened["claim_id"] == claim["claim_id"]:
        fail("post-hoc ALLOW widening did not change claim identity")
    vectors.append({"vector": "allow_widening_changes_claim_id", "result": "PASS"})

    deleted = copy.deepcopy(claim)
    deleted["worlds"] = [claim["worlds"][0]]
    deleted["allow"] = [claim["allow"][0]]
    deleted["claim_id"] = compute_claim_id(deleted)
    if deleted["claim_id"] == claim["claim_id"]:
        fail("world deletion did not change claim identity")
    vectors.append({"vector": "world_deletion_changes_claim_id", "result": "PASS"})

    # Open consequence universe: target-native consequence is intentionally absent from ALLOW.
    if certificate["realize"][0][1] in {row[1] for row in claim["allow"]}:
        fail("open-universe fixture accidentally reused an ALLOW consequence")
    validate_certificate(certificate, claim)
    vectors.append({"vector": "target_native_consequence_structurally_valid", "result": "PASS"})

    malformed = copy.deepcopy(certificate)
    malformed["closed"] = True
    vectors.append(expect_invalid("closed_boolean_rejected", validate_certificate, malformed, claim))

    malformed = copy.deepcopy(certificate)
    malformed["grounded"] = True
    vectors.append(expect_invalid("grounded_boolean_rejected", validate_certificate, malformed, claim))

    malformed = copy.deepcopy(claim)
    malformed["worlds"][0] = malformed["worlds"][0].upper()
    malformed["claim_id"] = compute_claim_id(malformed)
    vectors.append(expect_invalid("noncanonical_uppercase_digest_rejected", validate_claim, malformed))

    malformed = copy.deepcopy(claim)
    malformed["allow"].append(copy.deepcopy(malformed["allow"][0]))
    malformed["claim_id"] = compute_claim_id(malformed)
    vectors.append(expect_invalid("duplicate_allow_rejected", validate_claim, malformed))

    malformed = copy.deepcopy(certificate)
    malformed["realize"][0][0] = sha_token("w:sha256:", "undeclared")
    malformed["certificate_id"] = compute_certificate_id(malformed)
    vectors.append(expect_invalid("undeclared_realize_world_rejected", validate_certificate, malformed, claim))

    malformed = copy.deepcopy(claim)
    malformed["claim_id"] = "claim:sha256:" + "f" * 64
    vectors.append(expect_invalid("claim_id_mismatch_rejected", validate_claim, malformed))

    # W0 permits unknown proof kinds structurally. Semantic acceptance is deferred to a checker.
    unknown = copy.deepcopy(certificate)
    unknown["closure_proof"]["kind"] = "future.solver/v99"
    unknown["certificate_id"] = compute_certificate_id(unknown)
    validate_certificate(unknown, claim)
    vectors.append({"vector": "unknown_proof_kind_structural_only", "result": "PASS"})

    changed_proof = copy.deepcopy(certificate)
    original_cert_id = certificate["certificate_id"]
    changed_proof["closure_proof"]["artifact"] = sha_token("p:sha256:", "different-closure")
    changed_proof["certificate_id"] = compute_certificate_id(changed_proof)
    if changed_proof["certificate_id"] == original_cert_id:
        fail("certificate identity did not bind closure proof artifact")
    vectors.append({"vector": "proof_artifact_change_changes_certificate_id", "result": "PASS"})

    roots_a = copy.deepcopy(certificate)
    roots_a["evidence_roots"] = [
        sha_token("e:sha256:", "z"),
        sha_token("e:sha256:", "a"),
    ]
    roots_a["certificate_id"] = compute_certificate_id(roots_a)
    roots_b = copy.deepcopy(roots_a)
    roots_b["evidence_roots"].reverse()
    roots_b["certificate_id"] = compute_certificate_id(roots_b)
    if roots_a["certificate_id"] != roots_b["certificate_id"]:
        fail("certificate identity depends on evidence-root array ordering")
    vectors.append({"vector": "evidence_order_invariant_certificate_identity", "result": "PASS"})

    changed_witness = copy.deepcopy(witness)
    original_witness_id = witness["witness_id"]
    changed_witness["grounding_proof"]["artifact"] = sha_token("p:sha256:", "different-grounding")
    changed_witness["witness_id"] = compute_witness_id(changed_witness)
    if changed_witness["witness_id"] == original_witness_id:
        fail("witness identity did not bind grounding proof artifact")
    vectors.append({"vector": "grounding_change_changes_witness_id", "result": "PASS"})

    print(json.dumps({
        "status": "PASS",
        "protocol_id": protocol["protocol_id"],
        "wire_version": protocol["wire_version"],
        "vectors": vectors,
        "vector_count": len(vectors),
        "identity": {
            "claim": claim["claim_id"],
            "certificate": certificate["certificate_id"],
            "witness": witness["witness_id"],
            "arbitrary_json_canonicalization_in_claim_tcb": False,
            "open_consequence_universe": True,
            "unknown_proof_kind_is_authority": False,
        },
        "next": "tiny independent checker over an intentionally small recognized proof fragment"
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except WireError as exc:
        fail("wire validation failure", detail=str(exc))
