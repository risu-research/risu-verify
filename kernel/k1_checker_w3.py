#!/usr/bin/env python3
"""K1 checker W3: local observed-pair regression grounding.

W3 supports exactly one new evidence lane: k1.observed-pair/v1 for W0
regression_witness objects. It deliberately has zero preservation authority.
It does not import W1/W2 or the B0/B1 binding runners.
"""

import argparse
import base64
import hashlib
import json
import re
from pathlib import Path

PROOF_KIND = "k1.observed-pair/v1"
PROFILE = "risu.binding.effect-sink-e1/v1"
WORLD_DOMAIN = b"RISU-K1-BINDING-B0-WORLD\0"
CONSEQUENCE_DOMAIN = b"RISU-K1-BINDING-B0-CONSEQUENCE\0"
TARGET_DOMAIN = b"RISU-K1-TARGET-OBSERVED-PAIR-V1\0"
TOKEN_RE = re.compile(r"^[a-z0-9._:@/-]{1,128}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
ID_RE = {
    "w": re.compile(r"^w:sha256:[0-9a-f]{64}$"),
    "c": re.compile(r"^c:sha256:[0-9a-f]{64}$"),
    "t": re.compile(r"^t:sha256:[0-9a-f]{64}$"),
    "p": re.compile(r"^p:sha256:[0-9a-f]{64}$"),
    "e": re.compile(r"^e:sha256:[0-9a-f]{64}$"),
    "claim": re.compile(r"^claim:sha256:[0-9a-f]{64}$"),
    "wit": re.compile(r"^wit:sha256:[0-9a-f]{64}$"),
    "impl": re.compile(r"^impl:sha256:[0-9a-f]{64}$"),
}


class Reject(Exception):
    pass


class Unsupported(Exception):
    pass


def net_bytes(raw):
    return str(len(raw)).encode("ascii") + b":" + raw + b","


def net(text):
    return net_bytes(text.encode("utf-8"))


def vals(tag, xs):
    out = tag.encode("ascii") + net(str(len(xs)))
    for value in xs:
        out += b"V" + net(value)
    return out


def pairs(tag, xs):
    out = tag.encode("ascii") + net(str(len(xs)))
    for world, consequence in xs:
        out += b"P" + net(world) + net(consequence)
    return out


def sha(prefix, raw):
    return prefix + hashlib.sha256(raw).hexdigest()


def exact(obj, keys, where):
    if not isinstance(obj, dict) or set(obj) != set(keys):
        raise Reject(where + ": malformed object")


def ident(kind, value, where):
    if not isinstance(value, str) or ID_RE[kind].fullmatch(value) is None:
        raise Reject(where + ": noncanonical identifier")


def relation(rows, where):
    if not isinstance(rows, list):
        raise Reject(where + ": expected array")
    out = []
    for index, row in enumerate(rows):
        if not isinstance(row, list) or len(row) != 2:
            raise Reject(f"{where}[{index}]: expected pair")
        ident("w", row[0], f"{where}[{index}].world")
        ident("c", row[1], f"{where}[{index}].consequence")
        out.append((row[0], row[1]))
    if len(set(out)) != len(out):
        raise Reject(where + ": duplicate pair")
    return frozenset(out)


def claim_id(doc):
    worlds = sorted(doc["worlds"])
    allow = sorted((row[0], row[1]) for row in doc["allow"])
    pre = b"RISU-K1-CLAIM-W0\0" + b"S" + net(doc["semantics"])
    pre += vals("W", worlds) + pairs("A", allow)
    return sha("claim:sha256:", pre)


def witness_id(doc):
    roots = sorted(doc["evidence_roots"])
    proof = doc["grounding_proof"]
    pre = b"RISU-K1-WIT-W0\0" + b"C" + net(doc["claim_id"]) + b"T" + net(doc["target_id"])
    pre += b"P" + net(doc["pair"][0]) + net(doc["pair"][1])
    pre += b"G" + net(proof["kind"]) + net(proof["artifact"]) + vals("E", roots)
    return sha("wit:sha256:", pre)


def world_id(raw):
    return sha("w:sha256:", WORLD_DOMAIN + b"B" + net_bytes(raw))


def consequence_id(kind, subject, value):
    pre = CONSEQUENCE_DOMAIN + b"K" + net(kind) + b"S" + net(subject) + b"V" + net(value)
    return sha("c:sha256:", pre)


def canonical_b64(text, where):
    if not isinstance(text, str):
        raise Reject(where + ": expected string")
    try:
        raw = base64.b64decode(text.encode("ascii"), validate=True)
    except Exception as exc:
        raise Reject(where + ": invalid base64") from exc
    if base64.b64encode(raw).decode("ascii") != text:
        raise Reject(where + ": noncanonical base64")
    return raw


def parse_effect_log(raw):
    if not raw:
        return []
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise Reject("artifact.effect_log: non-ASCII bytes") from exc
    if not text.endswith("\n"):
        raise Reject("artifact.effect_log: partial trailing record")
    out = []
    for index, line in enumerate(text.splitlines()):
        parts = line.split("|")
        if len(parts) != 4 or parts[0] != "E1":
            raise Reject(f"artifact.effect_log[{index}]: malformed record")
        fields = []
        for part, prefix in zip(parts[1:], ("kind=", "subject=", "value=")):
            if not part.startswith(prefix):
                raise Reject(f"artifact.effect_log[{index}]: malformed field")
            value = part[len(prefix):]
            if TOKEN_RE.fullmatch(value) is None:
                raise Reject(f"artifact.effect_log[{index}]: noncanonical token")
            fields.append(value)
        out.append(consequence_id(*fields))
    return out


def target_id(artifact, world_raw, effect_raw):
    exit_token = "null" if artifact["exit_code"] is None else str(artifact["exit_code"])
    pre = TARGET_DOMAIN
    fields = [
        ("P", artifact["profile"]),
        ("C", artifact["claim_id"]),
        ("W", artifact["pair"][0]),
        ("U", artifact["pair"][1]),
        ("I", artifact["implementation_id"]),
        ("H", hashlib.sha256(world_raw).hexdigest()),
        ("L", hashlib.sha256(effect_raw).hexdigest()),
        ("N", str(artifact["record_index"])),
        ("O", "1" if artifact["timed_out"] else "0"),
        ("X", exit_token),
        ("S", artifact["stdout_sha256"]),
        ("E", artifact["stderr_sha256"]),
    ]
    for tag, value in fields:
        pre += tag.encode("ascii") + net(value)
    return sha("t:sha256:", pre)


def check_claim(doc):
    exact(doc, ["wire", "kind", "semantics", "worlds", "allow", "claim_id"], "claim")
    if (doc["wire"], doc["kind"], doc["semantics"]) != ("risu.k1.w0", "claim", "safety-subset-v1"):
        raise Reject("claim: unsupported wire/semantics")
    if not isinstance(doc["worlds"], list) or not doc["worlds"]:
        raise Reject("claim.worlds: empty")
    for world in doc["worlds"]:
        ident("w", world, "claim.world")
    if len(set(doc["worlds"])) != len(doc["worlds"]):
        raise Reject("claim.worlds: duplicate")
    allow = relation(doc["allow"], "claim.allow")
    worlds = frozenset(doc["worlds"])
    if not allow or any(world not in worlds for world, _ in allow):
        raise Reject("claim.allow: empty or undeclared world")
    for world in worlds:
        if not any(pair_world == world for pair_world, _ in allow):
            raise Reject("claim.allow: world without allowed consequence")
    ident("claim", doc["claim_id"], "claim.claim_id")
    if doc["claim_id"] != claim_id(doc):
        raise Reject("claim.claim_id: mismatch")
    return worlds, allow


def check_witness(doc, claim, artifact_raw, implementation_raw):
    exact(doc, ["wire", "kind", "claim_id", "target_id", "pair", "grounding_proof", "evidence_roots", "witness_id"], "witness")
    worlds, allow = check_claim(claim)
    if (doc["wire"], doc["kind"], doc["claim_id"]) != ("risu.k1.w0", "regression_witness", claim["claim_id"]):
        raise Reject("witness: wire/kind/claim mismatch")
    ident("t", doc["target_id"], "witness.target_id")
    pair = next(iter(relation([doc["pair"]], "witness.pair")))
    if pair[0] not in worlds:
        raise Reject("witness: undeclared world")
    if pair in allow:
        raise Reject("witness: observed consequence is allowed")

    proof = doc["grounding_proof"]
    exact(proof, ["kind", "artifact"], "witness.grounding_proof")
    if proof["kind"] != PROOF_KIND:
        raise Unsupported("unsupported grounding proof kind")
    ident("p", proof["artifact"], "witness.grounding_proof.artifact")
    if not isinstance(doc["evidence_roots"], list) or len(set(doc["evidence_roots"])) != len(doc["evidence_roots"]):
        raise Reject("witness.evidence_roots: malformed")
    for root in doc["evidence_roots"]:
        ident("e", root, "witness.evidence_root")
    ident("wit", doc["witness_id"], "witness.witness_id")
    if doc["witness_id"] != witness_id(doc):
        raise Reject("witness.witness_id: mismatch")

    actual_pid = sha("p:sha256:", artifact_raw)
    if actual_pid != proof["artifact"]:
        raise Reject("proof artifact: byte digest mismatch")
    try:
        artifact = json.loads(artifact_raw.decode("utf-8"))
    except Exception as exc:
        raise Reject("proof artifact: invalid UTF-8 JSON") from exc
    exact(artifact, [
        "proof_format", "profile", "claim_id", "target_id", "pair", "implementation_id",
        "world_input_b64", "effect_log_b64", "record_index", "timed_out", "exit_code",
        "stdout_sha256", "stderr_sha256"
    ], "observed-pair artifact")
    if artifact["proof_format"] != PROOF_KIND:
        raise Unsupported("unsupported proof artifact format")
    if artifact["profile"] != PROFILE:
        raise Unsupported("unsupported observation profile")
    if artifact["claim_id"] != claim["claim_id"] or artifact["pair"] != doc["pair"]:
        raise Reject("observed-pair artifact: claim/pair mismatch")
    ident("t", artifact["target_id"], "observed-pair artifact.target_id")
    ident("impl", artifact["implementation_id"], "observed-pair artifact.implementation_id")
    if artifact["implementation_id"] != sha("impl:sha256:", implementation_raw):
        raise Reject("observed-pair artifact: implementation substitution")
    if not isinstance(artifact["record_index"], int) or isinstance(artifact["record_index"], bool) or artifact["record_index"] < 0:
        raise Reject("observed-pair artifact.record_index: invalid")
    if not isinstance(artifact["timed_out"], bool):
        raise Reject("observed-pair artifact.timed_out: invalid")
    if artifact["exit_code"] is not None and (not isinstance(artifact["exit_code"], int) or isinstance(artifact["exit_code"], bool)):
        raise Reject("observed-pair artifact.exit_code: invalid")
    for key in ("stdout_sha256", "stderr_sha256"):
        if not isinstance(artifact[key], str) or HEX64.fullmatch(artifact[key]) is None:
            raise Reject("observed-pair artifact." + key + ": invalid")

    world_raw = canonical_b64(artifact["world_input_b64"], "observed-pair artifact.world_input_b64")
    effect_raw = canonical_b64(artifact["effect_log_b64"], "observed-pair artifact.effect_log_b64")
    if world_id(world_raw) != pair[0]:
        raise Reject("observed-pair artifact: world-input substitution")
    consequences = parse_effect_log(effect_raw)
    if artifact["record_index"] >= len(consequences):
        raise Reject("observed-pair artifact: record index out of range")
    if consequences[artifact["record_index"]] != pair[1]:
        raise Reject("observed-pair artifact: selected record does not ground witness consequence")

    expected_target = target_id(artifact, world_raw, effect_raw)
    if artifact["target_id"] != expected_target or doc["target_id"] != expected_target:
        raise Reject("observed-pair artifact: target commitment mismatch")

    return {
        "checker": "risu-k1-checker-w3",
        "proof_status": "ACCEPTED",
        "semantic_claim": "REGRESSION",
        "assurance_scope": "LOCAL_OBSERVED_PAIR",
        "preservation_authority": False,
        "implementation_content_binding": True,
        "causal_execution_attestation": False,
        "claim_id": claim["claim_id"],
        "target_id": expected_target,
        "witness_id": doc["witness_id"],
        "witness_pair": list(pair),
        "claim_world_count": len(worlds),
        "observed_world_count": 1,
    }


def load_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--claim", required=True)
    parser.add_argument("--proof-object", required=True)
    parser.add_argument("--artifact", required=True)
    parser.add_argument("--implementation", required=True)
    args = parser.parse_args(argv)

    claim = load_json(args.claim)
    obj = load_json(args.proof_object)
    artifact_raw = Path(args.artifact).read_bytes()
    implementation_raw = Path(args.implementation).read_bytes()
    try:
        if obj.get("kind") == "preservation_certificate":
            raise Unsupported("k1.observed-pair/v1 has zero preservation authority")
        if obj.get("kind") != "regression_witness":
            raise Reject("proof object: unsupported kind")
        result = check_witness(obj, claim, artifact_raw, implementation_raw)
        rc = 0
    except Unsupported as exc:
        result = {
            "checker": "risu-k1-checker-w3",
            "proof_status": "UNSUPPORTED",
            "semantic_claim": "UNKNOWN",
            "preservation_authority": False,
            "reason": str(exc),
        }
        rc = 2
    except Reject as exc:
        result = {
            "checker": "risu-k1-checker-w3",
            "proof_status": "REJECTED",
            "semantic_claim": "UNKNOWN",
            "preservation_authority": False,
            "reason": str(exc),
        }
        rc = 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
