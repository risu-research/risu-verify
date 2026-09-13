#!/usr/bin/env python3
"""RISU K1 checker W5: bounded hermetic capsule closure preservation.

W5 accepts one positive evidence lane: k1.capsule-closure/v1.  The proof
artifact contains only the claim binding, exact program digest, and explicit
finite boundary.  W5 derives REALIZE itself by exhaustive capsule execution.
It never trusts producer-supplied closure or target relations.
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import re
import sys

PROOF_KIND = "k1.capsule-closure/v1"
CAPSULE_SEMANTICS = "risu.k1.capsule/v1"
MAX_PROGRAM_BYTES = 65536
MAX_GAS = 10000

ID = {
    "w": re.compile(r"^w:sha256:[0-9a-f]{64}$"),
    "c": re.compile(r"^c:sha256:[0-9a-f]{64}$"),
    "t": re.compile(r"^t:sha256:[0-9a-f]{64}$"),
    "p": re.compile(r"^p:sha256:[0-9a-f]{64}$"),
    "e": re.compile(r"^e:sha256:[0-9a-f]{64}$"),
    "claim": re.compile(r"^claim:sha256:[0-9a-f]{64}$"),
    "cert": re.compile(r"^cert:sha256:[0-9a-f]{64}$"),
}
HEX64 = re.compile(r"^[0-9a-f]{64}$")
TOKEN_RE = re.compile(r"^[A-Za-z0-9_.@:-]+$")
HEX_RE = re.compile(r"^(?:[0-9a-f]{2})+$")
FORBIDDEN_AMBIENT = {"CLOCK", "RNG", "FILE", "NET", "HOSTCALL", "SPAWN"}
ALLOWED_OPS = {"LABEL", "IF_EQ", "GOTO", "EMIT_HEX", "HALT"}


class Reject(Exception):
    pass


class Unsupported(Exception):
    pass


def net(text: str) -> bytes:
    raw = text.encode("utf-8")
    return str(len(raw)).encode("ascii") + b":" + raw + b","


def vals(tag: str, xs) -> bytes:
    out = tag.encode("ascii") + net(str(len(xs)))
    for x in xs:
        out += b"V" + net(x)
    return out


def pairs_transcript(tag: str, pairs) -> bytes:
    rows = sorted(pairs)
    out = tag.encode("ascii") + net(str(len(rows)))
    for w, c in rows:
        out += b"P" + net(w) + net(c)
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
    if not isinstance(obj["kind"], str) or not re.fullmatch(r"[a-z0-9][a-z0-9._/-]{0,127}", obj["kind"]):
        raise Reject(where + ".kind: noncanonical proof kind")
    ident("p", obj["artifact"], where + ".artifact")


def claim_id(doc):
    ws = sorted(doc["worlds"])
    allow = sorted((x[0], x[1]) for x in doc["allow"])
    pre = b"RISU-K1-CLAIM-W0\0" + b"S" + net(doc["semantics"]) + vals("W", ws) + pairs_transcript("A", allow)
    return "claim:sha256:" + hashlib.sha256(pre).hexdigest()


def certificate_id(doc):
    realize = sorted((x[0], x[1]) for x in doc["realize"])
    ground = sorted(
        (x["pair"][0], x["pair"][1], x["proof"]["kind"], x["proof"]["artifact"])
        for x in doc["grounding_proofs"]
    )
    roots = sorted(doc["evidence_roots"])
    q = doc["closure_proof"]
    pre = b"RISU-K1-CERT-W0\0" + b"C" + net(doc["claim_id"]) + b"T" + net(doc["target_id"])
    pre += pairs_transcript("R", realize) + b"Q" + net(q["kind"]) + net(q["artifact"])
    pre += b"G" + net(str(len(ground)))
    for w, c, kind, artifact in ground:
        pre += b"g" + net(w) + net(c) + net(kind) + net(artifact)
    pre += vals("E", roots)
    return "cert:sha256:" + hashlib.sha256(pre).hexdigest()


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
    worlds = frozenset(doc["worlds"])
    if any(w not in worlds for w, _ in allow):
        raise Reject("claim.allow: undeclared world")
    if any(not any(pw == w for pw, _ in allow) for w in worlds):
        raise Reject("claim.allow: world without allowed consequence")
    ident("claim", doc["claim_id"], "claim.claim_id")
    if doc["claim_id"] != claim_id(doc):
        raise Reject("claim.claim_id: mismatch")
    return worlds, allow


def strict_lines(raw: bytes):
    if not raw or len(raw) > MAX_PROGRAM_BYTES:
        raise Reject("capsule program: invalid size")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise Reject("capsule program: invalid UTF-8") from exc
    if "\x00" in text or "\r" in text or "\t" in text:
        raise Reject("capsule program: ambiguous bytes")
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    if not lines or any(line == "" for line in lines):
        raise Reject("capsule program: empty line")
    for line in lines:
        if line.strip() != line or "  " in line:
            raise Reject("capsule program: noncanonical spacing")
    return lines


def parse_program(raw: bytes):
    instructions = []
    labels = {}
    refs = []
    for idx, line in enumerate(strict_lines(raw)):
        parts = line.split(" ")
        op = parts[0]
        if op in FORBIDDEN_AMBIENT:
            raise Reject("capsule program: ambient capability forbidden:" + op)
        if op not in ALLOWED_OPS:
            raise Reject("capsule program: unknown opcode:" + op)
        if op == "LABEL":
            if len(parts) != 2 or TOKEN_RE.fullmatch(parts[1]) is None:
                raise Reject("capsule program: label syntax")
            if parts[1] in labels:
                raise Reject("capsule program: duplicate label")
            labels[parts[1]] = idx
            instructions.append((op, parts[1]))
        elif op == "IF_EQ":
            if len(parts) != 4 or any(TOKEN_RE.fullmatch(x) is None for x in parts[1:]):
                raise Reject("capsule program: IF_EQ syntax")
            refs.append(parts[3])
            instructions.append((op, parts[1], parts[2], parts[3]))
        elif op == "GOTO":
            if len(parts) != 2 or TOKEN_RE.fullmatch(parts[1]) is None:
                raise Reject("capsule program: GOTO syntax")
            refs.append(parts[1])
            instructions.append((op, parts[1]))
        elif op == "EMIT_HEX":
            if len(parts) != 2 or HEX_RE.fullmatch(parts[1]) is None:
                raise Reject("capsule program: EMIT_HEX syntax")
            instructions.append((op, bytes.fromhex(parts[1])))
        elif op == "HALT":
            if len(parts) != 1:
                raise Reject("capsule program: HALT syntax")
            instructions.append((op,))
    if any(ref not in labels for ref in refs):
        raise Reject("capsule program: undefined label")
    return instructions, labels


def validate_boundary(boundary, claim_worlds):
    exact(boundary, ["worlds", "slots", "gas"], "artifact.boundary")
    worlds = boundary["worlds"]
    slots = boundary["slots"]
    gas = boundary["gas"]
    if not isinstance(worlds, list) or not worlds or len(set(worlds)) != len(worlds):
        raise Reject("artifact.boundary.worlds: malformed")
    for w in worlds:
        ident("w", w, "artifact.boundary.world")
    if frozenset(worlds) != claim_worlds or len(worlds) != len(claim_worlds):
        raise Reject("artifact.boundary.worlds: claim world domain mismatch")
    if not isinstance(slots, dict):
        raise Reject("artifact.boundary.slots: malformed")
    for name, values in slots.items():
        if name == "@world" or not isinstance(name, str) or TOKEN_RE.fullmatch(name) is None:
            raise Reject("artifact.boundary.slot name: malformed")
        if not isinstance(values, list) or not values or len(set(values)) != len(values):
            raise Reject("artifact.boundary.slot domain: malformed")
        if any(not isinstance(v, str) or TOKEN_RE.fullmatch(v) is None for v in values):
            raise Reject("artifact.boundary.slot value: malformed")
    if not isinstance(gas, int) or isinstance(gas, bool) or gas < 1 or gas > MAX_GAS:
        raise Reject("artifact.boundary.gas: malformed")
    return list(worlds), dict(slots), gas


def consequence(payload: bytes):
    return "c:sha256:" + hashlib.sha256(b"RISU-K1-CAPSULE-CONSEQUENCE-V1\0" + payload).hexdigest()


def execute(instructions, labels, point, gas):
    pc = 0
    effects = []
    while True:
        if gas == 0:
            raise Reject("capsule closure incomplete: gas exhausted")
        if pc < 0 or pc >= len(instructions):
            raise Reject("capsule closure incomplete: fell off program")
        gas -= 1
        ins = instructions[pc]
        op = ins[0]
        if op == "LABEL":
            pc += 1
        elif op == "IF_EQ":
            _, slot, value, label = ins
            if slot not in point:
                raise Reject("capsule closure incomplete: undeclared or missing input:" + slot)
            pc = labels[label] if point[slot] == value else pc + 1
        elif op == "GOTO":
            pc = labels[ins[1]]
        elif op == "EMIT_HEX":
            effects.append(consequence(ins[1]))
            pc += 1
        elif op == "HALT":
            if not effects:
                raise Reject("capsule closure incomplete: zero-effect halt")
            return effects
        else:
            raise AssertionError(op)


def enumerate_points(worlds, slots):
    names = sorted(slots)
    domains = [sorted(slots[n]) for n in names]
    combos = list(itertools.product(*domains)) if names else [()]
    for w in sorted(worlds):
        for combo in combos:
            point = {"@world": w}
            point.update(dict(zip(names, combo)))
            yield point


def derive_relation(program_raw, boundary, claim_worlds):
    worlds, slots, gas = validate_boundary(boundary, claim_worlds)
    instructions, labels = parse_program(program_raw)
    out = set()
    for point in enumerate_points(worlds, slots):
        effects = execute(instructions, labels, point, gas)
        w = point["@world"]
        out.update((w, c) for c in effects)
    if not out or any(not any(rw == w for rw, _ in out) for w in worlds):
        raise Reject("capsule closure incomplete: world without consequence")
    return frozenset(out), worlds, slots, gas


def target_id(program_sha256, worlds, slots, gas, realize):
    pre = b"RISU-K1-TARGET-CAPSULE-V1\0"
    pre += b"S" + net(CAPSULE_SEMANTICS)
    pre += b"P" + net(program_sha256)
    pre += b"G" + net(str(gas))
    ws = sorted(worlds)
    pre += b"W" + net(str(len(ws)))
    for w in ws:
        pre += b"w" + net(w)
    names = sorted(slots)
    pre += b"D" + net(str(len(names)))
    for name in names:
        values = sorted(slots[name])
        pre += b"s" + net(name) + net(str(len(values)))
        for value in values:
            pre += b"v" + net(value)
    rows = sorted(realize)
    pre += b"R" + net(str(len(rows)))
    for w, c in rows:
        pre += b"r" + net(w) + net(c)
    return "t:sha256:" + hashlib.sha256(pre).hexdigest()


def check_artifact(raw, expected_artifact, claim, program_raw):
    actual = "p:sha256:" + hashlib.sha256(raw).hexdigest()
    if actual != expected_artifact:
        raise Reject("proof artifact: byte digest mismatch")
    try:
        obj = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise Reject("proof artifact: invalid UTF-8 JSON") from exc
    exact(obj, ["proof_format", "claim_id", "capsule_semantics", "program_sha256", "boundary"], "capsule proof")
    if obj["proof_format"] != PROOF_KIND:
        raise Unsupported("unsupported proof artifact format")
    if obj["capsule_semantics"] != CAPSULE_SEMANTICS:
        raise Unsupported("unsupported capsule semantics")
    if obj["claim_id"] != claim["claim_id"]:
        raise Reject("capsule proof: claim mismatch")
    if not isinstance(obj["program_sha256"], str) or HEX64.fullmatch(obj["program_sha256"]) is None:
        raise Reject("capsule proof: malformed program digest")
    actual_program = hashlib.sha256(program_raw).hexdigest()
    if obj["program_sha256"] != actual_program:
        raise Reject("capsule proof: program digest mismatch")
    claim_worlds, _ = check_claim(claim)
    realize, worlds, slots, gas = derive_relation(program_raw, obj["boundary"], claim_worlds)
    tid = target_id(actual_program, worlds, slots, gas, realize)
    return obj, realize, tid


def check_certificate(cert, claim, artifact_raw, program_raw):
    exact(cert, ["wire", "kind", "claim_id", "target_id", "realize", "closure_proof", "grounding_proofs", "evidence_roots", "certificate_id"], "certificate")
    worlds, allow = check_claim(claim)
    if (cert["wire"], cert["kind"], cert["claim_id"]) != ("risu.k1.w0", "preservation_certificate", claim["claim_id"]):
        raise Reject("certificate: wire/kind/claim mismatch")
    ident("t", cert["target_id"], "certificate.target_id")
    submitted_realize = relation(cert["realize"], "certificate.realize")
    if not submitted_realize:
        raise Reject("certificate.realize: empty")
    proof_ref(cert["closure_proof"], "certificate.closure_proof")
    if cert["closure_proof"]["kind"] != PROOF_KIND:
        raise Unsupported("unsupported closure proof kind")

    if not isinstance(cert["grounding_proofs"], list):
        raise Reject("certificate.grounding_proofs: malformed")
    grounded = {}
    for item in cert["grounding_proofs"]:
        exact(item, ["pair", "proof"], "certificate.grounding_entry")
        pair = next(iter(relation([item["pair"]], "certificate.grounding_entry.pair")))
        proof_ref(item["proof"], "certificate.grounding_entry.proof")
        if pair in grounded:
            raise Reject("certificate.grounding_proofs: duplicate pair")
        grounded[pair] = item["proof"]

    if not isinstance(cert["evidence_roots"], list) or len(set(cert["evidence_roots"])) != len(cert["evidence_roots"]):
        raise Reject("certificate.evidence_roots: malformed")
    for root in cert["evidence_roots"]:
        ident("e", root, "certificate.evidence_root")
    ident("cert", cert["certificate_id"], "certificate.certificate_id")
    if cert["certificate_id"] != certificate_id(cert):
        raise Reject("certificate.certificate_id: mismatch")

    _, derived, tid = check_artifact(artifact_raw, cert["closure_proof"]["artifact"], claim, program_raw)
    if cert["target_id"] != tid:
        raise Reject("certificate: target commitment mismatch")
    if submitted_realize != derived:
        raise Reject("certificate: submitted REALIZE is not exact derived capsule closure")
    if set(grounded) != set(derived):
        raise Reject("certificate: grounding set is not exactly derived REALIZE")
    for pair in derived:
        ref = grounded[pair]
        if ref["kind"] != PROOF_KIND or ref["artifact"] != cert["closure_proof"]["artifact"]:
            raise Reject("certificate: grounding proof does not bind exact capsule artifact")

    forbidden = sorted(derived - allow)
    if forbidden:
        raise Reject("certificate: forbidden derived consequence present")

    return {
        "checker": "risu-k1-checker-w5",
        "proof_status": "ACCEPTED",
        "semantic_claim": "PRESERVATION",
        "assurance_scope": "BOUNDED_HERMETIC_CAPSULE_EXHAUSTIVE",
        "implementation_binding": True,
        "implementation_scope": "EXACT_CAPSULE_PROGRAM_AND_FINITE_BOUNDARY",
        "claim_id": claim["claim_id"],
        "target_id": tid,
        "certificate_id": cert["certificate_id"],
        "world_count": len(worlds),
        "realize_pair_count": len(derived),
        "derived_realize": [list(x) for x in sorted(derived)],
    }


def load_json(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--claim", required=True)
    ap.add_argument("--certificate", required=True)
    ap.add_argument("--artifact", required=True)
    ap.add_argument("--program", required=True)
    args = ap.parse_args(argv)

    try:
        claim = load_json(args.claim)
        cert = load_json(args.certificate)
        with open(args.artifact, "rb") as handle:
            artifact_raw = handle.read()
        with open(args.program, "rb") as handle:
            program_raw = handle.read()
        result = check_certificate(cert, claim, artifact_raw, program_raw)
    except Unsupported as exc:
        result = {
            "checker": "risu-k1-checker-w5",
            "proof_status": "UNSUPPORTED",
            "semantic_claim": "UNKNOWN",
            "reason": str(exc),
        }
    except (Reject, OSError, json.JSONDecodeError) as exc:
        result = {
            "checker": "risu-k1-checker-w5",
            "proof_status": "REJECTED",
            "semantic_claim": "NONE",
            "reason": str(exc),
        }

    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
