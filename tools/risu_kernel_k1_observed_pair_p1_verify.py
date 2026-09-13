#!/usr/bin/env python3
"""P1 adversarial + W3/W4 differential qualification for k1.observed-pair/v1."""

import argparse
import ast
import base64
import copy
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

WORLD_DOMAIN = b"RISU-K1-BINDING-B0-WORLD\0"
CONSEQUENCE_DOMAIN = b"RISU-K1-BINDING-B0-CONSEQUENCE\0"
TARGET_DOMAIN = b"RISU-K1-TARGET-OBSERVED-PAIR-V1\0"
PROOF_KIND = "k1.observed-pair/v1"
PROFILE = "risu.binding.effect-sink-e1/v1"


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


def world_id(raw):
    return sha("w:sha256:", WORLD_DOMAIN + b"B" + net_bytes(raw))


def consequence_id(kind, subject, value):
    pre = CONSEQUENCE_DOMAIN + b"K" + net(kind) + b"S" + net(subject) + b"V" + net(value)
    return sha("c:sha256:", pre)


def claim_id(doc):
    pre = b"RISU-K1-CLAIM-W0\0" + b"S" + net(doc["semantics"])
    pre += vals("W", sorted(doc["worlds"]))
    pre += pairs("A", sorted((row[0], row[1]) for row in doc["allow"]))
    return sha("claim:sha256:", pre)


def witness_id(doc):
    proof = doc["grounding_proof"]
    pre = b"RISU-K1-WIT-W0\0" + b"C" + net(doc["claim_id"]) + b"T" + net(doc["target_id"])
    pre += b"P" + net(doc["pair"][0]) + net(doc["pair"][1])
    pre += b"G" + net(proof["kind"]) + net(proof["artifact"])
    pre += vals("E", sorted(doc["evidence_roots"]))
    return sha("wit:sha256:", pre)


def target_id(artifact, world_raw, effect_raw):
    exit_token = "null" if artifact["exit_code"] is None else str(artifact["exit_code"])
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
    pre = TARGET_DOMAIN
    for tag, value in fields:
        pre += tag.encode("ascii") + net(value)
    return sha("t:sha256:", pre)


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8") + b"\n"


def build_bundle(claim, implementation_raw, *, world_raw=None, effect_raw=None, pair=None,
                 record_index=0, timed_out=False, exit_code=0, profile=PROFILE,
                 implementation_id=None, claim_override=None, target_override=None):
    world_raw = world_raw if world_raw is not None else b"request=transfer\nsubject=alice\nvalue=100\n"
    effect_raw = effect_raw if effect_raw is not None else b"E1|kind=transfer|subject=bob|value=100\n"
    pair = pair if pair is not None else [
        world_id(b"request=transfer\nsubject=alice\nvalue=100\n"),
        consequence_id("transfer", "bob", "100"),
    ]
    artifact = {
        "proof_format": PROOF_KIND,
        "profile": profile,
        "claim_id": claim_override if claim_override is not None else claim["claim_id"],
        "target_id": "t:sha256:" + "0" * 64,
        "pair": pair,
        "implementation_id": implementation_id if implementation_id is not None else sha("impl:sha256:", implementation_raw),
        "world_input_b64": base64.b64encode(world_raw).decode("ascii"),
        "effect_log_b64": base64.b64encode(effect_raw).decode("ascii"),
        "record_index": record_index,
        "timed_out": timed_out,
        "exit_code": exit_code,
        "stdout_sha256": hashlib.sha256(b"").hexdigest(),
        "stderr_sha256": hashlib.sha256(b"").hexdigest(),
    }
    artifact["target_id"] = target_override if target_override is not None else target_id(artifact, world_raw, effect_raw)
    artifact_raw = canonical(artifact)
    pid = sha("p:sha256:", artifact_raw)
    witness = {
        "wire": "risu.k1.w0",
        "kind": "regression_witness",
        "claim_id": claim["claim_id"],
        "target_id": artifact["target_id"],
        "pair": pair,
        "grounding_proof": {"kind": PROOF_KIND, "artifact": pid},
        "evidence_roots": [],
    }
    witness["witness_id"] = witness_id(witness)
    return artifact, artifact_raw, witness


def classify(rc, obj):
    if rc == 0 and obj.get("proof_status") == "ACCEPTED" and obj.get("semantic_claim") == "REGRESSION":
        return "ACCEPTED/REGRESSION"
    if rc == 1 and obj.get("proof_status") == "REJECTED":
        return "REJECTED"
    if rc == 2 and obj.get("proof_status") == "UNSUPPORTED":
        return "UNSUPPORTED"
    return f"UNEXPECTED(rc={rc},status={obj.get('proof_status')},semantic={obj.get('semantic_claim')})"


def run_checker(cmd, claim, proof_object, artifact_raw, implementation_path):
    with tempfile.TemporaryDirectory(prefix="risu-p1-check-") as td:
        root = Path(td)
        cp, op, ap = root / "claim.json", root / "proof.json", root / "artifact.json"
        cp.write_text(json.dumps(claim, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        op.write_text(json.dumps(proof_object, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        ap.write_bytes(artifact_raw)
        proc = subprocess.run(cmd + ["--claim", str(cp), "--proof-object", str(op), "--artifact", str(ap), "--implementation", str(implementation_path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        try:
            out = json.loads(proc.stdout.decode("utf-8"))
        except Exception:
            out = {"proof_status": "NON_JSON", "stderr": proc.stderr.decode("utf-8", errors="replace")}
        return classify(proc.returncode, out), out


def independence(w3_source, w4_source):
    tree = ast.parse(Path(w3_source).read_text(encoding="utf-8"))
    imports = sorted({node.names[0].name.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.Import)} |
                     {node.module.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.module})
    allowed_py = {"argparse", "base64", "hashlib", "json", "re", "pathlib"}
    py_ok = set(imports) <= allowed_py
    go = Path(w4_source).read_text(encoding="utf-8")
    nonstd_markers = ["github.com/", "golang.org/", "os/exec", "python", "k1_checker_w1", "k1_checker_w2"]
    bad_go = [marker for marker in nonstd_markers if marker in go.lower()]
    return {"python_imports": imports, "python_stdlib_only": py_ok, "go_forbidden_markers": bad_go, "pass": py_ok and not bad_go}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--w3", required=True)
    parser.add_argument("--w4", required=True)
    parser.add_argument("--w4-source", required=True)
    parser.add_argument("--claim", required=True)
    parser.add_argument("--implementation", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    claim = json.loads(Path(args.claim).read_text(encoding="utf-8"))
    implementation_raw = Path(args.implementation).read_bytes()
    base_artifact, base_raw, base_witness = build_bundle(claim, implementation_raw)
    vectors = []

    def add(vector_id, expected, c, obj, raw):
        w3_class, w3_out = run_checker([sys.executable, args.w3], c, obj, raw, args.implementation)
        w4_class, w4_out = run_checker([args.w4], c, obj, raw, args.implementation)
        ok = w3_class == expected and w4_class == expected and w3_class == w4_class
        vectors.append({"id": vector_id, "expected": expected, "w3": w3_class, "w4": w4_class, "pass": ok,
                        "w3_reason": w3_out.get("reason"), "w4_reason": w4_out.get("reason")})

    add("P1-01", "ACCEPTED/REGRESSION", claim, base_witness, base_raw)

    allowed = copy.deepcopy(claim)
    allowed["allow"].append(list(base_witness["pair"]))
    allowed["claim_id"] = claim_id(allowed)
    a, r, w = build_bundle(allowed, implementation_raw)
    add("P1-02", "REJECTED", allowed, w, r)

    other_raw = b"request=transfer\nsubject=dave\nvalue=1\n"
    undeclared_pair = [world_id(other_raw), base_witness["pair"][1]]
    a, r, w = build_bundle(claim, implementation_raw, world_raw=other_raw, pair=undeclared_pair)
    add("P1-03", "REJECTED", claim, w, r)

    fake_claim_id = "claim:sha256:" + "a" * 64
    a, r, w = build_bundle(claim, implementation_raw, claim_override=fake_claim_id)
    add("P1-04", "REJECTED", claim, w, r)

    a, r, w = build_bundle(claim, implementation_raw, world_raw=b"request=transfer\nsubject=carol\nvalue=50\n")
    add("P1-05", "REJECTED", claim, w, r)

    a, r, w = build_bundle(claim, implementation_raw, effect_raw=b"E1|kind=transfer|subject=alice|value=100\n")
    add("P1-06", "REJECTED", claim, w, r)

    a, r, w = build_bundle(claim, implementation_raw, record_index=4)
    add("P1-07", "REJECTED", claim, w, r)

    a, r, w = build_bundle(claim, implementation_raw, effect_raw=b"E1|kind=transfer|subject=bob|value=100")
    add("P1-08", "REJECTED", claim, w, r)

    a, r, w = build_bundle(claim, implementation_raw, implementation_id=sha("impl:sha256:", b"substituted executable"))
    add("P1-09", "REJECTED", claim, w, r)

    tampered_target = "t:sha256:" + "f" * 64
    a, r, w = build_bundle(claim, implementation_raw, target_override=tampered_target)
    add("P1-10", "REJECTED", claim, w, r)

    add("P1-11", "REJECTED", claim, base_witness, base_raw + b" ")

    bad_witness = copy.deepcopy(base_witness)
    bad_witness["witness_id"] = "wit:sha256:" + "0" * 64
    add("P1-12", "REJECTED", claim, bad_witness, base_raw)

    preservation_stub = {"kind": "preservation_certificate"}
    add("P1-13", "UNSUPPORTED", claim, preservation_stub, base_raw)

    many = copy.deepcopy(claim)
    for i in range(7):
        raw_world = f"unobserved-world-{i}\n".encode("ascii")
        wid = world_id(raw_world)
        cid = consequence_id("noop", f"u{i}", "ok")
        many["worlds"].append(wid)
        many["allow"].append([wid, cid])
    many["claim_id"] = claim_id(many)
    a, r, w = build_bundle(many, implementation_raw)
    add("P1-14", "ACCEPTED/REGRESSION", many, w, r)

    reordered = copy.deepcopy(claim)
    reordered["worlds"] = list(reversed(reordered["worlds"]))
    reordered["allow"] = list(reversed(reordered["allow"]))
    assert claim_id(reordered) == claim["claim_id"]
    add("P1-15", "ACCEPTED/REGRESSION", reordered, base_witness, base_raw)

    multi_log = b"E1|kind=transfer|subject=alice|value=100\nE1|kind=transfer|subject=bob|value=100\n"
    a, r, w = build_bundle(claim, implementation_raw, effect_raw=multi_log, record_index=1)
    add("P1-16", "ACCEPTED/REGRESSION", claim, w, r)

    a, r, w = build_bundle(claim, implementation_raw, timed_out=True, exit_code=-9)
    add("P1-17", "ACCEPTED/REGRESSION", claim, w, r)

    a, r, w = build_bundle(claim, implementation_raw, profile="unknown.observation/v1")
    add("P1-18", "UNSUPPORTED", claim, w, r)

    indep = independence(args.w3, args.w4_source)
    failed = [row["id"] for row in vectors if not row["pass"]]
    result = {
        "gate": "RISU_KERNEL_K1_OBSERVED_PAIR_P1",
        "status": "PASS" if not failed and indep["pass"] else "FAIL",
        "vector_count": len(vectors),
        "passed": sum(1 for row in vectors if row["pass"]),
        "failed": failed,
        "checker_independence": indep,
        "preservation_authority": False,
        "semantic_kernel_changed": False,
        "rows": vectors,
    }
    Path(args.output).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
