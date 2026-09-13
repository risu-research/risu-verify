#!/usr/bin/env python3
"""K1 B1 controlled local implementation binding for multi-world claims.

B1 executes exact implementation bytes against one admitted world, observes only
its fresh private effect sink, and may mint a k1.observed-pair/v1 regression
witness for the first forbidden durable record. It has zero preservation
authority. W3 and W4 remain the semantic/evidence authorities for the minted
P1 object; this runner does not import either checker.
"""

import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

PROFILE = "risu.binding.effect-sink-e1/v1"
PROOF_KIND = "k1.observed-pair/v1"
WORLD_DOMAIN = b"RISU-K1-BINDING-B0-WORLD\0"
CONSEQUENCE_DOMAIN = b"RISU-K1-BINDING-B0-CONSEQUENCE\0"
TARGET_DOMAIN = b"RISU-K1-TARGET-OBSERVED-PAIR-V1\0"
RUN_DOMAIN = b"RISU-K1-BINDING-B1-RUN-V1\0"
TOKEN_RE = re.compile(r"^[a-z0-9._:@/-]{1,128}$")
ID_RE = re.compile(r"^[a-z]+:sha256:[0-9a-f]{64}$")


class BindingError(Exception):
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


def digest(prefix, raw):
    return prefix + hashlib.sha256(raw).hexdigest()


def claim_id(doc):
    pre = b"RISU-K1-CLAIM-W0\0" + b"S" + net(doc["semantics"])
    pre += vals("W", sorted(doc["worlds"]))
    pre += pairs("A", sorted((row[0], row[1]) for row in doc["allow"]))
    return digest("claim:sha256:", pre)


def witness_id(doc):
    proof = doc["grounding_proof"]
    pre = b"RISU-K1-WIT-W0\0" + b"C" + net(doc["claim_id"]) + b"T" + net(doc["target_id"])
    pre += b"P" + net(doc["pair"][0]) + net(doc["pair"][1])
    pre += b"G" + net(proof["kind"]) + net(proof["artifact"])
    pre += vals("E", sorted(doc["evidence_roots"]))
    return digest("wit:sha256:", pre)


def world_id(raw):
    return digest("w:sha256:", WORLD_DOMAIN + b"B" + net_bytes(raw))


def consequence_id(kind, subject, value):
    pre = CONSEQUENCE_DOMAIN + b"K" + net(kind) + b"S" + net(subject) + b"V" + net(value)
    return digest("c:sha256:", pre)


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8") + b"\n"


def validate_claim(doc):
    if not isinstance(doc, dict) or set(doc) != {"wire", "kind", "semantics", "worlds", "allow", "claim_id"}:
        raise BindingError("claim: malformed object")
    if (doc["wire"], doc["kind"], doc["semantics"]) != ("risu.k1.w0", "claim", "safety-subset-v1"):
        raise BindingError("claim: unsupported wire/semantics")
    if not isinstance(doc["worlds"], list) or not doc["worlds"] or len(set(doc["worlds"])) != len(doc["worlds"]):
        raise BindingError("claim.worlds: malformed")
    for world in doc["worlds"]:
        if not isinstance(world, str) or not world.startswith("w:sha256:") or ID_RE.fullmatch(world) is None:
            raise BindingError("claim.worlds: noncanonical world")
    if not isinstance(doc["allow"], list) or not doc["allow"]:
        raise BindingError("claim.allow: malformed")
    allow = []
    for row in doc["allow"]:
        if not isinstance(row, list) or len(row) != 2:
            raise BindingError("claim.allow: malformed pair")
        w, c = row
        if w not in doc["worlds"] or not isinstance(c, str) or not c.startswith("c:sha256:") or ID_RE.fullmatch(c) is None:
            raise BindingError("claim.allow: invalid pair")
        allow.append((w, c))
    if len(set(allow)) != len(allow):
        raise BindingError("claim.allow: duplicate pair")
    for world in doc["worlds"]:
        if not any(w == world for w, _ in allow):
            raise BindingError("claim.allow: world without allowed consequence")
    if claim_id(doc) != doc["claim_id"]:
        raise BindingError("claim.claim_id: mismatch")
    return frozenset(doc["worlds"]), frozenset(allow)


def parse_effect_log(raw):
    if not raw:
        return []
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise BindingError("effect sink: non-ASCII bytes") from exc
    if not text.endswith("\n"):
        raise BindingError("effect sink: partial trailing record")
    out = []
    for index, line in enumerate(text.splitlines()):
        parts = line.split("|")
        if len(parts) != 4 or parts[0] != "E1":
            raise BindingError(f"effect sink[{index}]: malformed record")
        values = []
        for part, prefix in zip(parts[1:], ("kind=", "subject=", "value=")):
            if not part.startswith(prefix):
                raise BindingError(f"effect sink[{index}]: malformed field")
            value = part[len(prefix):]
            if TOKEN_RE.fullmatch(value) is None:
                raise BindingError(f"effect sink[{index}]: noncanonical token")
            values.append(value)
        out.append({
            "index": index,
            "kind": values[0],
            "subject": values[1],
            "value": values[2],
            "consequence_id": consequence_id(*values),
        })
    return out


def observed_target_id(artifact, world_raw, effect_raw):
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
    return digest("t:sha256:", pre)


def run_envelope_id(report):
    artifact_id = report.get("proof_artifact_id") or "null"
    witness = report.get("witness_id") or "null"
    exit_token = "null" if report["exit_code"] is None else str(report["exit_code"])
    fields = [
        ("C", report["claim_id"]),
        ("W", report["world_id"]),
        ("I", report["implementation_id"]),
        ("H", report["world_input_sha256"]),
        ("L", report["effect_log_sha256"]),
        ("O", "1" if report["timed_out"] else "0"),
        ("X", exit_token),
        ("S", report["stdout_sha256"]),
        ("E", report["stderr_sha256"]),
        ("P", artifact_id),
        ("V", witness),
        ("A", report["authority"]),
    ]
    pre = RUN_DOMAIN
    for tag, value in fields:
        pre += tag.encode("ascii") + net(value)
    return digest("run:sha256:", pre)


def checker_class(proc):
    try:
        obj = json.loads(proc.stdout.decode("utf-8"))
    except Exception:
        return "NON_JSON", {}
    if proc.returncode == 0 and obj.get("proof_status") == "ACCEPTED" and obj.get("semantic_claim") == "REGRESSION":
        return "ACCEPTED/REGRESSION", obj
    if proc.returncode == 1 and obj.get("proof_status") == "REJECTED":
        return "REJECTED", obj
    if proc.returncode == 2 and obj.get("proof_status") == "UNSUPPORTED":
        return "UNSUPPORTED", obj
    return "UNEXPECTED", obj


def run_checker(command, claim_path, witness_path, artifact_path, implementation_path):
    proc = subprocess.run(command + [
        "--claim", str(claim_path),
        "--proof-object", str(witness_path),
        "--artifact", str(artifact_path),
        "--implementation", str(implementation_path),
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    return checker_class(proc)


def execute(binary, world_raw, timeout_seconds):
    with tempfile.TemporaryDirectory(prefix="risu-k1-b1-run-") as td:
        root = Path(td)
        world_path = root / "world.input"
        sink = root / "sink"
        sink.mkdir(mode=0o700)
        if any(sink.iterdir()):
            raise BindingError("controlled sink was not empty before execution")
        world_path.write_bytes(world_raw)
        proc = subprocess.Popen(
            [str(binary), "--world", str(world_path), "--sink", str(sink)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(root),
            env={"PATH": os.environ.get("PATH", "")},
        )
        timed_out = False
        try:
            stdout, stderr = proc.communicate(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            proc.kill()
            stdout, stderr = proc.communicate()
        exit_code = proc.returncode
        effect_path = sink / "effects.log"
        effect_raw = effect_path.read_bytes() if effect_path.is_file() else b""
        unexpected = [p.name for p in sink.iterdir() if p.name != "effects.log"]
        if unexpected:
            raise BindingError("controlled sink contains unexpected entries")
        return {
            "timed_out": timed_out,
            "exit_code": exit_code,
            "stdout": stdout,
            "stderr": stderr,
            "effect_raw": effect_raw,
        }


def bind(claim_path, world_path, implementation_path, w3_path, w4_path, timeout_seconds):
    claim = json.loads(Path(claim_path).read_text(encoding="utf-8"))
    worlds, allow = validate_claim(claim)
    world_raw = Path(world_path).read_bytes()
    wid = world_id(world_raw)
    if wid not in worlds:
        raise BindingError("selected world bytes are not admitted by claim")
    implementation_raw = Path(implementation_path).read_bytes()
    implementation_id = digest("impl:sha256:", implementation_raw)

    observed = execute(Path(implementation_path).resolve(), world_raw, timeout_seconds)
    effect_raw = observed["effect_raw"]
    stdout = observed["stdout"]
    stderr = observed["stderr"]

    base_report = {
        "format": "risu.k1.binding.b1.run/v1",
        "binding_scope": "CONTROLLED_LOCAL_EXECUTION_REGRESSION_ONLY",
        "preservation_authority": False,
        "claim_id": claim["claim_id"],
        "world_id": wid,
        "world_input_b64": base64.b64encode(world_raw).decode("ascii"),
        "world_input_sha256": hashlib.sha256(world_raw).hexdigest(),
        "implementation_id": implementation_id,
        "effect_log_b64": base64.b64encode(effect_raw).decode("ascii"),
        "effect_log_sha256": hashlib.sha256(effect_raw).hexdigest(),
        "timed_out": observed["timed_out"],
        "exit_code": observed["exit_code"],
        "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
        "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
        "observed_consequences": [],
        "selected_forbidden_pair": None,
        "proof_artifact_id": None,
        "witness_id": None,
        "target_id": None,
        "p1_artifact_b64": None,
        "p1_witness": None,
        "w3_class": None,
        "w4_class": None,
        "authority": "NO_AUTHORITY",
        "observation_status": "OBSERVED_NO_FORBIDDEN_CONSEQUENCE",
        "causal_scope": "CONTROLLED_LOCAL_RUN_ONLY",
        "transferable_attestation": False,
    }

    try:
        records = parse_effect_log(effect_raw)
    except BindingError as exc:
        base_report["observation_status"] = "MALFORMED_OBSERVATION"
        base_report["reason"] = str(exc)
        base_report["run_envelope_id"] = run_envelope_id(base_report)
        return base_report

    base_report["observed_consequences"] = [row["consequence_id"] for row in records]
    forbidden = next((row for row in records if (wid, row["consequence_id"]) not in allow), None)
    if forbidden is None:
        base_report["run_envelope_id"] = run_envelope_id(base_report)
        return base_report

    pair = [wid, forbidden["consequence_id"]]
    artifact = {
        "proof_format": PROOF_KIND,
        "profile": PROFILE,
        "claim_id": claim["claim_id"],
        "target_id": "t:sha256:" + "0" * 64,
        "pair": pair,
        "implementation_id": implementation_id,
        "world_input_b64": base_report["world_input_b64"],
        "effect_log_b64": base_report["effect_log_b64"],
        "record_index": forbidden["index"],
        "timed_out": observed["timed_out"],
        "exit_code": observed["exit_code"],
        "stdout_sha256": base_report["stdout_sha256"],
        "stderr_sha256": base_report["stderr_sha256"],
    }
    artifact["target_id"] = observed_target_id(artifact, world_raw, effect_raw)
    artifact_raw = canonical(artifact)
    proof_id = digest("p:sha256:", artifact_raw)
    witness = {
        "wire": "risu.k1.w0",
        "kind": "regression_witness",
        "claim_id": claim["claim_id"],
        "target_id": artifact["target_id"],
        "pair": pair,
        "grounding_proof": {"kind": PROOF_KIND, "artifact": proof_id},
        "evidence_roots": [],
    }
    witness["witness_id"] = witness_id(witness)

    with tempfile.TemporaryDirectory(prefix="risu-k1-b1-check-") as td:
        root = Path(td)
        witness_path = root / "witness.json"
        artifact_path = root / "artifact.json"
        witness_path.write_text(json.dumps(witness, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        artifact_path.write_bytes(artifact_raw)
        w3_class, _ = run_checker([sys.executable, str(Path(w3_path).resolve())], claim_path, witness_path, artifact_path, implementation_path)
        w4_class, _ = run_checker([str(Path(w4_path).resolve())], claim_path, witness_path, artifact_path, implementation_path)

    base_report.update({
        "observation_status": "OBSERVED_FORBIDDEN_CONSEQUENCE",
        "selected_forbidden_pair": pair,
        "proof_artifact_id": proof_id,
        "witness_id": witness["witness_id"],
        "target_id": artifact["target_id"],
        "p1_artifact_b64": base64.b64encode(artifact_raw).decode("ascii"),
        "p1_witness": witness,
        "w3_class": w3_class,
        "w4_class": w4_class,
    })
    if w3_class == "ACCEPTED/REGRESSION" and w4_class == "ACCEPTED/REGRESSION":
        base_report["authority"] = "BOUND_REGRESSION"
    else:
        base_report["authority"] = "REJECT_BINDING_EVIDENCE"
        base_report["reason"] = "P1 checker pair did not independently accept the minted witness"
    base_report["run_envelope_id"] = run_envelope_id(base_report)
    return base_report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--claim", required=True)
    parser.add_argument("--world", required=True)
    parser.add_argument("--implementation", required=True)
    parser.add_argument("--w3", required=True)
    parser.add_argument("--w4", required=True)
    parser.add_argument("--timeout-seconds", type=float, default=0.25)
    parser.add_argument("--output")
    args = parser.parse_args()
    try:
        report = bind(args.claim, args.world, args.implementation, args.w3, args.w4, args.timeout_seconds)
        rc = 0
    except (BindingError, OSError, json.JSONDecodeError) as exc:
        report = {
            "format": "risu.k1.binding.b1.run/v1",
            "authority": "REJECTED",
            "preservation_authority": False,
            "reason": str(exc),
        }
        rc = 1
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    print(text, end="")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
