#!/usr/bin/env python3
"""Fail-closed verifier for saved B1 controlled-run regression evidence."""

import argparse
import base64
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

WORLD_DOMAIN = b"RISU-K1-BINDING-B0-WORLD\0"
RUN_DOMAIN = b"RISU-K1-BINDING-B1-RUN-V1\0"


def net_bytes(raw):
    return str(len(raw)).encode("ascii") + b":" + raw + b","


def net(text):
    return net_bytes(text.encode("utf-8"))


def digest(prefix, raw):
    return prefix + hashlib.sha256(raw).hexdigest()


def world_id(raw):
    return digest("w:sha256:", WORLD_DOMAIN + b"B" + net_bytes(raw))


def canonical_b64(text, where):
    if not isinstance(text, str):
        raise ValueError(where + ": expected string")
    raw = base64.b64decode(text.encode("ascii"), validate=True)
    if base64.b64encode(raw).decode("ascii") != text:
        raise ValueError(where + ": noncanonical base64")
    return raw


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
        return "NON_JSON"
    if proc.returncode == 0 and obj.get("proof_status") == "ACCEPTED" and obj.get("semantic_claim") == "REGRESSION":
        return "ACCEPTED/REGRESSION"
    if proc.returncode == 1 and obj.get("proof_status") == "REJECTED":
        return "REJECTED"
    if proc.returncode == 2 and obj.get("proof_status") == "UNSUPPORTED":
        return "UNSUPPORTED"
    return "UNEXPECTED"


def invoke(command, claim, witness, artifact, implementation):
    proc = subprocess.run(command + [
        "--claim", str(claim), "--proof-object", str(witness), "--artifact", str(artifact), "--implementation", str(implementation)
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    return checker_class(proc)


def verify(report, claim_path, world_path, implementation_path, w3, w4):
    if report.get("preservation_authority") is not False:
        raise ValueError("report: preservation authority must be false")
    if report.get("authority") != "BOUND_REGRESSION":
        return {"status": "NO_AUTHORITY", "preservation_authority": False}
    required = {
        "format", "binding_scope", "preservation_authority", "claim_id", "world_id", "world_input_b64",
        "world_input_sha256", "implementation_id", "effect_log_b64", "effect_log_sha256", "timed_out",
        "exit_code", "stdout_sha256", "stderr_sha256", "observed_consequences", "selected_forbidden_pair",
        "proof_artifact_id", "witness_id", "target_id", "p1_artifact_b64", "p1_witness", "w3_class",
        "w4_class", "authority", "observation_status", "causal_scope", "transferable_attestation", "run_envelope_id"
    }
    if set(report) != required:
        raise ValueError("report: unexpected or missing fields for bound regression evidence")
    if report["format"] != "risu.k1.binding.b1.run/v1":
        raise ValueError("report: wrong format")
    if report["binding_scope"] != "CONTROLLED_LOCAL_EXECUTION_REGRESSION_ONLY" or report["causal_scope"] != "CONTROLLED_LOCAL_RUN_ONLY":
        raise ValueError("report: scope mismatch")
    if report["transferable_attestation"] is not False:
        raise ValueError("report: transferable attestation must be false")
    if report["observation_status"] != "OBSERVED_FORBIDDEN_CONSEQUENCE":
        raise ValueError("report: bound regression lacks forbidden observation status")

    claim = json.loads(Path(claim_path).read_text(encoding="utf-8"))
    if report["claim_id"] != claim.get("claim_id"):
        raise ValueError("report: claim substitution")
    external_world = Path(world_path).read_bytes()
    embedded_world = canonical_b64(report["world_input_b64"], "report.world_input_b64")
    if embedded_world != external_world:
        raise ValueError("report: world-input substitution")
    if report["world_input_sha256"] != hashlib.sha256(external_world).hexdigest() or report["world_id"] != world_id(external_world):
        raise ValueError("report: world commitment mismatch")
    external_impl = Path(implementation_path).read_bytes()
    if report["implementation_id"] != digest("impl:sha256:", external_impl):
        raise ValueError("report: implementation substitution")
    effect_raw = canonical_b64(report["effect_log_b64"], "report.effect_log_b64")
    if report["effect_log_sha256"] != hashlib.sha256(effect_raw).hexdigest():
        raise ValueError("report: effect-log digest mismatch")

    artifact_raw = canonical_b64(report["p1_artifact_b64"], "report.p1_artifact_b64")
    if report["proof_artifact_id"] != digest("p:sha256:", artifact_raw):
        raise ValueError("report: P1 artifact substitution")
    artifact = json.loads(artifact_raw.decode("utf-8"))
    witness = report["p1_witness"]
    if artifact.get("claim_id") != report["claim_id"] or artifact.get("pair") != report["selected_forbidden_pair"]:
        raise ValueError("report: artifact claim/pair mismatch")
    if artifact.get("implementation_id") != report["implementation_id"]:
        raise ValueError("report: artifact implementation mismatch")
    if artifact.get("world_input_b64") != report["world_input_b64"] or artifact.get("effect_log_b64") != report["effect_log_b64"]:
        raise ValueError("report: artifact observation bytes mismatch")
    if artifact.get("timed_out") != report["timed_out"] or artifact.get("exit_code") != report["exit_code"]:
        raise ValueError("report: artifact process metadata mismatch")
    if artifact.get("stdout_sha256") != report["stdout_sha256"] or artifact.get("stderr_sha256") != report["stderr_sha256"]:
        raise ValueError("report: artifact stream digest mismatch")
    if artifact.get("target_id") != report["target_id"]:
        raise ValueError("report: artifact target mismatch")
    if not isinstance(witness, dict) or witness.get("witness_id") != report["witness_id"]:
        raise ValueError("report: witness substitution")
    if witness.get("target_id") != report["target_id"] or witness.get("pair") != report["selected_forbidden_pair"]:
        raise ValueError("report: witness target/pair mismatch")
    proof = witness.get("grounding_proof")
    if not isinstance(proof, dict) or proof.get("kind") != "k1.observed-pair/v1" or proof.get("artifact") != report["proof_artifact_id"]:
        raise ValueError("report: witness grounding reference mismatch")
    if report["run_envelope_id"] != run_envelope_id(report):
        raise ValueError("report: run envelope mismatch")

    with tempfile.TemporaryDirectory(prefix="risu-b1-report-verify-") as td:
        root = Path(td)
        wp = root / "witness.json"
        ap = root / "artifact.json"
        wp.write_text(json.dumps(witness, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        ap.write_bytes(artifact_raw)
        c3 = invoke([sys.executable, str(Path(w3).resolve())], claim_path, wp, ap, implementation_path)
        c4 = invoke([str(Path(w4).resolve())], claim_path, wp, ap, implementation_path)
    if c3 != "ACCEPTED/REGRESSION" or c4 != "ACCEPTED/REGRESSION":
        raise ValueError("report: checker pair does not accept embedded evidence")
    if report["w3_class"] != c3 or report["w4_class"] != c4:
        raise ValueError("report: recorded checker class mismatch")
    return {
        "status": "VERIFIED_BOUND_REGRESSION",
        "preservation_authority": False,
        "claim_id": report["claim_id"],
        "world_id": report["world_id"],
        "pair": report["selected_forbidden_pair"],
        "proof_artifact_id": report["proof_artifact_id"],
        "witness_id": report["witness_id"],
        "run_envelope_id": report["run_envelope_id"],
        "w3": c3,
        "w4": c4,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", required=True)
    parser.add_argument("--claim", required=True)
    parser.add_argument("--world", required=True)
    parser.add_argument("--implementation", required=True)
    parser.add_argument("--w3", required=True)
    parser.add_argument("--w4", required=True)
    args = parser.parse_args()
    try:
        report = json.loads(Path(args.report).read_text(encoding="utf-8"))
        out = verify(report, args.claim, args.world, args.implementation, args.w3, args.w4)
        rc = 0 if out["status"] in {"VERIFIED_BOUND_REGRESSION", "NO_AUTHORITY"} else 1
    except Exception as exc:
        out = {"status": "REJECT_BINDING_EVIDENCE", "preservation_authority": False, "reason": str(exc)}
        rc = 1
    print(json.dumps(out, indent=2, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
