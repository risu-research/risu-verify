#!/usr/bin/env python3
"""K1 B0: one-sided implementation binding for observed regression witnesses.

This tool deliberately does NOT prove preservation. It executes an exact target
binary, observes a strict effect sink at the consequential cut, derives world and
consequence commitments itself, and only when an observed pair is forbidden does
it construct a normal W0 regression witness for external W1/W2 consumption.

It imports neither checker implementation.
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

WORLD_DOMAIN = b"RISU-K1-BINDING-B0-WORLD\0"
CONSEQUENCE_DOMAIN = b"RISU-K1-BINDING-B0-CONSEQUENCE\0"
BINDING_DOMAIN = b"RISU-K1-BINDING-B0-REPORT\0"
PROOF_KIND = "k1.finite-model/v1"
TOKEN_RE = re.compile(r"^[a-z0-9._:@/-]{1,128}$")
ID_RE = {
    "w": re.compile(r"^w:sha256:[0-9a-f]{64}$"),
    "c": re.compile(r"^c:sha256:[0-9a-f]{64}$"),
    "t": re.compile(r"^t:sha256:[0-9a-f]{64}$"),
    "p": re.compile(r"^p:sha256:[0-9a-f]{64}$"),
    "claim": re.compile(r"^claim:sha256:[0-9a-f]{64}$"),
    "wit": re.compile(r"^wit:sha256:[0-9a-f]{64}$"),
}


class B0Error(Exception):
    pass


def net_bytes(b):
    return str(len(b)).encode("ascii") + b":" + b + b","


def net(s):
    return net_bytes(s.encode("utf-8"))


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


def sha(prefix, raw):
    return prefix + hashlib.sha256(raw).hexdigest()


def file_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def world_id(raw):
    return sha("w:sha256:", WORLD_DOMAIN + b"B" + net_bytes(raw))


def consequence_id(kind, subject, value):
    pre = CONSEQUENCE_DOMAIN + b"K" + net(kind) + b"S" + net(subject) + b"V" + net(value)
    return sha("c:sha256:", pre)


def claim_id(doc):
    worlds = sorted(doc["worlds"])
    allow = sorted((x[0], x[1]) for x in doc["allow"])
    pre = b"RISU-K1-CLAIM-W0\0" + b"S" + net(doc["semantics"]) + vals("W", worlds) + pairs("A", allow)
    return sha("claim:sha256:", pre)


def target_id(worlds, possible):
    pre = b"RISU-K1-TARGET-FINITE-V1\0" + vals("W", sorted(worlds)) + pairs("R", sorted(possible))
    return sha("t:sha256:", pre)


def witness_id(doc):
    roots = sorted(doc["evidence_roots"])
    q = doc["grounding_proof"]
    pre = b"RISU-K1-WIT-W0\0" + b"C" + net(doc["claim_id"]) + b"T" + net(doc["target_id"])
    pre += b"P" + net(doc["pair"][0]) + net(doc["pair"][1])
    pre += b"G" + net(q["kind"]) + net(q["artifact"]) + vals("E", roots)
    return sha("wit:sha256:", pre)


def strict_claim(doc, expected_world):
    keys = {"wire", "kind", "semantics", "worlds", "allow", "claim_id"}
    if not isinstance(doc, dict) or set(doc) != keys:
        raise B0Error("claim: malformed object")
    if (doc["wire"], doc["kind"], doc["semantics"]) != ("risu.k1.w0", "claim", "safety-subset-v1"):
        raise B0Error("claim: unsupported wire/semantics")
    if not isinstance(doc["worlds"], list) or len(doc["worlds"]) != 1:
        raise B0Error("claim: B0 supports exactly one admitted world")
    if doc["worlds"][0] != expected_world:
        raise B0Error("claim: world commitment does not match exact world-input bytes")
    if not ID_RE["w"].fullmatch(doc["worlds"][0]):
        raise B0Error("claim: noncanonical world id")
    if not isinstance(doc["allow"], list) or not doc["allow"]:
        raise B0Error("claim: empty ALLOW")
    seen = set()
    for row in doc["allow"]:
        if not isinstance(row, list) or len(row) != 2:
            raise B0Error("claim.allow: malformed pair")
        w, c = row
        if w != expected_world or ID_RE["c"].fullmatch(c) is None:
            raise B0Error("claim.allow: invalid pair")
        if (w, c) in seen:
            raise B0Error("claim.allow: duplicate pair")
        seen.add((w, c))
    if ID_RE["claim"].fullmatch(doc["claim_id"]) is None or doc["claim_id"] != claim_id(doc):
        raise B0Error("claim.claim_id: mismatch")
    return frozenset(seen)


def parse_effect_log(raw):
    if raw == b"":
        return []
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise B0Error("effect sink: non-ASCII bytes") from exc
    if not text.endswith("\n"):
        raise B0Error("effect sink: partial trailing record")
    records = []
    for index, line in enumerate(text.splitlines()):
        parts = line.split("|")
        if len(parts) != 4 or parts[0] != "E1":
            raise B0Error(f"effect sink: malformed record {index}")
        expected = ("kind=", "subject=", "value=")
        values = []
        for part, prefix in zip(parts[1:], expected):
            if not part.startswith(prefix):
                raise B0Error(f"effect sink: malformed field in record {index}")
            value = part[len(prefix):]
            if TOKEN_RE.fullmatch(value) is None:
                raise B0Error(f"effect sink: noncanonical token in record {index}")
            values.append(value)
        kind, subject, value = values
        records.append({
            "kind": kind,
            "subject": subject,
            "value": value,
            "consequence_id": consequence_id(kind, subject, value),
        })
    return records


def report_binding_id(report):
    observed = sorted(report.get("observed_consequences") or [])
    forbidden = sorted(report.get("forbidden_consequences") or [])
    pair = report.get("selected_forbidden_pair") or []
    fields = [
        report.get("format"),
        report.get("authority"),
        report.get("observation_status"),
        report.get("claim_id"),
        report.get("implementation_id"),
        report.get("world_id"),
        report.get("world_input_sha256"),
        report.get("effect_log_sha256"),
        report.get("effect_log_b64"),
        str(report.get("timed_out")),
        str(report.get("exit_code")),
        report.get("stdout_sha256"),
        report.get("stderr_sha256"),
        report.get("target_id"),
        report.get("proof_artifact_id"),
        report.get("witness_id"),
        report.get("w1_class"),
        report.get("w2_class"),
    ]
    pre = BINDING_DOMAIN
    for value in fields:
        pre += b"F" + net("" if value is None else str(value))
    pre += vals("O", observed) + vals("X", forbidden) + vals("P", [str(x) for x in pair])
    return sha("bind:sha256:", pre)


def run_target(executable, world_raw, timeout_ms):
    with tempfile.TemporaryDirectory(prefix="risu-k1-b0-") as td:
        root = Path(td)
        world_path = root / "world.input"
        sink_dir = root / "sink"
        sink_dir.mkdir()
        world_path.write_bytes(world_raw)
        cmd = [os.path.abspath(executable), "--world", str(world_path), "--sink", str(sink_dir)]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=str(root), env={})
        timed_out = False
        try:
            stdout, stderr = proc.communicate(timeout=timeout_ms / 1000.0)
        except subprocess.TimeoutExpired:
            timed_out = True
            proc.kill()
            stdout, stderr = proc.communicate()
        effect_path = sink_dir / "effects.log"
        raw_effect = effect_path.read_bytes() if effect_path.exists() else b""
        return {
            "stdout": stdout,
            "stderr": stderr,
            "exit_code": proc.returncode,
            "timed_out": timed_out,
            "effect_log": raw_effect,
        }


def write_json(path, obj, canonical=False):
    if canonical:
        raw = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8") + b"\n"
        Path(path).write_bytes(raw)
        return raw
    Path(path).write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return Path(path).read_bytes()


def run_checker(command, claim_path, witness_path, artifact_path):
    cmd = command + ["--claim", claim_path, "--proof-object", witness_path, "--artifact", artifact_path]
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    try:
        out = json.loads(proc.stdout.decode("utf-8"))
    except Exception as exc:
        raise B0Error("checker produced non-JSON output") from exc
    return proc.returncode, out


def no_authority_report(base, status, reason=None):
    out = dict(base)
    out.update({
        "authority": "NO_AUTHORITY",
        "observation_status": status,
        "implementation_binding": False,
        "preservation_authority": False,
        "target_id": None,
        "proof_artifact_id": None,
        "witness_id": None,
        "selected_forbidden_pair": None,
        "w1_class": None,
        "w2_class": None,
    })
    if reason is not None:
        out["reason"] = reason
    out["binding_id"] = report_binding_id(out)
    return out


def execute_binding(args):
    world_raw = Path(args.world).read_bytes()
    wid = world_id(world_raw)
    claim = json.loads(Path(args.claim).read_text(encoding="utf-8"))
    try:
        allow = strict_claim(claim, wid)
    except B0Error as exc:
        base = {
            "format": "risu.k1.binding.b0",
            "assurance_scope": "OBSERVED_EXECUTION_REGRESSION_WITNESS_ONLY",
            "claim_id": claim.get("claim_id") if isinstance(claim, dict) else None,
            "implementation_id": "impl:sha256:" + file_sha256(args.implementation),
            "world_id": wid,
            "world_input_sha256": hashlib.sha256(world_raw).hexdigest(),
            "effect_log_sha256": hashlib.sha256(b"").hexdigest(),
            "effect_log_b64": "",
            "timed_out": False,
            "exit_code": None,
            "stdout_sha256": hashlib.sha256(b"").hexdigest(),
            "stderr_sha256": hashlib.sha256(b"").hexdigest(),
            "observed_consequences": [],
            "forbidden_consequences": [],
        }
        status = "UNSUPPORTED" if "exactly one admitted world" in str(exc) else "REJECTED"
        return no_authority_report(base, status, str(exc))

    execution = run_target(args.implementation, world_raw, args.timeout_ms)
    raw_effect = execution["effect_log"]
    base = {
        "format": "risu.k1.binding.b0",
        "assurance_scope": "OBSERVED_EXECUTION_REGRESSION_WITNESS_ONLY",
        "claim_id": claim["claim_id"],
        "implementation_id": "impl:sha256:" + file_sha256(args.implementation),
        "world_id": wid,
        "world_input_sha256": hashlib.sha256(world_raw).hexdigest(),
        "effect_log_sha256": hashlib.sha256(raw_effect).hexdigest(),
        "effect_log_b64": base64.b64encode(raw_effect).decode("ascii"),
        "timed_out": execution["timed_out"],
        "exit_code": execution["exit_code"],
        "stdout_sha256": hashlib.sha256(execution["stdout"]).hexdigest(),
        "stderr_sha256": hashlib.sha256(execution["stderr"]).hexdigest(),
    }
    try:
        records = parse_effect_log(raw_effect)
    except B0Error as exc:
        base.update({"observed_consequences": [], "forbidden_consequences": []})
        return no_authority_report(base, "MALFORMED_OBSERVATION", str(exc))

    observed = sorted(set(x["consequence_id"] for x in records))
    forbidden = sorted(c for c in observed if (wid, c) not in allow)
    base.update({
        "observed_consequences": observed,
        "forbidden_consequences": forbidden,
    })
    if not forbidden:
        return no_authority_report(base, "OBSERVED_NO_FORBIDDEN_CONSEQUENCE")

    possible = sorted((wid, c) for c in observed)
    tid = target_id([wid], possible)
    artifact = {
        "proof_format": PROOF_KIND,
        "claim_id": claim["claim_id"],
        "target_id": tid,
        "worlds": [wid],
        "possible": [[a, b] for a, b in possible],
    }
    selected = [wid, forbidden[0]]

    with tempfile.TemporaryDirectory(prefix="risu-k1-b0-proof-") as td:
        root = Path(td)
        claim_path = root / "claim.json"
        artifact_path = root / "artifact.json"
        witness_path = root / "witness.json"
        write_json(claim_path, claim, canonical=False)
        artifact_raw = write_json(artifact_path, artifact, canonical=True)
        pid = sha("p:sha256:", artifact_raw)
        witness = {
            "wire": "risu.k1.w0",
            "kind": "regression_witness",
            "claim_id": claim["claim_id"],
            "target_id": tid,
            "pair": selected,
            "grounding_proof": {"kind": PROOF_KIND, "artifact": pid},
            "evidence_roots": [],
        }
        witness["witness_id"] = witness_id(witness)
        write_json(witness_path, witness, canonical=False)

        w1_rc, w1 = run_checker([sys.executable, args.w1], str(claim_path), str(witness_path), str(artifact_path))
        w2_rc, w2 = run_checker([args.w2], str(claim_path), str(witness_path), str(artifact_path))

    w1_class = str(w1.get("proof_status")) + "/" + str(w1.get("semantic_claim"))
    w2_class = str(w2.get("proof_status")) + "/" + str(w2.get("semantic_claim"))
    if w1_rc != 0 or w2_rc != 0 or w1_class != "ACCEPTED/REGRESSION" or w2_class != "ACCEPTED/REGRESSION":
        raise B0Error(f"independent K1 consumers failed to corroborate regression: W1={w1_class}, W2={w2_class}")

    out = dict(base)
    out.update({
        "authority": "BOUND_REGRESSION",
        "observation_status": "OBSERVED_FORBIDDEN_CONSEQUENCE",
        "implementation_binding": True,
        "preservation_authority": False,
        "target_id": tid,
        "proof_artifact_id": pid,
        "witness_id": witness["witness_id"],
        "selected_forbidden_pair": selected,
        "w1_class": w1_class,
        "w2_class": w2_class,
    })
    out["binding_id"] = report_binding_id(out)
    return out


def verify_report(args):
    report = json.loads(Path(args.report).read_text(encoding="utf-8"))
    if not isinstance(report, dict) or report.get("format") != "risu.k1.binding.b0":
        raise B0Error("report: malformed format")
    claimed = report.get("binding_id")
    if not isinstance(claimed, str):
        raise B0Error("report: missing binding_id")
    copy = dict(report)
    copy.pop("binding_id", None)
    if claimed != report_binding_id(copy):
        raise B0Error("report: binding_id mismatch")
    impl = "impl:sha256:" + file_sha256(args.implementation)
    if report.get("implementation_id") != impl:
        raise B0Error("report: implementation substitution")
    world_raw = Path(args.world).read_bytes()
    if report.get("world_id") != world_id(world_raw) or report.get("world_input_sha256") != hashlib.sha256(world_raw).hexdigest():
        raise B0Error("report: world-input substitution")
    try:
        raw_effect = base64.b64decode(report.get("effect_log_b64", ""), validate=True)
    except Exception as exc:
        raise B0Error("report: invalid effect_log_b64") from exc
    if report.get("effect_log_sha256") != hashlib.sha256(raw_effect).hexdigest():
        raise B0Error("report: effect-log digest mismatch")
    if report.get("observation_status") not in {"MALFORMED_OBSERVATION", "UNSUPPORTED", "REJECTED"}:
        records = parse_effect_log(raw_effect)
        observed = sorted(set(x["consequence_id"] for x in records))
        if observed != sorted(report.get("observed_consequences") or []):
            raise B0Error("report: observed consequence mismatch")
    return {"status": "ACCEPTED", "binding_id": claimed}


def main(argv=None):
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run")
    run.add_argument("--implementation", required=True)
    run.add_argument("--world", required=True)
    run.add_argument("--claim", required=True)
    run.add_argument("--w1", required=True)
    run.add_argument("--w2", required=True)
    run.add_argument("--timeout-ms", type=int, default=250)
    run.add_argument("--output")

    verify = sub.add_parser("verify-report")
    verify.add_argument("--report", required=True)
    verify.add_argument("--implementation", required=True)
    verify.add_argument("--world", required=True)

    args = parser.parse_args(argv)
    try:
        if args.command == "run":
            result = execute_binding(args)
            if args.output:
                write_json(args.output, result, canonical=False)
        else:
            result = verify_report(args)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except B0Error as exc:
        print(json.dumps({"status": "REJECTED", "reason": str(exc)}, indent=2, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
