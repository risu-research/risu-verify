#!/usr/bin/env python3
"""C1 falsification engine for a prospective hermetic K1 closure capsule.

This file defines a tiny deterministic execution model and attacks its closure
constitution.  It intentionally does NOT create a production K1 proof kind.
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import re
from pathlib import Path

WORLD_RE = re.compile(r"^w:sha256:[0-9a-f]{64}$")
TOKEN_RE = re.compile(r"^[A-Za-z0-9_.@:-]+$")
HEX_RE = re.compile(r"^(?:[0-9a-f]{2})+$")
FORBIDDEN_AMBIENT = {"CLOCK", "RNG", "FILE", "NET", "HOSTCALL", "SPAWN"}
ALLOWED = {"LABEL", "IF_EQ", "GOTO", "EMIT_HEX", "HALT"}
MAX_PROGRAM_BYTES = 65536
MAX_GAS = 10000


class CapsuleReject(Exception):
    pass


def net(text: str) -> bytes:
    b = text.encode("utf-8")
    return str(len(b)).encode("ascii") + b":" + b + b","


def world(label: str) -> str:
    return "w:sha256:" + hashlib.sha256(("RISU-K1-C1-WORLD\0" + label).encode()).hexdigest()


def consequence(payload: bytes) -> str:
    return "c:sha256:" + hashlib.sha256(b"RISU-K1-CAPSULE-CONSEQUENCE-V1\0" + payload).hexdigest()


def strict_lines(raw: bytes):
    if not raw or len(raw) > MAX_PROGRAM_BYTES:
        raise CapsuleReject("program-size")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise CapsuleReject("program-utf8") from exc
    if "\x00" in text or "\r" in text or "\t" in text:
        raise CapsuleReject("program-ambiguous-bytes")
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    if not lines or any(line == "" for line in lines):
        raise CapsuleReject("program-empty-line")
    for line in lines:
        if line.strip() != line or "  " in line:
            raise CapsuleReject("program-noncanonical-spacing")
    return lines


def parse_program(raw: bytes):
    instructions = []
    labels = {}
    branch_refs = []
    for idx, line in enumerate(strict_lines(raw)):
        parts = line.split(" ")
        op = parts[0]
        if op in FORBIDDEN_AMBIENT:
            raise CapsuleReject("ambient-capability-forbidden:" + op)
        if op not in ALLOWED:
            raise CapsuleReject("unknown-opcode:" + op)
        if op == "LABEL":
            if len(parts) != 2 or not TOKEN_RE.fullmatch(parts[1]):
                raise CapsuleReject("label-syntax")
            if parts[1] in labels:
                raise CapsuleReject("duplicate-label")
            labels[parts[1]] = idx
            instructions.append((op, parts[1]))
        elif op == "IF_EQ":
            if len(parts) != 4 or any(TOKEN_RE.fullmatch(x) is None for x in parts[1:]):
                raise CapsuleReject("if-syntax")
            branch_refs.append(parts[3])
            instructions.append((op, parts[1], parts[2], parts[3]))
        elif op == "GOTO":
            if len(parts) != 2 or TOKEN_RE.fullmatch(parts[1]) is None:
                raise CapsuleReject("goto-syntax")
            branch_refs.append(parts[1])
            instructions.append((op, parts[1]))
        elif op == "EMIT_HEX":
            if len(parts) != 2 or HEX_RE.fullmatch(parts[1]) is None:
                raise CapsuleReject("emit-syntax")
            instructions.append((op, bytes.fromhex(parts[1])))
        elif op == "HALT":
            if len(parts) != 1:
                raise CapsuleReject("halt-syntax")
            instructions.append((op,))
    if any(label not in labels for label in branch_refs):
        raise CapsuleReject("undefined-label")
    return instructions, labels


def validate_boundary(boundary):
    if not isinstance(boundary, dict) or set(boundary) != {"worlds", "slots", "gas"}:
        raise CapsuleReject("boundary-shape")
    worlds = boundary["worlds"]
    slots = boundary["slots"]
    gas = boundary["gas"]
    if not isinstance(worlds, list) or not worlds or len(set(worlds)) != len(worlds):
        raise CapsuleReject("world-domain")
    if any(not isinstance(w, str) or WORLD_RE.fullmatch(w) is None for w in worlds):
        raise CapsuleReject("world-id")
    if not isinstance(slots, dict):
        raise CapsuleReject("slots-shape")
    for name, values in slots.items():
        if name == "@world" or TOKEN_RE.fullmatch(name) is None:
            raise CapsuleReject("slot-name")
        if not isinstance(values, list) or not values or len(set(values)) != len(values):
            raise CapsuleReject("slot-domain:" + name)
        if any(not isinstance(v, str) or TOKEN_RE.fullmatch(v) is None for v in values):
            raise CapsuleReject("slot-value:" + name)
    if not isinstance(gas, int) or isinstance(gas, bool) or gas < 1 or gas > MAX_GAS:
        raise CapsuleReject("gas")
    return worlds, slots, gas


def target_id(raw: bytes, boundary) -> str:
    worlds, slots, gas = validate_boundary(boundary)
    pre = b"RISU-K1-CAPSULE-TARGET-C1\0"
    pre += b"P" + net(hashlib.sha256(raw).hexdigest())
    pre += b"G" + net(str(gas))
    pre += b"W" + net(str(len(worlds)))
    for w in sorted(worlds):
        pre += b"w" + net(w)
    pre += b"S" + net(str(len(slots)))
    for name in sorted(slots):
        values = sorted(slots[name])
        pre += b"s" + net(name) + net(str(len(values)))
        for value in values:
            pre += b"v" + net(value)
    return "t:sha256:" + hashlib.sha256(pre).hexdigest()


def execute(instructions, labels, point, gas):
    pc = 0
    effects = []
    steps = 0
    while True:
        if gas == 0:
            return {"status": "INCOMPLETE", "reason": "gas-exhausted", "effects": effects, "steps": steps}
        if pc < 0 or pc >= len(instructions):
            return {"status": "INCOMPLETE", "reason": "fell-off-program", "effects": effects, "steps": steps}
        gas -= 1
        steps += 1
        ins = instructions[pc]
        op = ins[0]
        if op == "LABEL":
            pc += 1
        elif op == "IF_EQ":
            _, slot, value, label = ins
            if slot not in point:
                return {"status": "INCOMPLETE", "reason": "undeclared-or-missing-input:" + slot, "effects": effects, "steps": steps}
            pc = labels[label] if point[slot] == value else pc + 1
        elif op == "GOTO":
            pc = labels[ins[1]]
        elif op == "EMIT_HEX":
            effects.append(consequence(ins[1]))
            pc += 1
        elif op == "HALT":
            if not effects:
                return {"status": "INCOMPLETE", "reason": "zero-effect-vacuity", "effects": effects, "steps": steps}
            return {"status": "COMPLETE", "reason": None, "effects": effects, "steps": steps}
        else:
            raise AssertionError(op)


def enumerate_points(worlds, slots, reverse=False):
    names = sorted(slots)
    value_sets = [sorted(slots[n]) for n in names]
    ws = sorted(worlds)
    if reverse:
        ws = list(reversed(ws))
        value_sets = [list(reversed(v)) for v in value_sets]
    combos = itertools.product(*value_sets) if names else [()]
    combos = list(combos)
    for w in ws:
        for combo in combos:
            point = {"@world": w}
            point.update(dict(zip(names, combo)))
            yield point


def close_capsule(raw: bytes, boundary, reverse=False):
    try:
        worlds, slots, gas = validate_boundary(boundary)
        instructions, labels = parse_program(raw)
        tid = target_id(raw, boundary)
    except CapsuleReject as exc:
        return {"status": "REJECTED", "reason": str(exc), "closure_candidate": False}

    relation = set()
    traces = []
    for point in enumerate_points(worlds, slots, reverse=reverse):
        run = execute(instructions, labels, point, gas)
        traces.append({"point": point, **run})
        if run["status"] != "COMPLETE":
            return {
                "status": "INCOMPLETE",
                "reason": run["reason"],
                "closure_candidate": False,
                "target_id": tid,
                "traces": traces,
            }
        w = point["@world"]
        relation.update((w, c) for c in run["effects"])

    if any(not any(w == rw for rw, _ in relation) for w in worlds):
        return {"status": "INCOMPLETE", "reason": "world-without-consequence", "closure_candidate": False, "target_id": tid, "traces": traces}
    return {
        "status": "ELIGIBLE_CLOSURE_CANDIDATE",
        "reason": None,
        "closure_candidate": True,
        "target_id": tid,
        "relation": sorted([list(x) for x in relation]),
        "traces": traces,
    }


def boundary(worlds=None, slots=None, gas=32):
    return {"worlds": worlds or [world("w0")], "slots": slots or {}, "gas": gas}


def rejected(program: bytes, b, reason_prefix=None):
    r = close_capsule(program, b)
    ok = r["status"] == "REJECTED"
    if reason_prefix is not None:
        ok = ok and str(r.get("reason", "")).startswith(reason_prefix)
    return ok, r


def incomplete(program: bytes, b, reason_prefix=None):
    r = close_capsule(program, b)
    ok = r["status"] == "INCOMPLETE" and not r["closure_candidate"]
    if reason_prefix is not None:
        ok = ok and str(r.get("reason", "")).startswith(reason_prefix)
    return ok, r


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", required=True)
    args = ap.parse_args()

    attacks = []
    for idx, op in enumerate(["CLOCK", "RNG", "FILE", "NET", "HOSTCALL", "SPAWN"], start=1):
        ok, r = rejected(f"{op} x\nEMIT_HEX 00\nHALT\n".encode(), boundary(), "ambient-capability-forbidden:")
        attacks.append({"id": f"C1-{idx:02d}", "pass": ok, "observed": r["status"], "reason": r.get("reason")})

    ok, r = rejected(b"MAGIC x\nEMIT_HEX 00\nHALT\n", boundary(), "unknown-opcode:")
    attacks.append({"id": "C1-07", "pass": ok, "observed": r["status"], "reason": r.get("reason")})

    ok, r = rejected(b"EMIT_HEX 00\x00\nHALT\n", boundary(), "program-ambiguous-bytes")
    attacks.append({"id": "C1-08", "pass": ok, "observed": r["status"], "reason": r.get("reason")})

    dup = b"LABEL x\nEMIT_HEX 00\nLABEL x\nHALT\n"
    ok, r = rejected(dup, boundary(), "duplicate-label")
    attacks.append({"id": "C1-09", "pass": ok, "observed": r["status"], "reason": r.get("reason")})

    loop = b"LABEL loop\nGOTO loop\n"
    ok, r = incomplete(loop, boundary(gas=5), "gas-exhausted")
    attacks.append({"id": "C1-10", "pass": ok, "observed": r["status"], "reason": r.get("reason")})

    ok, r = incomplete(b"HALT\n", boundary(), "zero-effect-vacuity")
    attacks.append({"id": "C1-11", "pass": ok, "observed": r["status"], "reason": r.get("reason")})

    missing = b"IF_EQ secret yes bad\nEMIT_HEX 00\nHALT\nLABEL bad\nEMIT_HEX ff\nHALT\n"
    ok, r = incomplete(missing, boundary(), "undeclared-or-missing-input:")
    attacks.append({"id": "C1-12", "pass": ok, "observed": r["status"], "reason": r.get("reason")})

    bad_b = {"worlds": [world("w0")], "slots": {"x": []}, "gas": 10}
    ok, r = rejected(b"EMIT_HEX 00\nHALT\n", bad_b, "slot-domain:")
    attacks.append({"id": "C1-13", "pass": ok, "observed": r["status"], "reason": r.get("reason")})

    w = world("w0")
    bad_b = {"worlds": [w, w], "slots": {}, "gas": 10}
    ok, r = rejected(b"EMIT_HEX 00\nHALT\n", bad_b, "world-domain")
    attacks.append({"id": "C1-14", "pass": ok, "observed": r["status"], "reason": r.get("reason")})

    p_a = b"EMIT_HEX 00\nHALT\n"
    p_b = b"EMIT_HEX 01\nHALT\n"
    b0 = boundary()
    ra = close_capsule(p_a, b0); rb = close_capsule(p_b, b0)
    ok = ra["closure_candidate"] and rb["closure_candidate"] and ra["target_id"] != rb["target_id"]
    attacks.append({"id": "C1-15", "pass": ok, "observed": "IDENTITY_CHANGED" if ok else "IDENTITY_COLLISION"})

    prog = b"EMIT_HEX 00\nHALT\n"
    full_b = boundary(slots={"mode": ["a", "b"]})
    shrunk_b = boundary(slots={"mode": ["a"]})
    rf = close_capsule(prog, full_b); rs = close_capsule(prog, shrunk_b)
    ok = rf["closure_candidate"] and rs["closure_candidate"] and rf["target_id"] != rs["target_id"]
    attacks.append({"id": "C1-16", "pass": ok, "observed": "IDENTITY_CHANGED" if ok else "IDENTITY_COLLISION"})

    rg1 = close_capsule(prog, boundary(gas=10)); rg2 = close_capsule(prog, boundary(gas=11))
    ok = rg1["closure_candidate"] and rg2["closure_candidate"] and rg1["target_id"] != rg2["target_id"]
    attacks.append({"id": "C1-17", "pass": ok, "observed": "IDENTITY_CHANGED" if ok else "IDENTITY_COLLISION"})

    multi = b"EMIT_HEX aa\nEMIT_HEX bb\nHALT\n"
    rm = close_capsule(multi, boundary())
    full_relation = rm.get("relation", [])
    first_only = full_relation[:1]
    ok = rm["closure_candidate"] and len(full_relation) == 2 and first_only != full_relation
    attacks.append({"id": "C1-18", "pass": ok, "observed": "PROJECTION_NONEXHAUSTIVE" if ok else "PROJECTION_NOT_DETECTED"})

    w0, w1 = world("w0"), world("w1")
    finite = b"IF_EQ mode bad bad\nEMIT_HEX 01\nHALT\nLABEL bad\nEMIT_HEX 02\nHALT\n"
    bf = {"worlds": [w0, w1], "slots": {"mode": ["safe", "bad"]}, "gas": 16}
    p1 = close_capsule(finite, bf)
    p1_ok = p1["closure_candidate"] and p1["status"] == "ELIGIBLE_CLOSURE_CANDIDATE" and len(p1["relation"]) == 4

    bf_reordered = {"worlds": [w1, w0], "slots": {"mode": ["bad", "safe"]}, "gas": 16}
    p2 = close_capsule(finite, bf_reordered, reverse=True)
    p2_ok = p2["closure_candidate"] and p2["target_id"] == p1["target_id"] and p2["relation"] == p1["relation"]

    native_payload = bytes.fromhex("deadbeefcafebabe0102030405060708")
    native_prog = ("EMIT_HEX " + native_payload.hex() + "\nHALT\n").encode()
    p3 = close_capsule(native_prog, boundary())
    expected_native = consequence(native_payload)
    p3_ok = p3["closure_candidate"] and any(row[1] == expected_native for row in p3["relation"])

    passed = sum(x["pass"] for x in attacks)
    controls = [
        {"id": "C1-P1", "pass": p1_ok, "target_id": p1.get("target_id"), "relation_pairs": len(p1.get("relation", []))},
        {"id": "C1-P2", "pass": p2_ok, "representation_invariant": p2_ok},
        {"id": "C1-P3", "pass": p3_ok, "target_native_consequence": expected_native},
    ]
    control_passed = sum(x["pass"] for x in controls)

    result = {
        "gate": "RISU_KERNEL_K1_CLOSURE_CAPSULE_C1_FALSIFICATION",
        "status": "PASS" if passed == 18 and control_passed == 3 else "FAIL",
        "frozen_base": "8dd0887bae68fbe7d2cd23ed28c0f979c9f922ce",
        "attack_vectors_total": 18,
        "attack_vectors_passed": passed,
        "positive_controls_total": 3,
        "positive_controls_passed": control_passed,
        "semantic_kernel_changed": False,
        "production_proof_kind_created": False,
        "preservation_authority_created": False,
        "attacks": attacks,
        "positive_controls": controls,
        "derived_architecture": {
            "execution_model": "tiny deterministic capability-free capsule",
            "identity_binds": ["exact program bytes", "exact W0 world set", "finite slot domains", "gas limit"],
            "ambient_capabilities": [],
            "incompleteness_rule": "parse error, missing input, gas exhaustion, fallthrough, or zero-effect halt => no closure authority",
            "consequence_universe": "open payload commitments",
            "next": "Only after this gate passes, define a versioned bounded-capsule closure artifact and independent checker pair; keep arbitrary native programs outside the positive lane."
        }
    }
    Path(args.output).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
