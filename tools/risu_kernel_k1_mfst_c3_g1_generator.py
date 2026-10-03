#!/usr/bin/env python3
"""Checker-independent C3 G1 profile generator.

This module knows only the frozen public MFST profile shape and literal finite
values committed by G1.  It intentionally imports no RISU checker, parser,
executor, canonicalizer, normalizer, replay, target, or certificate code.
"""
from __future__ import annotations

import copy
import itertools
import json
import random

WORLDS = [
    "w:sha256:" + "1" * 64,
    "w:sha256:" + "2" * 64,
]
CLAIM_ID = "claim:sha256:e4170f1652720fc49ac515418c905f1f374e6b1dbec0b711204f17e2eef3c016"
ALLOWED_PAYLOADS = ["01", "02", "03", "aa", "bb", "ff"]
FORBIDDEN_PAYLOAD = "de"
V2 = ["v0", "v1"]
V3 = ["v0", "v1", "v2"]
V4 = ["v0", "v1", "v2", "v3"]
DOMAIN_BANK = [V2, V3, V4]


def encode(obj, *, sort_keys=True):
    return json.dumps(obj, sort_keys=sort_keys, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _src(kind, name):
    return {"kind": kind, "name": name}


def _table(name, formal_sources, result_domain, offset=0):
    args = []
    domains = []
    for i, (_, _, dom) in enumerate(formal_sources):
        d = list(dom)
        args.append({"name": f"a{i}", "domain": d})
        domains.append(d)
    rows = []
    products = itertools.product(*domains) if domains else [()]
    for row_index, tup in enumerate(products):
        rows.append({"when": list(tup), "result": result_domain[(row_index + offset) % len(result_domain)]})
    return {
        "name": name,
        "arguments": args,
        "result_domain": list(result_domain),
        "rows": rows,
    }


def _effects(i, branch, *, force_multi=False, force_distinct=False):
    multi = force_multi or (i % 2 == 0)
    count = 1 if not multi else 2 + ((i + branch) % 3)
    start = (i * 3 + branch) % len(ALLOWED_PAYLOADS)
    out = [ALLOWED_PAYLOADS[(start + j) % len(ALLOWED_PAYLOADS)] for j in range(count)]
    if force_distinct and len(out) >= 2 and out[0] == out[1]:
        out[1] = ALLOWED_PAYLOADS[(start + 1) % len(ALLOWED_PAYLOADS)]
    if i % 4 == 0 and len(out) >= 2 and not force_distinct:
        out[1] = out[0]
    return [{"op": "EMIT_HEX", "payload": p} for p in out]


def _source_bank(slots, states):
    out = []
    for n, d in sorted(slots.items()):
        out.append(("input", n, list(d)))
    for s in states:
        out.append(("state", s["name"], list(s["domain"])))
    out.append(("input", "@world", list(WORLDS)))
    return out


def _ordinary_ops(i, slots, states, tables, table_calls):
    ops = []
    vstates = [s for s in states if set(s["domain"]).issubset(set(V4))]
    if vstates and i % 3 != 0:
        dst = vstates[0]
        ops.append({"op": "SET_CONST", "dst": dst["name"], "value": dst["domain"][(i + 1) % len(dst["domain"])]})
    if slots and vstates and i % 3 != 1:
        candidates = [(n, d) for n, d in sorted(slots.items()) if set(d).issubset(set(vstates[0]["domain"]))]
        if candidates:
            n, _ = candidates[i % len(candidates)]
            ops.append({"op": "SET_FROM", "dst": vstates[0]["name"], "source": _src("input", n)})
    if tables:
        name = tables[i % len(tables)]["name"]
        call = table_calls[name]
        ops.append({
            "op": "APPLY_TABLE",
            "dst": call["dst"],
            "table": name,
            "arguments": [copy.deepcopy(x) for x in call["arguments"]],
        })
    return ops


def _choose_branch_source(slots, states, i):
    if slots:
        n = sorted(slots)[i % len(slots)]
        d = slots[n]
        return _src("input", n), d[(i // 2) % len(d)]
    candidates = [s for s in states if s["name"] != "loop_state"]
    s = candidates[i % len(candidates)]
    return _src("state", s["name"]), s["domain"][(i // 2) % len(s["domain"])]


def make_structured(seed, i, *, force_meta=False):
    rng = random.Random((seed << 20) ^ i ^ 0xC3A55)
    slot_count = 1 + (i % 3) if force_meta else i % 4
    state_count = max(2, 1 + (i % 4)) if force_meta else 1 + (i % 4)
    table_count = max(1, 1 + (i % 3)) if force_meta else i % 4
    shape = 1 if force_meta else i % 5
    world_source = (i % 8 == 0)
    if world_source:
        state_count = max(state_count, 2)

    slots = {}
    for j in range(slot_count):
        size = 2 + ((i + j) % 3)
        slots[f"s{j}"] = list(DOMAIN_BANK[size - 2])

    states = []
    # q0 always supplies a broad finite destination for SET_FROM/table results.
    q0_init = {"kind": "const", "value": V4[i % 4]}
    if slots and i % 5 == 1:
        first = sorted(slots)[0]
        q0_init = {"kind": "input", "name": first}
    states.append({"name": "q0", "domain": list(V4), "initial": q0_init})
    next_q = 1
    if world_source and len(states) < state_count:
        states.append({"name": "world_state", "domain": list(WORLDS), "initial": {"kind": "input", "name": "@world"}})
    while len(states) < state_count:
        d = list(DOMAIN_BANK[(i + next_q) % len(DOMAIN_BANK)])
        init = {"kind": "const", "value": d[(i + next_q) % len(d)]}
        if slots and next_q % 2 == 0:
            compatible = [(n, sd) for n, sd in sorted(slots.items()) if set(sd).issubset(set(d))]
            if compatible:
                init = {"kind": "input", "name": compatible[0][0]}
        states.append({"name": f"q{next_q}", "domain": d, "initial": init})
        next_q += 1

    sources = _source_bank(slots, states)
    tables = []
    table_calls = {}
    for t in range(table_count):
        arity = 1 + ((i + t) % 3)
        # Draw from source descriptors, permitting repeated machine sources.  The
        # formal parameters remain distinct and position-sensitive.
        chosen = [sources[(rng.randrange(len(sources)) + k) % len(sources)] for k in range(arity)]
        dst = "q0"
        tab = _table(f"t{t}", chosen, V4, offset=(i + t) % 4)
        tables.append(tab)
        table_calls[tab["name"]] = {
            "dst": dst,
            "arguments": [_src(k, n) for k, n, _ in chosen],
        }

    entry_ops = _ordinary_ops(i, slots, states, tables, table_calls)
    src, val = _choose_branch_source(slots, states, i)
    blocks = []
    if shape == 0:
        blocks = [
            {"label": "entry", "ops": entry_ops, "term": {"op": "GOTO", "target": "done"}},
            {"label": "done", "ops": _effects(i, 0), "term": {"op": "HALT"}},
        ]
    elif shape == 1:
        blocks = [
            {"label": "entry", "ops": entry_ops, "term": {"op": "IF_EQ", "source": src, "value": val, "if_true": "left", "if_false": "right"}},
            {"label": "left", "ops": _effects(i, 0, force_multi=force_meta, force_distinct=force_meta), "term": {"op": "HALT"}},
            {"label": "right", "ops": _effects(i, 1, force_multi=force_meta, force_distinct=force_meta), "term": {"op": "HALT"}},
        ]
    elif shape == 2:
        src2, val2 = _choose_branch_source(slots, states, i + 1)
        blocks = [
            {"label": "entry", "ops": entry_ops, "term": {"op": "IF_EQ", "source": src, "value": val, "if_true": "mid", "if_false": "route"}},
            {"label": "mid", "ops": [], "term": {"op": "IF_EQ", "source": src2, "value": val2, "if_true": "a", "if_false": "b"}},
            {"label": "route", "ops": [], "term": {"op": "GOTO", "target": "c"}},
            {"label": "a", "ops": _effects(i, 0), "term": {"op": "HALT"}},
            {"label": "b", "ops": _effects(i, 1), "term": {"op": "HALT"}},
            {"label": "c", "ops": _effects(i, 2), "term": {"op": "HALT"}},
        ]
    elif shape == 3:
        # Revisit the same label with a changed complete state vector.  The
        # construction terminates without consulting checker execution.
        states.append({"name": "loop_state", "domain": ["l0", "l1"], "initial": {"kind": "const", "value": "l0"}})
        blocks = [
            {"label": "entry", "ops": entry_ops, "term": {"op": "GOTO", "target": "loop"}},
            {"label": "loop", "ops": [], "term": {"op": "IF_EQ", "source": _src("state", "loop_state"), "value": "l0", "if_true": "advance", "if_false": "done"}},
            {"label": "advance", "ops": [{"op": "SET_CONST", "dst": "loop_state", "value": "l1"}] + _effects(i, 0), "term": {"op": "GOTO", "target": "loop"}},
            {"label": "done", "ops": _effects(i, 1), "term": {"op": "HALT"}},
        ]
    else:
        blocks = [
            {"label": "entry", "ops": entry_ops, "term": {"op": "GOTO", "target": "done"}},
            {"label": "done", "ops": _effects(i, 0), "term": {"op": "HALT"}},
            {"label": "unreachable", "ops": [{"op": "SET_CONST", "dst": "q0", "value": "v0"}, {"op": "EMIT_HEX", "payload": "bb"}], "term": {"op": "HALT"}},
        ]

    p = {
        "wire": "risu.k1.c3.mfst/v1",
        "kind": "mediated_finite_state_transducer",
        "claim_id": CLAIM_ID,
        "boundary": {"worlds": list(WORLDS), "slots": slots},
        "state": states,
        "tables": tables,
        "entry": "entry",
        "blocks": blocks,
    }
    payloads = [op["payload"] for b in blocks for op in b["ops"] if op["op"] == "EMIT_HEX"]
    metadata = {
        "slot_count": slot_count,
        "max_slot_domain": max([len(x) for x in slots.values()] or [0]),
        "state_count": len(states),
        "table_count": table_count,
        "max_table_arity": max([len(x["arguments"]) for x in tables] or [0]),
        "uses_SET_CONST": any(op["op"] == "SET_CONST" for b in blocks for op in b["ops"]),
        "uses_SET_FROM": any(op["op"] == "SET_FROM" for b in blocks for op in b["ops"]),
        "uses_APPLY_TABLE": any(op["op"] == "APPLY_TABLE" for b in blocks for op in b["ops"]),
        "uses_IF_EQ": any(b["term"]["op"] == "IF_EQ" for b in blocks),
        "uses_GOTO": any(b["term"]["op"] == "GOTO" for b in blocks),
        "multi_effect": any(sum(op["op"] == "EMIT_HEX" for op in b["ops"]) >= 2 for b in blocks),
        "duplicate_effect": len(payloads) != len(set(payloads)) or any(
            len([op["payload"] for op in b["ops"] if op["op"] == "EMIT_HEX"]) != len(set(op["payload"] for op in b["ops"] if op["op"] == "EMIT_HEX"))
            for b in blocks
        ),
        "unreachable_block": shape == 4,
        "state_progress_loop": shape == 3,
        "world_source": world_source,
        "shape": shape,
    }
    return p, metadata


def make_meta_base(seed, i):
    # force_meta guarantees a table and reachable multi-effect branch.
    return make_structured(seed ^ 0x5A5A5A5A, i * 5 + 1, force_meta=True)


def _deep_reverse_declarations(p):
    q = copy.deepcopy(p)
    q["boundary"]["worlds"].reverse()
    for values in q["boundary"]["slots"].values():
        values.reverse()
    q["state"].reverse()
    q["tables"].reverse()
    for t in q["tables"]:
        t["rows"].reverse()
    q["blocks"].reverse()
    return q


def transform_meta(base, transform_index):
    q = copy.deepcopy(base)
    if transform_index == 0:
        q = _deep_reverse_declarations(q)
        raw = encode(q, sort_keys=False)
        return q, raw, "G1-META-KEY-DECL-PERMUTE"
    if transform_index == 1:
        if not q["tables"]:
            raise AssertionError("meta base lacks table")
        t = q["tables"][0]
        for j, a in enumerate(t["arguments"]):
            a["name"] = f"renamed{j}"
        return q, encode(q), "G1-META-FORMAL-RENAME"
    if transform_index == 2:
        labels = {b["label"] for b in q["blocks"]}
        label = "extra_unreachable"
        if label in labels:
            label = "extra_unreachable_2"
        q["blocks"].append({
            "label": label,
            "ops": [{"op": "SET_CONST", "dst": "q0", "value": "v0"}, {"op": "EMIT_HEX", "payload": "ff"}],
            "term": {"op": "HALT"},
        })
        return q, encode(q), "G1-META-UNREACHABLE-BLOCK"
    if transform_index == 3:
        # force_meta gives reachable left/right blocks with >=2 distinct effects.
        target = next(b for b in q["blocks"] if b["label"] in ("left", "right") and sum(op["op"] == "EMIT_HEX" for op in b["ops"]) >= 2)
        idx = [j for j, op in enumerate(target["ops"]) if op["op"] == "EMIT_HEX"]
        a, b = idx[0], idx[1]
        if target["ops"][a]["payload"] == target["ops"][b]["payload"]:
            target["ops"][b]["payload"] = ALLOWED_PAYLOADS[(ALLOWED_PAYLOADS.index(target["ops"][a]["payload"]) + 1) % len(ALLOWED_PAYLOADS)]
        target["ops"][a], target["ops"][b] = target["ops"][b], target["ops"][a]
        return q, encode(q), "G1-META-EFFECT-ORDER-MULTIPLICITY"
    raise ValueError(transform_index)


def make_stress(seed, i):
    rng = random.Random(seed ^ (i * 0x9E3779B1))
    slots = {"s0": list(V4), "s1": list(V3), "s2": list(V2)}
    states = [
        {"name": "q0", "domain": list(V4), "initial": {"kind": "const", "value": "v0"}},
        {"name": "q1", "domain": list(V4), "initial": {"kind": "input", "name": "s0"}},
        {"name": "q2", "domain": list(V3), "initial": {"kind": "input", "name": "s1"}},
        {"name": "q3", "domain": list(V2), "initial": {"kind": "input", "name": "s2"}},
    ]
    specs = [
        ("t0", [("input", "s0", V4), ("input", "s1", V3), ("input", "s2", V2)], "q0", V4),
        ("t1", [("state", "q0", V4), ("state", "q2", V3), ("state", "q3", V2)], "q1", V4),
        ("t2", [("input", "s0", V4), ("state", "q2", V3), ("state", "q3", V2)], "q0", V4),
    ]
    tables = [_table(n, srcs, rd, offset=(i + j) % len(rd)) for j, (n, srcs, _, rd) in enumerate(specs)]
    calls = {n: {"dst": dst, "arguments": [_src(k, sn) for k, sn, _ in srcs]} for n, srcs, dst, _ in specs}
    p0 = ALLOWED_PAYLOADS[(i + rng.randrange(6)) % 6]
    e1 = [ALLOWED_PAYLOADS[(i + j) % 6] for j in range(4)]
    e2 = [ALLOWED_PAYLOADS[(i + j + 2) % 6] for j in range(4)]
    blocks = [
        {"label": "entry", "ops": [
            {"op": "SET_FROM", "dst": "q0", "source": _src("input", "s0")},
            {"op": "APPLY_TABLE", "dst": calls["t0"]["dst"], "table": "t0", "arguments": calls["t0"]["arguments"]},
            {"op": "SET_CONST", "dst": "q2", "value": "v1"},
        ], "term": {"op": "IF_EQ", "source": _src("input", "s0"), "value": "v0", "if_true": "b1", "if_false": "b2"}},
        {"label": "b1", "ops": [{"op": "APPLY_TABLE", "dst": calls["t1"]["dst"], "table": "t1", "arguments": calls["t1"]["arguments"]}], "term": {"op": "GOTO", "target": "b3"}},
        {"label": "b2", "ops": [{"op": "SET_FROM", "dst": "q3", "source": _src("input", "s2")}], "term": {"op": "GOTO", "target": "b4"}},
        {"label": "b3", "ops": [{"op": "APPLY_TABLE", "dst": calls["t2"]["dst"], "table": "t2", "arguments": calls["t2"]["arguments"]}], "term": {"op": "IF_EQ", "source": _src("input", "s1"), "value": "v1", "if_true": "b5", "if_false": "b6"}},
        {"label": "b4", "ops": [], "term": {"op": "GOTO", "target": "b6"}},
        {"label": "b5", "ops": [{"op": "EMIT_HEX", "payload": p0}], "term": {"op": "GOTO", "target": "b7"}},
        {"label": "b6", "ops": [], "term": {"op": "GOTO", "target": "b8"}},
        {"label": "b7", "ops": [{"op": "EMIT_HEX", "payload": x} for x in e1], "term": {"op": "HALT"}},
        {"label": "b8", "ops": [{"op": "EMIT_HEX", "payload": x} for x in e2], "term": {"op": "HALT"}},
        {"label": "unreachable", "ops": [{"op": "SET_CONST", "dst": "q0", "value": "v2"}, {"op": "EMIT_HEX", "payload": "bb"}], "term": {"op": "HALT"}},
    ]
    p = {
        "wire": "risu.k1.c3.mfst/v1",
        "kind": "mediated_finite_state_transducer",
        "claim_id": CLAIM_ID,
        "boundary": {"worlds": list(WORLDS), "slots": slots},
        "state": states,
        "tables": tables,
        "entry": "entry",
        "blocks": blocks,
    }
    return p, {
        "boundary_points": 2 * 4 * 3 * 2,
        "state_count": 4,
        "table_count": 3,
        "max_table_arity": 3,
        "block_count": 10,
        "max_effects_one_trace": 5,
    }


def make_negative_base(seed, i):
    # A table-rich, slot-rich, multi-effect accepted source is the control for
    # every negative mutation.  The runner verifies the control first.
    return make_meta_base(seed ^ 0xBAD5EED, i + 10000)


def mutate_negative_profile(base, family):
    q = copy.deepcopy(base)
    if family == 0:
        q["tables"][0]["rows"].pop()
        return q, "missing_table_tuple"
    if family == 1:
        q["tables"][0]["rows"].append(copy.deepcopy(q["tables"][0]["rows"][0]))
        return q, "duplicate_table_tuple"
    if family == 2:
        row = copy.deepcopy(q["tables"][0]["rows"][0])
        if row["when"]:
            row["when"][0] = "outside_domain"
        else:
            row["when"] = ["outside_domain"]
        q["tables"][0]["rows"].append(row)
        return q, "out_of_domain_table_tuple"
    if family == 3:
        q["boundary"]["slots"]["bad_domain"] = ["z0", "z1"]
        op = next(op for b in q["blocks"] for op in b["ops"] if op["op"] == "APPLY_TABLE")
        op["arguments"][0] = _src("input", "bad_domain")
        return q, "apply_table_domain_mismatch"
    if family == 4:
        b = q["blocks"][0]
        b["term"] = {"op": "IF_EQ", "source": _src("input", "undeclared_input"), "value": "v0", "if_true": q["blocks"][1]["label"], "if_false": q["blocks"][2]["label"]}
        return q, "undeclared_input_source"
    if family == 5:
        q["blocks"] = [{"label": "entry", "ops": [], "term": {"op": "HALT"}}]
        q["entry"] = "entry"
        return q, "zero_effect_halt"
    if family == 6:
        q["blocks"] = [{"label": "entry", "ops": [{"op": "EMIT_HEX", "payload": "01"}], "term": {"op": "GOTO", "target": "entry"}}]
        q["entry"] = "entry"
        return q, "repeated_exact_configuration_after_effect"
    if family == 10:
        target = next(b for b in q["blocks"] if b["term"]["op"] == "HALT")
        target["ops"].append({"op": "EMIT_HEX", "payload": FORBIDDEN_PAYLOAD})
        return q, "forbidden_payload_injection"
    if family in (7, 8, 9, 11):
        return q, {7: "downstream_slot_shrink", 8: "downstream_gas_underbound", 9: "downstream_program_byte_stale_identity", 11: "producer_self_assertion_fields"}[family]
    raise ValueError(family)
