#!/usr/bin/env python3
"""R0 descriptor -> MFST compiler. Non-authoritative and checker-independent."""
from __future__ import annotations
import json

W0 = "w:sha256:" + "1" * 64
W1 = "w:sha256:" + "2" * 64
CLAIM_ID = "claim:sha256:e4170f1652720fc49ac515418c905f1f374e6b1dbec0b711204f17e2eef3c016"
BITS = ["v0", "v1"]
INITS = {"C0", "C1", "X"}
UPDATES = {"KEEP","CONST0","CONST1","COPY_X","NOT_Q_TABLE","ID_Q_TABLE","XOR_QX_TABLE","AND_QX_TABLE"}
PREDS = {"X_EQ0","X_EQ1","Q_EQ0","Q_EQ1","WORLD_EQ0","WORLD_EQ1"}
PREFIXES = {"NONE","E3"}
TRACE = {
    "A": ["01"], "B": ["02"], "AB": ["01","02"], "BA": ["02","01"],
    "AA": ["01","01"], "BB": ["02","02"], "ABA": ["01","02","01"], "BAB": ["02","01","02"],
}

def _source(kind, name):
    return {"kind": kind, "name": name}

def _table(name, rows, arity):
    args = [{"name": f"a{i}", "domain": list(BITS)} for i in range(arity)]
    return {
        "name": name,
        "arguments": args,
        "result_domain": list(BITS),
        "rows": [{"when": list(k), "result": v} for k, v in rows],
    }

def validate_descriptor(d):
    exact = {"descriptor_id","initial_q","update","predicate","prefix","true_trace","false_trace","point_traces"}
    if set(d) != exact:
        raise ValueError("descriptor keys")
    if d["initial_q"] not in INITS or d["update"] not in UPDATES or d["predicate"] not in PREDS or d["prefix"] not in PREFIXES:
        raise ValueError("descriptor axis")
    if d["true_trace"] not in TRACE or d["false_trace"] not in TRACE:
        raise ValueError("trace symbol")
    if not isinstance(d["descriptor_id"], str) or not d["descriptor_id"].startswith("R0-"):
        raise ValueError("descriptor id")

def compile_descriptor(d, mutation=None):
    validate_descriptor(d)

    init = d["initial_q"]
    if init == "C0":
        initial = {"kind":"const","value":"v0"}
    elif init == "C1":
        initial = {"kind":"const","value":"v1"}
    else:
        initial = {"kind":"input","name":"x"}

    tables = []
    ops = []
    u = d["update"]
    if u == "CONST0":
        ops.append({"op":"SET_CONST","dst":"q","value":"v0"})
    elif u == "CONST1":
        ops.append({"op":"SET_CONST","dst":"q","value":"v1"})
    elif u == "COPY_X":
        ops.append({"op":"SET_FROM","dst":"q","source":_source("input","x")})
    elif u == "NOT_Q_TABLE":
        rows = [(("v0",),"v1"),(("v1",),"v0")]
        tables.append(_table("not_q", rows, 1))
        ops.append({"op":"APPLY_TABLE","dst":"q","table":"not_q","arguments":[_source("state","q")]})
    elif u == "ID_Q_TABLE":
        rows = [(("v0",),"v0"),(("v1",),"v1")]
        tables.append(_table("id_q", rows, 1))
        ops.append({"op":"APPLY_TABLE","dst":"q","table":"id_q","arguments":[_source("state","q")]})
    elif u == "XOR_QX_TABLE":
        rows = [
            (("v0","v0"),"v0"),(("v0","v1"),"v1"),
            (("v1","v0"),"v1"),(("v1","v1"),"v0"),
        ]
        if mutation == "table_row":
            rows[-1] = (("v1","v1"),"v1")
        tables.append(_table("xor_qx", rows, 2))
        ops.append({"op":"APPLY_TABLE","dst":"q","table":"xor_qx","arguments":[_source("state","q"),_source("input","x")]})
    elif u == "AND_QX_TABLE":
        rows = [
            (("v0","v0"),"v0"),(("v0","v1"),"v0"),
            (("v1","v0"),"v0"),(("v1","v1"),"v1"),
        ]
        tables.append(_table("and_qx", rows, 2))
        ops.append({"op":"APPLY_TABLE","dst":"q","table":"and_qx","arguments":[_source("state","q"),_source("input","x")]})
    elif u != "KEEP":
        raise ValueError("update")

    if d["prefix"] == "E3" and mutation != "prefix_drop":
        ops.append({"op":"EMIT_HEX","payload":"03"})

    p = d["predicate"]
    if p.startswith("X_EQ"):
        source = _source("input","x")
        value = "v0" if p == "X_EQ0" else "v1"
        if mutation == "predicate_flip":
            value = "v1" if value == "v0" else "v0"
    elif p.startswith("Q_EQ"):
        source = _source("state","q")
        value = "v0" if p == "Q_EQ0" else "v1"
    elif p == "WORLD_EQ0":
        source = _source("input","@world")
        value = W0
    elif p == "WORLD_EQ1":
        source = _source("input","@world")
        value = W1
    else:
        raise ValueError("predicate")

    true_payloads = list(TRACE[d["true_trace"]])
    false_payloads = list(TRACE[d["false_trace"]])
    if mutation == "effect_order":
        if true_payloads != ["01","02"]:
            raise ValueError("effect_order control expects AB")
        true_payloads = ["02","01"]

    def emits(payloads):
        return [{"op":"EMIT_HEX","payload":x} for x in payloads]

    profile = {
        "wire": "risu.k1.c3.mfst/v1",
        "kind": "mediated_finite_state_transducer",
        "claim_id": CLAIM_ID,
        "boundary": {"worlds":[W0,W1], "slots":{"x":list(BITS)}},
        "state": [{"name":"q","domain":list(BITS),"initial":initial}],
        "tables": tables,
        "entry": "entry",
        "blocks": [
            {
                "label":"entry",
                "ops":ops,
                "term":{"op":"IF_EQ","source":source,"value":value,"if_true":"T","if_false":"F"},
            },
            {"label":"T","ops":emits(true_payloads),"term":{"op":"HALT"}},
            {"label":"F","ops":emits(false_payloads),"term":{"op":"HALT"}},
        ],
    }
    return profile

def compile_bytes(d, mutation=None):
    return json.dumps(compile_descriptor(d, mutation), sort_keys=True, separators=(",",":"), ensure_ascii=True).encode("utf-8")
