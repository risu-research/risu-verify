#!/usr/bin/env python3
"""Post-anchor audit for frozen W7/W8 implementations.

This file intentionally does not implement MFST semantics. It constructs small
profiles from the frozen F0 baseline, runs the already-anchored W7 and W8
implementations independently, and compares authority-relevant outputs. It is
an audit layer only and creates no C3 authority.
"""
from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KERNEL = ROOT / "kernel"
CLAIM = ROOT / "fixtures" / "k1_mfst_c3_f0" / "claim.json"
BASE = ROOT / "fixtures" / "k1_mfst_c3_f0" / "baseline.json"
W8 = ROOT / "build" / "k1_checker_w8"

sys.path.insert(0, str(KERNEL))
spec = importlib.util.spec_from_file_location("w7_postanchor", KERNEL / "k1_checker_w7.py")
w7 = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(w7)

claim_raw = CLAIM.read_bytes()
base = json.loads(BASE.read_text(encoding="utf-8"))
passed = 0


def enc(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def run7(obj):
    return w7.check(claim_raw, enc(obj))


def run8(obj):
    with tempfile.NamedTemporaryFile() as f:
        f.write(enc(obj))
        f.flush()
        cp = subprocess.run(
            [str(W8), "--claim", str(CLAIM), "--profile", f.name],
            capture_output=True,
            text=True,
            check=True,
        )
    return json.loads(cp.stdout)


def ok(name, cond):
    global passed
    if not cond:
        raise AssertionError(name)
    passed += 1
    print("PASS", name)


FIELDS = [
    "c3_semantic_id",
    "graph_id",
    "trace_map_id",
    "projected_realize",
    "c2_program_sha256",
    "c2_derived_gas",
    "c2_artifact_id",
    "c2_target_id",
    "k1_subset_allowed",
]


def agree(name, obj):
    a = run7(obj)
    b = run8(obj)
    ok(name + ":accepted", a["proof_status"] == "ACCEPTED" and b["proof_status"] == "ACCEPTED")
    for field in FIELDS:
        ok(name + ":" + field, a[field] == b[field])
    ok(name + ":non-authoritative", not a["authority_created"] and not b["authority_created"])
    return a, b


# A. Frozen baseline must still agree after both independent anchors.
b7, b8 = agree("baseline", base)
ok("baseline:source-id", b7["c3_source_id"] == b8["c3_source_id"])

# B. Amendment 001 alias rule: APPLY_TABLE reads all arguments from the
# pre-operation state and writes dst only after lookup. phase p0 -> flip -> p1.
alias = copy.deepcopy(base)
alias["blocks"][0]["term"] = {
    "op": "IF_EQ",
    "source": {"kind": "state", "name": "phase"},
    "value": "p1",
    "if_true": "safe",
    "if_false": "alt",
}
a7, _ = agree("alias-preoperation", alias)
ok(
    "alias-preoperation:all-safe",
    a7["trace_payload_count"] == 4
    and all(pair[1] == "c:sha256:cc70494af8fcd9fdd5d8e55945e2a682e52e9cc837b77c8637da33874d912488" for pair in a7["projected_realize"]),
)

# C. Stronger sequential-state discriminator. Correct semantics is:
# SET_CONST phase=p1; then APPLY_TABLE reads *current pre-operation* p1 and
# writes flip(p1)=p0. A block-entry snapshot bug instead reads old p0 and
# incorrectly produces p1. Branching makes the difference observable.
seq = copy.deepcopy(base)
seq["blocks"][0]["ops"] = [
    {"op": "SET_CONST", "dst": "phase", "value": "p1"},
    {
        "op": "APPLY_TABLE",
        "dst": "phase",
        "table": "flip",
        "arguments": [{"kind": "state", "name": "phase"}],
    },
]
seq["blocks"][0]["term"] = {
    "op": "IF_EQ",
    "source": {"kind": "state", "name": "phase"},
    "value": "p0",
    "if_true": "safe",
    "if_false": "alt",
}
s7, _ = agree("sequential-preoperation", seq)
ok(
    "sequential-preoperation:detects-block-snapshot-bug",
    s7["trace_payload_count"] == 4
    and all(pair[1] == "c:sha256:cc70494af8fcd9fdd5d8e55945e2a682e52e9cc837b77c8637da33874d912488" for pair in s7["projected_realize"]),
)

# D. Amendment 001 call-site binding is semantic even when source domains are
# identical. Bind flip to a second p0/p1 state cell with a different value.
bind_a = copy.deepcopy(base)
bind_a["state"].append({"name": "other", "domain": ["p0", "p1"], "initial": {"kind": "const", "value": "p1"}})
bind_a["blocks"][0]["term"] = {
    "op": "IF_EQ",
    "source": {"kind": "state", "name": "phase"},
    "value": "p1",
    "if_true": "safe",
    "if_false": "alt",
}
bind_b = copy.deepcopy(bind_a)
bind_b["blocks"][0]["ops"][0]["arguments"] = [{"kind": "state", "name": "other"}]
ba7, _ = agree("binding-phase", bind_a)
bb7, _ = agree("binding-other", bind_b)
ok("binding:same-domain-changes-semantic-id", ba7["c3_semantic_id"] != bb7["c3_semantic_id"])
ok("binding:same-domain-changes-trace", ba7["trace_map_id"] != bb7["trace_map_id"])
ok("binding:same-domain-changes-c2", ba7["c2_program_sha256"] != bb7["c2_program_sha256"])

# E. State-progress loop: revisiting the same block label with a different full
# state must not be mistaken for a repeated configuration.
loop = copy.deepcopy(base)
loop["boundary"]["slots"] = {}
loop["tables"] = [{
    "name": "advance",
    "arguments": [{"name": "x", "domain": ["p0", "p1"]}],
    "result_domain": ["p0", "p1"],
    "rows": [
        {"when": ["p0"], "result": "p1"},
        {"when": ["p1"], "result": "p1"},
    ],
}]
loop["blocks"] = [
    {"label": "entry", "ops": [], "term": {"op": "GOTO", "target": "loop"}},
    {"label": "loop", "ops": [], "term": {
        "op": "IF_EQ", "source": {"kind": "state", "name": "phase"}, "value": "p0",
        "if_true": "advance", "if_false": "done"}},
    {"label": "advance", "ops": [{
        "op": "APPLY_TABLE", "dst": "phase", "table": "advance",
        "arguments": [{"kind": "state", "name": "phase"}]}],
     "term": {"op": "GOTO", "target": "loop"}},
    {"label": "done", "ops": [{"op": "EMIT_HEX", "payload": "01"}], "term": {"op": "HALT"}},
]
agree("full-state-cycle-key", loop)

# F. Trace refinement must be stricter than K1 set projection. Reordering the
# two alt effects leaves projected REALIZE unchanged but changes trace/C2 IDs.
reorder = copy.deepcopy(base)
reorder["blocks"][2]["ops"].reverse()
r7, _ = agree("effect-reorder", reorder)
ok("effect-reorder:k1-set-same", r7["projected_realize"] == b7["projected_realize"])
ok("effect-reorder:trace-different", r7["trace_map_id"] != b7["trace_map_id"])
ok("effect-reorder:c2-different", r7["c2_program_sha256"] != b7["c2_program_sha256"])

print("POSTANCHOR_W7_W8_AUDIT_PASS", passed)
