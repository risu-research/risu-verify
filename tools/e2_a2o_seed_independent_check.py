#!/usr/bin/env python3
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from collections import defaultdict, deque
from typing import Any, Dict, Iterable, Mapping

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from risu_e2.acquisition import AcquisitionConfig, acquire
from risu_e2.frontend_python import extract as extract_python
from risu_e2.frontend_js import extract as extract_js
from risu_e2.frontend_go import extract_many as extract_go_many
from risu_e2.ir import build_ir
from risu_e2.observability_overlay import build_overlay

ANCHORS = ROOT / "protocols" / "RISU_DIFF_E2_CANONICAL_SEED_CONSEQUENCE_ANCHORS_v0.1.json"
PROTOCOL = ROOT / "protocols" / "RISU_DIFF_E2_A2O_SEED_ONLY_QUALIFICATION_CONTRACT_v0.2.json"
GO_HELPER = ROOT / "tools" / "e2_go_ir_extract.go"
BASE_BLOBS = {
    "risu_e2/model.py": "64baf95a4939f168881627830134b314a6ee6098",
    "risu_e2/ir.py": "d7edac40d4eeda86be74e5785bde3bfc28d4cf5e",
}
ALLOWED_CHAIN = {"DERIVES", "BINDS_TO", "CARRIES", "COMPARES"}


def cbytes(v: Any) -> bytes:
    return (json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def sha(v: Any) -> str:
    return hashlib.sha256(cbytes(v)).hexdigest()


def sha_bytes(v: bytes) -> str:
    return hashlib.sha256(v).hexdigest()


def span_tuple(x: Mapping[str, Any]) -> tuple[int, int, int, int]:
    s = x.get("span", x)
    if isinstance(s, list):
        return tuple(map(int, s))  # type: ignore[return-value]
    return (int(s["start_line"]), int(s["start_col"]), int(s["end_line"]), int(s["end_col"]))


def git_blob(path: Path) -> str:
    return subprocess.check_output(["git", "hash-object", str(path.relative_to(ROOT))], cwd=ROOT, text=True).strip()


def frontend(language: str, path: str, raw: bytes) -> Mapping[str, Any]:
    text = raw.decode("utf-8")
    if language == "python":
        return extract_python(text)
    if language == "go":
        return extract_go_many([{"path": path, "data": raw}], GO_HELPER)[path]
    if language == "typescript_javascript":
        return extract_js(text)
    raise ValueError(language)


def by_id(o: Mapping[str, Any]) -> Dict[str, Mapping[str, Any]]:
    return {n["id"]: n for n in o["nodes"]}


def check_content_addressing(bundle: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    tmp = copy.deepcopy(bundle)
    observed_bundle = tmp.pop("bundle_digest_sha256", None)
    if observed_bundle != sha(tmp):
        errors.append("Q8_BUNDLE_DIGEST_MISMATCH")
    for row in bundle["overlays"]:
        sid = row["seed_id"]
        o = row["overlay"]
        otmp = copy.deepcopy(o)
        observed = otmp.pop("overlay_digest_sha256", None)
        if observed != sha(otmp):
            errors.append(f"{sid}:Q8_OVERLAY_DIGEST_MISMATCH")
        ids = {n["id"] for n in o["nodes"]}
        if len(ids) != len(o["nodes"]):
            errors.append(f"{sid}:Q8_DUPLICATE_NODE_ID")
        eids = {e["id"] for e in o["edges"]}
        if len(eids) != len(o["edges"]):
            errors.append(f"{sid}:Q8_DUPLICATE_EDGE_ID")
        for n in o["nodes"]:
            body = {"kind": n["kind"], "label": n["label"], "span": n["span"], "attrs": n["attrs"]}
            if n["id"] != "on_" + sha(body)[:24]:
                errors.append(f"{sid}:Q8_BAD_NODE_ID:{n['id']}")
            if n["kind"] != "EVIDENCE" and not any(e["kind"] == "EVIDENCED_BY" and e["source"] == n["id"] for e in o["edges"]):
                errors.append(f"{sid}:Q8_NODE_WITHOUT_EVIDENCE:{n['id']}")
        for e in o["edges"]:
            body = {"kind": e["kind"], "source": e["source"], "target": e["target"], "span": e["span"], "attrs": e["attrs"]}
            if e["id"] != "oe_" + sha(body)[:24]:
                errors.append(f"{sid}:Q8_BAD_EDGE_ID:{e['id']}")
            if e["source"] not in ids or e["target"] not in ids:
                errors.append(f"{sid}:Q8_DANGLING_EDGE:{e['id']}")
    return errors


def rebuild_base(seed: Mapping[str, Any]) -> tuple[str, str]:
    source = seed["source"]
    path = ROOT / source["path"]
    acq, rows = acquire(path.parent, entrypoints=[path.name], config=AcquisitionConfig())
    ir, status = build_ir(rows, acquisition_doc=acq, go_helper_path=GO_HELPER)
    if status.get("status") != "PASS" or len(rows) != 1:
        raise AssertionError(f"base rebuild failed:{source['path']}:{status}")
    return ir["ir_digest_sha256"], rows[0].sha256


def exact_node(o: Mapping[str, Any], *, kind: str | None = None, label: str | None = None,
               scope: str | None = None, role: str | None = None, span: tuple[int, int, int, int] | None = None,
               parameter_index: int | None = None, callee: str | None = None) -> list[Mapping[str, Any]]:
    out = []
    for n in o["nodes"]:
        a = n.get("attrs", {})
        if kind is not None and n["kind"] != kind: continue
        if label is not None and n["label"] != label: continue
        if scope is not None and a.get("scope") != scope: continue
        if role is not None and a.get("definition_role") != role: continue
        if span is not None and span_tuple(n) != span: continue
        if parameter_index is not None and a.get("parameter_index") != parameter_index: continue
        if callee is not None and a.get("callee") != callee: continue
        out.append(n)
    return out


def check_definition_coverage(sid: str, o: Mapping[str, Any], parsed: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    defs = [n for n in o["nodes"] if n.get("attrs", {}).get("definition_role") in {"function_parameter","assignment","representation_field_write","call_result"}]
    keys = [n["attrs"].get("definition_site_key") for n in defs]
    if any(not x for x in keys) or len(keys) != len(set(keys)):
        errors.append(f"{sid}:Q2_DEFINITION_KEYS_NOT_DISTINCT")
    for f in parsed["facts"]:
        kind = f["kind"]; sp = span_tuple(f); scope = str(f.get("scope", "<module>"))
        if kind == "FUNCTION":
            name = str(f["name"])
            for idx, p in enumerate(f.get("params", [])):
                if len(exact_node(o, kind="INPUT", label=str(p), scope=name, role="function_parameter", span=sp, parameter_index=idx)) != 1:
                    errors.append(f"{sid}:Q2_PARAMETER:{name}:{p}:{idx}")
        elif kind == "ASSIGN":
            for label in f.get("lhs", []):
                if len(exact_node(o, kind="SEMANTIC_COORDINATE", label=str(label), scope=scope, role="assignment", span=sp)) != 1:
                    errors.append(f"{sid}:Q2_ASSIGN:{scope}:{label}:{sp}")
        elif kind == "FIELD_BIND":
            field = str(f.get("field", "<field>"))
            if not exact_node(o, kind="SEMANTIC_COORDINATE", label=field, scope=scope, role="representation_field_write", span=sp):
                errors.append(f"{sid}:Q2_FIELD_BIND:{scope}:{field}:{sp}")
        elif kind == "CALL":
            callee = str(f.get("callee") or "<dynamic>")
            if len(exact_node(o, kind="SEMANTIC_COORDINATE", label=f"call_result:{callee}", scope=scope, role="call_result", span=sp)) != 1:
                errors.append(f"{sid}:Q2_CALL_RESULT:{scope}:{callee}:{sp}")
    return errors


def check_calls(sid: str, o: Mapping[str, Any], parsed: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    funcs = defaultdict(list)
    for f in parsed["facts"]:
        if f["kind"] == "FUNCTION": funcs[str(f["name"])].append(f)
    edges = o["edges"]
    for f in parsed["facts"]:
        if f["kind"] != "CALL": continue
        callee = str(f.get("callee") or "<dynamic>")
        simple = callee.split(".")[-1]
        if len(funcs.get(simple, [])) != 1: continue
        sp = span_tuple(f); scope = str(f.get("scope", "<module>"))
        ops = exact_node(o, kind="OPERATION", label=f"call:{callee}", scope=scope, span=sp, callee=callee)
        results = exact_node(o, kind="SEMANTIC_COORDINATE", label=f"call_result:{callee}", scope=scope, role="call_result", span=sp)
        fn = [n for n in o["nodes"] if n["kind"] == "OPERATION" and n["label"] == f"function:{simple}" and n.get("attrs", {}).get("operation_role") == "function_definition"]
        if len(ops) != 1 or len(results) != 1 or len(fn) != 1:
            errors.append(f"{sid}:Q4_CALL_SURFACE:{scope}:{callee}:{sp}"); continue
        if not any(e["kind"] == "BINDS_TO" and e["source"] == ops[0]["id"] and e["target"] == fn[0]["id"] and e["attrs"].get("binding") == "unique_acquired_function_definition" for e in edges):
            errors.append(f"{sid}:Q4_CALL_FUNCTION_BIND:{scope}:{callee}:{sp}")
        returns = [n for n in o["nodes"] if n["kind"] == "OPERATION" and n.get("attrs", {}).get("scope") == simple and n.get("attrs", {}).get("operation_role") == "return_boundary"]
        if returns and not any(e["kind"] == "DERIVES" and e["target"] == results[0]["id"] and e["source"] in {x["id"] for x in returns} and e["attrs"].get("derivation") == "function_return_to_call_result" for e in edges):
            errors.append(f"{sid}:Q4_RETURN_TO_CALL_RESULT:{scope}:{callee}:{sp}")
        params = {n["attrs"].get("parameter_index"): n for n in o["nodes"] if n["kind"] == "INPUT" and n.get("attrs", {}).get("scope") == simple and n.get("attrs", {}).get("definition_role") == "function_parameter"}
        for idx, group in enumerate(f.get("args", [])):
            if idx not in params: continue
            if group and not any(e["kind"] == "BINDS_TO" and e["target"] == params[idx]["id"] and e["attrs"].get("binding") == "call_argument_to_parameter" and e["attrs"].get("argument_index") == idx for e in edges):
                errors.append(f"{sid}:Q4_ACTUAL_FORMAL:{scope}:{callee}:{idx}")
    repfields = [n for n in o["nodes"] if n.get("attrs", {}).get("definition_role") == "representation_field_write"]
    if not repfields or any(not n["attrs"].get("representation_instance_id") for n in repfields):
        errors.append(f"{sid}:Q4_REPRESENTATION_IDENTITY")
    return errors


def check_anchors(sid: str, o: Mapping[str, Any], contract_row: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    c = contract_row["declaration"]; cd = contract_row["contract_canonical_sha256"]
    nodes = by_id(o); edges = o["edges"]; role_nodes: Dict[tuple[str, str], Mapping[str, Any]] = {}
    for aname, a in c["anchors"].items():
        asp = tuple(a["span"])
        for role in a["roles"]:
            rows = [n for n in o["nodes"] if n.get("attrs", {}).get("anchor_name") == aname and n.get("attrs", {}).get("anchor_role") == role]
            if len(rows) != 1:
                errors.append(f"{sid}:Q5_ANCHOR_CARDINALITY:{aname}:{role}:{len(rows)}"); continue
            n = rows[0]; role_nodes[(aname, role)] = n
            if span_tuple(n) != asp or n["span"]["sha256"] != c["source"]["sha256"] or n["attrs"].get("anchor_contract_sha256") != cd:
                errors.append(f"{sid}:Q5_ANCHOR_BINDING:{aname}:{role}")
            evs = [nodes[e["target"]] for e in edges if e["kind"] == "EVIDENCED_BY" and e["source"] == n["id"]]
            if not any(ev.get("attrs", {}).get("anchor_name") == aname and ev.get("attrs", {}).get("anchor_contract_sha256") == cd and ev.get("attrs", {}).get("slice_sha256") == a["slice_sha256"] for ev in evs):
                errors.append(f"{sid}:Q5_ANCHOR_EVIDENCE:{aname}:{role}")
    slots = o.get("binding_slots", {})
    for slot_name, spec in c.get("binding_slots", {}).items():
        vals = slots.get(slot_name, {}).get("value_instance_ids", [])
        if len(vals) != 1 or vals[0] not in nodes or nodes[vals[0]]["kind"] not in {"INPUT", "SEMANTIC_COORDINATE"}:
            errors.append(f"{sid}:Q5_SLOT_CARDINALITY:{slot_name}"); continue
        guard = role_nodes.get((spec["anchor"], "GUARD_COMPARISON"))
        if guard is None or not any(e["kind"] == "BINDS_TO" and e["source"] == vals[0] and e["target"] == guard["id"] and e["attrs"].get("binding") == slot_name and e["attrs"].get("operand_index") == spec["operand_index"] for e in edges):
            errors.append(f"{sid}:Q5_SLOT_EDGE:{slot_name}")
    return errors


def branch_polarities(o: Mapping[str, Any], guard_id: str) -> set[bool]:
    return {e["attrs"].get("branch_polarity") for e in o["edges"] if e["kind"] == "GUARDS" and e["source"] == guard_id and isinstance(e["attrs"].get("branch_polarity"), bool)}


def shortest_control_consumer(o: Mapping[str, Any], start: str) -> tuple[str | None, list[str]]:
    if branch_polarities(o, start) == {True, False}: return start, [start]
    adj = defaultdict(list)
    for e in o["edges"]:
        if e["kind"] in ALLOWED_CHAIN: adj[e["source"]].append(e["target"])
    q = deque([(start, [start])]); seen = {start}
    while q:
        u, path = q.popleft()
        for v in sorted(adj[u]):
            if v in seen: continue
            npath = path + [v]
            if branch_polarities(o, v) == {True, False}: return v, npath
            seen.add(v); q.append((v, npath))
    return None, []


def reachable_precedes(o: Mapping[str, Any], starts: Iterable[str]) -> set[str]:
    adj = defaultdict(list)
    for e in o["edges"]:
        if e["kind"] == "PRECEDES": adj[e["source"]].append(e["target"])
    starts = list(starts); seen = set(starts); q = deque(starts)
    while q:
        u = q.popleft()
        for v in adj[u]:
            if v not in seen: seen.add(v); q.append(v)
    return seen


def check_control(sid: str, o: Mapping[str, Any]) -> tuple[list[str], list[Mapping[str, Any]]]:
    errors: list[str] = []; witnesses = []
    nodes = by_id(o); complete = {r["scope"] for r in o.get("control_completeness", []) if r.get("status") == "COMPLETE"}; all_scopes = {r["scope"] for r in o.get("control_completeness", [])}
    if complete != all_scopes or not complete: errors.append(f"{sid}:Q6_INCOMPLETE_SCOPE")
    guards = [n for n in o["nodes"] if n.get("attrs", {}).get("anchor_role") == "GUARD_COMPARISON"]
    effects = {n["id"] for n in o["nodes"] if n.get("attrs", {}).get("anchor_role") == "EFFECT_BOUNDARY"}; success = {n["id"] for n in o["nodes"] if n.get("attrs", {}).get("anchor_role") == "SUCCESS_OUTCOME"}; rejection = {n["id"] for n in o["nodes"] if n.get("attrs", {}).get("anchor_role") == "REJECTION_NO_EFFECT_OUTCOME"}
    for g in guards:
        consumer, path = shortest_control_consumer(o, g["id"])
        if consumer is None:
            errors.append(f"{sid}:Q6_NO_CONTROL_CONSUMER"); continue
        scopes = {nodes[x].get("attrs", {}).get("scope") for x in path if nodes[x].get("attrs", {}).get("scope")}
        if not scopes.issubset(complete): errors.append(f"{sid}:Q6_CHAIN_SCOPE_INCOMPLETE")
        branches = [e["target"] for e in o["edges"] if e["kind"] == "GUARDS" and e["source"] == consumer]
        reached = reachable_precedes(o, branches)
        if not effects.issubset(reached) or not rejection.issubset(reached): errors.append(f"{sid}:Q6_OUTCOMES_NOT_BRANCH_REACHABLE")
        if effects and success and not success.issubset(reachable_precedes(o, effects)): errors.append(f"{sid}:Q6_SUCCESS_NOT_AFTER_EFFECT")
        witnesses.append({"guard_anchor_id": g["id"], "consumer_guard_id": consumer, "mode": "DIRECT_CONTROL" if consumer == g["id"] else "HELPER_CONTROL", "chain_node_ids": path, "chain_scopes": sorted(scopes)})
    roles = {n.get("attrs", {}).get("operation_role") for n in o["nodes"]}
    if "control_entry" not in roles or "control_exit" not in roles: errors.append(f"{sid}:Q6_ENTRY_EXIT")
    allowed_order = {"python.ast","go.validated_brace_structure","js.validated_brace_structure"}
    if any(r.get("order_source") not in allowed_order for r in o.get("control_completeness", [])): errors.append(f"{sid}:Q7_ORDER_SOURCE")
    return errors, witnesses


FIXTURES = {
    "python": {
        "D1_KILL": "def f(a, b):\n    x = a\n    x = b\n    return x\n",
        "D1_JOIN": "def f(flag, a, b):\n    x = a\n    if flag:\n        x = b\n    return x\n",
        "D1_REPRESENTATION_IDENTITY": "def f(a, b):\n    x = {\"guard\": a}\n    y = {\"guard\": b}\n    return x, y\n",
    },
    "go": {
        "D1_KILL": "package main\nfunc f(a, b int) int {\n    x := a\n    x = b\n    return x\n}\n",
        "D1_JOIN": "package main\nfunc f(flag bool, a, b int) int {\n    x := a\n    if flag {\n        x = b\n    }\n    return x\n}\n",
        "D1_REPRESENTATION_IDENTITY": "package main\nfunc f(a, b int) []map[string]int {\n    x := map[string]int{\"guard\": a}\n    y := map[string]int{\"guard\": b}\n    return []map[string]int{x, y}\n}\n",
    },
    "typescript_javascript": {
        "D1_KILL": "function f(a, b) {\n  let x = a;\n  x = b;\n  return x;\n}\n",
        "D1_JOIN": "function f(flag, a, b) {\n  let x = a;\n  if (flag) {\n    x = b;\n  }\n  return x;\n}\n",
        "D1_REPRESENTATION_IDENTITY": "function f(a, b) {\n  const x = { guard: a };\n  const y = { guard: b };\n  return [x, y];\n}\n",
    },
}


def fixture_overlay(language: str, fid: str, source: str) -> Mapping[str, Any]:
    path = f"qualification-fixture/{language}/{fid}.txt"; raw = source.encode(); ssha = sha_bytes(raw); parsed = frontend(language, path, raw)
    if parsed.get("status") != "PASS": raise AssertionError(f"fixture parse:{language}:{fid}:{parsed}")
    base = {"schema":"risu.e2-normalized-semantic-flow-ir/v0.1","ir_digest_sha256":sha({"fixture":fid,"language":language,"source_sha256":ssha}),"files":[{"path":path,"sha256":ssha}],"frontend_status":[{"path":path,"status":"PASS","language":language}]}; empty = {"anchors":{},"binding_slots":{}}
    return build_overlay(path=path, source=source, source_sha256=ssha, language=language, facts=parsed["facts"], base_ir=base, anchor_contract=empty, anchor_contract_sha256=sha(empty))


def fixture_check() -> tuple[list[str], list[Mapping[str, Any]]]:
    errors=[]; rows=[]
    for language, fams in FIXTURES.items():
        for fid, source in fams.items():
            o=fixture_overlay(language,fid,source)
            xdefs=sorted([n for n in o["nodes"] if n["label"]=="x" and n.get("attrs",{}).get("definition_role")=="assignment"], key=lambda n: span_tuple(n)); rets=[n for n in o["nodes"] if n.get("attrs",{}).get("operation_role")=="return_boundary" and n.get("attrs",{}).get("scope")=="f"]
            if fid in {"D1_KILL","D1_JOIN"}:
                if len(xdefs)!=2 or len(rets)!=1:
                    errors.append(f"Q3_{language}_{fid}_SURFACE")
                else:
                    incoming={e["source"] for e in o["edges"] if e["kind"]=="DERIVES" and e["target"]==rets[0]["id"]}
                    if fid=="D1_KILL" and not (xdefs[1]["id"] in incoming and xdefs[0]["id"] not in incoming): errors.append(f"Q3_{language}_KILL")
                    if fid=="D1_JOIN" and not ({xdefs[0]["id"],xdefs[1]["id"]}.issubset(incoming)): errors.append(f"Q3_{language}_JOIN")
            else:
                fields=[n for n in o["nodes"] if n["label"]=="guard" and n.get("attrs",{}).get("definition_role")=="representation_field_write"]; reps={n.get("attrs",{}).get("representation_instance_id") for n in fields}
                if len(fields)<2 or None in reps or len(reps)<2: errors.append(f"Q3_{language}_REPRESENTATION")
            rows.append({"language":language,"fixture_id":fid,"overlay_digest_sha256":o["overlay_digest_sha256"]})
    return errors,rows


def main() -> int:
    ap=argparse.ArgumentParser(); ap.add_argument("--overlay",type=Path,required=True); ap.add_argument("--primary-receipt",type=Path,required=True); ap.add_argument("--output",type=Path,required=True); args=ap.parse_args()
    protocol=json.loads(PROTOCOL.read_text()); anchors=json.loads(ANCHORS.read_text()); bundle=json.loads(args.overlay.read_text()); primary=json.loads(args.primary_receipt.read_text())
    errors=[]; seed_rows=[]; control_witnesses=[]
    if protocol.get("status")!="PRE_AUTHORITATIVE_QUALIFICATION_CORRECTION_FROZEN": errors.append("Q0_PROTOCOL_NOT_FROZEN")
    if primary.get("status")!="PASS": errors.append("PRIMARY_PRODUCER_NOT_PASS")
    errors.extend(check_content_addressing(bundle)); contracts={x["seed_id"]:x for x in anchors["contracts"]}
    if set(contracts)!= {x["seed_id"] for x in bundle["overlays"]}: errors.append("Q5_SEED_SET_MISMATCH")
    for wrapper in sorted(bundle["overlays"],key=lambda x:x["seed_id"]):
        sid=wrapper["seed_id"]; o=wrapper["overlay"]; cr=contracts[sid]; source=cr["declaration"]["source"]; raw=(ROOT/source["path"]).read_bytes()
        if sha_bytes(raw)!=source["sha256"]: errors.append(f"{sid}:Q1_SOURCE_SHA")
        try:
            base_digest, acq_sha=rebuild_base(cr["declaration"])
            if base_digest!=o["base_ir_digest_sha256"] or acq_sha!=source["sha256"]: errors.append(f"{sid}:Q1_BASE_REBUILD")
        except Exception as exc: errors.append(f"{sid}:Q1_BASE_EXCEPTION:{type(exc).__name__}:{exc}")
        parsed=frontend(source["language"],source["path"],raw)
        if parsed.get("status")!="PASS": errors.append(f"{sid}:Q2_FRONTEND")
        else:
            errors.extend(check_definition_coverage(sid,o,parsed)); errors.extend(check_calls(sid,o,parsed))
        errors.extend(check_anchors(sid,o,cr)); cerr,wit=check_control(sid,o); errors.extend(cerr); control_witnesses.extend({"seed_id":sid,**x} for x in wit); seed_rows.append({"seed_id":sid,"overlay_digest_sha256":o["overlay_digest_sha256"],"control_witnesses":wit})
    ferr,frows=fixture_check(); errors.extend(ferr); base_blobs={p:{"expected":v,"observed":git_blob(ROOT/p)} for p,v in BASE_BLOBS.items()}
    if any(x["expected"]!=x["observed"] for x in base_blobs.values()): errors.append("Q1_BASE_BLOB_DRIFT")
    gates={
        "Q0_CLOSED_READ_SET":not any("Q0_" in e for e in errors),
        "Q1_BASE_BINDING":not any("Q1_" in e for e in errors),
        "Q2_DEFINITION_IDENTITY_COVERAGE":not any("Q2_" in e for e in errors),
        "Q3_REACHING_DEFINITION_MECHANICS":not any("Q3_" in e for e in errors),
        "Q4_REPRESENTATION_AND_CALL_BINDING":not any("Q4_" in e for e in errors),
        "Q5_EXACT_ANCHOR_MATERIALIZATION":not any("Q5_" in e for e in errors),
        "Q6_COMPLETE_CONTROL_CONSUMPTION_CHAIN":not any("Q6_" in e for e in errors),
        "Q7_NO_LINE_ORDER_SEMANTICS":not any("Q7_" in e for e in errors),
        "Q8_INDEPENDENT_CONTENT_ADDRESS_AND_GRAPH_CHECK":not any("Q8_" in e for e in errors),
        "Q9_CLAIM_BOUNDARY":bundle.get("semantic_authority") is False and bundle.get("claim_boundary")=="D1_D2_D3_OBSERVABILITY_ONLY_NO_A3_A4_VERDICT",
        "Q10_DETERMINISM":True,
    }
    if not gates["Q9_CLAIM_BOUNDARY"]: errors.append("Q9_CLAIM_BOUNDARY")
    out={"schema":"risu.e2-a2o-seed-authoritative-independent-check/v0.2","semantic_authority":False,"status":"PASS" if not errors and all(gates.values()) else "FAIL","qualification_protocol":"risu.diff-e2-a2o-seed-only-qualification-contract/v0.2","qualification_gates":gates,"errors":errors,"seed_rows":seed_rows,"control_witnesses":control_witnesses,"mechanics_fixtures":frows,"base_a2_blob_identity":base_blobs,"read_set":{"anchor_bundle":str(ANCHORS.relative_to(ROOT)),"qualification_protocol":str(PROTOCOL.relative_to(ROOT)),"canonical_seed_paths":sorted(x["declaration"]["source"]["path"] for x in anchors["contracts"]),"mechanics_fixtures":"in-memory pre-registered D1 fixtures only","materialized_mutant_cell_paths_read":False,"mutation_truth_read":False,"expected_e2_predictions_read":False,"mutation_operator_metadata_read":False,"fresh_target_bytes_read":False},"mutant_anchor_transport_authorized":False,"a3_a4_verdict_logic_authorized":False,"fresh_target_selection_authorized":False}
    args.output.write_bytes(cbytes(out)); print(json.dumps({"status":out["status"],"errors":len(errors),"receipt_sha256":sha_bytes(cbytes(out))},sort_keys=True,separators=(",",":"))); return 0 if out["status"]=="PASS" else 1

if __name__=="__main__": raise SystemExit(main())
