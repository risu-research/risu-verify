#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
from pathlib import Path
from typing import Any, Mapping

from risu_e2.acquisition import AcquisitionConfig, acquire
from risu_e2.frontend_python import extract as extract_python
from risu_e2.frontend_js import extract as extract_js
from risu_e2.frontend_go import extract_many as extract_go_many
from risu_e2.ir import build_ir
from risu_e2.model import canonical_bytes
from risu_e2.observability_overlay import build_overlay, validate_overlay
from risu_e2.path_observability import build_path_observability

SCHEMA = "risu.e2-a3-a4-candidate-observability-microqualification/v0.1"
CORPUS_SCHEMA = "risu.e2-a3-a4-candidate-observability-microfixture-corpus/v0.1"
PROTOCOL_SCHEMA = "risu.diff-e2-a3-a4-candidate-observability-qualification/v0.1"
FORBIDDEN_OUTPUT_TOKENS = (
    '"expected_truth"', '"expected_e2_primary"', '"operator_id"', '"operator_name"',
    '"operator_class"', 'M_PLUS', 'M_ZERO', 'M_QUESTION', 'transport_case_id',
)


def canon(value: Any) -> bytes:
    return canonical_bytes(value)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def span_tuple(fact: Mapping[str, Any]) -> tuple[int, int, int, int]:
    s = fact["span"]
    return (int(s["start_line"]), int(s["start_col"]), int(s["end_line"]), int(s["end_col"]))


def source_slice(source: str, span: tuple[int, int, int, int]) -> bytes:
    sl, sc, el, ec = span
    lines = source.splitlines(keepends=True)
    if sl == el:
        return lines[sl - 1].encode("utf-8")[sc:ec]
    out = lines[sl - 1].encode("utf-8")[sc:]
    for line in lines[sl:el - 1]:
        out += line.encode("utf-8")
    out += lines[el - 1].encode("utf-8")[:ec]
    return out


def frontend(language: str, path: str, data: bytes, go_helper: Path) -> dict[str, Any]:
    text = data.decode("utf-8")
    if language == "python":
        return extract_python(text)
    if language == "go":
        return extract_go_many([{"path": path, "data": data}], go_helper)[path]
    if language == "typescript_javascript":
        return extract_js(text)
    raise ValueError(language)


def locate_fact(facts: list[Mapping[str, Any]], source: str, locator: Mapping[str, Any]) -> Mapping[str, Any]:
    rows = []
    needle = str(locator["source_contains"])
    for fact in facts:
        if fact.get("kind") != locator["fact_kind"]:
            continue
        raw = source_slice(source, span_tuple(fact)).decode("utf-8")
        if needle in raw:
            rows.append(fact)
    rows.sort(key=lambda f: (span_tuple(f), repr(sorted(f.items()))))
    idx = int(locator.get("occurrence", 0))
    if idx >= len(rows):
        raise ValueError(f"anchor locator unresolved:{locator}:matches={len(rows)}")
    return rows[idx]


def make_contract(fixture: Mapping[str, Any], facts: list[Mapping[str, Any]], source: str, source_sha: str) -> tuple[dict[str, Any], str]:
    loc = fixture["anchor_locators"]
    guard = locate_fact(facts, source, loc["guard_comparison"])
    reject = locate_fact(facts, source, loc["rejection_no_effect"])
    effect = locate_fact(facts, source, loc["effect_applied"])

    def anchor(fact: Mapping[str, Any], roles: list[str]) -> dict[str, Any]:
        sp = span_tuple(fact)
        raw = source_slice(source, sp)
        return {
            "roles": roles,
            "slice_bytes": len(raw),
            "slice_sha256": sha(raw),
            "span": list(sp),
            "syntax_kind": str(fact["kind"]).lower(),
            "unique_in_source": True,
        }

    contract = {
        "schema": "risu.e2-consequence-anchor-contract/v0.1",
        "contract_id": "MICRO_" + str(fixture["fixture_id"]).replace("::", "_").replace("-", "_"),
        "seed_id": str(fixture["fixture_id"]),
        "source": {
            "git_blob_sha": "SYNTHETIC_MICROFIXTURE",
            "language": fixture["language"],
            "path": fixture["filename"],
            "sha256": source_sha,
        },
        "scope_authority": True,
        "verdict_authority": False,
        "resource_identity_required": False,
        "failure_outcome_required": False,
        "locator_convention": "L1_C0_END_EXCLUSIVE_UTF8_BYTE",
        "anchors": {
            "guard_comparison": anchor(guard, ["GUARD_COMPARISON"]),
            "rejection_no_effect": anchor(reject, ["REJECTION_NO_EFFECT_OUTCOME"]),
            "effect_applied": anchor(effect, ["EFFECT_BOUNDARY", "SUCCESS_OUTCOME"]),
        },
        "binding_slots": {
            "expected_coordinate": {"anchor": "guard_comparison", "operand_index": int(fixture["binding_slots"]["expected_coordinate"]["operand_index"])},
            "current_coordinate": {"anchor": "guard_comparison", "operand_index": int(fixture["binding_slots"]["current_coordinate"]["operand_index"])},
        },
        "transport": {"mutant_revision_authorized": False, "fresh_revision_authorized": False},
    }
    return contract, sha(canon(contract))


def make_signature(fixture: Mapping[str, Any]) -> dict[str, Any]:
    sig = {
        "schema": "risu.e2-a3-a4-microfixture-consequence-signature/v0.1",
        "semantic_authority": False,
        "fixture_id": fixture["fixture_id"],
        "effect_invocation_binding_surface": {
            "operation_role": fixture["effect_operation_role"],
            "resolution": "MICROFIXTURE_DECLARED_STRUCTURAL_SURFACE",
        },
    }
    sig["canonical_signature_digest_sha256"] = sha(canon(sig))
    return sig


def reverse_origins(overlay: Mapping[str, Any], node_id: str) -> set[str]:
    nodes = {n["id"]: n for n in overlay["nodes"]}
    incoming: dict[str, list[Mapping[str, Any]]] = {}
    for edge in overlay["edges"]:
        incoming.setdefault(edge["target"], []).append(edge)
    seen: set[str] = set()
    stack = [node_id]
    out: set[str] = set()
    while stack:
        cur = stack.pop()
        if cur in seen:
            continue
        seen.add(cur)
        node = nodes.get(cur, {})
        if node.get("attrs", {}).get("definition_site_key"):
            out.add(cur)
        for edge in incoming.get(cur, []):
            if edge["kind"] in {"DERIVES", "BINDS_TO"}:
                stack.append(edge["source"])
    return out


def assignment_nodes(overlay: Mapping[str, Any], label: str) -> list[Mapping[str, Any]]:
    rows = [
        n for n in overlay["nodes"]
        if n["label"] == label and n.get("attrs", {}).get("definition_role") == "assignment"
    ]
    rows.sort(key=lambda n: (n["span"]["start_line"], n["span"]["start_col"], n["id"]))
    return rows


def family_observation(fixture: Mapping[str, Any], overlay: Mapping[str, Any], pathdoc: Mapping[str, Any]) -> tuple[str, list[str]]:
    family = str(fixture["family_id"])
    diag: list[str] = []
    eg = pathdoc["effective_guard_observability"]
    effect_paths = list(pathdoc["entry_effect_paths"])
    rejection_paths = list(pathdoc["rejection_paths"])
    success_paths = list(pathdoc["success_paths"])
    states = {row["path_state_id"]: row for row in pathdoc["path_states"]}

    def complete_surface() -> bool:
        return (
            pathdoc["material_control_complete"] is True
            and pathdoc["path_dataflow_correlation"] == "COMPLETE"
            and pathdoc["effect_binding_surface"]["status"] == "UNIQUE"
            and bool(effect_paths) and bool(rejection_paths) and bool(success_paths)
        )

    if family == "CQ_DIRECT_STABLE":
        ok = complete_surface() and eg["form"] == "DIRECT_CONTROL"
        if ok:
            return "COMPLETE_EVIDENCE_SURFACE", diag
    elif family == "CQ_HELPER_IDENTITY":
        ok = complete_surface() and eg["form"] == "HELPER_CONTROL"
        if ok:
            return "COMPLETE_IDENTITY_HELPER_SURFACE", diag
    elif family == "CQ_HELPER_NEGATED":
        if eg["form"] == "UNPROVEN" and eg.get("reason") == "HELPER_PREDICATE_POLARITY_UNPROVEN":
            return "HELPER_PREDICATE_POLARITY_UNPROVEN", diag
    elif family == "CQ_STRAIGHT_LINE_KILL":
        xs = assignment_nodes(overlay, "x")
        if len(xs) == 2:
            old, new = xs
            effect_origin_sets = [set(r["active_origin_definition_ids"]) for r in pathdoc["terminal_reaching_facts"]]
            if effect_origin_sets and all(new["id"] in s and old["id"] not in s for s in effect_origin_sets):
                return "KILL_CORRELATION_PROVED", diag
            diag.append("kill correlation did not isolate second x definition")
        else:
            diag.append(f"expected two x assignment nodes, got {len(xs)}")
    elif family == "CQ_BRANCH_JOIN":
        xs = assignment_nodes(overlay, "x")
        if len(xs) == 2 and len(effect_paths) >= 2:
            reaching = [set(states[p["path_state_id"]]["reaching_definitions"].get("x", [])) for p in effect_paths]
            if reaching and all(len(s) == 1 for s in reaching) and set().union(*reaching) >= {xs[0]["id"], xs[1]["id"]}:
                return "DISTINCT_PATH_STATES_AT_JOIN", diag
        diag.append("branch join did not retain two singleton x path states")
    elif family == "CQ_FALSE_CROSS_PRODUCT_TRAP":
        xs = assignment_nodes(overlay, "x")
        if len(xs) == 2 and effect_paths:
            wrong = xs[1]["id"]
            effect_reaching = [set(states[p["path_state_id"]]["reaching_definitions"].get("x", [])) for p in effect_paths]
            if all(wrong not in s for s in effect_reaching):
                return "NO_FABRICATED_WRONGDEF_EFFECT_PATH", diag
        diag.append("wrong-branch x definition appeared on effect path")
    elif family == "CQ_WRONG_BINDING_COMPLETE_PATH":
        vals = overlay.get("binding_slots", {}).get("current_coordinate", {}).get("value_instance_ids", [])
        other_params = [n["id"] for n in overlay["nodes"] if n["label"] == "other" and n.get("attrs", {}).get("definition_role") == "function_parameter" and n.get("attrs", {}).get("scope") == "target"]
        if len(vals) == 1 and len(other_params) == 1 and other_params[0] in reverse_origins(overlay, vals[0]) and complete_surface():
            return "WRONG_BINDING_PATH_FACT_OBSERVABLE_NO_VERDICT", diag
        diag.append("declared current slot did not expose origin in other parameter")
    elif family == "CQ_EFFECT_SURFACE_UNIQUE":
        if pathdoc["effect_binding_surface"]["status"] == "UNIQUE":
            return "UNIQUE_EFFECT_SURFACE", diag
    elif family == "CQ_EFFECT_SURFACE_AMBIGUOUS":
        if pathdoc["effect_binding_surface"]["status"] == "AMBIGUOUS":
            return "EFFECT_SURFACE_INCOMPLETE", diag
    elif family == "CQ_CONTROL_INCOMPLETE_UNSUPPORTED":
        if pathdoc["material_control_complete"] is False:
            return "CONTROL_INCOMPLETE", diag
    elif family == "CQ_GUARD_BYPASS_PATH":
        gid = eg.get("guard_id")
        if gid and effect_paths and any(all(d.get("guard_id") != gid for d in p["guard_decisions"]) for p in effect_paths):
            return "BYPASS_PATH_FACT_OBSERVABLE_NO_VERDICT", diag
        diag.append("no effect path bypassing effective guard was observable")
    elif family == "CQ_EFFECT_BEFORE_GUARD_PATH":
        gid = eg.get("guard_id")
        if gid and effect_paths and any(all(d.get("guard_id") != gid for d in p["guard_decisions"]) for p in effect_paths):
            return "ORDER_PATH_FACT_OBSERVABLE_NO_VERDICT", diag
        diag.append("effect-before-guard path not isolated")
    elif family == "CQ_REJECTION_FALLBACK_PATH":
        for p in rejection_paths:
            events = p["events"]
            if "EFFECT_BOUNDARY" in events and events.index("EFFECT_BOUNDARY") < events.index("REJECTION_NO_EFFECT_OUTCOME"):
                return "REJECTION_EFFECT_PATH_FACT_OBSERVABLE_NO_VERDICT", diag
        diag.append("no rejection path with prior effect event")
    elif family == "CQ_OUTCOME_DISTINCT":
        rid = {p["path_state_id"] for p in rejection_paths}
        sid = {p["path_state_id"] for p in success_paths}
        if rid and sid and rid.isdisjoint(sid) and any("EFFECT_BOUNDARY" not in p["events"] for p in rejection_paths) and any("EFFECT_BOUNDARY" in p["events"] for p in success_paths):
            return "DISTINCT_OUTCOME_PATHS_OBSERVABLE", diag
        diag.append("rejection and success outcomes were not path-distinct")
    elif family == "CQ_REPRESENTATION_SURVIVAL":
        fields = [str(n.get("attrs", {}).get("field", "")).lower() for n in overlay["nodes"] if n.get("attrs", {}).get("definition_role") == "representation_field_write"]
        if "guard" in fields and pathdoc["effect_binding_surface"]["status"] == "UNIQUE":
            return "REPRESENTATION_SURVIVAL_OBSERVABLE", diag
        diag.append("guard representation field was not observable")
    elif family == "CQ_REPRESENTATION_OMISSION_UNQUALIFIED":
        if pathdoc["representation_closure_status"] == "REPRESENTATION_CLOSURE_UNPROVEN":
            return "REPRESENTATION_CLOSURE_UNPROVEN", diag
    else:
        diag.append("unknown family")

    return "MICROQUALIFICATION_EXPECTATION_NOT_MET", diag


def compact_path(pathdoc: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "effective_guard_observability": pathdoc["effective_guard_observability"],
        "material_control_complete": pathdoc["material_control_complete"],
        "control_scope_completeness": pathdoc["control_scope_completeness"],
        "path_dataflow_correlation": pathdoc["path_dataflow_correlation"],
        "effect_binding_surface": pathdoc["effect_binding_surface"],
        "representation_closure_status": pathdoc["representation_closure_status"],
        "path_state_ids": [r["path_state_id"] for r in pathdoc["path_states"]],
        "predecessor_edge_ids": [r["id"] for r in pathdoc["path_state_predecessor_edges"]],
        "effect_path_state_ids": [r["path_state_id"] for r in pathdoc["entry_effect_paths"]],
        "rejection_path_state_ids": [r["path_state_id"] for r in pathdoc["rejection_paths"]],
        "success_path_state_ids": [r["path_state_id"] for r in pathdoc["success_paths"]],
        "terminal_reaching_facts": pathdoc["terminal_reaching_facts"],
    }


def run_fixture(fixture: Mapping[str, Any], go_helper: Path) -> dict[str, Any]:
    source = str(fixture["source"])
    raw = source.encode("utf-8")
    source_sha = sha(raw)
    parsed = frontend(str(fixture["language"]), str(fixture["filename"]), raw, go_helper)
    if parsed.get("status") != "PASS":
        raise ValueError("frontend parse failure")
    contract, contract_sha = make_contract(fixture, parsed["facts"], source, source_sha)
    signature = make_signature(fixture)
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / str(fixture["filename"])
        p.write_bytes(raw)
        acq, acquired = acquire(Path(td), entrypoints=[p.name], config=AcquisitionConfig())
        base_ir, base_status = build_ir(acquired, acquisition_doc=acq, go_helper_path=go_helper)
    if base_status.get("status") != "PASS":
        raise ValueError(f"base IR status:{base_status.get('status')}")
    overlay = build_overlay(
        path=str(fixture["filename"]), source=source, source_sha256=source_sha,
        language=str(fixture["language"]), facts=parsed["facts"], base_ir=base_ir,
        anchor_contract=contract, anchor_contract_sha256=contract_sha,
    )
    validate_overlay(overlay)
    pathdoc = build_path_observability(
        path=str(fixture["filename"]), source=source, source_sha256=source_sha,
        language=str(fixture["language"]), facts=parsed["facts"], overlay=overlay,
        canonical_signature=signature,
    )
    observed, diagnostics = family_observation(fixture, overlay, pathdoc)
    passed = observed == fixture["expected_observation"]
    return {
        "fixture_id": fixture["fixture_id"],
        "family_id": fixture["family_id"],
        "language": fixture["language"],
        "source_sha256": source_sha,
        "expected_observation": fixture["expected_observation"],
        "observed_observation": observed,
        "passed": passed,
        "diagnostics": diagnostics,
        "base_ir_digest_sha256": base_ir["ir_digest_sha256"],
        "candidate_anchor_contract_sha256": contract_sha,
        "overlay_digest_sha256": overlay["overlay_digest_sha256"],
        "path_observability_digest_sha256": pathdoc["path_observability_digest_sha256"],
        "overlay_node_count": len(overlay["nodes"]),
        "overlay_edge_count": len(overlay["edges"]),
        "path_summary": compact_path(pathdoc),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--protocol", required=True)
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--go-helper", required=True)
    ap.add_argument("--output", required=True)
    args = ap.parse_args()

    protocol_raw = Path(args.protocol).read_bytes()
    protocol = json.loads(protocol_raw)
    corpus_raw = Path(args.corpus).read_bytes()
    corpus = json.loads(corpus_raw)
    if protocol.get("schema") != PROTOCOL_SCHEMA or protocol.get("status") != "PRE_IMPLEMENTATION_CANDIDATE_OBSERVABILITY_QUALIFICATION_FROZEN":
        raise SystemExit("candidate observability protocol not frozen")
    if corpus.get("schema") != CORPUS_SCHEMA or corpus.get("fixture_count") != 48 or corpus.get("family_count") != 16:
        raise SystemExit("microfixture corpus malformed")
    tmp = dict(corpus)
    expected_digest = tmp.pop("corpus_digest_sha256")
    if sha(canon(tmp)) != expected_digest:
        raise SystemExit("microfixture corpus digest mismatch")
    if corpus.get("claim_boundary", {}).get("candidate_58_bytes_included") is not False:
        raise SystemExit("58-byte firewall violation")

    frozen_families = {x["id"]: x["expected"] for x in protocol["preimplementation_end_to_end_microqualification"]["families"]}
    observed_families = {x["family_id"]: x["expected_observation"] for x in corpus["fixtures"]}
    if frozen_families != observed_families:
        raise SystemExit("corpus family expectations differ from frozen protocol")
    if len({x["fixture_id"] for x in corpus["fixtures"]}) != 48:
        raise SystemExit("duplicate microfixture id")
    by_family: dict[str, set[str]] = {}
    for fixture in corpus["fixtures"]:
        by_family.setdefault(fixture["family_id"], set()).add(fixture["language"])
    required_langs = {"python", "go", "typescript_javascript"}
    if set(by_family) != set(frozen_families) or any(v != required_langs for v in by_family.values()):
        raise SystemExit("microfixture family/language coverage mismatch")

    rows = [run_fixture(f, Path(args.go_helper)) for f in sorted(corpus["fixtures"], key=lambda x: x["fixture_id"])]
    failures = [r["fixture_id"] for r in rows if not r["passed"]]
    family_status = {}
    for family in sorted(frozen_families):
        fr = [r for r in rows if r["family_id"] == family]
        family_status[family] = {
            "expected": frozen_families[family],
            "languages": {r["language"]: r["observed_observation"] for r in fr},
            "pass": len(fr) == 3 and all(r["passed"] for r in fr),
        }

    out = {
        "schema": SCHEMA,
        "semantic_authority": False,
        "status": "PASS" if not failures else "FAIL",
        "fixture_count": 48,
        "family_count": 16,
        "protocol_sha256": sha(protocol_raw),
        "corpus_sha256": sha(corpus_raw),
        "corpus_internal_digest_sha256": corpus["corpus_digest_sha256"],
        "rows": rows,
        "family_status": family_status,
        "failed_fixture_ids": failures,
        "read_set_attestation": {
            "frozen_protocol": True,
            "frozen_microfixture_corpus": True,
            "frozen_frontends_ir_overlay": True,
            "path_observability_sidecar": True,
            "candidate_58_bytes": False,
            "sanitized_58_manifest": False,
            "raw_blind_58_transport": False,
            "mutation_truth": False,
            "operator_metadata": False,
            "expected_e2_predictions": False,
            "fresh_target_bytes": False,
        },
        "claim_boundary": {
            "actual_pipeline_microqualification_only": True,
            "a3_a4_semantic_verdicts_emitted": False,
            "mutant_58_observability_executed": False,
            "fresh_target_evaluation_executed": False,
        },
    }
    out["bundle_digest_sha256"] = sha(canon(out))
    raw = canon(out)
    text = raw.decode("utf-8")
    for token in FORBIDDEN_OUTPUT_TOKENS:
        if token in text:
            raise SystemExit("forbidden output token:" + token)
    Path(args.output).write_bytes(raw)
    print(json.dumps({"status": out["status"], "fixtures": 48, "failures": len(failures), "sha256": sha(raw)}, sort_keys=True, separators=(",", ":")))
    return 0 if out["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
