#!/usr/bin/env python3
from __future__ import annotations

"""Gate 2B.2: profile provenance of frozen Gate2B1 F-closure deficits.

This is a descriptive, standard-library-only diagnostic.  It does not import
or execute RISU semantic, kernel, adapter, or C1 code.  Scientific content
reads are restricted to the exact frozen Gate2B1 ledger/summary/freeze receipt
plus the frozen Gate2B2 protocol that defines the producer-site taxonomy.
"""

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any, Mapping

EXPECTED_LEDGER_SHA256 = "e487cfdcac7e6ed4d024086e989560bdf8054e4d5181c7a5929af1187801fa63"
EXPECTED_SUMMARY_SHA256 = "c41e17b964fbf3877c66842c44c22c6b9662a69647ac00a1752d8afbc27c822e"
EXPECTED_CASE_COUNT = 39
KERNEL_WRAPPER = "F_SCOPE_NOT_COMPLETE"
UNRESOLVED_PREFIX = "F_UNRESOLVED:"
FLAG_PREFIX = "F_FLAG_FALSE:"
CARDINALITY_WRAPPER = "FINITE_WORLD_TARGET_REALIZATION_INCOMPLETE"


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def sha256_path(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: Any) -> str:
    raw = canonical_bytes(value)
    path.write_bytes(raw)
    return sha256_bytes(raw)


def taxonomy(protocol: Mapping[str, Any]) -> tuple[list[str], dict[str, str], set[str]]:
    classes = protocol["producer_provenance_taxonomy"]["classes"]
    order: list[str] = []
    prefix_to_class: dict[str, str] = {}
    wrappers: set[str] = set()
    for row in classes:
        cid = str(row["id"])
        if cid in order:
            raise ValueError(f"duplicate provenance class: {cid}")
        order.append(cid)
        primitive = row.get("primitive") is True
        wrapper = row.get("wrapper") is True
        if primitive == wrapper:
            raise ValueError(f"class must be exactly primitive xor wrapper: {cid}")
        for prefix in row.get("atom_prefixes", []) or []:
            p = str(prefix)
            if not p or p in prefix_to_class:
                raise ValueError(f"duplicate/empty atom prefix: {p}")
            prefix_to_class[p] = cid
            if wrapper:
                wrappers.add(p)
    if wrappers != {CARDINALITY_WRAPPER}:
        raise ValueError(f"unexpected wrapper set: {sorted(wrappers)}")
    return order, prefix_to_class, wrappers


def atom_prefix(payload: str) -> str:
    return payload.split(":", 1)[0]


def classify_payload(payload: str, prefix_to_class: Mapping[str, str], wrappers: set[str]) -> tuple[str, bool]:
    prefix = atom_prefix(payload)
    if prefix not in prefix_to_class:
        raise ValueError(f"UNMAPPED_PRODUCER_ATOM:{prefix}")
    return str(prefix_to_class[prefix]), prefix in wrappers


def self_test(protocol: Mapping[str, Any]) -> None:
    order, p2c, wrappers = taxonomy(protocol)
    assert order[0] == "ADAPTER_ANCHOR_GUARD_REALIZATION"
    assert classify_payload("GUARD_SCOPE_UNRESOLVED", p2c, wrappers) == ("ADAPTER_ANCHOR_GUARD_REALIZATION", False)
    assert classify_payload("WORLD_ROLE_VALUE_MISSING:SYN-X:effect", p2c, wrappers) == ("WORLD_DECLARATION_ROLE_VALUE_REALIZATION", False)
    assert classify_payload(CARDINALITY_WRAPPER, p2c, wrappers) == ("WORLD_CARDINALITY_CLOSURE_WRAPPER", True)
    try:
        classify_payload("SYNTHETIC_UNKNOWN_ATOM", p2c, wrappers)
    except ValueError as exc:
        assert str(exc) == "UNMAPPED_PRODUCER_ATOM:SYNTHETIC_UNKNOWN_ATOM"
    else:
        raise AssertionError("unknown atom did not fail closed")


def stable_signature(items: list[str], *, none: str = "NONE") -> str:
    return "+".join(items) if items else none


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--protocol", required=True, type=Path)
    ap.add_argument("--gate2b1-ledger", required=True, type=Path)
    ap.add_argument("--gate2b1-summary", required=True, type=Path)
    ap.add_argument("--gate2b1-freeze-receipt", required=True, type=Path)
    ap.add_argument("--output-dir", type=Path)
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    protocol = load_json(args.protocol)
    if protocol.get("schema") != "risu.e2-candidate58-gate2b2-closure-deficit-provenance-profile-protocol/v0.1":
        raise ValueError("Gate2B2 protocol schema mismatch")
    self_test(protocol)
    if args.self_test:
        print("GATE2B2_ANALYZER_SELF_TEST=PASS")
        return 0
    if args.output_dir is None:
        raise ValueError("--output-dir required outside --self-test")

    # Exact immutable input identity checks happen before aggregation.
    if sha256_path(args.gate2b1_ledger) != EXPECTED_LEDGER_SHA256:
        raise ValueError("Gate2B1 ledger SHA256 mismatch")
    if sha256_path(args.gate2b1_summary) != EXPECTED_SUMMARY_SHA256:
        raise ValueError("Gate2B1 summary SHA256 mismatch")

    ledger = load_json(args.gate2b1_ledger)
    summary1 = load_json(args.gate2b1_summary)
    freeze1 = load_json(args.gate2b1_freeze_receipt)
    if freeze1.get("status") != "FIRST_COMPLETE_GATE2B1_DIAGNOSTIC_IMMUTABLY_FROZEN_BY_CONTAINING_COMMIT":
        raise ValueError("Gate2B1 freeze status mismatch")
    if freeze1.get("selected_case_count") != EXPECTED_CASE_COUNT:
        raise ValueError("Gate2B1 freeze population mismatch")
    if freeze1.get("admission_profile_ledger_sha256") != EXPECTED_LEDGER_SHA256:
        raise ValueError("Gate2B1 freeze ledger digest mismatch")
    if freeze1.get("admission_profile_summary_sha256") != EXPECTED_SUMMARY_SHA256:
        raise ValueError("Gate2B1 freeze summary digest mismatch")
    if summary1.get("selected_case_count") != EXPECTED_CASE_COUNT:
        raise ValueError("Gate2B1 summary population mismatch")
    if summary1.get("admission_failure_counts", {}).get("F") != EXPECTED_CASE_COUNT:
        raise ValueError("Gate2B1 summary F population mismatch")

    rows1 = ledger.get("rows", []) or []
    if len(rows1) != EXPECTED_CASE_COUNT:
        raise ValueError(f"Gate2B1 ledger population mismatch: {len(rows1)}")
    ids = [str(x.get("case_id", "")) for x in rows1]
    if len(set(ids)) != EXPECTED_CASE_COUNT or any(len(x) != 64 for x in ids):
        raise ValueError("Gate2B1 ledger case-id integrity failure")

    class_order, prefix_to_class, wrappers = taxonomy(protocol)
    primitive_classes = [x for x in class_order if x != "WORLD_CARDINALITY_CLOSURE_WRAPPER"]

    atom_prefix_counts: Counter[str] = Counter()
    full_atom_counts: Counter[str] = Counter()
    primitive_class_counts: Counter[str] = Counter()
    primitive_class_signature_counts: Counter[str] = Counter()
    primitive_atom_signature_counts: Counter[str] = Counter()
    primitive_atom_count_distribution: Counter[str] = Counter()
    wrapper_atom_counts: Counter[str] = Counter()
    flag_counts: Counter[str] = Counter()
    wrapper_by_primitive_signature: Counter[str] = Counter()
    admission_by_primitive_signature: Counter[str] = Counter()
    pairwise = {a: {b: 0 for b in primitive_classes} for a in primitive_classes}
    wrapper_without_primitive = 0
    primitive_without_cardinality_wrapper = 0
    out_rows: list[dict[str, Any]] = []

    for row in sorted(rows1, key=lambda x: str(x.get("case_id", ""))):
        cid = str(row["case_id"])
        if row.get("top_level_incomplete_branch") != "WORLD_INTERPRETATION_INCOMPLETE":
            raise ValueError(f"unexpected Gate2B1 branch:{cid}")
        failed = list(row.get("failed_admission_ids", []) or [])
        if "F" not in failed:
            raise ValueError(f"selected Gate2B1 row missing F failure:{cid}")
        freasons = list((row.get("admission_reasons", {}) or {}).get("F", []) or [])
        if KERNEL_WRAPPER not in freasons:
            raise ValueError(f"F kernel wrapper missing:{cid}")

        payloads: list[str] = []
        flags: list[str] = []
        for reason in freasons:
            reason = str(reason)
            if reason == KERNEL_WRAPPER:
                continue
            if reason.startswith(UNRESOLVED_PREFIX):
                payload = reason[len(UNRESOLVED_PREFIX):]
                if not payload:
                    raise ValueError(f"empty unresolved payload:{cid}")
                payloads.append(payload)
            elif reason.startswith(FLAG_PREFIX):
                flag = reason[len(FLAG_PREFIX):]
                if not flag:
                    raise ValueError(f"empty scope flag payload:{cid}")
                flags.append(flag)
            else:
                raise ValueError(f"unknown F reason surface:{cid}:{reason}")

        if not payloads and not flags:
            raise ValueError(f"F failure has no producer atom or scope-flag deficit:{cid}")

        prefixes: list[str] = []
        primitive_prefixes: list[str] = []
        wrapper_prefixes: list[str] = []
        primitive_class_set: set[str] = set()
        for payload in sorted(set(payloads)):
            prefix = atom_prefix(payload)
            pclass, is_wrapper = classify_payload(payload, prefix_to_class, wrappers)
            prefixes.append(prefix)
            atom_prefix_counts[prefix] += 1
            full_atom_counts[payload] += 1
            if is_wrapper:
                wrapper_prefixes.append(prefix)
                wrapper_atom_counts[prefix] += 1
            else:
                primitive_prefixes.append(prefix)
                primitive_class_set.add(pclass)

        primitive_classes_here = [c for c in primitive_classes if c in primitive_class_set]
        for c in primitive_classes_here:
            primitive_class_counts[c] += 1
        for a in primitive_classes_here:
            for b in primitive_classes_here:
                pairwise[a][b] += 1
        for flag in sorted(set(flags)):
            flag_counts[flag] += 1

        class_sig = stable_signature(primitive_classes_here)
        atom_sig = stable_signature(sorted(set(primitive_prefixes)))
        admission_sig = str(row.get("failed_admission_signature", ""))
        cardinality_present = CARDINALITY_WRAPPER in wrapper_prefixes
        primitive_class_signature_counts[class_sig] += 1
        primitive_atom_signature_counts[atom_sig] += 1
        primitive_atom_count_distribution[str(len(set(primitive_prefixes)))] += 1
        admission_by_primitive_signature[f"{admission_sig}|{class_sig}"] += 1
        wrapper_by_primitive_signature[f"{'WRAPPER' if cardinality_present else 'NO_WRAPPER'}|{class_sig}"] += 1
        if cardinality_present and not primitive_prefixes:
            wrapper_without_primitive += 1
        if primitive_prefixes and not cardinality_present:
            primitive_without_cardinality_wrapper += 1

        out_rows.append({
            "case_id": cid,
            "gate2b1_failed_admission_signature": admission_sig,
            "exact_F_admission_reasons": sorted(freasons),
            "F_unresolved_atom_instances": sorted(set(payloads)),
            "atom_prefixes": sorted(set(prefixes)),
            "primitive_atom_prefixes": sorted(set(primitive_prefixes)),
            "wrapper_atom_prefixes": sorted(set(wrapper_prefixes)),
            "primitive_provenance_classes": primitive_classes_here,
            "primitive_provenance_class_signature": class_sig,
            "primitive_atom_prefix_signature": atom_sig,
            "scope_flag_deficits": sorted(set(flags)),
            "primitive_atom_count": len(set(primitive_prefixes)),
            "wrapper_atom_count": len(set(wrapper_prefixes)),
            "finite_world_cardinality_wrapper_present": cardinality_present,
        })

    out = args.output_dir
    out.mkdir(parents=True, exist_ok=False)
    ledger2 = {
        "schema": "risu.e2-candidate58-gate2b2-closure-provenance-ledger/v0.1",
        "status": "GATE2B2_FROZEN_CLOSURE_PROVENANCE_PROFILE_NOT_ROOT_CAUSE",
        "case_count": EXPECTED_CASE_COUNT,
        "rows": out_rows,
    }
    summary2 = {
        "schema": "risu.e2-candidate58-gate2b2-closure-provenance-summary/v0.1",
        "status": "GATE2B2_DESCRIPTIVE_PRODUCER_SITE_PROFILE_NOT_ROOT_CAUSE",
        "case_count": EXPECTED_CASE_COUNT,
        "atom_prefix_counts": dict(sorted(atom_prefix_counts.items())),
        "full_atom_instance_counts": dict(sorted(full_atom_counts.items())),
        "primitive_provenance_class_counts": {k: primitive_class_counts.get(k, 0) for k in primitive_classes},
        "primitive_provenance_class_signature_counts": dict(sorted(primitive_class_signature_counts.items())),
        "primitive_atom_prefix_signature_counts": dict(sorted(primitive_atom_signature_counts.items())),
        "primitive_atom_count_distribution": dict(sorted(primitive_atom_count_distribution.items(), key=lambda kv: int(kv[0]))),
        "wrapper_atom_counts": dict(sorted(wrapper_atom_counts.items())),
        "scope_flag_deficit_counts": dict(sorted(flag_counts.items())),
        "primitive_provenance_class_pairwise_cooccurrence": pairwise,
        "gate2b1_admission_signature_by_primitive_provenance_signature": dict(sorted(admission_by_primitive_signature.items())),
        "finite_world_cardinality_wrapper_by_primitive_provenance_signature": dict(sorted(wrapper_by_primitive_signature.items())),
        "wrapper_without_primitive_count": wrapper_without_primitive,
        "primitive_without_cardinality_wrapper_count": primitive_without_cardinality_wrapper,
        "unmapped_producer_atom_count": 0,
        "interpretation_boundary": {
            "provenance_class_is_emission_site_not_semantic_cause": True,
            "cooccurrence_is_not_causality": True,
            "counterfactual_coverage_gain_inferred": False,
            "remediation_priority_authorized": False,
            "truth_operator_language_seed_strata_used": False,
        },
    }
    ledger_sha = write_json(out / "E2_CANDIDATE58_GATE2B2_CLOSURE_PROVENANCE_LEDGER.json", ledger2)
    summary_sha = write_json(out / "E2_CANDIDATE58_GATE2B2_CLOSURE_PROVENANCE_SUMMARY.json", summary2)
    receipt = {
        "schema": "risu.e2-candidate58-gate2b2-diagnostic-receipt/v0.1",
        "status": "FIRST_COMPLETE_GATE2B2_LOGICAL_OUTPUT",
        "inputs": {
            "gate2b1_ledger_sha256": EXPECTED_LEDGER_SHA256,
            "gate2b1_summary_sha256": EXPECTED_SUMMARY_SHA256,
            "gate2b1_freeze_receipt_sha256": sha256_path(args.gate2b1_freeze_receipt),
            "protocol_sha256": sha256_path(args.protocol),
        },
        "integrity": {
            "selected_case_count": EXPECTED_CASE_COUNT,
            "all_selected_failed_F": True,
            "all_selected_world_interpretation_incomplete": True,
            "zero_unmapped_producer_atoms": True,
            "producer_taxonomy_self_test_passed": True,
        },
        "outputs": {
            "closure_provenance_ledger_sha256": ledger_sha,
            "closure_provenance_summary_sha256": summary_sha,
        },
        "scientific_firewall": {
            "candidate_source_read": False,
            "semantic_slice_read": False,
            "kernel_result_or_machine_bundle_read": False,
            "adapter_receipt_read": False,
            "certificate_or_c1_read": False,
            "semantic_engine_kernel_adapter_or_c1_rerun": False,
            "gate2a_truth_join_input": False,
            "truth_or_operator_read": False,
            "fresh_heldout_read": False,
            "remediation": False,
            "semantic_rule_change": False,
        },
    }
    receipt_sha = write_json(out / "E2_CANDIDATE58_GATE2B2_DIAGNOSTIC_RECEIPT.json", receipt)
    print(json.dumps({
        "status": receipt["status"],
        "case_count": EXPECTED_CASE_COUNT,
        "ledger_sha256": ledger_sha,
        "summary_sha256": summary_sha,
        "receipt_sha256": receipt_sha,
    }, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
