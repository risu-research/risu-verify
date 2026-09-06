from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

SCHEMA = "risu.e2-blind-58-anchor-transport-independent-audit/v0.1"
BUNDLE_SCHEMA = "risu.e2-blind-58-anchor-transport-bundle/v0.1"
ADMISSION_SHA256 = "847d85c2274cd6b94a83eefe0f6153a8fb183dbad758efa75118a4fd368623e4"
ANCHOR_KEYS = ("guard_comparison", "rejection_no_effect", "effect_applied")
SLOT_KEYS = ("expected_coordinate", "current_coordinate")
PRESENT = {"TRANSPORT_PRESENT_EXACT", "TRANSPORT_PRESENT_EDIT_DESCENDANT"}
COMPLETE = PRESENT | {"TRANSPORT_ABSENT_BY_EDIT_LINEAGE"}
FORBIDDEN_OUTPUT_TOKENS = (
    '"expected_truth"', '"expected_e2_primary"', '"expected_e2_secondary"',
    '"operator_id"', '"operator_name"', '"operator_class"',
    'M_PLUS', 'M_ZERO', 'M_QUESTION', 'CELL.json', '/materialized/',
)


def canon(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_json(path: Path, require_canonical: bool = False) -> tuple[dict[str, Any], bytes]:
    raw = path.read_bytes()
    obj = json.loads(raw)
    if require_canonical and raw != canon(obj):
        raise ValueError(f"non-canonical json: {path.name}")
    return obj, raw


def load_checker(path: Path):
    spec = importlib.util.spec_from_file_location("frozen_transport_independent_checker", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load frozen independent checker")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def suffix_for(language: str) -> str:
    return {"python": ".py", "go": ".go", "typescript_javascript": ".mjs"}[language]


def aggregate(receipts: list[dict[str, Any]]) -> dict[str, Any]:
    parser = Counter()
    case = Counter()
    lineage = {k: Counter() for k in ANCHOR_KEYS}
    realization = {k: Counter() for k in ANCHOR_KEYS}
    slots = {k: Counter() for k in SLOT_KEYS}
    for receipt in receipts:
        parser[receipt["parser_status"]] += 1
        case[receipt["case_transport_status"]] += 1
        amap = {a["anchor_key"]: a for a in receipt["anchors"]}
        for key in ANCHOR_KEYS:
            lineage[key][amap[key]["lineage_status"]] += 1
            realization[key][amap[key]["realization_status"]] += 1
        for key in SLOT_KEYS:
            slots[key][receipt["binding_slots"][key]["status"]] += 1
    conv = lambda c: {k: c[k] for k in sorted(c)}
    return {
        "parser_status_counts": conv(parser),
        "case_transport_status_counts": conv(case),
        "anchor_lineage_status_counts": {k: conv(lineage[k]) for k in ANCHOR_KEYS},
        "anchor_realization_status_counts": {k: conv(realization[k]) for k in ANCHOR_KEYS},
        "binding_slot_status_counts": {k: conv(slots[k]) for k in SLOT_KEYS},
    }


def structural_invariants(receipt: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if receipt.get("semantic_authority") is not False:
        errors.append("semantic_authority")
    if receipt.get("implementation_claim_boundary") != "ANCHOR_SOURCE_LINEAGE_ONLY_NO_A3_A4_VERDICT":
        errors.append("claim_boundary")
    anchors = receipt.get("anchors", [])
    amap = {a.get("anchor_key"): a for a in anchors if isinstance(a, dict)}
    if set(amap) != set(ANCHOR_KEYS) or len(anchors) != 3:
        errors.append("anchor_key_set")
        return errors
    witness_ids = {"W1_EXACT_CODE_SLICE", "W2_LEXICAL_EDIT_ENVELOPE", "W3_ALPHA_EDIT_ENVELOPE", "W4_STRUCTURAL_SUBTREE", "W5_STRUCTURAL_HOLE_CONTEXT"}
    for key in ANCHOR_KEYS:
        ws = amap[key].get("witness_records", [])
        if {w.get("witness_id") for w in ws if isinstance(w, dict)} != witness_ids or len(ws) != 5:
            errors.append("witness_key_set:" + key)
    present_spans = [tuple(a["candidate_span"]) for a in anchors if a.get("lineage_status") in PRESENT and a.get("candidate_span") is not None]
    expected_complete = (
        receipt.get("parser_status") == "PARSE_OK"
        and len(present_spans) == len(set(present_spans))
        and all(a.get("lineage_status") in COMPLETE for a in anchors)
    )
    if (receipt.get("case_transport_status") == "COMPLETE") != expected_complete:
        errors.append("case_complete_consistency")
    if set(receipt.get("binding_slots", {})) != set(SLOT_KEYS):
        errors.append("binding_slot_key_set")
    att = receipt.get("forbidden_input_attestation", {})
    if any(att.get(k) is not False for k in (
        "mutation_truth_read", "expected_e2_predictions_read", "mutation_operator_metadata_read",
        "fresh_target_bytes_read", "comments_or_docstrings_semantic", "target_or_repository_name_semantic",
    )):
        errors.append("forbidden_input_attestation")
    return errors


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True)
    ap.add_argument("--admission", required=True)
    ap.add_argument("--anchor-bundle", required=True)
    ap.add_argument("--candidate-dir", required=True)
    ap.add_argument("--bundle", required=True)
    ap.add_argument("--frozen-checker", required=True)
    ap.add_argument("--output", required=True)
    args = ap.parse_args()

    errors: list[str] = []
    try:
        root = Path(args.root).resolve()
        admission, admission_raw = read_json(Path(args.admission), require_canonical=True)
        anchors, _ = read_json(Path(args.anchor_bundle), require_canonical=False)
        bundle, bundle_raw = read_json(Path(args.bundle), require_canonical=True)
        checker = load_checker(Path(args.frozen_checker))
        candidate_dir = Path(args.candidate_dir).resolve()

        if sha(admission_raw) != ADMISSION_SHA256:
            errors.append("admission_sha256")
        if bundle.get("schema") != BUNDLE_SCHEMA:
            errors.append("bundle_schema")
        if bundle.get("semantic_authority") is not False:
            errors.append("bundle_semantic_authority")
        if bundle.get("case_count") != 58 or len(bundle.get("receipts", [])) != 58:
            errors.append("bundle_case_count")
        d = dict(bundle)
        got = d.pop("bundle_digest_sha256", None)
        if got != sha(canon(d)):
            errors.append("bundle_digest")
        if bundle.get("admission_manifest_sha256") != ADMISSION_SHA256:
            errors.append("bundle_admission_binding")

        admission_by_id = {x["transport_case_id"]: x for x in admission["cases"]}
        if len(admission_by_id) != 58:
            errors.append("admission_unique_ids")
        receipts = bundle.get("receipts", [])
        receipt_by_id = {x.get("transport_case_id"): x for x in receipts if isinstance(x, dict)}
        if len(receipt_by_id) != 58 or set(receipt_by_id) != set(admission_by_id):
            errors.append("receipt_exact_admission_set")

        anchor_by_seed = {x["seed_id"]: x for x in anchors["contracts"]}
        for case_id in sorted(set(receipt_by_id) & set(admission_by_id)):
            row = admission_by_id[case_id]
            receipt = receipt_by_id[case_id]
            entry = anchor_by_seed.get(row["seed_id"])
            if entry is None:
                errors.append("unknown_seed:" + case_id)
                continue
            decl = entry["declaration"]
            if decl["source"]["language"] != row["language"]:
                errors.append("language_contract:" + case_id)
                continue
            baseline_bytes = (root / decl["source"]["path"]).read_bytes()
            candidate_path = candidate_dir / (case_id + suffix_for(row["language"]))
            candidate_bytes = candidate_path.read_bytes()
            if sha(baseline_bytes) != decl["source"]["sha256"]:
                errors.append("baseline_digest:" + case_id)
                continue
            if sha(candidate_bytes) != row["candidate_source_sha256"]:
                errors.append("candidate_digest:" + case_id)
                continue
            if receipt.get("seed_id") != row["seed_id"]:
                errors.append("seed_binding:" + case_id)
            if receipt.get("candidate_source_sha256") != row["candidate_source_sha256"]:
                errors.append("candidate_binding:" + case_id)
            if receipt.get("anchor_contract_sha256") != entry["contract_canonical_sha256"]:
                errors.append("anchor_contract_binding:" + case_id)
            if sha(canon(decl)) != entry["contract_canonical_sha256"]:
                errors.append("anchor_contract_digest:" + case_id)
            try:
                checker.verify_transport_receipt(receipt, baseline_bytes.decode("utf-8"), candidate_bytes.decode("utf-8"))
            except Exception:
                errors.append("frozen_checker_reject:" + case_id)
            for err in structural_invariants(receipt):
                errors.append(err + ":" + case_id)

        if aggregate(receipts) != bundle.get("aggregate_observations"):
            errors.append("aggregate_observation_mismatch")

        text = bundle_raw.decode("utf-8")
        for token in FORBIDDEN_OUTPUT_TOKENS:
            if token in text:
                errors.append("forbidden_output_token:" + token)
        if re.search(r'"Q[0-9]{3}"', text):
            errors.append("original_cell_identifier_leak")
    except Exception as exc:
        errors.append("auditor_exception:" + type(exc).__name__)
        bundle_raw = b""

    result = {
        "schema": SCHEMA,
        "status": "PASS" if not errors else "FAIL",
        "case_count": 58,
        "errors": sorted(set(errors)),
        "bundle_sha256": sha(bundle_raw),
        "frozen_checker_receipt_integrity_applied_to_all_cases": not errors,
        "lineage_reimplementation_claimed": False,
        "aggregate_recomputed_independently": not errors,
        "truth_or_operator_metadata_read": False,
        "a3_a4_verdict_logic_executed": False,
    }
    result["receipt_digest_sha256"] = sha(canon(result))
    Path(args.output).write_bytes(canon(result))
    print(json.dumps({"status": result["status"], "error_count": len(result["errors"]), "bundle_sha256": result["bundle_sha256"]}, sort_keys=True, separators=(",", ":")))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
