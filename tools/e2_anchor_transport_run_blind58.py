from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

from risu_e2.anchor_transport import transport_case, verify_receipt_digest

SCHEMA = "risu.e2-blind-58-anchor-transport-bundle/v0.1"
ADMISSION_SHA256 = "847d85c2274cd6b94a83eefe0f6153a8fb183dbad758efa75118a4fd368623e4"
ADMISSION_FREEZE_BLOB = "2c2ea8b9f6ca72c2262ffe6294287ee2e58fc00f"
CELLS_TREE = "34a30574c7420728bff57958c815194979a622ab"
ANCHOR_BUNDLE_BLOB = "ec8d8b287a80b87c815f0362be366be076d2b091"
TRANSPORT_PROTOCOL_BLOB = "7da7d3ac536d5edda56aa2c2636db1c8b02569b3"
IMPLEMENTATION_ARCHIVE_SHA256 = "7e08347694e82210bdcf53a8cec3f0684dcda5089020ad0d33e21b144fb88278"
ENGINE_SHA256 = "3b626fc83fe76a1dfafdcf896efc8a16440bbeec062cfb1dbb86badd23b7af4c"
INDEPENDENT_CHECKER_SHA256 = "a24d6350636098e6083629f31db142e8061525f0b0d6af3538bab9a2d96048c6"
CASE_FIELDS = {"transport_case_id", "seed_id", "language", "candidate_source_sha256"}
ANCHOR_KEYS = ("guard_comparison", "rejection_no_effect", "effect_applied")
SLOT_KEYS = ("expected_coordinate", "current_coordinate")
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
        raise SystemExit(f"non-canonical input: {path.name}")
    return obj, raw


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


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True)
    ap.add_argument("--admission", required=True)
    ap.add_argument("--anchor-bundle", required=True)
    ap.add_argument("--candidate-dir", required=True)
    ap.add_argument("--output", required=True)
    args = ap.parse_args()

    root = Path(args.root).resolve()
    admission, admission_raw = read_json(Path(args.admission), require_canonical=True)
    anchors, _ = read_json(Path(args.anchor_bundle), require_canonical=False)
    candidate_dir = Path(args.candidate_dir).resolve()

    if sha(admission_raw) != ADMISSION_SHA256:
        raise SystemExit("admission manifest sha256 mismatch")
    if admission.get("case_count") != 58 or len(admission.get("cases", [])) != 58:
        raise SystemExit("admission count mismatch")
    if admission.get("semantic_authority") is not False:
        raise SystemExit("admission semantic authority mismatch")
    if any(set(row) != CASE_FIELDS for row in admission["cases"]):
        raise SystemExit("admission case field allowlist mismatch")
    if len({row["transport_case_id"] for row in admission["cases"]}) != 58:
        raise SystemExit("duplicate admission transport_case_id")

    by_seed = {row["seed_id"]: row for row in anchors["contracts"]}
    if len(by_seed) != 6:
        raise SystemExit("anchor contract count mismatch")

    receipts: list[dict[str, Any]] = []
    for row in sorted(admission["cases"], key=lambda x: x["transport_case_id"]):
        seed_id = row["seed_id"]
        if seed_id not in by_seed:
            raise SystemExit("unknown seed_id in admission")
        entry = by_seed[seed_id]
        decl = entry["declaration"]
        if decl["source"]["language"] != row["language"]:
            raise SystemExit("admission language/contract mismatch")
        if sha(canon(decl)) != entry["contract_canonical_sha256"]:
            raise SystemExit("anchor contract canonical digest mismatch")

        baseline_path = root / decl["source"]["path"]
        baseline_bytes = baseline_path.read_bytes()
        if sha(baseline_bytes) != decl["source"]["sha256"]:
            raise SystemExit("baseline source digest mismatch")
        baseline_source = baseline_bytes.decode("utf-8")

        candidate_path = candidate_dir / (row["transport_case_id"] + suffix_for(row["language"]))
        candidate_bytes = candidate_path.read_bytes()
        if sha(candidate_bytes) != row["candidate_source_sha256"]:
            raise SystemExit("candidate source digest mismatch")
        candidate_source = candidate_bytes.decode("utf-8")

        receipt = transport_case(
            baseline_source,
            candidate_source,
            row["language"],
            seed_id,
            decl,
            entry["contract_canonical_sha256"],
        )
        if receipt["transport_case_id"] != row["transport_case_id"]:
            raise SystemExit("engine transport_case_id/admission mismatch")
        if receipt["candidate_source_sha256"] != row["candidate_source_sha256"]:
            raise SystemExit("engine candidate sha/admission mismatch")
        if receipt["anchor_contract_sha256"] != entry["contract_canonical_sha256"]:
            raise SystemExit("engine anchor contract mismatch")
        if not verify_receipt_digest(receipt):
            raise SystemExit("engine receipt digest verification failed")
        receipts.append(receipt)

    bundle = {
        "schema": SCHEMA,
        "semantic_authority": False,
        "case_count": 58,
        "admission_manifest_sha256": ADMISSION_SHA256,
        "admission_manifest_digest_sha256": admission["manifest_digest_sha256"],
        "authorities": {
            "admission_freeze_receipt_git_blob": ADMISSION_FREEZE_BLOB,
            "materialized_cells_tree_git_sha": CELLS_TREE,
            "canonical_anchor_bundle_git_blob": ANCHOR_BUNDLE_BLOB,
            "transport_protocol_git_blob": TRANSPORT_PROTOCOL_BLOB,
            "implementation_archive_sha256": IMPLEMENTATION_ARCHIVE_SHA256,
            "transport_engine_sha256": ENGINE_SHA256,
            "independent_checker_sha256": INDEPENDENT_CHECKER_SHA256,
        },
        "receipts": receipts,
        "aggregate_observations": aggregate(receipts),
        "forbidden_input_attestation": {
            "cell_json_read": False,
            "mutation_truth_read": False,
            "expected_e2_predictions_read": False,
            "mutation_operator_metadata_read": False,
            "fresh_target_bytes_read": False,
        },
        "claim_boundary": {
            "source_lineage_observation_only": True,
            "a3_a4_verdict_logic_executed": False,
            "truth_or_operator_unblinded": False,
            "fresh_target_evaluation_executed": False,
        },
    }
    bundle["bundle_digest_sha256"] = sha(canon(bundle))
    raw = canon(bundle)
    text = raw.decode("utf-8")
    for token in FORBIDDEN_OUTPUT_TOKENS:
        if token in text:
            raise SystemExit(f"forbidden output token: {token}")
    import re
    if re.search(r'"Q[0-9]{3}"', text):
        raise SystemExit("original cell identifier leaked")
    Path(args.output).write_bytes(raw)
    print(json.dumps({"status": "PASS", "case_count": 58, "bundle_sha256": sha(raw)}, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
