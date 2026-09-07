#!/usr/bin/env python3
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from risu_e2.frontend_python_v2 import extract as extract_python
from risu_e2.path_observability import build_path_observability as build_v1
from risu_e2.path_observability_v2 import build_path_observability as build_v2

SCHEMA = "risu.e2-helper-polarity-canonical-integration-regression/v0.1"
SEEDS = ("SYN-PY-01", "SYN-PY-02")


def cbytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def normalize_v1_v2_identity(doc: Mapping[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(dict(doc))
    out.pop("path_observability_digest_sha256", None)
    out.pop("path_observability_v1_digest_sha256", None)
    out["schema"] = "risu.e2-path-observability/v0.1"
    guard = out.get("effective_guard_observability", {})
    for key in (
        "polarity_certificate_status",
        "polarity_to_transported_guard",
        "polarity_certificate_sha256",
        "polarity_certificate_reason",
        "polarity_certificate_flip_count",
    ):
        guard.pop(key, None)
    return out


def decision_truths(rows: list[Mapping[str, Any]], guard_id: str) -> list[bool]:
    out: list[bool] = []
    for row in rows:
        for decision in row.get("guard_decisions", []):
            if decision.get("guard_id") == guard_id and type(decision.get("transported_guard_truth")) is bool:
                out.append(bool(decision["transported_guard_truth"]))
    return sorted(out)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--overlay-bundle", required=True)
    ap.add_argument("--signature-bundle", required=True)
    ap.add_argument("--seed-catalog", required=True)
    ap.add_argument("--source-root", required=True)
    ap.add_argument("--output", required=True)
    args = ap.parse_args()

    overlay_bundle = json.loads(Path(args.overlay_bundle).read_text())
    signature_bundle = json.loads(Path(args.signature_bundle).read_text())
    seed_catalog = json.loads(Path(args.seed_catalog).read_text())
    overlays = {row["seed_id"]: row["overlay"] for row in overlay_bundle["overlays"]}
    signatures = {row["seed_id"]: row for row in signature_bundle["signatures"]}
    catalog = {row["seed_id"]: row for row in seed_catalog["seeds"]}

    rows = []
    for seed_id in SEEDS:
        seed = catalog[seed_id]
        source_path = Path(args.source_root) / Path(seed["program_path"]).name
        raw = source_path.read_bytes()
        source = raw.decode("utf-8")
        if sha256(raw) != seed["program_sha256"]:
            raise SystemExit(f"SOURCE_SHA_MISMATCH:{seed_id}")
        front = extract_python(source)
        if front.get("status") != "PASS":
            raise SystemExit(f"FRONTEND_FAIL:{seed_id}")
        overlay = overlays[seed_id]
        signature = signatures[seed_id]
        v1 = build_v1(
            path=source_path.name,
            source=source,
            source_sha256=seed["program_sha256"],
            language="python",
            facts=front["facts"],
            overlay=overlay,
            canonical_signature=signature,
        )
        v2 = build_v2(
            path=source_path.name,
            source=source,
            source_sha256=seed["program_sha256"],
            language="python",
            facts=front["facts"],
            overlay=overlay,
            canonical_signature=signature,
        )
        g1 = v1["effective_guard_observability"]
        g2 = v2["effective_guard_observability"]
        row: dict[str, Any] = {
            "seed_id": seed_id,
            "frontend_status": front["status"],
            "v1_form": g1.get("form"),
            "v1_reason": g1.get("reason"),
            "v2_form": g2.get("form"),
            "v2_reason": g2.get("reason"),
            "polarity_certificate_status": g2.get("polarity_certificate_status"),
            "polarity_to_transported_guard": g2.get("polarity_to_transported_guard"),
            "polarity_certificate_flip_count": g2.get("polarity_certificate_flip_count"),
            "v1_digest": v1.get("path_observability_digest_sha256"),
            "v2_digest": v2.get("path_observability_digest_sha256"),
            "canonical_expected_form": signature["effective_guard_form"],
        }
        if seed_id == "SYN-PY-01":
            identity = normalize_v1_v2_identity(v1) == normalize_v1_v2_identity(v2)
            row["full_core_regression_identity"] = identity
            row["passed"] = (
                g1.get("form") == "DIRECT_CONTROL"
                and g2.get("form") == "DIRECT_CONTROL"
                and g2.get("polarity_certificate_status") == "NOT_APPLICABLE"
                and identity
            )
        else:
            guard_id = str(g2.get("guard_id") or "")
            rejection_truths = decision_truths(v2.get("rejection_paths", []), guard_id)
            effect_truths = decision_truths(v2.get("entry_effect_paths", []), guard_id)
            success_truths = decision_truths(v2.get("success_paths", []), guard_id)
            row["rejection_transported_guard_truths"] = rejection_truths
            row["effect_transported_guard_truths"] = effect_truths
            row["success_transported_guard_truths"] = success_truths
            row["passed"] = (
                g1.get("form") == "UNPROVEN"
                and g1.get("reason") == "HELPER_PREDICATE_POLARITY_UNPROVEN"
                and g2.get("form") == "HELPER_CONTROL"
                and g2.get("reason") is None
                and g2.get("polarity_certificate_status") == "PROVED"
                and g2.get("polarity_to_transported_guard") == "INVERTED"
                and g2.get("polarity_certificate_flip_count") == 1
                and rejection_truths == [False]
                and effect_truths == [True]
                and success_truths == [True]
            )
        rows.append(row)

    failed = [row["seed_id"] for row in rows if not row["passed"]]
    out = {
        "schema": SCHEMA,
        "status": "PASS" if not failed and len(rows) == 2 else "FAIL",
        "classification": "NON_PROSPECTIVE_PREEXISTING_CANONICAL_SEED_REGRESSION",
        "seed_count": len(rows),
        "failed_seed_ids": failed,
        "rows": rows,
        "firewall": {
            "frozen48_read": False,
            "candidate58_read": False,
            "epistemic10_read": False,
            "a3_a4_semantic_verdicts_executed": False,
        },
    }
    Path(args.output).write_bytes(cbytes(out))
    return 0 if out["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
