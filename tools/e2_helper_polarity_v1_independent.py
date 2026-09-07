#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path
from typing import Any

from risu_e2.predicate_polarity_v1 import prove_python_helper_polarity

SCHEMA = "risu.e2-helper-polarity-independent-qualification/v0.1"
PAIR_ORACLE = {
    "HP01": ("PROVED", "SAME", "HELPER_CONTROL"),
    "HP02": ("PROVED", "INVERTED", "HELPER_CONTROL"),
    "HP03": ("PROVED", "INVERTED", "HELPER_CONTROL"),
    "HP04": ("PROVED", "SAME", "HELPER_CONTROL"),
    "HP05": ("PROVED", "SAME", "HELPER_CONTROL"),
    "HP06": ("PROVED", "INVERTED", "HELPER_CONTROL"),
    "HP07": ("PROVED", "SAME", "HELPER_CONTROL"),
    "HP08": ("PROVED", "INVERTED", "HELPER_CONTROL"),
    "HP09": ("UNKNOWN", "UNKNOWN", "UNPROVEN"),
    "HP10": ("UNKNOWN", "UNKNOWN", "UNPROVEN"),
    "HP11": ("UNKNOWN", "UNKNOWN", "UNPROVEN"),
    "HP12": ("UNKNOWN", "UNKNOWN", "UNPROVEN"),
    "HP13": ("UNKNOWN", "UNKNOWN", "UNPROVEN"),
    "HP14": ("UNKNOWN", "UNKNOWN", "UNPROVEN"),
    "HP15": ("UNKNOWN", "UNKNOWN", "UNPROVEN"),
    "HP16": ("UNKNOWN", "UNKNOWN", "UNPROVEN"),
}


def cbytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def root_span(source: str, text: str) -> list[int]:
    tree = ast.parse(source)
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Compare) and ast.get_source_segment(source, node) == text:
            found.append([node.lineno, node.col_offset, node.end_lineno, node.end_col_offset])
    if len(found) != 1:
        raise ValueError("root comparison not unique")
    return found[0]


def certificate_digest_valid(cert: dict[str, Any]) -> bool:
    body = {key: value for key, value in cert.items() if key != "certificate_sha256"}
    digest = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return digest == cert.get("certificate_sha256")


def step_parity(cert: dict[str, Any]) -> bool:
    if cert["status"] != "PROVED":
        return cert["flip_count"] is None and cert["final_relation"] == "UNKNOWN" and bool(cert["reason"])
    flips = sum(1 for step in cert["steps"] if step.get("kind") == "BOOLEAN_NOT_FLIP")
    expected = "INVERTED" if flips % 2 else "SAME"
    return cert["flip_count"] == flips and cert["final_relation"] == expected and cert["reason"] is None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--output", required=True)
    args = ap.parse_args()
    corpus = json.loads(Path(args.corpus).read_text())
    rows = []
    for case in corpus["cases"]:
        expected = PAIR_ORACLE[case["pair_id"]]
        cert = prove_python_helper_polarity(case["source"], root_span(case["source"], case["transported_comparison_text"]))
        form = "HELPER_CONTROL" if cert["status"] == "PROVED" else "UNPROVEN"
        structural = certificate_digest_valid(cert) and step_parity(cert)
        passed = (cert["status"], cert["final_relation"], form) == expected and structural
        rows.append({
            "case_id": case["case_id"],
            "pair_id": case["pair_id"],
            "variant": case["variant"],
            "passed": passed,
            "status": cert["status"],
            "final_relation": cert["final_relation"],
            "integration_form": form,
            "flip_count": cert["flip_count"],
            "reason": cert["reason"],
            "certificate_digest_valid": certificate_digest_valid(cert),
            "step_parity_valid": step_parity(cert),
            "semantic_signature": [cert["status"], cert["final_relation"], form, cert["reason"]],
        })
    failed = [row["case_id"] for row in rows if not row["passed"]]
    pair_failures = []
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        grouped.setdefault(row["pair_id"], []).append(row)
    for pair_id, members in sorted(grouped.items()):
        if len(members) != 2 or members[0]["semantic_signature"] != members[1]["semantic_signature"]:
            pair_failures.append(pair_id)
    out = {
        "schema": SCHEMA,
        "status": "PASS" if len(rows) == 32 and not failed and not pair_failures else "FAIL",
        "case_count": len(rows),
        "passed_count": len(rows) - len(failed),
        "failed_case_ids": failed,
        "pair_failures": pair_failures,
        "oracle_pair_count": len(PAIR_ORACLE),
        "rows": rows,
    }
    Path(args.output).write_bytes(cbytes(out))
    return 0 if out["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
