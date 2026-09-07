#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path
from typing import Any

from risu_e2.predicate_polarity_v1 import prove_python_helper_polarity

SCHEMA = "risu.e2-helper-polarity-primary-qualification/v0.1"


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def comparison_span(source: str, text: str) -> list[int]:
    tree = ast.parse(source)
    rows = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Compare) and ast.get_source_segment(source, node) == text
    ]
    if len(rows) != 1:
        raise ValueError("transported comparison text not unique")
    node = rows[0]
    return [node.lineno, node.col_offset, node.end_lineno, node.end_col_offset]


def integration_form(cert: dict[str, Any]) -> str:
    return "HELPER_CONTROL" if cert["status"] == "PROVED" else "UNPROVEN"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--output", required=True)
    args = ap.parse_args()
    corpus = json.loads(Path(args.corpus).read_text())
    cases = corpus["cases"]
    rows = []
    for case in cases:
        source = case["source"]
        span = comparison_span(source, case["transported_comparison_text"])
        cert = prove_python_helper_polarity(source, span)
        observed_form = integration_form(cert)
        passed = (
            cert["status"] == case["expected_status"]
            and cert["final_relation"] == case["expected_relation"]
            and observed_form == case["expected_integration_form"]
            and ((cert["reason"] is None) if cert["status"] == "PROVED" else bool(cert["reason"]))
        )
        rows.append({
            "case_id": case["case_id"],
            "pair_id": case["pair_id"],
            "variant": case["variant"],
            "passed": passed,
            "status": cert["status"],
            "final_relation": cert["final_relation"],
            "integration_form": observed_form,
            "flip_count": cert["flip_count"],
            "reason": cert["reason"],
            "certificate_sha256": cert["certificate_sha256"],
            "step_kinds": [step["kind"] for step in cert["steps"]],
            "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
        })
    by_id = {row["case_id"]: row for row in rows}
    pair_failures = []
    for left, right in corpus["metamorphic_pairs"]:
        a, b = by_id[left], by_id[right]
        sig_a = (a["status"], a["final_relation"], a["integration_form"], a["reason"])
        sig_b = (b["status"], b["final_relation"], b["integration_form"], b["reason"])
        if sig_a != sig_b:
            pair_failures.append({"left": left, "right": right, "left_signature": sig_a, "right_signature": sig_b})
    failed = [row["case_id"] for row in rows if not row["passed"]]
    out = {
        "schema": SCHEMA,
        "status": "PASS" if not failed and not pair_failures and len(rows) == 32 else "FAIL",
        "case_count": len(rows),
        "passed_count": len(rows) - len(failed),
        "failed_case_ids": failed,
        "metamorphic_pair_count": len(corpus["metamorphic_pairs"]),
        "metamorphic_pair_failures": pair_failures,
        "negative_controls_fail_closed": all(row["status"] == "UNKNOWN" for row in rows if by_id[row["case_id"]]["case_id"].startswith(("HPB09", "HPM09", "HPB10", "HPM10", "HPB11", "HPM11", "HPB12", "HPM12", "HPB13", "HPM13", "HPB14", "HPM14", "HPB15", "HPM15", "HPB16", "HPM16"))),
        "rows": rows,
    }
    Path(args.output).write_bytes(canonical_bytes(out))
    return 0 if out["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
