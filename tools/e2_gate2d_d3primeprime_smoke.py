#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

LANES = [
    ("B3A_GPT56_TERRA_COPILOT", "gpt-5.6-terra"),
    ("B3B_CLAUDE_SONNET5_COPILOT", "claude-sonnet-5"),
]
FIXTURE_SHA256 = "8f89253ab4a2f1eae2baaf0364a3e5e7dc9946eda69780d38cfe29b3893819d6"
D3PP_REQUEST_SHA256 = "f8519b04e17a92203f6e974f2276b9bc7e45a6deaeca8594d30194bc6402119c"
VALID_OUTCOMES = {"DEFINITIVE_PRESERVATION", "DEFINITIVE_REGRESSION", "INCOMPLETE"}


def canonical(v: Any) -> bytes:
    return (json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_bytes())
        return value if isinstance(value, dict) else {}
    except Exception:
        return {}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    root = Path(a.root).resolve()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)

    protocol = load(root / "protocols/RISU_DIFF_E2_GATE2D_D3PRIMEPRIME_COPILOT_SMOKE_PROTOCOL_v0.1.json")
    fx = protocol["nonheldout_fixture"]
    fixture_bytes = fx["content"].encode()
    fixture_path = root / fx["path"]
    fixture_path.parent.mkdir(parents=True, exist_ok=True)
    fixture_path.write_bytes(fixture_bytes)
    if len(fixture_bytes) != 314 or sha256(fixture_bytes) != FIXTURE_SHA256:
        raise SystemExit("FIXTURE_IDENTITY")

    artifact_fixture = out / "fixture" / "blinded_document.txt"
    artifact_fixture.parent.mkdir(parents=True, exist_ok=True)
    artifact_fixture.write_bytes(fixture_bytes)

    manifest = fx["manifest"]
    manifest_path = out / "D3PP_MANIFEST.json"
    manifest_path.write_bytes(canonical(manifest))

    token = os.environ.get("COPILOT_GITHUB_TOKEN", "")
    if not token:
        summary = {
            "schema": "risu.e2-gate2d-d3pp-smoke/v0.1",
            "status": "PRE_PROVIDER_CREDENTIAL_MISSING",
            "provider_semantic_request_count": 0,
            "total_process_invocation_count": 0,
            "lane_count": 0,
            "transport_retry_count": 0,
            "semantic_retry_count": 0,
            "semantic_outcome_values_used_for_gate_decision": False,
            "semantic_outcome_values_recorded_in_summary": False,
            "epistemic10_read": False,
            "truth_read": False,
            "fresh_target_read": False,
            "mutation_algebra_opened": False,
            "gate2e_authorized": False,
        }
        (out / "D3PP_SMOKE_SUMMARY.json").write_bytes(canonical(summary))
        return

    rows: list[dict[str, Any]] = []
    invoked = 0
    for baseline_id, model in LANES:
        lane_dir = out / baseline_id
        lane_dir.mkdir(parents=True, exist_ok=True)
        output = lane_dir / "output.json"
        raw = lane_dir / "raw.jsonl"
        receipt = lane_dir / "receipt.json"
        cmd = [
            sys.executable,
            str(root / "tools/e2_gate2d_copilot_baseline_v2.py"),
            "--baseline-id",
            baseline_id,
            "--root",
            str(root),
            "--manifest",
            str(manifest_path),
            "--output",
            str(output),
            "--raw-jsonl",
            str(raw),
            "--receipt",
            str(receipt),
        ]

        invoked += 1
        try:
            cp = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            runner_rc = cp.returncode
            runner_stdout = cp.stdout
            runner_stderr = cp.stderr
        except Exception as exc:
            runner_rc = 125
            runner_stdout = b""
            runner_stderr = (type(exc).__name__ + "\n").encode()

        (lane_dir / "runner_stdout.sha256").write_text(sha256(runner_stdout) + "\n")
        (lane_dir / "runner_stderr.sha256").write_text(sha256(runner_stderr) + "\n")

        rec = load(receipt) if receipt.exists() else {}
        od = load(output) if output.exists() else {}
        normalized = od.get("normalized_outcome")
        normalized_valid = normalized in VALID_OUTCOMES

        row = {
            "baseline_id": baseline_id,
            "expected_model": model,
            "runner_returncode": runner_rc,
            "receipt_present": bool(rec),
            "output_present": bool(od),
            "receipt_model_exact": rec.get("model") == model,
            "receipt_cli_exact": rec.get("cli_package") == "@github/copilot" and rec.get("cli_version") == "1.0.83",
            "request_sha256": rec.get("request_sha256"),
            "request_sha256_exact": rec.get("request_sha256") == D3PP_REQUEST_SHA256,
            "visible_input_bytes": rec.get("visible_input_bytes"),
            "raw_jsonl_sha256_present": isinstance(rec.get("raw_jsonl_sha256"), str) and len(rec.get("raw_jsonl_sha256", "")) == 64,
            "stderr_sha256_present": isinstance(rec.get("stderr_sha256"), str) and len(rec.get("stderr_sha256", "")) == 64,
            "semantically_valid": rec.get("semantically_valid") is True,
            "normalized_schema_valid": normalized_valid,
            "tool_permissions_granted_exact_empty": rec.get("tool_permissions_granted") == [],
            "credential_value_persisted": rec.get("credential_value_persisted"),
            "provider_semantic_request_count": 1,
            "process_invocation_count": 1,
        }
        rows.append(row)

    reqs = [x.get("request_sha256") for x in rows]
    passed = (
        len(rows) == 2
        and invoked == 2
        and all(
            x["runner_returncode"] == 0
            and x["receipt_model_exact"]
            and x["receipt_cli_exact"]
            and x["request_sha256_exact"]
            and x["semantically_valid"]
            and x["normalized_schema_valid"]
            and x["visible_input_bytes"] == 314
            and x["raw_jsonl_sha256_present"]
            and x["stderr_sha256_present"]
            and x["tool_permissions_granted_exact_empty"]
            and x["credential_value_persisted"] is False
            and x["provider_semantic_request_count"] == 1
            and x["process_invocation_count"] == 1
            for x in rows
        )
        and reqs == [D3PP_REQUEST_SHA256, D3PP_REQUEST_SHA256]
    )

    summary = {
        "schema": "risu.e2-gate2d-d3pp-smoke/v0.1",
        "status": "PASS" if passed else "FAIL",
        "provider_semantic_request_count": invoked,
        "total_process_invocation_count": invoked,
        "lane_count": len(rows),
        "both_lane_request_sha256_equal": len(reqs) == 2 and len(set(reqs)) == 1,
        "request_sha256_exact": reqs == [D3PP_REQUEST_SHA256, D3PP_REQUEST_SHA256],
        "frozen_request_sha256": D3PP_REQUEST_SHA256,
        "lanes": rows,
        "transport_retry_count": 0,
        "semantic_retry_count": 0,
        "orchestration_failure_count": 0 if passed else sum(1 for x in rows if x["runner_returncode"] != 0),
        "semantic_outcome_values_used_for_gate_decision": False,
        "semantic_outcome_values_recorded_in_summary": False,
        "epistemic10_read": False,
        "truth_read": False,
        "fresh_target_read": False,
        "mutation_algebra_opened": False,
        "gate2e_authorized": False,
    }
    (out / "D3PP_SMOKE_SUMMARY.json").write_bytes(canonical(summary))


if __name__ == "__main__":
    main()
