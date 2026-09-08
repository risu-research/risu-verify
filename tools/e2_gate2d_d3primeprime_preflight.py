#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
from pathlib import Path
from typing import Any

PROTOCOL_COMMIT = "6964a2eb2e713040baf20034fcd00b7e4216298d"
PROTOCOL_PATH = "protocols/RISU_DIFF_E2_GATE2D_D3PRIMEPRIME_COPILOT_SMOKE_PROTOCOL_v0.1.json"
PROTOCOL_SHA256 = "a82b684c7b719a65b3f1818423c9a4f88859565bf6c6f3f4f3870cf330aadd1d"
PROTOCOL_BLOB = "30788e7708ee14f3bc918f5a50b225076508832f"

D1PP_PASS_COMMIT = "bc8f7511ef213d10b76d193e4459bc177bd3bf0a"
D1PP_RESULT_PATH = "experiments/risu-diff-e2/qualification/gate2d-evaluation-constitution/d1pp-r2-first-complete-pass/result.json"
D2PP_PASS_COMMIT = "0f33705585aeae17ac460b2379546b26f78cfa6c"
D2PP_SUMMARY_PATH = "experiments/risu-diff-e2/qualification/gate2d-evaluation-constitution/d2pp-first-complete-pass/first_complete_summary.json"

D3P_IMPLEMENTATION_COMMIT = "4a5bd9dc3db1d0e7c7ca134580bf1114d7c11a74"
D3P_FAILURE_COMMIT = "c1fd9c397a4285d3c5ddd319ae8be06332fea12c"
D3P_FAILURE_PATH = "experiments/risu-diff-e2/qualification/gate2d-evaluation-constitution/d3p-copilot-first-complete-failure/first_complete.json"
D3P_DIAGNOSIS_COMMIT = "e2c5f3e6457fd11b27feb9f5467280e95dcba076"
D3P_DIAGNOSIS_PATH = "experiments/risu-diff-e2/qualification/gate2d-evaluation-constitution/d3p-copilot-first-complete-diagnosis/diagnosis.json"

EXPECTED_COPIED_BLOBS = {
    "evaluation/gate2d/B3_COPILOT_CONFIG_v0.2.json": "3216bed626d0f1994893c8a89e35a5fdbe3aeb27",
    "evaluation/gate2d/BASELINE_REGISTRY_v0.3.json": "6e90075c29b0ae497148cadca5ac83a1bf9c2186",
    "tools/e2_gate2d_copilot_baseline_v2.py": "4c68a92f3404cffce0f8bb92494bdd78b3119f13",
}
EXPECTED_UNCHANGED_BLOBS = {
    "evaluation/gate2d/B3_LLM_PROMPT_v0.1.txt": "d2aeec22e6a500a60b53dc36ef4238a7c734d060",
    "evaluation/gate2d/B3_LLM_RESPONSE_SCHEMA_v0.1.json": "ec2578ccfba33f70c7b0057a5fbfe9b994eaf48d",
    "evaluation/gate2d/COMMON_BLINDED_INPUT_CONTRACT_v0.1.json": "db7e6e53ea82ef7942557adaf31b7b781c71365d",
}
EXPECTED_HISTORICAL_D3P_BLOBS = {
    ".github/workflows/e2-gate2d-d3prime-copilot-smoke.yml": "e9d2401e35550ce8543da9dfdc5fa7da30e5ec2e",
    "tools/e2_gate2d_d3prime_preflight.py": "778dd3d9a9d025a13827bc3745e3ce7b3b16b960",
    "tools/e2_gate2d_d3prime_smoke.py": "368faae2d9dafc63e01fb632dfb86ac5e7bbe238",
}
EXPECTED_CHANGED = {
    ".github/workflows/e2-gate2d-d3primeprime-copilot-smoke.yml",
    "evaluation/gate2d/B3_COPILOT_CONFIG_v0.2.json",
    "evaluation/gate2d/BASELINE_REGISTRY_v0.3.json",
    "tools/e2_gate2d_copilot_baseline_v2.py",
    "tools/e2_gate2d_d3primeprime_preflight.py",
    "tools/e2_gate2d_d3primeprime_smoke.py",
}
FIXTURE_SHA256 = "8f89253ab4a2f1eae2baaf0364a3e5e7dc9946eda69780d38cfe29b3893819d6"
HISTORICAL_D3P_REQUEST_SHA256 = "ba8d79525969d306134e1b68a3252dd08f2e654124f9d2108ece36405fa3743f"
D3PP_REQUEST_SHA256 = "f8519b04e17a92203f6e974f2276b9bc7e45a6deaeca8594d30194bc6402119c"


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def git_blob_sha(b: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(b)).encode() + b"\0" + b).hexdigest()


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], text=True).strip()


def git_json(commit: str, path: str) -> dict[str, Any]:
    raw = subprocess.check_output(["git", "show", f"{commit}:{path}"])
    return json.loads(raw)


def make_request(prompt: str, schema: str, fixture_path: str, fixture_content: str) -> bytes:
    docs = [{"path": fixture_path, "content": fixture_content}]
    request = (
        prompt.rstrip()
        + "\n\n"
        + "COPILOT_BASELINE_EXECUTION_RULES:\n"
        + "- Do not use tools, files, shell, URLs, memory, repository context, or unstated information.\n"
        + "- Decide only from BLINDED_DOCUMENTS_JSON below.\n"
        + "- Return exactly one JSON object conforming to RESPONSE_SCHEMA_JSON, with no markdown fence or surrounding prose.\n\n"
        + "RESPONSE_SCHEMA_JSON:\n"
        + schema.strip()
        + "\n\n"
        + "BLINDED_DOCUMENTS_JSON:\n"
        + json.dumps(docs, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    )
    return request.encode()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    root = Path(a.root).resolve()
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)

    failures: list[str] = []
    checks: dict[str, Any] = {}

    protocol_bytes = (root / PROTOCOL_PATH).read_bytes()
    checks["protocol_sha256"] = sha256(protocol_bytes)
    checks["protocol_git_blob"] = git_blob_sha(protocol_bytes)
    if checks["protocol_sha256"] != PROTOCOL_SHA256:
        failures.append("D3PP_PROTOCOL_RAW_SHA256")
    if checks["protocol_git_blob"] != PROTOCOL_BLOB:
        failures.append("D3PP_PROTOCOL_GIT_BLOB")

    parent = git("rev-parse", "HEAD^")
    checks["implementation_parent"] = parent
    if parent != PROTOCOL_COMMIT:
        failures.append("IMPLEMENTATION_PARENT_NOT_D3PP_PROTOCOL")

    changed = {x for x in git("diff", "--name-only", PROTOCOL_COMMIT, "HEAD").splitlines() if x}
    checks["implementation_surface"] = sorted(changed)
    if changed != EXPECTED_CHANGED:
        failures.append("IMPLEMENTATION_SURFACE")

    for rel, want in sorted(EXPECTED_COPIED_BLOBS.items()):
        p = root / rel
        got = git_blob_sha(p.read_bytes()) if p.is_file() else None
        checks["copied_blob:" + rel] = got
        if got != want:
            failures.append("D1PP_COPIED_BLOB:" + rel)

    for rel, want in sorted(EXPECTED_UNCHANGED_BLOBS.items()):
        p = root / rel
        got = git_blob_sha(p.read_bytes()) if p.is_file() else None
        checks["unchanged_blob:" + rel] = got
        if got != want:
            failures.append("UNCHANGED_BLOB:" + rel)

    for rel, want in sorted(EXPECTED_HISTORICAL_D3P_BLOBS.items()):
        try:
            got = git("rev-parse", f"{D3P_IMPLEMENTATION_COMMIT}:{rel}")
        except subprocess.CalledProcessError:
            got = None
        checks["historical_d3p_blob:" + rel] = got
        if got != want:
            failures.append("HISTORICAL_D3P_IMPLEMENTATION_BLOB:" + rel)

    d1 = git_json(D1PP_PASS_COMMIT, D1PP_RESULT_PATH)
    if (
        d1.get("status") != "GATE2D_D1PP_R2_COPILOT_PRO_IDENTITY_PASS_IMMUTABLY_FROZEN_BY_CONTAINING_COMMIT"
        or d1.get("provider_semantic_request_count") != 0
        or d1.get("lanes") != {
            "B3A_GPT56_TERRA_COPILOT": "gpt-5.6-terra",
            "B3B_CLAUDE_SONNET5_COPILOT": "claude-sonnet-5",
        }
        or d1.get("gate2e_authorized") is not False
    ):
        failures.append("D1PP_PASS_AUTHORITY")
    checks["d1pp_status"] = d1.get("status")

    d2 = git_json(D2PP_PASS_COMMIT, D2PP_SUMMARY_PATH)
    if (
        d2.get("status") != "PASS"
        or d2.get("case_count") != 30
        or d2.get("predicate_pass_count") != 30
        or d2.get("copilot_semantic_request_count") != 0
        or d2.get("checks", {}).get("orchestration_zero") is not True
        or d2.get("checks", {}).get("preflight_pass") is not True
        or d2.get("gate2e_authorized") is not False
    ):
        failures.append("D2PP_PASS_AUTHORITY")
    checks["d2pp_status"] = d2.get("status")
    checks["d2pp_predicate_pass_count"] = d2.get("predicate_pass_count")

    d3f = git_json(D3P_FAILURE_COMMIT, D3P_FAILURE_PATH)
    if (
        d3f.get("status") != "GATE2D_D3PRIME_FIRST_COMPLETE_FAIL_UNDIAGNOSED_IMMUTABLY_FROZEN_BY_CONTAINING_COMMIT"
        or d3f.get("truth_or_heldout_exposure") is not False
        or d3f.get("semantic_artifact_contents_inspected_before_freeze") is not False
        or d3f.get("semantic_outcome_values_inspected_before_freeze") is not False
        or d3f.get("gate2e_authorized") is not False
    ):
        failures.append("HISTORICAL_D3P_FAILURE_AUTHORITY")

    d3d = git_json(D3P_DIAGNOSIS_COMMIT, D3P_DIAGNOSIS_PATH)
    if (
        d3d.get("classification") != "D3PRIME_COPILOT_PRO_MODEL_ENTITLEMENT_MISMATCH_BEFORE_SCHEMA_RESPONSE"
        or d3d.get("provider_semantic_request_count_first_complete") != 2
        or d3d.get("truth_or_heldout_exposure") is not False
        or d3d.get("request_identity", {}).get("both_lane_request_sha256_equal") is not True
        or d3d.get("request_identity", {}).get("request_sha256") != HISTORICAL_D3P_REQUEST_SHA256
        or d3d.get("request_identity", {}).get("visible_input_bytes_each") != 314
    ):
        failures.append("HISTORICAL_D3P_DIAGNOSIS_AUTHORITY")
    lane_evidence = d3d.get("lane_evidence", [])
    if (
        len(lane_evidence) != 2
        or sum(int(x.get("provider_semantic_invocation_count", 0)) for x in lane_evidence) != 2
        or any(x.get("candidate_count") != 0 for x in lane_evidence)
        or any(x.get("semantically_valid") is not False for x in lane_evidence)
    ):
        failures.append("HISTORICAL_D3P_EXPOSURE_ACCOUNTING")

    cfg = json.loads((root / "evaluation/gate2d/B3_COPILOT_CONFIG_v0.2.json").read_bytes())
    t = cfg.get("transport", {})
    if (
        t.get("cli_package") != "@github/copilot"
        or t.get("cli_version") != "1.0.83"
        or t.get("repository_secret") != "RISU_COPILOT_PERSONAL_TOKEN"
        or t.get("authentication_env") != "COPILOT_GITHUB_TOKEN"
        or t.get("max_ai_credits_per_response") != 30
        or t.get("semantic_retry_cap") != 0
        or t.get("transport_retry_cap") != 1
    ):
        failures.append("COPILOT_TRANSPORT_IDENTITY")
    want_lanes = {
        "B3A_GPT56_TERRA_COPILOT": {"model": "gpt-5.6-terra", "provider_family": "OpenAI"},
        "B3B_CLAUDE_SONNET5_COPILOT": {"model": "claude-sonnet-5", "provider_family": "Anthropic"},
    }
    if cfg.get("lanes") != want_lanes:
        failures.append("COPILOT_LANE_IDENTITY")
    if cfg.get("isolation", {}).get("tools_denied") != ["shell", "write", "read", "url", "memory"]:
        failures.append("COPILOT_TOOL_DENIAL_IDENTITY")

    protocol = json.loads(protocol_bytes)
    fx = protocol.get("nonheldout_fixture", {})
    fixture_content = fx.get("content", "")
    fixture_bytes = fixture_content.encode()
    checks["fixture_size"] = len(fixture_bytes)
    checks["fixture_sha256"] = sha256(fixture_bytes)
    if (
        fx.get("path") != "d3_smoke/blinded_document.txt"
        or len(fixture_bytes) != 314
        or sha256(fixture_bytes) != FIXTURE_SHA256
        or fx.get("expected_semantic_outcome") is not None
        or fx.get("heldout_bytes_present")
        or fx.get("truth_label_present")
        or fx.get("fresh_target_bytes_present")
        or fx.get("mutation_operator_identity_present")
        or fx.get("risu_output_present")
    ):
        failures.append("NONHELDOUT_FIXTURE_IDENTITY")

    prompt = (root / "evaluation/gate2d/B3_LLM_PROMPT_v0.1.txt").read_text()
    schema = (root / "evaluation/gate2d/B3_LLM_RESPONSE_SCHEMA_v0.1.json").read_text()
    d3pp_req = make_request(prompt, schema, fx.get("path", ""), fixture_content)
    historical_req = make_request(prompt, schema, "d3p_smoke/blinded_document.txt", fixture_content)
    checks["d3pp_request_sha256"] = sha256(d3pp_req)
    checks["historical_d3p_reconstructed_request_sha256"] = sha256(historical_req)
    checks["request_construction_delta"] = "visible_path_namespace_only:d3p_smoke->d3_smoke"
    if sha256(d3pp_req) != D3PP_REQUEST_SHA256:
        failures.append("D3PP_REQUEST_PREIMAGE")
    if sha256(historical_req) != HISTORICAL_D3P_REQUEST_SHA256:
        failures.append("D3P_REQUEST_MECHANICAL_RECOVERY")
    if len(d3pp_req) != len(historical_req) - 1:
        failures.append("REQUEST_NAMESPACE_LENGTH_DELTA")

    if platform.python_version() != "3.13.5":
        failures.append("PYTHON_RUNTIME")
    for k, v in {"LC_ALL": "C.UTF-8", "PYTHONHASHSEED": "0", "TZ": "UTC"}.items():
        if os.environ.get(k) != v:
            failures.append("ENV_" + k)
    if Path(os.environ.get("PYTHONPATH", "")).resolve() != root:
        failures.append("ENV_PYTHONPATH")

    wf = (root / ".github/workflows/e2-gate2d-d3primeprime-copilot-smoke.yml").read_text()
    required_wf_fragments = [
        "gate2d-d3primeprime-copilot-smoke-run",
        "secrets.RISU_COPILOT_PERSONAL_TOKEN",
        "python tools/e2_gate2d_d3primeprime_smoke.py",
        "e2-gate2d-d3primeprime-copilot-smoke",
        "@github/copilot@1.0.83",
    ]
    if any(x not in wf for x in required_wf_fragments):
        failures.append("WORKFLOW_REQUIRED_BINDING")
    if "secrets.GITHUB_TOKEN" in wf or "github.token" in wf:
        failures.append("WORKFLOW_ORG_TOKEN_SEMANTIC_ROUTE")

    report = {
        "schema": "risu.e2-gate2d-d3pp-preflight/v0.1",
        "status": "PASS" if not failures else "FAIL",
        "failures": sorted(failures),
        "checks": checks,
        "provider_semantic_request_count": 0,
        "historical_d3p_copilot_process_invocation_count": 2,
        "historical_d3p_schema_candidate_count": 0,
        "d3primeprime_semantic_invocation_count_before_smoke": 0,
        "epistemic10_read": False,
        "truth_read": False,
        "fresh_target_read": False,
        "mutation_algebra_opened": False,
        "gate2e_authorized": False,
    }
    out.write_text(json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n")
    if failures:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
