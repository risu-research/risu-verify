#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json, os, platform, subprocess
from pathlib import Path

D3_CONTRACT_COMMIT = "4a06481243654da6237c23474a4fe0fc64b9e69b"
D3_CONTRACT_BLOB = "e528f6022de092f492d01b1057db3b956398848d"
D3_CONTRACT_SHA256 = "dd51563e3194241e3bbeb60948b4aed1dc26e969c46cbc437cd19a69320b6ae3"
D3_CONTRACT_SIZE = 6394
D3_CONTRACT_PATH = "protocols/RISU_DIFF_E2_GATE2D_D3_CLOSURE_PROTOCOL_v0.1.json"
D3_FREEZE_RECEIPT = "experiments/risu-diff-e2/qualification/gate2d-evaluation-constitution/d3-closure-protocol-freeze/freeze_receipt.json"
D3_FIRST_FAILURE_COMMIT = "501e3dfa3aacf41a4808a38f0efedb1b0ff36b75"
D3_FIRST_FAILURE_RECEIPT = "experiments/risu-diff-e2/qualification/gate2d-evaluation-constitution/d3-closure-first-complete/freeze_receipt.json"
D3_DIAGNOSIS_COMMIT = "6abfd76590d1e810a39c24c772d405b48534450a"
D3_DIAGNOSIS_PATH = "experiments/risu-diff-e2/qualification/gate2d-evaluation-constitution/d3-closure-first-complete-diagnosis/diagnosis.json"
D3_ERRATUM_COMMIT = "7efa6e5dbb949312b66264fcf6ff60bbef5e42e9"
D3_ERRATUM_BLOB = "435e258abad2aa16c2e55eb0cccb605655dc7250"
D3_ERRATUM_PATH = "protocols/RISU_DIFF_E2_GATE2D_D3_CLOSURE_DIGEST_ERRATUM_v0.1.json"
D3_ERRATUM_RECEIPT = "experiments/risu-diff-e2/qualification/gate2d-evaluation-constitution/d3-closure-digest-erratum-freeze/freeze_receipt.json"
PROVIDER_SMOKE_BLOB = "b60ab434aeffd6a411039f7ff9e4d32e190ffd87"

def cb(v):
    return (json.dumps(v, sort_keys=True, separators=(",",":"), ensure_ascii=False) + "\n").encode()

def sha256(b):
    return hashlib.sha256(b).hexdigest()

def git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git","-C",str(root),*args], text=True).strip()

def blob_bytes(b: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(b)).encode() + b"\0" + b).hexdigest()

def current_blob(root: Path, rel: str) -> str:
    return git(root, "hash-object", rel)

def authority_blob(root: Path, commit: str, rel: str) -> str:
    return git(root, "rev-parse", f"{commit}:{rel}")

def exact_authority_file(root: Path, commit: str, rel: str, failures: list[str]) -> None:
    p = root / rel
    if not p.is_file():
        failures.append("MISSING_AUTHORITY_FILE:" + rel)
        return
    try:
        want = authority_blob(root, commit, rel)
        got = current_blob(root, rel)
    except Exception:
        failures.append("AUTHORITY_LOOKUP:" + rel)
        return
    if got != want:
        failures.append("AUTHORITY_BLOB_MISMATCH:" + rel)

def ancestor(root: Path, commit: str) -> bool:
    return subprocess.run(
        ["git","-C",str(root),"merge-base","--is-ancestor",commit,"HEAD"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    ).returncode == 0

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    root = Path(a.root).resolve()
    failures: list[str] = []

    if platform.python_version() != "3.13.5":
        failures.append("PYTHON_VERSION")
    expected_env = {
        "LC_ALL": "C.UTF-8",
        "PYTHONHASHSEED": "0",
        "TZ": "UTC",
        "PYTHONPATH": str(root),
    }
    for k, v in expected_env.items():
        if os.environ.get(k) != v:
            failures.append("RUNTIME_ENV:" + k)

    for name, commit in (
        ("D3_CONTRACT", D3_CONTRACT_COMMIT),
        ("D3_FIRST_FAILURE", D3_FIRST_FAILURE_COMMIT),
        ("D3_DIAGNOSIS", D3_DIAGNOSIS_COMMIT),
        ("D3_ERRATUM", D3_ERRATUM_COMMIT),
    ):
        if not ancestor(root, commit):
            failures.append(name + "_NOT_ANCESTOR")

    cp = root / D3_CONTRACT_PATH
    if not cp.is_file():
        failures.append("D3_CONTRACT_MISSING")
        protocol = {}
    else:
        b = cp.read_bytes()
        if current_blob(root, D3_CONTRACT_PATH) != D3_CONTRACT_BLOB:
            failures.append("D3_CONTRACT_BLOB")
        if len(b) != D3_CONTRACT_SIZE:
            failures.append("D3_CONTRACT_SIZE")
        if sha256(b) != D3_CONTRACT_SHA256:
            failures.append("D3_CONTRACT_SHA256")
        protocol = json.loads(b)

    fr = root / D3_FREEZE_RECEIPT
    if not fr.is_file():
        failures.append("D3_FREEZE_RECEIPT_MISSING")
    else:
        f = json.loads(fr.read_bytes())
        if f.get("status") != "GATE2D_D3_CLOSURE_PROTOCOL_PROSPECTIVELY_FROZEN":
            failures.append("D3_FREEZE_STATUS")
        if f.get("provider_smoke_executed") is not False or f.get("gate2e_authorized") is not False:
            failures.append("D3_FREEZE_PREEXEC_STATE")
        if f.get("contract_git_blob") != D3_CONTRACT_BLOB:
            failures.append("D3_FREEZE_GIT_BLOB")
        if f.get("contract_sha256") != "8997609894766d4c541f34c18c1e070d7c8f86a55b2b54536eab82749195f327":
            failures.append("D3_ORIGINAL_BAD_SHA_HISTORY_CHANGED")

    ep = root / D3_ERRATUM_PATH
    if not ep.is_file():
        failures.append("D3_ERRATUM_MISSING")
        erratum = {}
    else:
        eb = ep.read_bytes()
        if current_blob(root, D3_ERRATUM_PATH) != D3_ERRATUM_BLOB:
            failures.append("D3_ERRATUM_BLOB")
        erratum = json.loads(eb)
        correction = erratum.get("correction", {})
        scope = erratum.get("first_failure_scope", {})
        if erratum.get("status") != "PROSPECTIVE_METADATA_ERRATUM_FROZEN_BEFORE_ANY_PROVIDER_REQUEST":
            failures.append("D3_ERRATUM_STATUS")
        if correction.get("contract_git_blob_unchanged") is not True or correction.get("contract_bytes_changed") is not False:
            failures.append("D3_ERRATUM_BYTES_RULE")
        if correction.get("contract_sha256_correct") != D3_CONTRACT_SHA256 or correction.get("contract_size_bytes_correct") != D3_CONTRACT_SIZE:
            failures.append("D3_ERRATUM_CORRECT_DIGEST")
        if correction.get("protocol_semantics_changed") is not False or erratum.get("success_rule_changed") is not False:
            failures.append("D3_ERRATUM_SEMANTICS")
        if scope.get("provider_request_count") != 0 or scope.get("provider_or_model_result_observed") is not False:
            failures.append("D3_ERRATUM_PROVIDER_SCOPE")
        if not all(scope.get(k) is True for k in ("d1_manifest_exact","semantic_snapshot_exact","historical_d2_authority_exact","runtime_exact")):
            failures.append("D3_ERRATUM_PRIOR_CLOSURE")

    er = root / D3_ERRATUM_RECEIPT
    if not er.is_file():
        failures.append("D3_ERRATUM_RECEIPT_MISSING")
    else:
        x = json.loads(er.read_bytes())
        if x.get("status") != "GATE2D_D3_METADATA_ERRATUM_PROSPECTIVELY_FROZEN":
            failures.append("D3_ERRATUM_RECEIPT_STATUS")
        if x.get("provider_request_count_before_erratum_freeze") != 0 or x.get("r2_execution_present_in_this_freeze") is not False:
            failures.append("D3_ERRATUM_RECEIPT_SCOPE")
        if x.get("erratum_git_blob") != D3_ERRATUM_BLOB:
            failures.append("D3_ERRATUM_RECEIPT_BLOB")

    allowed = {
        ".github/workflows/e2-gate2d-d3-closure-qualification.yml",
        "tools/e2_gate2d_d3_preflight.py",
        "tools/e2_gate2d_d3_provider_smoke.py",
    }
    changed = set(git(root, "diff", "--name-only", D3_ERRATUM_COMMIT, "HEAD").splitlines())
    if changed != allowed:
        failures.append("D3_R2_IMPLEMENTATION_SURFACE:" + repr(sorted(changed)))
    if current_blob(root, "tools/e2_gate2d_d3_provider_smoke.py") != PROVIDER_SMOKE_BLOB:
        failures.append("D3_PROVIDER_SMOKE_BLOB_CHANGED")

    manifest_path = root / "evaluation/gate2d/D1_IDENTITY_MANIFEST_v0.1.json"
    m = json.loads(manifest_path.read_bytes())
    for rel, ident in sorted(m.get("files", {}).items()):
        p = root / rel
        if not p.is_file():
            failures.append("D1_MISSING:" + rel)
            continue
        b = p.read_bytes()
        if len(b) != ident["size"]:
            failures.append("D1_SIZE:" + rel)
        if sha256(b) != ident["sha256"]:
            failures.append("D1_SHA256:" + rel)
        if blob_bytes(b) != ident["git_blob"]:
            failures.append("D1_GIT_BLOB:" + rel)

    cpath = root / "protocols/RISU_DIFF_E2_GATE2D_EVALUATION_CONSTITUTION_v0.1.json"
    constitution = json.loads(cpath.read_bytes())
    locks = constitution["authority_locks"]["semantic_snapshot"]["critical_blob_locks"]
    for rel, want in sorted(locks.items()):
        p = root / rel
        if not p.is_file() or current_blob(root, rel) != want:
            failures.append("SEMANTIC_SNAPSHOT:" + rel)

    authority_files = [
        ("13a20a8c68c2eafadfc00d7a2e873543a6845ecb",
         "experiments/risu-diff-e2/qualification/gate2d-evaluation-constitution/d2-adversarial-synthetic-first-complete/freeze_receipt.json"),
        ("c5c78fd799672d6cb1d7d60acc2d9356806b49a4",
         "experiments/risu-diff-e2/qualification/gate2d-evaluation-constitution/d2-adversarial-synthetic-first-complete-diagnosis/diagnosis.json"),
        ("e40eba526510835d1e988baf6f09397ff6023bc5",
         "experiments/risu-diff-e2/qualification/gate2d-evaluation-constitution/d2-remediation-contract-freeze/freeze_receipt.json"),
        ("a6cbdfcaadf978b7076558b351f0f5ecb43e38f6",
         "experiments/risu-diff-e2/qualification/gate2d-evaluation-constitution/d2-remediation-first-complete/freeze_receipt.json"),
        (D3_CONTRACT_COMMIT, D3_CONTRACT_PATH),
        (D3_CONTRACT_COMMIT, D3_FREEZE_RECEIPT),
        (D3_FIRST_FAILURE_COMMIT, D3_FIRST_FAILURE_RECEIPT),
        (D3_DIAGNOSIS_COMMIT, D3_DIAGNOSIS_PATH),
        (D3_ERRATUM_COMMIT, D3_ERRATUM_PATH),
        (D3_ERRATUM_COMMIT, D3_ERRATUM_RECEIPT),
    ]
    for commit, rel in authority_files:
        exact_authority_file(root, commit, rel, failures)

    orig = json.loads((root / authority_files[0][1]).read_bytes())
    om = orig.get("matrix", {})
    if om.get("predicate_pass_count") != 29 or om.get("case_count") != 30 or om.get("failed_case_ids") != ["T22_ABLATION_CANNOT_MUTATE_PRIMARY"] or orig.get("d2_success") is not False:
        failures.append("ORIGINAL_D2_FAILURE_STATE")

    diag = json.loads((root / authority_files[1][1]).read_bytes())
    if diag.get("status") != "GATE2D_D2_T22_POSTHOC_DIAGNOSIS_COMPLETE_NO_REMEDIATION_AUTHORIZED":
        failures.append("D2_DIAGNOSIS_STATE")

    rem = json.loads((root / authority_files[3][1]).read_bytes())
    rr = rem.get("remediation_result", {})
    if rem.get("status") != "GATE2D_D2_REMEDIATION_FIRST_COMPLETE_PASS_IMMUTABLY_FROZEN_BY_CONTAINING_COMMIT":
        failures.append("D2_REMEDIATION_FREEZE_STATE")
    if rr.get("predicate_pass_count") != 30 or rr.get("case_count") != 30 or rr.get("success") is not True:
        failures.append("D2_REMEDIATION_RESULT")
    if rem.get("frozen_evidence_sha256", {}).get("full_artifact_zip") != protocol.get("authority", {}).get("d2_remediation_artifact_sha256"):
        failures.append("D2_REMEDIATION_ARTIFACT_DIGEST")

    ff = json.loads((root / D3_FIRST_FAILURE_RECEIPT).read_bytes())
    if ff.get("status") != "GATE2D_D3_FIRST_COMPLETE_CLOSURE_FAIL_UNDIAGNOSED_IMMUTABLY_FROZEN_BY_CONTAINING_COMMIT":
        failures.append("D3_FIRST_FAILURE_STATE")
    if ff.get("d3_success") is not False or ff.get("gate2e_authorized") is not False:
        failures.append("D3_FIRST_FAILURE_AUTHORIZATION")

    fd = json.loads((root / D3_DIAGNOSIS_PATH).read_bytes())
    if fd.get("status") != "GATE2D_D3_FIRST_COMPLETE_DIAGNOSIS_COMPLETE_METADATA_ONLY":
        failures.append("D3_FIRST_DIAGNOSIS_STATE")
    if fd.get("classification") != "D3_PROSPECTIVE_FREEZE_SHA256_METADATA_DEFECT_PRE_PROVIDER":
        failures.append("D3_FIRST_DIAGNOSIS_CLASS")
    if fd.get("evidence", {}).get("provider_request_count") != 0:
        failures.append("D3_FIRST_DIAGNOSIS_PROVIDER_COUNT")

    d1p = json.loads((root / "protocols/RISU_DIFF_E2_GATE2D_D1_EVALUATOR_BASELINE_ABLATION_IDENTITY_FREEZE_v0.2.json").read_bytes())
    rule = d1p["baseline_panel"]["B3"]["provider_availability_rule"]
    if "Both lanes must pass D3" not in rule:
        failures.append("D1_B3_D3_RULE")
    cfg = json.loads((root / "evaluation/gate2d/B3_LLM_CONFIG_v0.1.json").read_bytes())
    for provider in ("openai","anthropic"):
        want = protocol["b3_provider_smoke"]["required_lanes"][provider]
        got = cfg["providers"][provider]
        if got.get("lane_id") != want["lane_id"] or got.get("endpoint") != want["endpoint"] or got.get("model") != want["model"]:
            failures.append("B3_IDENTITY:" + provider)

    fw = protocol.get("closure_obligations", {}).get("heldout_firewall", {})
    if any(fw.get(k) is not False for k in ("epistemic10_read","truth_read","fresh_target_read","mutation_algebra_opened")):
        failures.append("PROTOCOL_FIREWALL")

    out = {
        "schema": "risu.e2-gate2d-d3-r2-preflight/v0.1",
        "status": "PASS" if not failures else "FAIL",
        "failures": sorted(failures),
        "changed_files": sorted(changed),
        "d3_contract_git_blob_exact": "D3_CONTRACT_BLOB" not in failures,
        "d3_contract_corrected_sha256_exact": "D3_CONTRACT_SHA256" not in failures,
        "d3_erratum_exact": not any(x.startswith("D3_ERRATUM") for x in failures),
        "provider_smoke_blob_exact": "D3_PROVIDER_SMOKE_BLOB_CHANGED" not in failures,
        "d1_manifest_exact": not any(x.startswith("D1_") for x in failures),
        "semantic_snapshot_exact": not any(x.startswith("SEMANTIC_SNAPSHOT:") for x in failures),
        "historical_d2_authority_exact": not any(x.startswith(("AUTHORITY_","ORIGINAL_D2_","D2_")) for x in failures),
        "historical_d3_failure_and_diagnosis_exact": not any(x.startswith(("D3_FIRST_FAILURE","D3_FIRST_DIAGNOSIS")) for x in failures),
        "runtime_exact": not any(x.startswith(("PYTHON_VERSION","RUNTIME_ENV:")) for x in failures),
        "epistemic10_read": False,
        "truth_read": False,
        "fresh_target_read": False,
        "mutation_algebra_opened": False,
        "provider_request_emitted": False,
        "gate2e_authorized": False,
    }
    Path(a.out).write_bytes(cb(out))
    if failures:
        raise SystemExit(2)

if __name__ == "__main__":
    main()
