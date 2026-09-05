#!/usr/bin/env python3
from __future__ import annotations

import ast
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = "4d9026e4b967f938afea9a6c2a6c039b41dbdd63"
PROTOCOL_FREEZE_COMMIT = "d51700e5fc24ba777c830f11ca18b0299b6a6f4f"
PROTOCOL = "protocols/RISU_DIFF_E0_MACHINE_FIRST_FREEZE_v0.1.json"
QUALIFICATION = ROOT / "experiments" / "risu-diff-e0" / "MACHINE_FIRST_FREEZE_QUALIFICATION.json"
FOUNDATION = ROOT / "experiments" / "risu-diff-e0" / "FOUNDATION_QUALIFICATION.json"
EVALUATION = ROOT / "protocols" / "RISU_DIFF_E0_EVALUATION_CONTRACT_v0.1.json"
ENROLLMENT = ROOT / "corpus" / "0.1" / "ENROLLMENT.json"

ALLOWED_CHANGED = {
    ".github/workflows/risu-diff-e0-machine-freeze.yml",
    "docs/RISU_DIFF_E0_MACHINE_FIRST_FREEZE.md",
    "experiments/risu-diff-e0/MACHINE_FIRST_FREEZE_QUALIFICATION.json",
    "protocols/RISU_DIFF_E0_MACHINE_FIRST_FREEZE_v0.1.json",
    "risu_e0/machine_first.py",
    "schemas/risu-diff-e0-machine-input.v0.1.schema.json",
    "schemas/risu-diff-e0-output-seal.v0.1.schema.json",
    "tests/test_risu_diff_e0_machine_freeze.py",
    "tools/risu_e0_machine_first.py",
    "tools/risu_e0_machine_freeze_verify.py",
}


def fail(reason: str, **extra: object) -> None:
    print(json.dumps({"status": "FAIL", "reason": reason, **extra}, indent=2, sort_keys=True))
    raise SystemExit(1)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def git_text(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def git_bytes(ref: str, rel: str) -> bytes:
    try:
        return subprocess.check_output(["git", "show", f"{ref}:{rel}"], cwd=ROOT)
    except subprocess.CalledProcessError as exc:
        fail("Git object missing", ref=ref, path=rel, returncode=exc.returncode)
        raise AssertionError("unreachable")


def verify_no_network_core() -> None:
    path = ROOT / "risu_e0" / "machine_first.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    forbidden_roots = {"socket", "requests", "urllib", "http", "ftplib", "ssl"}
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in forbidden_roots:
                    found.append(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module:
            if node.module.split(".")[0] in forbidden_roots:
                found.append(node.module)
    if found:
        fail("network-capable import in sealed core", imports=sorted(set(found)))
    source = path.read_text(encoding="utf-8")
    for token in ("time.time(", "datetime.now(", "random.", "uuid.uuid"):
        if token in source:
            fail("nondeterministic primitive in sealed semantic core", token=token)


def main() -> None:
    q = json.loads(QUALIFICATION.read_text(encoding="utf-8"))
    f = json.loads(FOUNDATION.read_text(encoding="utf-8"))
    e = json.loads(EVALUATION.read_text(encoding="utf-8"))
    enrollment = json.loads(ENROLLMENT.read_text(encoding="utf-8"))

    if q["freeze_id"] != "RISU_DIFF_E0_MACHINE_FIRST_E0":
        fail("freeze identity changed")
    if q["freeze_protocol_id"] != "RISU_DIFF_E0_MACHINE_FIRST_FREEZE_001":
        fail("freeze protocol identity changed")
    if q["foundation_qualification_id"] != "RISU_DIFF_E0_FOUNDATION_001":
        fail("foundation binding changed")
    if q["evaluation_contract_id"] != "RISU_DIFF_E0_EVALUATION_001":
        fail("evaluation-contract binding changed")
    if q["base_main_sha"] != BASE:
        fail("freeze base changed", actual=q["base_main_sha"])

    subprocess.check_call(["git", "merge-base", "--is-ancestor", BASE, "HEAD"], cwd=ROOT)
    subprocess.check_call(["git", "merge-base", "--is-ancestor", PROTOCOL_FREEZE_COMMIT, "HEAD"], cwd=ROOT)

    frozen_protocol_bytes = git_bytes(PROTOCOL_FREEZE_COMMIT, PROTOCOL)
    head_protocol_bytes = git_bytes("HEAD", PROTOCOL)
    if frozen_protocol_bytes != head_protocol_bytes:
        fail("prospective machine-first protocol changed after protocol freeze")
    if sha256_bytes(head_protocol_bytes) != q["protocol_sha256"]:
        fail("protocol SHA-256 mismatch")

    if f["qualification_id"] != q["foundation_qualification_id"]:
        fail("foundation qualification record mismatch")
    for rel, expected in sorted(f["file_sha256"].items()):
        actual = sha256_bytes(git_bytes("HEAD", rel))
        if actual != expected:
            fail("foundation component changed", path=rel, expected=expected, actual=actual)

    for rel, expected in sorted(q["file_sha256"].items()):
        obj = git_bytes("HEAD", rel)
        actual = sha256_bytes(obj)
        if actual != expected:
            fail("freeze Git-object digest mismatch", path=rel, expected=expected, actual=actual)
        wt = ROOT / rel
        if not wt.is_file() or sha256_bytes(wt.read_bytes()) != actual:
            fail("freeze working tree differs from Git object", path=rel)

    component_map = q["engine_identity_components"]
    for rel, expected in sorted(component_map.items()):
        actual = sha256_bytes(git_bytes("HEAD", rel))
        if actual != expected:
            fail("engine identity component mismatch", path=rel, expected=expected, actual=actual)
    digest = sha256_bytes(canonical_bytes(component_map))
    if digest != q["engine_identity_digest"]:
        fail("engine identity digest mismatch", expected=q["engine_identity_digest"], actual=digest)

    changed = set(filter(None, git_text("diff", "--name-only", f"{BASE}...HEAD").splitlines()))
    unexpected = sorted(changed - ALLOWED_CHANGED)
    missing_expected = sorted(set(q["file_sha256"]) - changed)
    if unexpected:
        fail("freeze branch changed paths outside the prospective allowlist", paths=unexpected)
    if missing_expected:
        fail("manifested freeze path absent from branch diff", paths=missing_expected)

    units = {u["unit_id"]: u for u in enrollment["units"]}
    heldout = [f"corpus01-unit-{i:03d}" for i in range(3, 9)]
    if e["heldout_sequence"] != heldout:
        fail("evaluation held-out sequence changed")
    for uid in heldout:
        unit = units[uid]
        if unit["authoring_started"] or unit["authoring_frozen"] or unit["verdict_observed_at_enrollment"]:
            fail("held-out unit no longer pristine", unit_id=uid)

    future_dirs = sorted(
        p.name for p in (ROOT / "corpus" / "0.1" / "units").iterdir()
        if p.is_dir() and p.name[:3].isdigit() and int(p.name[:3]) >= 3
    )
    if future_dirs:
        fail("held-out scientific directory appeared before engine freeze", directories=future_dirs)

    protocol = json.loads(head_protocol_bytes.decode("utf-8"))
    if protocol["status"] != "PROSPECTIVE_PROTOCOL_FROZEN_BEFORE_IMPLEMENTATION_QUALIFICATION_AND_BEFORE_UNIT003_SEMANTIC_INSPECTION":
        fail("prospective protocol status changed")
    if protocol["contamination_boundary"]["unit003_008_target_specific_semantics_consumed_before_protocol_freeze"] is not False:
        fail("protocol contamination attestation changed")
    if protocol["qualification_before_main_freeze"]["minimum_adversarial_tests"] > q["qualification_tests_expected"]:
        fail("qualification test count below prospective minimum")
    if e["required_machine_first_artifacts"] != protocol["semantic_artifact_contract"]["required"]:
        fail("machine-first required artifact set drifted from frozen evaluation contract")

    verify_no_network_core()

    if q["file_identity"]["authority"] != "COMMITTED_GIT_OBJECT_SHA256":
        fail("file identity authority weakened")
    if q["file_identity"]["tested_checkout_must_equal_git_object"] is not True:
        fail("working-tree equality requirement weakened")

    print(json.dumps({
        "status": "PASS",
        "freeze_id": q["freeze_id"],
        "protocol_freeze_commit": PROTOCOL_FREEZE_COMMIT,
        "protocol_sha256": q["protocol_sha256"],
        "engine_identity_digest": q["engine_identity_digest"],
        "identity_authority": q["file_identity"]["authority"],
        "manifested_freeze_files_verified": len(q["file_sha256"]),
        "engine_identity_components_verified": len(component_map),
        "heldout_pristine": True,
        "heldout_sequence": heldout,
        "network_free_semantic_core": True,
        "changed_paths": sorted(changed),
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
