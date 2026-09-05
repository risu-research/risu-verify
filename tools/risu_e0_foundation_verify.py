#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "experiments" / "risu-diff-e0" / "FOUNDATION_QUALIFICATION.json"
CONTRACT = ROOT / "protocols" / "RISU_DIFF_E0_EVALUATION_CONTRACT_v0.1.json"
SEAL = ROOT / "protocols" / "RISU_DIFF_E0_EVALUATION_CONTRACT_v0.1_SEAL.json"
ENROLLMENT = ROOT / "corpus" / "0.1" / "ENROLLMENT.json"
FOUNDATION_BASE = "51f56743373e7d979fef5905f6a5c1dadf7b791e"


def fail(reason: str, **extra: object) -> None:
    print(json.dumps({"status": "FAIL", "reason": reason, **extra}, indent=2, sort_keys=True))
    raise SystemExit(1)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def main() -> None:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
    seal = json.loads(SEAL.read_text(encoding="utf-8"))
    enrollment = json.loads(ENROLLMENT.read_text(encoding="utf-8"))

    if manifest["qualification_id"] != "RISU_DIFF_E0_FOUNDATION_001":
        fail("foundation qualification identity changed")
    if manifest["base_main_sha"] != FOUNDATION_BASE:
        fail("foundation base changed", actual=manifest["base_main_sha"])
    subprocess.check_call(["git", "merge-base", "--is-ancestor", FOUNDATION_BASE, "HEAD"], cwd=ROOT)

    # Exact E0 foundation bytes: the qualification record commits to every implementation,
    # test, workflow, checker, and documentation byte except itself.
    for rel, expected in sorted(manifest["file_sha256"].items()):
        path = ROOT / rel
        if not path.is_file():
            fail("manifested foundation file missing", path=rel)
        actual = sha256(path)
        if actual != expected:
            fail("foundation byte digest mismatch", path=rel, expected=expected, actual=actual)

    # The earlier firewall verifier is a historical PR-surface auditor. Future E0 work instead
    # preserves its sealed normative bytes and rechecks the still-held-out state directly.
    for rel, expected in sorted(seal["normative_file_sha256"].items()):
        path = ROOT / rel
        if not path.is_file() or sha256(path) != expected:
            fail("sealed E0 firewall normative byte changed", path=rel)
    if contract["status"] != "FROZEN_BEFORE_UNIT003_SEMANTIC_INSPECTION":
        fail("E0 firewall status changed")
    if not contract["prequential_rule"].startswith("TEST_THEN_LEARN"):
        fail("prequential rule weakened")

    units = {u["unit_id"]: u for u in enrollment["units"]}
    expected_heldout = [f"corpus01-unit-{i:03d}" for i in range(3, 9)]
    if contract["heldout_sequence"] != expected_heldout:
        fail("held-out sequence changed", actual=contract["heldout_sequence"])
    for uid in expected_heldout:
        unit = units[uid]
        if unit["authoring_started"] or unit["authoring_frozen"] or unit["verdict_observed_at_enrollment"]:
            fail("held-out unit is no longer pristine during E0 foundation", unit_id=uid)

    unit_root = ROOT / "corpus" / "0.1" / "units"
    future_dirs = sorted(
        p.name for p in unit_root.iterdir()
        if p.is_dir() and p.name[:3].isdigit() and int(p.name[:3]) >= 3
    )
    if future_dirs:
        fail("held-out scientific directory appeared during E0 foundation", directories=future_dirs)

    changed = set(filter(None, git("diff", "--name-only", f"{FOUNDATION_BASE}...HEAD").splitlines()))
    forbidden_prefixes = (
        "corpus/0.1/units/",
        "protocols/CTV_META_THEORY_",
        "docs/CONSEQUENCE_TRANSLATION_VALIDATION_",
        "schemas/consequence-ir.",
        "schemas/refinement-map.",
        "protocols/RISU_DIFF_E0_EVALUATION_CONTRACT_",
    )
    forbidden = sorted(p for p in changed if p.startswith(forbidden_prefixes))
    if forbidden:
        fail("E0 foundation changed frozen scientific/theory/firewall authority", paths=forbidden)

    semantic = set(contract["development_firewall"]["semantic_training_allowlist"])
    guard = set(contract["development_firewall"]["guard_only_paths"])
    if semantic & guard:
        fail("guard-only paths leaked into semantic training", overlap=sorted(semantic & guard))

    print(json.dumps({
        "status": "PASS",
        "qualification_id": manifest["qualification_id"],
        "foundation_base": FOUNDATION_BASE,
        "manifested_files_verified": len(manifest["file_sha256"]),
        "heldout_sequence": expected_heldout,
        "heldout_pristine": True,
        "frozen_authority_untouched": True,
        "changed_paths": sorted(changed),
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
