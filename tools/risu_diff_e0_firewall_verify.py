#!/usr/bin/env python3
import hashlib
import json
import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "protocols" / "RISU_DIFF_E0_EVALUATION_CONTRACT_v0.1.json"
SEAL = ROOT / "protocols" / "RISU_DIFF_E0_EVALUATION_CONTRACT_v0.1_SEAL.json"
ENROLLMENT = ROOT / "corpus" / "0.1" / "ENROLLMENT.json"
U1 = ROOT / "corpus" / "0.1" / "units" / "001-github-mcp-merge" / "primary-result" / "CLOSURE.json"
U2 = ROOT / "corpus" / "0.1" / "units" / "002-octokit-pulls-merge" / "CLOSURE.json"

EXPECTED_SURFACE = {
    ".github/workflows/risu-diff-e0-firewall.yml",
    "docs/RISU_DIFF_E0_EVALUATION_CONTRACT_v0.1.md",
    "protocols/RISU_DIFF_E0_EVALUATION_CONTRACT_v0.1.json",
    "protocols/RISU_DIFF_E0_EVALUATION_CONTRACT_v0.1_SEAL.json",
    "tests/test_risu_diff_e0_firewall.py",
    "tools/risu_diff_e0_firewall_verify.py",
}


def fail(reason, **extra):
    print(json.dumps({"status": "FAIL", "reason": reason, **extra}, indent=2, sort_keys=True))
    raise SystemExit(1)


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    c = json.loads(CONTRACT.read_text())
    s = json.loads(SEAL.read_text())
    enrollment = json.loads(ENROLLMENT.read_text())

    if c["status"] != "FROZEN_BEFORE_UNIT003_SEMANTIC_INSPECTION":
        fail("E0 evaluation contract is not frozen at the held-out boundary")
    if c["base_main_sha"] != "bd9ed54e9c1703f505f1b08ff3cb4c8f22c48afc":
        fail("E0 base moved", actual=c["base_main_sha"])
    if s["contract_id"] != c["contract_id"] or s["base_main_sha"] != c["base_main_sha"]:
        fail("seal/contract identity mismatch")

    base = c["base_main_sha"]
    try:
        subprocess.check_call(["git", "merge-base", "--is-ancestor", base, "HEAD"], cwd=ROOT)
    except subprocess.CalledProcessError:
        fail("frozen E0 base is not an ancestor of HEAD")

    changed = set(filter(None, git("diff", "--name-only", f"{base}...HEAD").splitlines()))
    if changed != EXPECTED_SURFACE:
        fail("E0 firewall PR changed surface is not exact", expected=sorted(EXPECTED_SURFACE), actual=sorted(changed))

    # Closed scientific history and parent CTV theory are immutable in this freeze.
    forbidden_changed_prefixes = (
        "corpus/0.1/units/001-github-mcp-merge/",
        "corpus/0.1/units/002-octokit-pulls-merge/",
        "protocols/CTV_META_THEORY_",
        "docs/CONSEQUENCE_TRANSLATION_VALIDATION_",
        "schemas/consequence-ir.",
        "schemas/refinement-map.",
    )
    bad = sorted(p for p in changed if p.startswith(forbidden_changed_prefixes))
    if bad:
        fail("E0 evaluation freeze mutated prior scientific/theory authority", paths=bad)
    if not U1.exists() or not U2.exists():
        fail("closed Unit001/002 authority missing")

    units = {u["unit_id"]: u for u in enrollment["units"]}
    expected_heldout = [f"corpus01-unit-{i:03d}" for i in range(3, 9)]
    if c["heldout_sequence"] != expected_heldout:
        fail("held-out sequence changed", actual=c["heldout_sequence"])
    for uid in expected_heldout:
        u = units[uid]
        if u["authoring_started"] or u["authoring_frozen"] or u["verdict_observed_at_enrollment"]:
            fail("future held-out unit is not pristine at firewall freeze", unit_id=uid, unit=u)

    unit_root = ROOT / "corpus" / "0.1" / "units"
    future_dirs = [p.name for p in unit_root.iterdir() if p.is_dir() and p.name[:3].isdigit() and int(p.name[:3]) >= 3]
    if future_dirs:
        fail("future held-out unit scientific directory exists before E0 freeze", directories=sorted(future_dirs))

    fw = c["development_firewall"]
    semantic = set(fw["semantic_training_allowlist"])
    guard = set(fw["guard_only_paths"])
    if semantic & guard:
        fail("guard-only paths leaked into semantic training allowlist", overlap=sorted(semantic & guard))
    banned_literals = {
        "corpus/0.1/CANDIDATE_POOL.json",
        "corpus/0.1/SCREENING_LOG.jsonl",
        "corpus/0.1/SCREENING_PROCEDURE.json",
    }
    if semantic & banned_literals:
        fail("future-candidate metadata leaked into semantic training allowlist", overlap=sorted(semantic & banned_literals))
    for prefix in semantic:
        if "/units/003" in prefix or "/units/004" in prefix or "/units/005" in prefix or "/units/006" in prefix or "/units/007" in prefix or "/units/008" in prefix:
            fail("held-out unit leaked into semantic training allowlist", path=prefix)

    if c["gold_isolation"]["machine_first_must_be_sealed_before_gold_authoring"] is not True:
        fail("machine-first sealing weakened")
    if c["gold_isolation"]["gold_authoring_must_be_blind_to_machine_first_output_until_gold_freeze"] is not True:
        fail("gold isolation weakened")
    if not c["prequential_rule"].startswith("TEST_THEN_LEARN"):
        fail("prequential test-then-learn rule weakened")

    canonical_words = {"PRESERVED", "PRESERVED_IN_DECLARED_SCOPE", "CONSEQUENCE_REGRESSION", "CONSEQUENCE_STABLE_IN_DECLARED_SCOPE", "ASSURANCE_INCOMPLETE"}
    predictions = set(c["prediction_namespace"])
    if predictions & canonical_words:
        fail("E0 prediction namespace aliases canonical scientific vocabulary", overlap=sorted(predictions & canonical_words))
    if not all(x.startswith("E0_") for x in predictions):
        fail("E0 prediction namespace contains non-E0 token", predictions=sorted(predictions))

    hard = "\n".join(c["hard_stops"]).lower()
    for phrase in ["false stable", "unsupported established fact", "silent unknown", "held-out contamination", "gold contamination", "canonical scientific verdict"]:
        if phrase not in hard:
            fail("required E0 hard stop missing", phrase=phrase)

    roles = c["evaluation_metrics"]["material_role_set"]
    if len(roles) != 5 or len(set(roles)) != 5:
        fail("VBE material role set changed unexpectedly", roles=roles)

    baselines = c["baseline_contract"]
    for key in ["B0_SURFACE", "B1_NAME_SHAPE", "B2_FLOW_ONLY", "ORACLE_HUMAN_GOLD", "extension_rule"]:
        if key not in baselines:
            fail("baseline contract incomplete", missing=key)

    for rel, expected in s["normative_file_sha256"].items():
        path = ROOT / rel
        if not path.exists():
            fail("sealed E0 normative file missing", path=rel)
        actual = sha256(path)
        if actual != expected:
            fail("sealed E0 normative file digest mismatch", path=rel, expected=expected, actual=actual)

    print(json.dumps({
        "status": "PASS",
        "contract_id": c["contract_id"],
        "base_main_sha": base,
        "heldout_sequence": expected_heldout,
        "all_heldout_units_pristine": True,
        "closed_units_untouched": True,
        "meta_theory_untouched": True,
        "semantic_training_prefixes": len(semantic),
        "guard_only_paths": sorted(guard),
        "gold_blind_isolation": True,
        "prequential_test_then_learn": True,
        "exact_changed_surface": sorted(changed),
        "hard_stop_count": len(c["hard_stops"]),
        "prediction_namespace": sorted(predictions),
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
