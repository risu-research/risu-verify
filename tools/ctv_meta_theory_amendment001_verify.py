#!/usr/bin/env python3
import hashlib
import json
import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
AMENDMENT_PATH = ROOT / "protocols" / "CTV_META_THEORY_v0.1_AMENDMENT_001.json"
SEAL_PATH = ROOT / "protocols" / "CTV_META_THEORY_v0.1_AMENDMENT_001_SEAL.json"
ENROLLMENT_PATH = ROOT / "corpus" / "0.1" / "ENROLLMENT.json"
U1_CLOSURE = ROOT / "corpus" / "0.1" / "units" / "001-github-mcp-merge" / "primary-result" / "CLOSURE.json"
U2_CLOSURE = ROOT / "corpus" / "0.1" / "units" / "002-octokit-pulls-merge" / "CLOSURE.json"

EXPECTED_CHANGED_FROM_PARENT = {
    ".github/workflows/ctv-meta-theory.yml",
    "docs/CONSEQUENCE_TRANSLATION_VALIDATION_v0.1_AMENDMENT_001.md",
    "protocols/CTV_META_THEORY_v0.1_AMENDMENT_001.json",
    "protocols/CTV_META_THEORY_v0.1_AMENDMENT_001_SEAL.json",
    "tests/test_ctv_meta_theory_amendment001.py",
    "tools/ctv_meta_theory_amendment001_verify.py",
}


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def fail(reason, **extra):
    payload = {"status": "FAIL", "reason": reason, **extra}
    print(json.dumps(payload, indent=2, sort_keys=True))
    raise SystemExit(1)


def main():
    amendment = json.loads(AMENDMENT_PATH.read_text())
    seal = json.loads(SEAL_PATH.read_text())
    enrollment = json.loads(ENROLLMENT_PATH.read_text())

    if amendment["amendment_id"] != "RISU_CTV_META_THEORY_AMENDMENT_001":
        fail("amendment identity changed")
    if amendment["parent_contract_id"] != "RISU_CTV_META_THEORY_001":
        fail("parent contract identity changed")
    if amendment["status"] != "FROZEN_PRE_UNIT003_PRE_VERDICT":
        fail("A001 is not frozen pre-Unit003/pre-verdict")
    if seal["status"] != "SEALED_PRE_UNIT003_PRE_VERDICT":
        fail("A001 seal status changed")
    if seal["amendment_id"] != amendment["amendment_id"]:
        fail("A001 seal/amendment identity mismatch")
    if seal["parent_merge_sha"] != amendment["parent_merge_sha"]:
        fail("A001 parent merge mismatch")

    parent = amendment["parent_merge_sha"]
    try:
        subprocess.check_call(["git", "merge-base", "--is-ancestor", parent, "HEAD"], cwd=ROOT)
    except subprocess.CalledProcessError:
        fail("A001 parent merge is not an ancestor of HEAD", parent_merge_sha=parent)

    units = {u["unit_id"]: u for u in enrollment["units"]}
    u3 = units["corpus01-unit-003"]
    if u3["authoring_started"] or u3["authoring_frozen"] or u3["verdict_observed_at_enrollment"]:
        fail("Unit003 is not pristine at A001 boundary", unit003=u3)
    timing = amendment["timing"]
    if timing != {
        "effective_from_unit": "corpus01-unit-003",
        "unit003_authoring_started_at_amendment": False,
        "unit003_authoring_frozen_at_amendment": False,
        "unit003_verdict_observed_at_amendment": False,
    }:
        fail("A001 timing attestation changed", timing=timing)

    changed = set(filter(None, git("diff", "--name-only", f"{parent}...HEAD").splitlines()))
    if changed != EXPECTED_CHANGED_FROM_PARENT:
        fail(
            "A001 changed surface is not exact",
            expected=sorted(EXPECTED_CHANGED_FROM_PARENT),
            actual=sorted(changed),
        )

    if not U1_CLOSURE.exists() or not U2_CLOSURE.exists():
        fail("closed-unit authority missing")
    u2_text = U2_CLOSURE.read_text()
    for token in ['"PRESERVED_IN_DECLARED_SCOPE"', '"coverage_complete": false']:
        if token not in u2_text:
            fail("Unit002 canonical boundary no longer present", token=token)

    anti = amendment["anti_retroactivity"]
    if anti != {
        "rule": "NO_REINTERPRETATION_NO_UPGRADE",
        "corpus01-unit-001": "UNCHANGED_CANONICAL_HISTORY",
        "corpus01-unit-002": "UNCHANGED_CANONICAL_HISTORY",
        "historical_recompute_forbidden": True,
    }:
        fail("A001 anti-retroactivity weakened", actual=anti)

    for rel, expected in seal["normative_file_sha256"].items():
        path = ROOT / rel
        if not path.exists():
            fail("A001 sealed normative file missing", path=rel)
        actual = sha256(path)
        if actual != expected:
            fail("A001 sealed normative digest mismatch", path=rel, expected=expected, actual=actual)

    if set(amendment["defects_closed"]) != {
        "EMPTY_INTERPRETATION_VACUITY",
        "IMPLICIT_COMPATIBILITY_TOTAL_ORDER",
    }:
        fail("A001 defect scope changed")

    overrides = amendment["normative_overrides"]
    nonempty = overrides["interpretation_nonemptiness"]
    if "M(r) MUST be nonempty" not in nonempty["rule"]:
        fail("nonempty interpretation requirement weakened")
    if "M(r) is nonempty" not in nonempty["effective_relational_refinement"]:
        fail("effective relational refinement lost nonempty mapping condition")
    if "factorization/kernel rule" not in nonempty["deterministic_bridge"]:
        fail("deterministic bridge changed")

    compat = overrides["compatibility_structure"]
    if compat["kind"] != "NAMED_OBLIGATION_VECTOR_NOT_TOTAL_ORDER":
        fail("compatibility structure became implicitly ordered")
    if compat["implicit_level_implications"] != []:
        fail("implicit compatibility implications introduced", edges=compat["implicit_level_implications"])

    verdict = overrides["verdict_hardening"]
    if "nonempty consequence interpretation" not in verdict["consequence_stable"]:
        fail("stable verdict lost nonempty interpretation requirement")
    if "ASSURANCE_INCOMPLETE" not in verdict["assurance_incomplete"]:
        fail("uninterpreted realization no longer fails closed")

    print(json.dumps({
        "status": "PASS",
        "amendment_id": amendment["amendment_id"],
        "parent_merge_sha": parent,
        "unit003_pristine": True,
        "pre_verdict": True,
        "anti_retroactivity": True,
        "empty_interpretation_vacuity_closed": True,
        "compatibility_structure": compat["kind"],
        "implicit_level_implications": compat["implicit_level_implications"],
        "sealed_normative_files": len(seal["normative_file_sha256"]),
        "exact_changed_surface": sorted(changed),
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
