#!/usr/bin/env python3
import hashlib
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "protocols" / "CTV_META_THEORY_v0.1.json"
SEAL_PATH = ROOT / "protocols" / "CTV_META_THEORY_v0.1_SEAL.json"
ENROLLMENT_PATH = ROOT / "corpus" / "0.1" / "ENROLLMENT.json"
U1_CLOSURE = ROOT / "corpus" / "0.1" / "units" / "001-github-mcp-merge" / "primary-result" / "CLOSURE.json"
U2_CLOSURE = ROOT / "corpus" / "0.1" / "units" / "002-octokit-pulls-merge" / "CLOSURE.json"


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def fail(reason, **extra):
    payload = {"status": "FAIL", "reason": reason, **extra}
    print(json.dumps(payload, indent=2, sort_keys=True))
    raise SystemExit(1)


def main():
    contract = json.loads(CONTRACT_PATH.read_text())
    seal = json.loads(SEAL_PATH.read_text())
    enrollment = json.loads(ENROLLMENT_PATH.read_text())

    if contract["status"] != "FROZEN_BEFORE_UNIT003_AUTHORING":
        fail("meta-theory status is not frozen")
    if contract["effective_from_unit"] != "corpus01-unit-003":
        fail("effective unit moved")
    if contract["retroactivity_rule"] != "NO_REINTERPRETATION_NO_UPGRADE":
        fail("anti-retroactivity rule changed")
    if seal["status"] != "SEALED_BEFORE_UNIT003_AUTHORING":
        fail("seal status changed")
    if seal["base_main_sha"] != contract["base_main_sha"]:
        fail("seal/contract base-main mismatch")

    base = contract["base_main_sha"]
    try:
        subprocess.check_call(["git", "merge-base", "--is-ancestor", base, "HEAD"], cwd=ROOT)
    except subprocess.CalledProcessError:
        fail("frozen pre-Unit003 base is not an ancestor of HEAD", base_main_sha=base)

    units = {u["unit_id"]: u for u in enrollment["units"]}
    u3 = units["corpus01-unit-003"]
    if u3["authoring_started"] or u3["authoring_frozen"] or u3["verdict_observed_at_enrollment"]:
        fail("Unit003 is not pristine at the v0.1 freeze boundary", unit003=u3)

    # This freeze may add only meta-theory machinery. Closed scientific objects stay byte/history untouched.
    changed = sorted(filter(None, git("diff", "--name-only", f"{base}...HEAD").splitlines()))
    forbidden_prefixes = (
        "corpus/0.1/units/001-github-mcp-merge/",
        "corpus/0.1/units/002-octokit-pulls-merge/",
    )
    forbidden = [p for p in changed if p.startswith(forbidden_prefixes)]
    if forbidden:
        fail("meta-theory branch changed closed Unit001/002 scientific history", paths=forbidden)

    if not U1_CLOSURE.exists() or not U2_CLOSURE.exists():
        fail("closed-unit authority missing")
    u2_text = U2_CLOSURE.read_text()
    for token in ['"PRESERVED_IN_DECLARED_SCOPE"', '"coverage_complete": false']:
        if token not in u2_text:
            fail("Unit002 canonical boundary no longer present", token=token)

    for rel, expected in seal["normative_file_sha256"].items():
        path = ROOT / rel
        if not path.exists():
            fail("sealed normative file missing", path=rel)
        actual = sha256(path)
        if actual != expected:
            fail("sealed normative file digest mismatch", path=rel, expected=expected, actual=actual)

    required_theory = {
        "general_relational_refinement",
        "deterministic_factorization",
        "deterministic_equivalent_kernel_rule",
        "deterministic_regression_witness",
        "repair_rule",
    }
    if set(contract["theory"]) != required_theory:
        fail("normative theory clause set changed", actual=sorted(contract["theory"]))

    future = set(contract["future_verdicts"])
    historical = {"PRESERVED", "PRESERVED_IN_DECLARED_SCOPE", "CLOSED"}
    if future & historical:
        fail("future verdict namespace aliases closed canonical vocabulary", overlap=sorted(future & historical))

    if contract["refinement_mapping"]["must_be_explicit"] is not True:
        fail("explicit refinement mapping weakened")
    if contract["coverage_model_adequacy_separation"] is not True:
        fail("coverage/model-adequacy separation weakened")

    cir_schema = json.loads((ROOT / contract["cir"]["schema"]).read_text())
    map_schema = json.loads((ROOT / contract["refinement_mapping"]["schema"]).read_text())
    cir_node_enum = set(cir_schema["properties"]["nodes"]["items"]["properties"]["kind"]["enum"])
    cir_edge_enum = set(cir_schema["properties"]["edges"]["items"]["properties"]["kind"]["enum"])
    map_rel_enum = set(map_schema["properties"]["entries"]["items"]["properties"]["relation"]["enum"])
    if cir_node_enum != set(contract["cir"]["node_kinds"]):
        fail("CIR node schema/contract divergence")
    if cir_edge_enum != set(contract["cir"]["edge_kinds"]):
        fail("CIR edge schema/contract divergence")
    if map_rel_enum != set(contract["refinement_mapping"]["relations"]):
        fail("refinement-map schema/contract divergence")

    print(json.dumps({
        "status": "PASS",
        "contract_id": contract["contract_id"],
        "base_main_sha": base,
        "effective_from_unit": contract["effective_from_unit"],
        "unit003_pristine": True,
        "anti_retroactivity": True,
        "sealed_normative_files": len(seal["normative_file_sha256"]),
        "changed_paths_from_pre_unit003_base": changed,
        "deterministic_theory": "factorization <=> kernel inclusion <=> no collapse witness",
        "future_verdicts": sorted(future),
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
