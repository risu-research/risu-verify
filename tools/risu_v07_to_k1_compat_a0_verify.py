#!/usr/bin/env python3
import copy
import importlib.util
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
ADAPTER_PATH = ROOT / "adapters" / "v07_to_k1_compat_a0.py"
SNAPSHOT_PATH = ROOT / "compatibility" / "v07_k1" / "VBE_CALIBRATION_4ROW_SNAPSHOT.json"

spec = importlib.util.spec_from_file_location("v07_to_k1_compat_a0", ADAPTER_PATH)
A = importlib.util.module_from_spec(spec)
spec.loader.exec_module(A)


def expect_failure(label, fn, *args):
    try:
        fn(*args)
    except (A.CompatError, A.K.Reject, A.K.Unsupported):
        return {"test": label, "result": "PASS"}
    raise AssertionError(label + ": expected failure")


def main():
    snapshot = json.loads(SNAPSHOT_PATH.read_text(encoding="utf-8"))
    result = A.run(snapshot)
    assert result["status"] == "PASS"
    assert result["semantic_equivalence"] == "4/4"
    assert result["diagnostic_ablation_invariance"] == "4/4"
    assert result["kernel_primitives_needed_from_v07"] == []
    assert result["implementation_binding"] is False

    tests = [{"test": "baseline_4_of_4", "result": "PASS"}]

    rows = {row["instance"]: row for row in result["rows"]}
    assert rows["001-github-guarded-merge"]["forbidden_pair_count"] == 1
    assert rows["003-before-github-blob-sha"]["forbidden_pair_count"] == 1
    assert rows["002-azure-wiki-etag"]["forbidden_pair_count"] == 0
    assert rows["003-after-github-blob-sha"]["forbidden_pair_count"] == 0
    tests.append({"test": "forbidden_pair_structure", "result": "PASS"})

    # Anti-tautology: changing frozen semantics while retaining the legacy label
    # must cause equivalence failure. The adapter may not simply copy status.
    semantic_tamper = copy.deepcopy(snapshot)
    row = next(r for r in semantic_tamper["rows"] if r["instance"] == "002-azure-wiki-etag")
    world = next(w for w in row["worlds"] if w["world"] == "W-91d952c20f111d685f4a")
    world["projected_effect"] = {"space": "C", "label": "UPDATE_COMMITTED"}
    world["matches"] = False
    tests.append(expect_failure("semantic_tamper_breaks_equivalence", A.run, semantic_tamper))

    # Diagnostics may vary without entering the semantic result.
    diagnostic_tamper = copy.deepcopy(snapshot)
    for row in diagnostic_tamper["rows"]:
        row["structural"] = {"C": "ATTACK", "D": "ATTACK", "O": "ATTACK"}
        row["exact_status"] = "ATTACK"
        row["exact_failure_mode"] = "ATTACK"
        for world in row["worlds"]:
            world["coordinates"] = {"attacker": "changed-nonsemantic-metadata"}
    diagnostic_result = A.run(diagnostic_tamper)
    assert diagnostic_result["semantic_equivalence"] == "4/4"
    tests.append({"test": "diagnostic_tamper_semantically_inert", "result": "PASS"})

    # The pinned source locator is constitutional input to this migration test.
    provenance_tamper = copy.deepcopy(snapshot)
    provenance_tamper["source"]["git_blob_sha1"] = "0" * 40
    tests.append(expect_failure("source_locator_tamper_rejected", A.run, provenance_tamper))

    # OUTSIDE_C must remain open-universe target-native, not be erased/coerced.
    outside = next(r for r in rows.values() if r["instance"] == "001-github-guarded-merge")
    translated = next(w for w in outside["translated_worlds"] if not w["frozen_matches"])
    assert translated["realized_atom"].startswith("OUTSIDE_C:")
    assert translated["realized_consequence_id"] != translated["required_consequence_id"]
    tests.append({"test": "outside_c_survives_as_target_native_consequence", "result": "PASS"})

    # BEFORE and AFTER share the same legacy source semantic digest, while K1
    # reproduces the repair transition by changing the realized target relation.
    before = rows["003-before-github-blob-sha"]
    after = rows["003-after-github-blob-sha"]
    assert before["legacy_source_semantic_digest"] == after["legacy_source_semantic_digest"]
    assert before["claim_id"] == after["claim_id"]
    assert before["target_id"] != after["target_id"]
    assert before["k1_product_status"] == "CONSEQUENCE_REGRESSION"
    assert after["k1_product_status"] == "PRESERVED"
    tests.append({"test": "historical_repair_same_claim_changed_target", "result": "PASS"})

    print(json.dumps({
        "status": "PASS",
        "gate": "RISU_V07_TO_K1_COMPAT_A0_VERIFY",
        "source_commit": snapshot["source"]["commit"],
        "source_blob": snapshot["source"]["git_blob_sha1"],
        "equivalence": result["semantic_equivalence"],
        "tests": tests,
        "test_count": len(tests),
        "conclusion": "The K1 ALLOW/REALIZE + W1 finite-model checker reproduces all four frozen calibration conclusions without C/D/O or Exact as kernel primitives. This is calibration equivalence only, not new implementation assurance."
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
