#!/usr/bin/env python3
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import zipfile
from pathlib import Path
from typing import Any, Mapping

SCHEMA = "risu.e2-a3-a4-frozen48-helper-polarity-checker-only-adjudication/v0.1"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
SEMANTIC_EVIDENCE_KEYS = (
    "status", "effective_guard_form", "certificate_status", "relation",
    "certificate_sha256", "certificate_reason", "flip_count",
    "transported_guard_truths",
)
PROVENANCE_DIGEST_KEYS = (
    "path_observability_v1_digest_sha256", "path_observability_v2_digest_sha256",
)


def canonical_bytes(obj: Any) -> bytes:
    return (json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def h256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    obj = json.loads(path.read_bytes())
    if not isinstance(obj, dict):
        raise ValueError(f"root_not_object:{path.name}")
    return obj


def exact_unique_rows(doc: Mapping[str, Any], key: str) -> dict[str, Mapping[str, Any]]:
    rows = doc.get(key)
    if not isinstance(rows, list):
        raise ValueError(f"{key}_not_array")
    out: dict[str, Mapping[str, Any]] = {}
    for row in rows:
        if not isinstance(row, Mapping) or type(row.get("cell_id")) is not str:
            raise ValueError(f"{key}_invalid_row")
        cid = str(row["cell_id"])
        if cid in out:
            raise ValueError(f"{key}_duplicate:{cid}")
        out[cid] = row
    return out


def semantic_evidence(row: Mapping[str, Any]) -> dict[str, Any]:
    ev = row.get("helper_polarity_evidence")
    if not isinstance(ev, Mapping):
        raise ValueError("helper_polarity_evidence_missing")
    return {k: copy.deepcopy(ev.get(k)) for k in SEMANTIC_EVIDENCE_KEYS}


def valid_provenance_digests(row: Mapping[str, Any]) -> bool:
    ev = row.get("helper_polarity_evidence")
    if not isinstance(ev, Mapping):
        return False
    return all(type(ev.get(k)) is str and HEX64.fullmatch(str(ev[k])) is not None for k in PROVENANCE_DIGEST_KEYS)


def zip_docs(zip_path: Path, protocol: Mapping[str, Any]) -> tuple[dict[str, bytes], dict[str, Any]]:
    raw = zip_path.read_bytes()
    authority = protocol["authority"]
    if len(raw) != int(authority["immutable_first_complete_zip_bytes"]):
        raise ValueError("zip_byte_count_mismatch")
    if h256(raw) != authority["immutable_first_complete_zip_sha256"]:
        raise ValueError("zip_sha256_mismatch")
    contract = protocol["immutable_input_contract"]
    required = list(contract["required_zip_members"])
    with zipfile.ZipFile(zip_path) as zf:
        names = zf.namelist()
        if sorted(names) != sorted(required) or len(names) != len(set(names)):
            raise ValueError("zip_member_set_mismatch")
        blobs = {name: zf.read(name) for name in names}
    for name, expected in contract["member_sha256"].items():
        if name not in blobs or h256(blobs[name]) != expected:
            raise ValueError(f"zip_member_sha256_mismatch:{name}")
    docs: dict[str, Any] = {}
    for name, data in blobs.items():
        if not name.endswith(".json"):
            continue
        obj = json.loads(data)
        if not isinstance(obj, dict):
            raise ValueError(f"zip_json_root_not_object:{name}")
        docs[name] = obj
    return blobs, docs


def authoritative_historical_hashes(receipt: Mapping[str, Any]) -> tuple[str, str]:
    try:
        files = receipt["artifact"]["files"]
        p = files["primary_run1.json"]["sha256"]
        i = files["independent_run1.json"]["sha256"]
        status = receipt["first_complete_result"]["official_overall_status"]
        qp = receipt["first_complete_result"]["primary_qualified_count"]
        qi = receipt["first_complete_result"]["independent_qualified_count"]
    except (KeyError, TypeError) as exc:
        raise ValueError("historical_receipt_shape") from exc
    if status != "FROZEN_FAIL" or qp != 26 or qi != 26:
        raise ValueError("historical_receipt_result_mismatch")
    if not (isinstance(p, str) and isinstance(i, str) and HEX64.fullmatch(p) and HEX64.fullmatch(i)):
        raise ValueError("historical_receipt_hash_shape")
    return p, i


def evaluate(protocol: Mapping[str, Any], erratum: Mapping[str, Any], diagnosis: Mapping[str, Any], historical_receipt: Mapping[str, Any], blobs: Mapping[str, bytes], docs: Mapping[str, Any]) -> dict[str, Any]:
    failures: list[str] = []
    def fail(label: str) -> None:
        if label not in failures:
            failures.append(label)

    if erratum.get("status") != "FROZEN_PRE_IMPLEMENTATION_PRE_EXECUTION_ERRATUM": fail("erratum_status")
    if diagnosis.get("status") != "ROOT_CAUSE_ESTABLISHED_CHECKER_BOOKKEEPING_DEFECT": fail("diagnosis_status")

    hp = docs["historical_primary.json"]
    hi = docs["historical_independent.json"]
    p1 = docs["primary_run1.json"]
    p2 = docs["primary_run2.json"]
    i1 = docs["independent_run1.json"]
    i2 = docs["independent_run2.json"]
    summary = docs["first_complete_summary.json"]
    cross = docs["cross_check.json"]
    exits = docs["exit_codes.json"]
    source_receipt = docs["source_read_receipt.json"]

    gate = protocol["adjudication_gate"]
    hist_contract = protocol["historical_authority_contract"]
    legacy = protocol["legacy_exit_contract"]
    partition = protocol["frozen_partition"]

    if summary.get("status") != gate["require_original_first_complete_summary_status"]: fail("original_summary_status_not_preserved")
    if summary.get("failures") != gate["require_original_first_complete_failures_exact"]: fail("original_summary_failure_set_not_preserved")
    if cross.get("status") != gate["require_cross_check_status"] or cross.get("agreed_count") != 48 or cross.get("mismatch_cell_ids") != []: fail("frozen_cross_check")
    if exits != legacy["expected_exit_codes"]: fail("legacy_exit_contract")
    if blobs["primary_run1.json"] != blobs["primary_run2.json"]: fail("primary_repeat_byte_identity")
    if blobs["independent_run1.json"] != blobs["independent_run2.json"]: fail("independent_repeat_byte_identity")
    if h256(blobs["transport_bundle.json"]) != gate["require_transport_bundle_sha256"]: fail("transport_bundle_digest")

    try:
        receipt_p, receipt_i = authoritative_historical_hashes(historical_receipt)
    except ValueError as exc:
        receipt_p = receipt_i = ""
        fail(str(exc))
    if receipt_p != hist_contract["authoritative_primary_sha256"] or receipt_i != hist_contract["authoritative_independent_sha256"]:
        fail("protocol_vs_historical_receipt_hash_mismatch")
    if h256(blobs["historical_primary.json"]) != receipt_p: fail("historical_primary_exact_authoritative_bytes")
    if h256(blobs["historical_independent.json"]) != receipt_i: fail("historical_independent_exact_authoritative_bytes")

    for label, doc, expected_q in (("historical_primary", hp, 26), ("historical_independent", hi, 26), ("new_primary", p1, 31), ("new_independent", i1, 31)):
        if doc.get("case_count") != 48: fail(f"{label}_case_count")
        if doc.get("status") != "FAIL": fail(f"{label}_legacy_top_level_status")
        if doc.get("qualified_count") != expected_q: fail(f"{label}_qualified_count")
        if doc.get("semantic_authority") is not False: fail(f"{label}_semantic_authority")
        if doc.get("candidate_58_bytes_read") is not False or doc.get("a3_a4_semantic_verdicts_emitted") is not False:
            fail(f"{label}_firewall")

    try:
        hpr = exact_unique_rows(hp, "rows"); hir = exact_unique_rows(hi, "rows")
        pr = exact_unique_rows(p1, "rows"); ir = exact_unique_rows(i1, "rows")
        hpc = exact_unique_rows(hp, "canonical_rows"); hic = exact_unique_rows(hi, "canonical_rows")
        pc = exact_unique_rows(p1, "canonical_rows"); ic = exact_unique_rows(i1, "canonical_rows")
    except ValueError as exc:
        fail(str(exc)); hpr=hir=pr=ir=hpc=hic=pc=ic={}

    ids = set(pr)
    excluded = set(partition["transport_ineligible_cells"])
    fixed = set(partition["diagnosed_helper_polarity_cells"])
    eligible = ids - excluded
    prior = eligible - fixed
    if len(ids) != 48 or ids != set(ir) or ids != set(hpr) or ids != set(hir): fail("selected_identity_set")
    if (len(excluded), len(eligible), len(prior), len(fixed)) != (17,31,26,5): fail("partition_cardinality")
    if hpc != hic: fail("historical_primary_independent_canonical_agreement")
    if pc != ic: fail("new_primary_independent_canonical_agreement")

    if ids:
        for cid in sorted(excluded):
            for label, row in (("primary", pr[cid]), ("independent", ir[cid])):
                if row.get("qualification_status") != "OBSERVABILITY_INCOMPLETE": fail(f"{label}:{cid}:ineligible_status")
                if row.get("sorted_reasons") != ["OBSERVABILITY_INCOMPLETE_TRANSPORT"]: fail(f"{label}:{cid}:ineligible_reason")
                if row.get("base_ir_status") != "NOT_EVALUATED": fail(f"{label}:{cid}:ineligible_base_ir")
                if row.get("overlay_status") != "NOT_EVALUATED": fail(f"{label}:{cid}:ineligible_overlay")
                if row.get("path_observability_status") != "NOT_EVALUATED": fail(f"{label}:{cid}:ineligible_path")
                if row.get("anchor_usability") != "INCOMPLETE": fail(f"{label}:{cid}:ineligible_anchor")
            if pc[cid] != hpc[cid] or ic[cid] != hic[cid]: fail(f"{cid}:ineligible_canonical_changed")

        for cid in sorted(prior):
            if hpr[cid].get("qualification_status") != "OBSERVABILITY_QUALIFIED_FOR_A3_A4_EXECUTION": fail(f"{cid}:historical_prior_not_qualified")
            if pr[cid].get("qualification_status") != "OBSERVABILITY_QUALIFIED_FOR_A3_A4_EXECUTION" or ir[cid].get("qualification_status") != "OBSERVABILITY_QUALIFIED_FOR_A3_A4_EXECUTION": fail(f"{cid}:prior_not_preserved")
            if pc[cid] != hpc[cid] or ic[cid] != hic[cid]: fail(f"{cid}:prior_canonical_changed")

        for cid in sorted(fixed):
            if hpr[cid].get("qualification_status") != "OBSERVABILITY_INCOMPLETE": fail(f"{cid}:historical_fixed_not_incomplete")
            for label, row in (("primary", pr[cid]), ("independent", ir[cid])):
                if row.get("qualification_status") != "OBSERVABILITY_QUALIFIED_FOR_A3_A4_EXECUTION": fail(f"{label}:{cid}:not_promoted")
                if row.get("effective_guard_form") != "HELPER_CONTROL": fail(f"{label}:{cid}:guard_form")
                try:
                    ev = semantic_evidence(row)
                except ValueError:
                    fail(f"{label}:{cid}:evidence_missing"); continue
                if ev["status"] != "EVALUATED" or ev["effective_guard_form"] != "HELPER_CONTROL" or ev["certificate_status"] != "PROVED": fail(f"{label}:{cid}:certificate_state")
                if type(ev["certificate_sha256"]) is not str or HEX64.fullmatch(str(ev["certificate_sha256"])) is None: fail(f"{label}:{cid}:certificate_hash")
                if not valid_provenance_digests(row): fail(f"{label}:{cid}:provenance_digest_shape")
            try:
                if semantic_evidence(pr[cid]) != semantic_evidence(ir[cid]): fail(f"{cid}:semantic_certificate_cross_checker_mismatch")
            except ValueError:
                pass

        changed = {cid for cid in ids if pc[cid] != hpc[cid]}
        if changed != fixed: fail("canonical_delta_set")
        pq = {cid for cid,row in pr.items() if row.get("qualification_status") == "OBSERVABILITY_QUALIFIED_FOR_A3_A4_EXECUTION"}
        iq = {cid for cid,row in ir.items() if row.get("qualification_status") == "OBSERVABILITY_QUALIFIED_FOR_A3_A4_EXECUTION"}
        if pq != eligible or iq != eligible: fail("31_of_31_admission_gate")
    else:
        changed=set(); pq=iq=set()

    if source_receipt.get("status") != "PASS" or source_receipt.get("selected48_source_blob_count") != 48 or source_receipt.get("candidate58_read") is not False or source_receipt.get("epistemic10_read") is not False or source_receipt.get("raw_blind58_transport_read") is not False:
        fail("source_read_firewall_receipt")

    status = "PASS_CLOSED_ADJUDICATED" if not failures else "FAIL_ADJUDICATION"
    return {
        "schema": SCHEMA,
        "status": status,
        "classification": "CHECKER_ONLY_POST_FREEZE_ADJUDICATION_OF_IMMUTABLE_FIRST_COMPLETE_OUTPUTS",
        "original_first_complete_status_preserved": "FROZEN_FAIL",
        "original_first_complete_result_status_preserved": summary.get("status"),
        "root_cause_class": "CHECKER_BOOKKEEPING_DEFECT",
        "case_count": 48,
        "strict_transport_eligible_count": len(eligible),
        "strict_transport_ineligible_count": len(excluded),
        "qualified_given_admission_primary": len(pq),
        "qualified_given_admission_independent": len(iq),
        "diagnosed_helper_polarity_count": len(fixed),
        "canonical_agreed_count": sum(1 for cid in ids if cid in ic and pc[cid] == ic[cid]),
        "changed_canonical_cell_ids": sorted(changed),
        "historical_reproduction": {
            "primary_exact_authoritative_bytes": h256(blobs["historical_primary.json"]) == receipt_p,
            "independent_exact_authoritative_bytes": h256(blobs["historical_independent.json"]) == receipt_i,
            "historical_primary_status": hp.get("status"),
            "historical_independent_status": hi.get("status"),
            "historical_primary_qualified_count": hp.get("qualified_count"),
            "historical_independent_qualified_count": hi.get("qualified_count"),
        },
        "legacy_exit_contract": {
            "observed": exits,
            "expected": legacy["expected_exit_codes"],
            "exact_match": exits == legacy["expected_exit_codes"],
            "interpretation": legacy["interpretation"],
        },
        "repeat_byte_identity": {
            "primary": blobs["primary_run1.json"] == blobs["primary_run2.json"],
            "independent": blobs["independent_run1.json"] == blobs["independent_run2.json"],
        },
        "coverage_statement": "31/48 strict-transport eligible; 31/31 observability-qualified given admission; 17/17 conservative transport exclusions preserved.",
        "mandatory_interpretation": protocol["result_contract"]["mandatory_statement"],
        "failure_count": len(failures),
        "failures": failures,
        "scientific_rerun": False,
        "source_or_transport_execution": False,
        "candidate58_read": False,
        "a3_a4_semantic_verdict_execution": False,
    }


def run_self_tests(protocol: Mapping[str, Any], erratum: Mapping[str, Any], diagnosis: Mapping[str, Any], historical_receipt: Mapping[str, Any], blobs: Mapping[str, bytes], docs: Mapping[str, Any]) -> dict[str, Any]:
    base = evaluate(protocol, erratum, diagnosis, historical_receipt, blobs, docs)
    if base["status"] != "PASS_CLOSED_ADJUDICATED":
        raise AssertionError("base_input_does_not_pass_before_self_tests:" + ",".join(base["failures"]))
    passed: list[str] = []

    # 1 wrong historical hash rejected
    bad_receipt = copy.deepcopy(historical_receipt)
    bad_receipt["artifact"]["files"]["primary_run1.json"]["sha256"] = "0" * 64
    if evaluate(protocol, erratum, diagnosis, bad_receipt, blobs, docs)["status"] == "FAIL_ADJUDICATION": passed.append("wrong_historical_hash_rejected")

    # 2 zero exit code rejected
    bad_docs = copy.deepcopy(docs); bad_docs["exit_codes.json"]["primary_run1"] = 0
    if evaluate(protocol, erratum, diagnosis, historical_receipt, blobs, bad_docs)["status"] == "FAIL_ADJUDICATION": passed.append("zero_exit_code_rejected")

    excluded = protocol["frozen_partition"]["transport_ineligible_cells"][0]
    fixed = protocol["frozen_partition"]["diagnosed_helper_polarity_cells"][0]
    prior_candidates = sorted(set(r["cell_id"] for r in docs["primary_run1.json"]["rows"]) - set(protocol["frozen_partition"]["transport_ineligible_cells"]) - set(protocol["frozen_partition"]["diagnosed_helper_polarity_cells"]))
    prior = prior_candidates[0]

    # 3 promoted transport-ineligible rejected
    bad_docs = copy.deepcopy(docs)
    for name in ("primary_run1.json", "independent_run1.json"):
        next(r for r in bad_docs[name]["rows"] if r["cell_id"] == excluded)["qualification_status"] = "OBSERVABILITY_QUALIFIED_FOR_A3_A4_EXECUTION"
    if evaluate(protocol, erratum, diagnosis, historical_receipt, blobs, bad_docs)["status"] == "FAIL_ADJUDICATION": passed.append("promoted_transport_ineligible_rejected")

    # 4 missing diagnosed promotion rejected
    bad_docs = copy.deepcopy(docs)
    for name in ("primary_run1.json", "independent_run1.json"):
        next(r for r in bad_docs[name]["rows"] if r["cell_id"] == fixed)["qualification_status"] = "OBSERVABILITY_INCOMPLETE"
    if evaluate(protocol, erratum, diagnosis, historical_receipt, blobs, bad_docs)["status"] == "FAIL_ADJUDICATION": passed.append("missing_diagnosed_promotion_rejected")

    # 5 unexpected canonical delta rejected
    bad_docs = copy.deepcopy(docs)
    for name in ("primary_run1.json", "independent_run1.json"):
        row = next(r for r in bad_docs[name]["canonical_rows"] if r["cell_id"] == prior)
        row["effective_guard_form"] = "UNPROVEN"
    if evaluate(protocol, erratum, diagnosis, historical_receipt, blobs, bad_docs)["status"] == "FAIL_ADJUDICATION": passed.append("unexpected_canonical_delta_rejected")

    # 6 primary-independent mismatch rejected
    bad_docs = copy.deepcopy(docs)
    row = next(r for r in bad_docs["independent_run1.json"]["canonical_rows"] if r["cell_id"] == prior)
    row["effective_guard_form"] = "UNPROVEN"
    if evaluate(protocol, erratum, diagnosis, historical_receipt, blobs, bad_docs)["status"] == "FAIL_ADJUDICATION": passed.append("primary_independent_mismatch_rejected")

    # 7 missing certificate rejected
    bad_docs = copy.deepcopy(docs)
    for name in ("primary_run1.json", "independent_run1.json"):
        next(r for r in bad_docs[name]["rows"] if r["cell_id"] == fixed)["helper_polarity_evidence"]["certificate_status"] = None
    if evaluate(protocol, erratum, diagnosis, historical_receipt, blobs, bad_docs)["status"] == "FAIL_ADJUDICATION": passed.append("missing_certificate_rejected")

    # 8 wrong zip member hash rejected by immutable member-hash contract
    contract = copy.deepcopy(protocol["immutable_input_contract"])
    contract["member_sha256"]["cross_check.json"] = "0" * 64
    rejected = h256(blobs["cross_check.json"]) != contract["member_sha256"]["cross_check.json"]
    if rejected: passed.append("wrong_zip_member_hash_rejected")

    required = protocol["self_tests"]["required"]
    return {"status":"PASS" if passed == required else "FAIL", "count":len(passed), "required_count":len(required), "passed":passed, "required":required}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--protocol", required=True)
    ap.add_argument("--erratum", required=True)
    ap.add_argument("--diagnosis", required=True)
    ap.add_argument("--historical-receipt", required=True)
    ap.add_argument("--zip", required=True)
    ap.add_argument("--output", required=True)
    args = ap.parse_args()

    protocol = read_json(Path(args.protocol))
    erratum = read_json(Path(args.erratum))
    diagnosis = read_json(Path(args.diagnosis))
    historical_receipt = read_json(Path(args.historical_receipt))
    blobs, docs = zip_docs(Path(args.zip), protocol)
    result = evaluate(protocol, erratum, diagnosis, historical_receipt, blobs, docs)
    self_tests = run_self_tests(protocol, erratum, diagnosis, historical_receipt, blobs, docs)
    result["self_tests"] = self_tests
    if self_tests["status"] != "PASS":
        result["status"] = "FAIL_ADJUDICATION"
        result["failures"] = list(result["failures"]) + ["self_tests"]
        result["failure_count"] = len(result["failures"])
    Path(args.output).write_bytes(canonical_bytes(result))
    print(json.dumps({"status":result["status"],"failure_count":result["failure_count"],"self_test_count":self_tests["count"],"bytes":Path(args.output).stat().st_size,"sha256":h256(Path(args.output).read_bytes())},sort_keys=True,separators=(",",":")))
    return 0 if result["status"] == "PASS_CLOSED_ADJUDICATED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
