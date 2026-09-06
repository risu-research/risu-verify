#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from e2_a3_a4_candidate_observability_microcheck import (
    canon, sha, rerun, compact,
)

PRIMARY_SCHEMA = "risu.e2-a3-a4-candidate-observability-microqualification/v0.2"
AUDIT_SCHEMA = "risu.e2-a3-a4-candidate-observability-microqualification-independent-audit/v0.2"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--protocol", required=True)
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--primary", required=True)
    ap.add_argument("--go-helper", required=True)
    ap.add_argument("--output", required=True)
    args = ap.parse_args()

    protocol_raw = Path(args.protocol).read_bytes(); protocol = json.loads(protocol_raw)
    corpus_raw = Path(args.corpus).read_bytes(); corpus = json.loads(corpus_raw)
    primary_raw = Path(args.primary).read_bytes(); primary = json.loads(primary_raw)
    integrity_errors: list[str] = []
    qualification_failures: list[str] = []

    if primary.get("schema") != PRIMARY_SCHEMA or primary.get("fixture_count") != 48 or primary.get("complete_matrix_emitted") is not True:
        integrity_errors.append("PRIMARY_SCHEMA_COUNT_OR_COMPLETENESS")
    if corpus.get("fixture_count") != 48 or corpus.get("family_count") != 16:
        integrity_errors.append("CORPUS_COUNT")
    tmp = dict(corpus); declared = tmp.pop("corpus_digest_sha256", None)
    if declared != sha(canon(tmp)):
        integrity_errors.append("CORPUS_INTERNAL_DIGEST")
    frozen = {x["id"]: x["expected"] for x in protocol["preimplementation_end_to_end_microqualification"]["families"]}
    if {x["family_id"]: x["expected_observation"] for x in corpus["fixtures"]} != frozen:
        integrity_errors.append("PROTOCOL_CORPUS_FAMILY_BINDING")
    primary_rows = {r["fixture_id"]: r for r in primary.get("rows", [])}
    if len(primary_rows) != 48:
        integrity_errors.append("PRIMARY_ROW_BIJECTION")

    audit_rows = []
    for fx in sorted(corpus["fixtures"], key=lambda x: x["fixture_id"]):
        fid = fx["fixture_id"]
        prow = primary_rows.get(fid)
        if prow is None:
            integrity_errors.append(fid + ":PRIMARY_ROW_MISSING")
            audit_rows.append({"fixture_id": fid, "integrity_pass": False})
            continue
        checks: dict[str, bool] = {
            "source_sha256": prow.get("source_sha256") == sha(str(fx["source"]).encode("utf-8")),
            "expected_observation": prow.get("expected_observation") == fx["expected_observation"],
        }
        independent_observed: str
        independent_infra = "VALID"
        diagnostic_type = None
        try:
            base_ir, overlay, pathdoc, observed = rerun(fx, Path(args.go_helper))
            independent_observed = observed
            checks.update({
                "primary_infrastructure_status": prow.get("infrastructure_status") == "VALID",
                "base_ir_digest": prow.get("base_ir_digest_sha256") == base_ir.get("ir_digest_sha256"),
                "overlay_digest": prow.get("overlay_digest_sha256") == overlay.get("overlay_digest_sha256"),
                "path_digest": prow.get("path_observability_digest_sha256") == pathdoc.get("path_observability_digest_sha256"),
                "path_summary": prow.get("path_summary") == compact(pathdoc),
                "observed_observation": prow.get("observed_observation") == observed,
                "primary_pass_consistency": prow.get("passed") is (observed == fx["expected_observation"]),
            })
        except Exception as exc:
            independent_observed = "INFRASTRUCTURE_INVALID_BEFORE_PREDICTION"
            independent_infra = "INVALID"
            diagnostic_type = type(exc).__name__
            checks.update({
                "primary_infrastructure_status": prow.get("infrastructure_status") == "INVALID",
                "observed_observation": prow.get("observed_observation") == independent_observed,
                "diagnostic_type": prow.get("diagnostic_type") == diagnostic_type,
                "primary_pass_consistency": prow.get("passed") is False,
            })
        bad = [name for name, ok in checks.items() if not ok]
        for name in bad:
            integrity_errors.append(fid + ":" + name)
        if independent_observed != fx["expected_observation"]:
            qualification_failures.append(fid)
        audit_rows.append({
            "fixture_id": fid,
            "family_id": fx["family_id"],
            "language": fx["language"],
            "independent_observation": independent_observed,
            "independent_infrastructure_status": independent_infra,
            "diagnostic_type": diagnostic_type,
            "checks": checks,
            "integrity_pass": not bad,
            "qualification_pass": independent_observed == fx["expected_observation"],
        })

    ptmp = dict(primary); pdig = ptmp.pop("bundle_digest_sha256", None)
    if pdig != sha(canon(ptmp)):
        integrity_errors.append("PRIMARY_INTERNAL_DIGEST")
    expected_primary_status = "PASS" if not qualification_failures else "FAIL"
    if primary.get("status") != expected_primary_status:
        integrity_errors.append("PRIMARY_STATUS_MISMATCH")
    if sorted(primary.get("failed_fixture_ids", [])) != sorted(qualification_failures):
        integrity_errors.append("PRIMARY_FAILURE_SET_MISMATCH")

    out = {
        "schema": AUDIT_SCHEMA,
        "semantic_authority": False,
        "status": "PASS" if not integrity_errors else "FAIL",
        "qualification_status": expected_primary_status,
        "fixture_count": 48,
        "family_count": 16,
        "complete_matrix_independently_replayed": len(audit_rows) == 48,
        "protocol_sha256": sha(protocol_raw),
        "corpus_sha256": sha(corpus_raw),
        "primary_sha256": sha(primary_raw),
        "rows": audit_rows,
        "integrity_errors": sorted(integrity_errors),
        "qualification_failed_fixture_ids": sorted(qualification_failures),
        "independence_attestation": {
            "imports_primary_microqualifier": False,
            "imports_primary_path_observability": False,
            "reuses_prior_independent_checker_only": True,
            "recomputes_frontend_base_ir_overlay": True,
            "recomputes_overlay_node_edge_content_addressing": True,
            "recomputes_path_state_transition_identities": True,
            "recomputes_kill_and_branch_state_separation": True,
            "recomputes_false_cross_product_exclusion": True,
            "recomputes_effective_guard_and_effect_surface": True,
            "recomputes_family_observation": True,
            "treats_agreed_scientific_failure_as_integrity_pass": True,
        },
        "read_set_attestation": {
            "candidate_58_bytes": False, "sanitized_58_manifest": False,
            "raw_blind_58_transport": False, "mutation_truth": False,
            "operator_metadata": False, "expected_e2_predictions": False,
            "fresh_target_bytes": False,
        },
        "claim_boundary": {
            "microqualification_audit_only": True,
            "a3_a4_semantic_verdicts_emitted": False,
            "mutant_58_observability_executed": False,
        },
    }
    out["audit_digest_sha256"] = sha(canon(out))
    Path(args.output).write_bytes(canon(out))
    print(json.dumps({"status":out["status"],"qualification_status":out["qualification_status"],"integrity_errors":len(integrity_errors),"qualification_failures":len(qualification_failures),"sha256":sha(Path(args.output).read_bytes())},sort_keys=True,separators=(",",":")))
    return 0 if out["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
