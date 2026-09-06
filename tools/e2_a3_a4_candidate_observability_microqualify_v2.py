#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from risu_e2.model import canonical_bytes
from e2_a3_a4_candidate_observability_microqualify import (
    CORPUS_SCHEMA, PROTOCOL_SCHEMA, canon, sha, run_fixture,
)

SCHEMA = "risu.e2-a3-a4-candidate-observability-microqualification/v0.2"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--protocol", required=True)
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--go-helper", required=True)
    ap.add_argument("--output", required=True)
    args = ap.parse_args()

    protocol_raw = Path(args.protocol).read_bytes(); protocol = json.loads(protocol_raw)
    corpus_raw = Path(args.corpus).read_bytes(); corpus = json.loads(corpus_raw)
    if protocol.get("schema") != PROTOCOL_SCHEMA or protocol.get("status") != "PRE_IMPLEMENTATION_CANDIDATE_OBSERVABILITY_QUALIFICATION_FROZEN":
        raise SystemExit("candidate observability protocol not frozen")
    if corpus.get("schema") != CORPUS_SCHEMA or corpus.get("fixture_count") != 48 or corpus.get("family_count") != 16:
        raise SystemExit("microfixture corpus malformed")
    tmp = dict(corpus); declared = tmp.pop("corpus_digest_sha256")
    if sha(canon(tmp)) != declared:
        raise SystemExit("microfixture corpus digest mismatch")
    if corpus.get("claim_boundary", {}).get("candidate_58_bytes_included") is not False:
        raise SystemExit("58-byte firewall violation")

    frozen = {x["id"]: x["expected"] for x in protocol["preimplementation_end_to_end_microqualification"]["families"]}
    observed = {x["family_id"]: x["expected_observation"] for x in corpus["fixtures"]}
    if frozen != observed:
        raise SystemExit("corpus expectations differ from frozen protocol")
    if len({x["fixture_id"] for x in corpus["fixtures"]}) != 48:
        raise SystemExit("duplicate fixture id")
    required_langs = {"python", "go", "typescript_javascript"}
    by_family: dict[str, set[str]] = {}
    for fx in corpus["fixtures"]:
        by_family.setdefault(fx["family_id"], set()).add(fx["language"])
    if set(by_family) != set(frozen) or any(v != required_langs for v in by_family.values()):
        raise SystemExit("family/language coverage mismatch")

    rows = []
    for fx in sorted(corpus["fixtures"], key=lambda x: x["fixture_id"]):
        try:
            row = run_fixture(fx, Path(args.go_helper))
            row["infrastructure_status"] = "VALID"
        except Exception as exc:
            row = {
                "fixture_id": fx["fixture_id"],
                "family_id": fx["family_id"],
                "language": fx["language"],
                "source_sha256": sha(str(fx["source"]).encode("utf-8")),
                "expected_observation": fx["expected_observation"],
                "observed_observation": "INFRASTRUCTURE_INVALID_BEFORE_PREDICTION",
                "passed": False,
                "infrastructure_status": "INVALID",
                "diagnostic_type": type(exc).__name__,
                "diagnostic_message": str(exc),
            }
        rows.append(row)

    failures = [r["fixture_id"] for r in rows if not r["passed"]]
    infra_invalid = [r["fixture_id"] for r in rows if r["infrastructure_status"] == "INVALID"]
    family_status = {}
    for family in sorted(frozen):
        fr = [r for r in rows if r["family_id"] == family]
        family_status[family] = {
            "expected": frozen[family],
            "languages": {r["language"]: r["observed_observation"] for r in fr},
            "pass": len(fr) == 3 and all(r["passed"] for r in fr),
        }

    out = {
        "schema": SCHEMA,
        "semantic_authority": False,
        "status": "PASS" if not failures else "FAIL",
        "fixture_count": 48,
        "family_count": 16,
        "complete_matrix_emitted": len(rows) == 48,
        "protocol_sha256": sha(protocol_raw),
        "corpus_sha256": sha(corpus_raw),
        "corpus_internal_digest_sha256": corpus["corpus_digest_sha256"],
        "rows": rows,
        "family_status": family_status,
        "failed_fixture_ids": failures,
        "infrastructure_invalid_fixture_ids": infra_invalid,
        "read_set_attestation": {
            "frozen_protocol": True, "frozen_microfixture_corpus": True,
            "frozen_frontends_ir_overlay": True, "path_observability_sidecar": True,
            "candidate_58_bytes": False, "sanitized_58_manifest": False,
            "raw_blind_58_transport": False, "mutation_truth": False,
            "operator_metadata": False, "expected_e2_predictions": False,
            "fresh_target_bytes": False,
        },
        "claim_boundary": {
            "actual_pipeline_microqualification_only": True,
            "a3_a4_semantic_verdicts_emitted": False,
            "mutant_58_observability_executed": False,
            "fresh_target_evaluation_executed": False,
            "fixture_failure_never_drops_row": True,
        },
    }
    out["bundle_digest_sha256"] = sha(canon(out))
    Path(args.output).write_bytes(canon(out))
    print(json.dumps({"status":out["status"],"fixtures":48,"failures":len(failures),"infra_invalid":len(infra_invalid),"sha256":sha(Path(args.output).read_bytes())},sort_keys=True,separators=(",",":")))
    return 0 if out["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
