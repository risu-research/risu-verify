#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping, Sequence

SCHEMA = "risu.e2-a3-a4-v0.3-on-frozen-v0.2-24-cross-check-adjudication/v0.1"
COMPONENT_ORDER = (
    "calls",
    "compares",
    "returns",
    "representations",
    "representation_field_arities",
)


def canonical_json(obj: Any) -> bytes:
    return (json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _nonnegative_int(value: Any, label: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(f"{label}:expected_nonnegative_json_integer")
    return value


def canonical_signature(value: Any) -> list[Any]:
    if isinstance(value, Mapping):
        if set(value.keys()) != set(COMPONENT_ORDER):
            raise ValueError("signature_mapping:exact_key_set_required")
        raw = [value[k] for k in COMPONENT_ORDER]
    elif isinstance(value, list):
        if len(value) != len(COMPONENT_ORDER):
            raise ValueError("signature_sequence:exact_length_5_required")
        raw = list(value)
    else:
        raise ValueError("signature:unsupported_shape")

    out = [
        _nonnegative_int(raw[0], "calls"),
        _nonnegative_int(raw[1], "compares"),
        _nonnegative_int(raw[2], "returns"),
        _nonnegative_int(raw[3], "representations"),
    ]
    arities = raw[4]
    if not isinstance(arities, list):
        raise ValueError("representation_field_arities:expected_json_array")
    normalized_arities = [_nonnegative_int(v, "representation_field_arities") for v in arities]
    if normalized_arities != sorted(normalized_arities):
        raise ValueError("representation_field_arities:must_be_sorted_nondecreasing")
    out.append(normalized_arities)
    return out


def run_self_tests() -> dict[str, Any]:
    mapping = {
        "calls": 1,
        "compares": 2,
        "returns": 3,
        "representations": 1,
        "representation_field_arities": [2, 4],
    }
    sequence = [1, 2, 3, 1, [2, 4]]
    assertions: list[str] = []

    assert canonical_signature(mapping) == canonical_signature(sequence)
    assertions.append("equivalent_mapping_sequence")
    assert canonical_signature(mapping) != canonical_signature([2, 2, 3, 1, [2, 4]])
    assertions.append("changed_scalar_unequal")
    assert canonical_signature(mapping) != canonical_signature([1, 2, 3, 1, [2, 5]])
    assertions.append("changed_field_arity_unequal")

    rejected = []
    bad_values = [
        {"calls": 1, "compares": 2, "returns": 3, "representations": 1},
        {**mapping, "extra": 0},
        [1, 2, 3, 1],
        [True, 2, 3, 1, [2, 4]],
        [-1, 2, 3, 1, [2, 4]],
        [1, 2, 3, 1, [4, 2]],
    ]
    for idx, value in enumerate(bad_values):
        try:
            canonical_signature(value)
        except ValueError:
            rejected.append(idx)
        else:
            raise AssertionError(f"negative_self_test_not_rejected:{idx}")
    assert rejected == list(range(len(bad_values)))
    assertions.extend([
        "missing_key_rejected",
        "extra_key_rejected",
        "wrong_length_rejected",
        "boolean_rejected",
        "negative_integer_rejected",
        "unsorted_arities_rejected",
    ])
    return {"status": "PASS", "assertions": assertions, "count": len(assertions)}


def _load_exact(path: Path, expected_sha256: str) -> tuple[dict[str, Any], str, int]:
    raw = path.read_bytes()
    actual = sha256_bytes(raw)
    if actual != expected_sha256:
        raise ValueError(f"input_sha256_mismatch:{path.name}:{actual}")
    doc = json.loads(raw)
    if not isinstance(doc, dict):
        raise ValueError(f"input_root_not_object:{path.name}")
    return doc, actual, len(raw)


def _unique_rows(doc: Mapping[str, Any], label: str) -> dict[str, Mapping[str, Any]]:
    rows = doc.get("rows")
    if not isinstance(rows, list):
        raise ValueError(f"{label}:rows_not_array")
    out: dict[str, Mapping[str, Any]] = {}
    for row in rows:
        if not isinstance(row, Mapping) or type(row.get("fixture_id")) is not str:
            raise ValueError(f"{label}:invalid_row")
        fid = str(row["fixture_id"])
        if fid in out:
            raise ValueError(f"{label}:duplicate_fixture_id:{fid}")
        out[fid] = row
    return out


def _require_global(doc: Mapping[str, Any], label: str, variant_key: str) -> list[str]:
    errors: list[str] = []
    if doc.get("status") != "PASS": errors.append(f"{label}:status_not_PASS")
    if doc.get("case_count") != 24: errors.append(f"{label}:case_count_not_24")
    if doc.get("passed_case_count") != 24: errors.append(f"{label}:passed_case_count_not_24")
    if doc.get("failed_fixture_ids") != []: errors.append(f"{label}:failed_fixture_ids_nonempty")
    if doc.get(variant_key) != []: errors.append(f"{label}:{variant_key}_nonempty")
    spec = doc.get("specialization_scan")
    if not isinstance(spec, Mapping) or spec.get("status") != "PASS": errors.append(f"{label}:specialization_not_PASS")
    rs = doc.get("read_set_attestation")
    if not isinstance(rs, Mapping) or rs.get("frozen_48_bytes") is not False or rs.get("candidate_58_bytes") is not False:
        errors.append(f"{label}:read_set_firewall_not_false")
    if doc.get("semantic_verdicts_emitted") is not False: errors.append(f"{label}:semantic_verdicts_emitted")
    return errors


def adjudicate(protocol: Mapping[str, Any], primary: Mapping[str, Any], independent: Mapping[str, Any], *, primary_sha: str, independent_sha: str, primary_bytes: int, independent_bytes: int) -> dict[str, Any]:
    failures: list[str] = []
    failures.extend(_require_global(primary, "primary", "variant_errors"))
    failures.extend(_require_global(independent, "independent", "variant_pair_failures"))

    prows = _unique_rows(primary, "primary")
    irows = _unique_rows(independent, "independent")
    fixture_set_equal = set(prows) == set(irows)
    if not fixture_set_equal:
        failures.append("fixture_set_mismatch")
    if len(prows) != 24 or len(irows) != 24:
        failures.append(f"fixture_count_mismatch:{len(prows)}:{len(irows)}")

    comparisons = []
    for fid in sorted(set(prows) & set(irows)):
        p = prows[fid]
        i = irows[fid]
        row_failures = []
        for key in ("passed", "source_sha256", "language", "variant_of", "obligation_ids", "parser"):
            if p.get(key) != i.get(key):
                row_failures.append(f"{key}_mismatch")
        try:
            psig = canonical_signature(p.get("abstract_signature"))
        except ValueError as exc:
            psig = None
            row_failures.append(f"primary_signature_invalid:{exc}")
        try:
            isig = canonical_signature(i.get("abstract_signature"))
        except ValueError as exc:
            isig = None
            row_failures.append(f"independent_signature_invalid:{exc}")
        if psig != isig:
            row_failures.append("canonical_signature_mismatch")
        if row_failures:
            failures.append(f"{fid}:" + ",".join(row_failures))
        comparisons.append({
            "fixture_id": fid,
            "passed": p.get("passed") if p.get("passed") == i.get("passed") else None,
            "source_sha256": p.get("source_sha256") if p.get("source_sha256") == i.get("source_sha256") else None,
            "canonical_signature": psig if psig == isig else None,
            "agreement": not row_failures,
            "errors": row_failures,
        })

    all_agree = fixture_set_equal and len(comparisons) == 24 and all(r["agreement"] for r in comparisons)
    status = "PASS" if not failures and all_agree else "FAIL"
    return {
        "schema": SCHEMA,
        "status": status,
        "claim_scope": "CHECKER_ONLY_POST_FREEZE_ADJUDICATION_OF_IMMUTABLE_FIRST_COMPLETE_OUTPUTS",
        "canonical_signature_order": list(COMPONENT_ORDER),
        "self_tests": run_self_tests(),
        "inputs": {
            "primary_sha256": primary_sha,
            "primary_bytes": primary_bytes,
            "independent_sha256": independent_sha,
            "independent_bytes": independent_bytes,
        },
        "case_count": 24,
        "same_fixture_set": fixture_set_equal,
        "canonical_per_case_agreement": all_agree,
        "agreed_case_count": sum(r["agreement"] for r in comparisons),
        "failure_count": len(failures),
        "failures": failures,
        "primary_status": primary.get("status"),
        "independent_status": independent.get("status"),
        "original_first_complete_bundle_status_preserved": "FROZEN_FAIL",
        "scientific_regression_rerun": False,
        "frozen_48_bytes_read": False,
        "candidate_58_bytes_read": False,
        "semantic_verdicts_emitted": False,
        "comparisons": comparisons,
        "protocol_schema": protocol.get("schema"),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--protocol", required=True)
    ap.add_argument("--primary")
    ap.add_argument("--independent")
    ap.add_argument("--output")
    ap.add_argument("--self-test-only", action="store_true")
    args = ap.parse_args()

    if args.self_test_only:
        print(json.dumps(run_self_tests(), sort_keys=True, separators=(",", ":")))
        return 0

    if not args.primary or not args.independent or not args.output:
        raise SystemExit("--primary, --independent, and --output are required unless --self-test-only is used")

    protocol = json.loads(Path(args.protocol).read_bytes())
    auth = protocol.get("authority")
    if not isinstance(auth, Mapping):
        raise ValueError("protocol_authority_missing")
    expected_primary = auth["immutable_primary"]["sha256"]
    expected_independent = auth["immutable_independent"]["sha256"]
    primary, psha, pbytes = _load_exact(Path(args.primary), str(expected_primary))
    independent, isha, ibytes = _load_exact(Path(args.independent), str(expected_independent))
    result = adjudicate(protocol, primary, independent, primary_sha=psha, independent_sha=isha, primary_bytes=pbytes, independent_bytes=ibytes)
    Path(args.output).write_bytes(canonical_json(result))
    print(json.dumps({
        "status": result["status"],
        "case_count": result["case_count"],
        "agreed_case_count": result["agreed_case_count"],
        "failure_count": result["failure_count"],
        "sha256": sha256_bytes(Path(args.output).read_bytes()),
        "bytes": Path(args.output).stat().st_size,
    }, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
