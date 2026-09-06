#!/usr/bin/env python3
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

PARENT_PROTOCOL_BLOB = "8d1860312d259e628e86070416a4757c570ba05f"
ERRATUM_BLOB = "a226d19994b55e7668658a94604db2d1ce07cb05"
FROZEN_QUALIFIER_BLOB = "3b5cbe1bac55503e135426ccaab5ed73b65e5480"
MATRIX_SHA256 = "afd681d308a6f4ec8c183edd9b139c6b914fe501936cf84e5845a6a1c0d6b7cb"


def canon(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_json(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = path.read_bytes()
    return json.loads(raw.decode("utf-8")), raw


def load_jsonl(path: Path) -> tuple[list[dict[str, Any]], bytes]:
    raw = path.read_bytes()
    rows = [json.loads(line) for line in raw.decode("utf-8").splitlines() if line.strip()]
    return rows, raw


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--qualifier", required=True)
    ap.add_argument("--protocol", required=True)
    ap.add_argument("--erratum", required=True)
    ap.add_argument("--matrix", required=True)
    ap.add_argument("--root", required=True)
    ap.add_argument("--transport-bundle", required=True)
    ap.add_argument("--cells", required=True)
    ap.add_argument("--output", required=True)
    args = ap.parse_args()

    parent, parent_raw = load_json(Path(args.protocol))
    erratum, erratum_raw = load_json(Path(args.erratum))
    rows, matrix_raw = load_jsonl(Path(args.matrix))

    assert erratum["erratum_id"] == "ERRATUM_001_OPERATOR_ID_REPRESENTATION"
    assert erratum["status"] == "FROZEN_AFTER_LABEL_SCHEMA_UNBLINDING_BEFORE_ANY_TRUTH_TRANSPORT_JOIN"
    assert erratum["parent_protocol"]["git_blob"] == PARENT_PROTOCOL_BLOB
    assert erratum["frozen_evidence"]["qualifier_git_blob_at_failure"] == FROZEN_QUALIFIER_BLOB
    assert sha(matrix_raw) == MATRIX_SHA256
    assert parent["frozen_authorities"]["expanded_truth_matrix_sha256"] == MATRIX_SHA256
    assert erratum["representation_correction"]["transport_join_key_unchanged"] == [
        "seed_id", "language", "candidate_source_sha256"
    ]
    assert erratum["unchanged_scientific_contract"]["predeclared_strata_unchanged"] is True
    assert erratum["unchanged_scientific_contract"]["predeclared_metrics_unchanged"] is True
    assert erratum["unchanged_scientific_contract"]["no_transport_output_change"] is True

    short_allowed = {
        cls: set(str(x) for x in vals)
        for cls, vals in parent["truth_contract"]["allowed_operator_ids"].items()
    }
    full_by_class: dict[str, set[str]] = {cls: set() for cls in short_allowed}
    codes_by_class: dict[str, set[str]] = {cls: set() for cls in short_allowed}
    for row in rows:
        cls = str(row["operator_class"])
        opid = str(row["operator_id"])
        assert cls in short_allowed
        assert "_" in opid
        code = opid.split("_", 1)[0]
        assert code in short_allowed[cls]
        full_by_class[cls].add(opid)
        codes_by_class[cls].add(code)

    # The correction is representation-only: the matrix must exercise exactly
    # the same short-code universe that was preregistered for every class.
    for cls in short_allowed:
        assert codes_by_class[cls] == short_allowed[cls]

    effective = copy.deepcopy(parent)
    effective["truth_contract"]["allowed_operator_ids"] = {
        cls: sorted(full_by_class[cls]) for cls in sorted(full_by_class)
    }
    effective_raw = canon(effective)

    with tempfile.TemporaryDirectory(prefix="risu-e2-erratum001-") as td:
        effective_path = Path(td) / "effective_protocol.json"
        raw_output = Path(td) / "qualification.raw.json"
        effective_path.write_bytes(effective_raw)
        cmd = [
            sys.executable,
            str(Path(args.qualifier)),
            "--root", args.root,
            "--protocol", str(effective_path),
            "--transport-bundle", args.transport_bundle,
            "--matrix", args.matrix,
            "--cells", args.cells,
            "--output", str(raw_output),
        ]
        subprocess.run(cmd, check=True)
        result = json.loads(raw_output.read_text(encoding="utf-8"))

    assert result["status"] == "PASS"
    result.pop("result_digest_sha256", None)
    result["representation_erratum"] = {
        "erratum_id": "ERRATUM_001_OPERATOR_ID_REPRESENTATION",
        "parent_protocol_git_blob": PARENT_PROTOCOL_BLOB,
        "parent_protocol_sha256": sha(parent_raw),
        "erratum_git_blob": ERRATUM_BLOB,
        "erratum_sha256": sha(erratum_raw),
        "frozen_qualifier_git_blob": FROZEN_QUALIFIER_BLOB,
        "effective_protocol_sha256": sha(effective_raw),
        "matrix_operator_ids_retained_verbatim": True,
        "operator_code_validation_only": True,
        "join_metrics_strata_changed": False,
        "first_label_schema_unblinding_run_id": 34032454347,
        "truth_transport_association_observed_before_erratum_freeze": False,
    }
    result["result_digest_sha256"] = sha(canon(result))
    out_raw = canon(result)
    Path(args.output).write_bytes(out_raw)
    print(json.dumps({
        "status": "PASS",
        "case_count": result["integrity"]["cell_count"],
        "result_sha256": sha(out_raw),
        "result_digest_sha256": result["result_digest_sha256"],
        "erratum_id": "ERRATUM_001_OPERATOR_ID_REPRESENTATION",
    }, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
