#!/usr/bin/env python3
from __future__ import annotations

"""Gate2A plumbing correction after a pre-output fail-closed run.

The frozen v1 joiner assumed each materialized Q directory contained exactly
one source-like file. Q029 legitimately contains an additional source-like
fixture file. This wrapper changes no truth, metric, or verdict semantics.
It constructs an outcome-blind view in which the unique source-like file whose
SHA-256 is already present in the frozen sanitized admission manifest is the
candidate file for that Q directory, then executes the frozen v1 joiner over
that view.
"""

import hashlib
import json
from pathlib import Path
import shutil
import tempfile

import e2_candidate58_gate2a_truth_join as base

SOURCE_SUFFIXES = {".py", ".go", ".mjs", ".js", ".ts"}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def build_admission_addressed_view(root: Path) -> dict[str, object]:
    admission = json.loads(base.ADMISSION.read_text())
    if admission.get("case_count") != 58 or len(admission.get("cases", [])) != 58:
        raise SystemExit("admission not exactly 58 before mapping correction")

    admission_hashes = [str(x["candidate_source_sha256"]) for x in admission["cases"]]
    if len(set(admission_hashes)) != 58:
        raise SystemExit("admission candidate hashes not bijective")
    allowed = set(admission_hashes)

    consumed: set[str] = set()
    total_source_like = 0
    total_noncandidate_source_like = 0
    multi_source_directories = 0
    per_q: list[dict[str, object]] = []

    for i in range(1, 59):
        q = f"Q{i:03d}"
        src_dir = base.CELLS / q
        if not src_dir.is_dir():
            raise SystemExit(f"missing materialized cell:{q}")

        source_like = sorted(
            p for p in src_dir.iterdir()
            if p.is_file() and p.name != "CELL.json" and p.suffix in SOURCE_SUFFIXES
        )
        total_source_like += len(source_like)
        if len(source_like) > 1:
            multi_source_directories += 1

        addressed = [(p, sha256(p)) for p in source_like]
        matches = [(p, digest) for p, digest in addressed if digest in allowed]
        if len(matches) != 1:
            raise SystemExit(f"admission-addressed candidate count must be one:{q}:{len(matches)}")

        candidate, digest = matches[0]
        if digest in consumed:
            raise SystemExit(f"duplicate admission-addressed candidate hash:{q}")
        consumed.add(digest)
        total_noncandidate_source_like += len(source_like) - 1

        dst_dir = root / q
        dst_dir.mkdir(parents=True, exist_ok=False)
        shutil.copyfile(candidate, dst_dir / candidate.name)
        if sha256(dst_dir / candidate.name) != digest:
            raise SystemExit(f"candidate copy digest mismatch:{q}")

        per_q.append({
            "q_id": q,
            "source_like_file_count": len(source_like),
            "admission_matching_file_count": 1,
            "candidate_source_sha256": digest,
            "noncandidate_source_like_file_count": len(source_like) - 1,
        })

    if consumed != allowed:
        raise SystemExit("58-way admission-addressed source bijection failed")

    return {
        "schema": "risu.e2-candidate58-gate2a-source-identity-view-receipt/v0.1",
        "status": "PASS_UNIQUE_ADMISSION_HASH_PER_Q",
        "q_count": 58,
        "admission_hash_count": 58,
        "consumed_admission_hash_count": 58,
        "total_source_like_file_count": total_source_like,
        "total_noncandidate_source_like_file_count": total_noncandidate_source_like,
        "multi_source_directory_count": multi_source_directories,
        "mapping_rule": "Select exactly one source-like file per Q whose SHA-256 belongs to the frozen sanitized admission candidate_source_sha256 set; zero or multiple matches fail closed.",
        "cell_json_read_for_mapping": False,
        "truth_or_operator_used_for_mapping": False,
        "machine_prediction_used_for_mapping": False,
        "rows": per_q,
    }


def main() -> int:
    original_cells = base.CELLS
    with tempfile.TemporaryDirectory(prefix="risu-gate2a-admission-view-") as td:
        view = Path(td)
        mapping_receipt = build_admission_addressed_view(view)
        base.CELLS = view
        try:
            rc = base.main()
        finally:
            base.CELLS = original_cells

        # base.main() has parsed --output-dir from argv and completed successfully.
        # Recover that output directory without changing the frozen v1 API.
        import sys
        try:
            idx = sys.argv.index("--output-dir")
            out = Path(sys.argv[idx + 1])
        except (ValueError, IndexError) as exc:
            raise SystemExit("--output-dir required by frozen v1 joiner") from exc
        raw = canonical_bytes(mapping_receipt)
        (out / "E2_CANDIDATE58_GATE2A_SOURCE_IDENTITY_VIEW_RECEIPT.json").write_bytes(raw)
        print(json.dumps({
            "status": mapping_receipt["status"],
            "q_count": 58,
            "multi_source_directory_count": mapping_receipt["multi_source_directory_count"],
            "mapping_receipt_sha256": hashlib.sha256(raw).hexdigest(),
        }, sort_keys=True, separators=(",", ":")))
        return rc


if __name__ == "__main__":
    raise SystemExit(main())
