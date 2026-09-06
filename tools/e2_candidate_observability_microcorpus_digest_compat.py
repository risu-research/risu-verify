#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

OLD_DECLARED = "720029930f003b3a0cc66691a3b3dd09c10617aedb603780f80bda1a7ac1ab04"
SOURCE_FILE_SHA256 = "9eb55e2bd64f82f443a4765544f1d10e20166eb6a48076678a3e11835612d7ed"
SOURCE_GIT_BLOB = "f990130b782ab242e4e341b45d0d58d298f4f316"
NO_LF_PREIMAGE_SHA256 = "55f3c293f8324b9f94b7a6c7b60ddc4f15a1016db06d63e630b788647a50e087"
RISU_CANONICAL_PREIMAGE_SHA256 = "8d5c5cc3cac3603c8b2b4be8324d0803d8886380865046a55ef97fbaadf3771f"


def compact(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def risu_canonical(value: object) -> bytes:
    return compact(value) + b"\n"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--attestation", required=True)
    args = ap.parse_args()

    source_raw = Path(args.input).read_bytes()
    if sha(source_raw) != SOURCE_FILE_SHA256:
        raise SystemExit("frozen corpus file sha256 mismatch")
    source = json.loads(source_raw)
    if source.get("corpus_digest_sha256") != OLD_DECLARED:
        raise SystemExit("unexpected frozen declared digest")
    semantic_payload = dict(source)
    semantic_payload.pop("corpus_digest_sha256")
    if sha(compact(semantic_payload)) != NO_LF_PREIMAGE_SHA256:
        raise SystemExit("compact preimage digest mismatch")
    if sha(risu_canonical(semantic_payload)) != RISU_CANONICAL_PREIMAGE_SHA256:
        raise SystemExit("RISU canonical preimage digest mismatch")
    if semantic_payload.get("fixture_count") != 48 or semantic_payload.get("family_count") != 16:
        raise SystemExit("frozen corpus count mismatch")
    if semantic_payload.get("claim_boundary", {}).get("candidate_58_bytes_included") is not False:
        raise SystemExit("candidate-58 firewall violation")

    compat = dict(semantic_payload)
    compat["corpus_digest_sha256"] = RISU_CANONICAL_PREIMAGE_SHA256
    compat_raw = risu_canonical(compat)
    projected = dict(json.loads(compat_raw))
    projected.pop("corpus_digest_sha256")
    if projected != semantic_payload:
        raise SystemExit("compatibility projection changed semantic payload")
    Path(args.output).write_bytes(compat_raw)

    attestation = {
        "schema": "risu.e2-candidate-observability-microcorpus-digest-compatibility-attestation/v0.1",
        "status": "PASS",
        "source_git_blob": SOURCE_GIT_BLOB,
        "source_file_sha256": SOURCE_FILE_SHA256,
        "source_declared_digest_sha256": OLD_DECLARED,
        "semantic_payload_compact_no_lf_sha256": NO_LF_PREIMAGE_SHA256,
        "semantic_payload_risu_canonical_sha256": RISU_CANONICAL_PREIMAGE_SHA256,
        "compatibility_file_sha256": sha(compat_raw),
        "only_changed_field": "corpus_digest_sha256",
        "semantic_payload_exactly_equal_after_digest_field_removal": True,
        "fixture_count": 48,
        "family_count": 16,
        "candidate_58_bytes_read": False,
        "microfixture_pipeline_executed": False,
        "scientific_logic_changed": False,
    }
    Path(args.attestation).write_bytes(compact(attestation))
    print(json.dumps(attestation, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
