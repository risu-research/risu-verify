#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UNIT = ROOT / "corpus" / "0.1" / "units" / "001-github-mcp-merge" / "primary-result"
ARCHIVE = UNIT / "archive"
PRIMARY_ZIP = ARCHIVE / "raw" / "corpus01-unit001-primary.zip"
REPLAY_ZIP = ARCHIVE / "raw" / "corpus01-unit001-replay.zip"

PRIMARY_ZIP_SHA256 = "b4bce32ad794e0e356a4bd886084021e49a245c9696c8eca42c32b45dcebe27e"
REPLAY_ZIP_SHA256 = "5d18f5412b69f3aa4116613592e816b0bce8ff84119f1fded9a6c611c46837f1"

PRIMARY = {
    "corpus01-unit001-artifact.sha256": "2fc12b490c7922c71a456d5c36dcdf32fa972709bea272e137388026447456ca",
    "corpus01-unit001-case/PROVENANCE_OVERLAY_APPLICATION.json": "da61cd492e2ba0d1cccfce6a451aebb69e2d1cbf58b3715dea250081617da92d",
    "corpus01-unit001-case/VBE_COMPILE_MANIFEST.json": "5f82e63df66ef2a8fa03a869bf1a932287d74835934bc9ae1f55d64d90b1cd1f",
    "corpus01-unit001-console.json": "65946b88c7a5da3b7a1289ed2dacbaf37636d7d206e6c19731448dbdcfc3fef4",
    "corpus01-unit001-output/certificate.json": "ac57a340d5300602bb7655a5bd16f559c35bd751011a09bb5e071d69cfeca138",
    "corpus01-unit001-output/consumer.log": "e9e761cbcedfda246c1d55b5f79887b91683aa10e44b6ec1946fc896eed977e0",
    "corpus01-unit001-output/producer.log": "7b095de59d1daa2e508b8b1d17e7f49ef2a6b28287f70bacae076cb4c32cd346",
    "corpus01-unit001-output/report.json": "65946b88c7a5da3b7a1289ed2dacbaf37636d7d206e6c19731448dbdcfc3fef4",
    "corpus01-unit001-output/report.md": "1991e7b4418b01929d4930ccf1e5489f75b480a4d1831cf1c488a32dd0fd97c4",
    "corpus01-unit001-output/run-manifest.json": "956ec0fd8cb61fe3d611d0df3724a47c6b3151636c3bc79328ee85c14e6d3ff7",
    "corpus01-unit001-primary-observation.json": "f53d34fc4689ffbbaccd9267ccaf50c433543b02096cd2ac79d86a610d1bb5a9",
    "corpus01-unit001-semantic-exit-code.txt": "9a271f2a916b0b6ee6cecb2426f0b3206ef074578be55d9bc94f6f3fe3ab86aa",
}
REPLAY_RUN_SPECIFIC = {
    "corpus01-unit001-artifact.sha256": "baec948f2c6480d555e25271acda74004acd76a3f7c012fdaed155c10ee55b22",
    "corpus01-unit001-primary-observation.json": "b18beb049aa6cbd2f7d29e1a43e41effe8e7167b53ad332cccb4025a80d18c83",
}
SHARED = set(PRIMARY) - set(REPLAY_RUN_SPECIFIC)

def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def fail(msg: str) -> None:
    raise RuntimeError(msg)

def load_zip(path: Path, expected_zip_sha: str) -> dict[str, bytes]:
    raw = path.read_bytes()
    if digest(raw) != expected_zip_sha:
        fail(f"ZIP SHA-256 mismatch: {path}")
    with zipfile.ZipFile(path, "r") as zf:
        names = [n for n in zf.namelist() if not n.endswith("/")]
        if len(names) != 12 or set(names) != set(PRIMARY):
            fail(f"unexpected uploaded entry set in {path}")
        return {n: zf.read(n) for n in names}

def main() -> int:
    p = load_zip(PRIMARY_ZIP, PRIMARY_ZIP_SHA256)
    r = load_zip(REPLAY_ZIP, REPLAY_ZIP_SHA256)

    for name, expected in PRIMARY.items():
        if digest(p[name]) != expected:
            fail(f"primary entry SHA-256 mismatch: {name}")
        extracted = ARCHIVE / "primary-uploaded" / name
        if not extracted.is_file() or extracted.read_bytes() != p[name]:
            fail(f"primary extracted mirror mismatch: {name}")

    for name in SHARED:
        if p[name] != r[name]:
            fail(f"replay shared entry differs: {name}")
    for name, expected in REPLAY_RUN_SPECIFIC.items():
        if digest(r[name]) != expected:
            fail(f"replay run-specific entry SHA-256 mismatch: {name}")
    for name in PRIMARY:
        extracted = ARCHIVE / "replay-uploaded" / name
        if not extracted.is_file() or extracted.read_bytes() != r[name]:
            fail(f"replay extracted mirror mismatch: {name}")

    primary_result = json.loads((UNIT / "PRIMARY_RESULT.json").read_text(encoding="utf-8"))
    if primary_result.get("status") != "FROZEN_FIRST_PRIMARY_RESULT":
        fail("primary result status changed")
    if primary_result.get("execution", {}).get("github_actions_run_id") != 33939000332:
        fail("canonical first primary run identity changed")
    if primary_result.get("execution", {}).get("artifact", {}).get("id") != 9961142844:
        fail("canonical primary artifact identity changed")
    if primary_result.get("execution", {}).get("artifact", {}).get("zip_sha256") != PRIMARY_ZIP_SHA256:
        fail("canonical primary artifact SHA changed")
    if primary_result.get("cryptographic_commitments", {}).get("certificate_sha256") != PRIMARY["corpus01-unit001-output/certificate.json"]:
        fail("certificate commitment changed")
    if primary_result.get("selection_and_authoring", {}).get("authoring_freeze_commit") != "355a4b77187d5b2118ac71eae9dec1cadc036847":
        fail("authoring freeze identity changed")

    print("Unit 001 archive integrity: PASS")
    print("  primary_zip=PASS entries=12/12")
    print("  replay_zip=PASS shared_byte_identical=10/10 run_specific=2/2")
    print("  canonical_primary_identity=PASS")
    return 0

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"Unit 001 archive integrity: FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
