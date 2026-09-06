#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Iterable, Mapping

ROOT = Path(__file__).resolve().parents[1]
BUNDLE = ROOT / "protocols" / "RISU_DIFF_E2_CANONICAL_SEED_CONSEQUENCE_ANCHORS_v0.1.json"
SCHEMA = ROOT / "schemas" / "RISU_E2_CONSEQUENCE_ANCHOR_CONTRACT_v0.1.schema.json"
EXPECTED_SEEDS = {"SYN-GO-01", "SYN-GO-02", "SYN-PY-01", "SYN-PY-02", "SYN-TS-01", "SYN-TS-02"}
ALLOWED_ROLES = {"GUARD_COMPARISON", "EFFECT_BOUNDARY", "SUCCESS_OUTCOME", "REJECTION_NO_EFFECT_OUTCOME"}
FORBIDDEN_KEYS = {"expected_truth", "expected_e2_primary", "operator_id", "operator_class", "mutation_operator_id", "mutation_operator_class", "mutation_specific_repair"}
COMMENT_MARKERS = (b"//", b"/*", b"*/", b"#", b'\"\"\"', bytes((39, 39, 39)))


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_blob_sha1(data: bytes) -> str:
    return hashlib.sha1(f"blob {len(data)}\0".encode("ascii") + data).hexdigest()


def walk_keys(value: Any) -> Iterable[str]:
    if isinstance(value, Mapping):
        for k, v in value.items():
            yield str(k)
            yield from walk_keys(v)
    elif isinstance(value, list):
        for v in value:
            yield from walk_keys(v)


def byte_slice_by_span(data: bytes, span: list[int]) -> bytes:
    lines = data.splitlines(keepends=True)
    sl, sc, el, ec = map(int, span)
    if sl < 1 or el < sl or el > len(lines):
        raise AssertionError(f"invalid line span: {sl}-{el}")
    if sl == el:
        line = lines[sl - 1]
        logical = line[:-1] if line.endswith(b"\n") else line
        if logical.endswith(b"\r"):
            logical = logical[:-1]
        if not (0 <= sc <= ec <= len(logical)):
            raise AssertionError(f"invalid column span: {sc}-{ec}")
        return logical[sc:ec]
    pieces = [lines[sl - 1][sc:]]
    for idx in range(sl, el - 1):
        pieces.append(lines[idx])
    last = lines[el - 1]
    logical_last = last[:-1] if last.endswith(b"\n") else last
    if logical_last.endswith(b"\r"):
        logical_last = logical_last[:-1]
    pieces.append(logical_last[:ec])
    return b"".join(pieces)


def validate_declaration(doc: Mapping[str, Any], expected_canonical_sha: str) -> dict[str, Any]:
    assert doc["schema"] == "risu.e2-consequence-anchor-contract/v0.1"
    assert doc["scope_authority"] is True
    assert doc["verdict_authority"] is False
    assert doc["seed_id"] in EXPECTED_SEEDS
    assert doc["locator_convention"] == "L1_C0_END_EXCLUSIVE_UTF8_BYTE"
    assert doc["transport"] == {"fresh_revision_authorized": False, "mutant_revision_authorized": False}
    assert FORBIDDEN_KEYS.isdisjoint(set(walk_keys(doc)))
    canonical_sha = sha256_bytes(canonical_bytes(doc))
    assert canonical_sha == expected_canonical_sha

    src_path = ROOT / doc["source"]["path"]
    seeds_root = ROOT / "experiments" / "risu-diff-e2" / "qualification" / "seeds"
    assert src_path.resolve().is_relative_to(seeds_root.resolve())
    src = src_path.read_bytes()
    assert sha256_bytes(src) == doc["source"]["sha256"]
    assert git_blob_sha1(src) == doc["source"]["git_blob_sha"]

    anchors = doc["anchors"]
    assert set(anchors) == {"guard_comparison", "rejection_no_effect", "effect_applied"}
    roles = []
    resolved = []
    for anchor_id, anchor in sorted(anchors.items()):
        assert set(anchor["roles"]).issubset(ALLOWED_ROLES)
        piece = byte_slice_by_span(src, anchor["span"])
        assert len(piece) == int(anchor["slice_bytes"])
        assert sha256_bytes(piece) == anchor["slice_sha256"]
        assert anchor["unique_in_source"] is True
        assert src.count(piece) == 1
        assert not any(marker in piece for marker in COMMENT_MARKERS)
        roles.extend(anchor["roles"])
        resolved.append({"anchor_id": anchor_id, "semantic_roles": sorted(anchor["roles"]), "slice_sha256": anchor["slice_sha256"], "unique_resolution": True})

    assert roles.count("GUARD_COMPARISON") == 1
    assert roles.count("EFFECT_BOUNDARY") == 1
    assert roles.count("SUCCESS_OUTCOME") == 1
    assert roles.count("REJECTION_NO_EFFECT_OUTCOME") == 1

    slots = doc["binding_slots"]
    assert set(slots) == {"expected_coordinate", "current_coordinate"}
    assert all(s["anchor"] == "guard_comparison" for s in slots.values())
    assert len({int(s["operand_index"]) for s in slots.values()}) == 2
    assert doc["resource_identity_required"] is False
    assert doc["failure_outcome_required"] is False

    return {
        "seed_id": doc["seed_id"],
        "contract_canonical_sha256": canonical_sha,
        "source_path": doc["source"]["path"],
        "source_sha256": sha256_bytes(src),
        "source_git_blob_sha": git_blob_sha1(src),
        "anchor_count": len(anchors),
        "binding_slot_count": len(slots),
        "anchors": resolved,
    }


def main() -> int:
    bundle_raw = BUNDLE.read_bytes()
    bundle = json.loads(bundle_raw.decode("utf-8"))
    schema_raw = SCHEMA.read_bytes()
    schema = json.loads(schema_raw.decode("utf-8"))
    assert schema["$id"] == "risu.e2-consequence-anchor-contract/v0.1"
    assert bundle["schema"] == "risu.e2-canonical-seed-consequence-anchor-bundle/v0.1"
    assert bundle["seed_count"] == 6
    assert bundle["firewall"]["mutation_results_consulted_for_authoring"] is False
    assert bundle["firewall"]["materialized_mutant_cells_consulted_for_authoring"] is False
    assert bundle["firewall"]["expected_truth_allowed"] is False
    assert bundle["firewall"]["expected_e2_primary_allowed"] is False
    assert bundle["firewall"]["mutation_operator_metadata_allowed"] is False
    assert bundle["mutant_anchor_transport_authorized"] is False

    entries = sorted(bundle["contracts"], key=lambda x: x["seed_id"])
    assert len(entries) == 6
    assert {e["seed_id"] for e in entries} == EXPECTED_SEEDS
    assert all(e["seed_id"] == e["declaration"]["seed_id"] for e in entries)
    results = [validate_declaration(e["declaration"], e["contract_canonical_sha256"]) for e in entries]
    assert len({r["source_path"] for r in results}) == 6

    read_paths = [BUNDLE.relative_to(ROOT).as_posix(), SCHEMA.relative_to(ROOT).as_posix(), *[r["source_path"] for r in results]]
    out = {
        "schema": "risu.e2-consequence-anchor-freeze-validation/v0.1",
        "head_sha": os.environ.get("GITHUB_SHA"),
        "status": "PASS",
        "scope_authority": True,
        "verdict_authority": False,
        "bundle_path": BUNDLE.relative_to(ROOT).as_posix(),
        "bundle_canonical_sha256": sha256_bytes(canonical_bytes(bundle)),
        "bundle_file_sha256": sha256_bytes(bundle_raw),
        "schema_path": SCHEMA.relative_to(ROOT).as_posix(),
        "schema_file_sha256": sha256_bytes(schema_raw),
        "seed_count": len(results),
        "contract_count": len(results),
        "anchor_count": sum(r["anchor_count"] for r in results),
        "binding_slot_count": sum(r["binding_slot_count"] for r in results),
        "unique_anchor_resolution_count": sum(r["anchor_count"] for r in results),
        "contracts": results,
        "input_read_set": sorted(read_paths),
        "materialized_mutant_cell_paths_read": False,
        "mutation_truth_read": False,
        "mutation_operator_metadata_read": False,
        "expected_e2_predictions_read": False,
        "comments_or_docstrings_used_as_anchor_semantics": False,
        "mutant_anchor_transport_authorized": False,
        "fresh_target_reuse_authorized": False,
        "decision": "CANONICAL_SEED_CONSEQUENCE_ANCHORS_VALIDATED",
        "recommended_next": "FREEZE_VALIDATION_RECEIPT_THEN_IMPLEMENT_D1_D2_D3_OVERLAY_WITHOUT_A3_A4_VERDICT_LOGIC",
    }
    print(json.dumps(out, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
