#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "risu.corpus-bound-evidence/v0.8alpha1"
MANAGED_PREFIXES = {"evidence", "qualification"}


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def safe_bound_path(assurance: Path, rel: str) -> Path:
    p = (assurance / rel).resolve()
    p.relative_to(assurance.resolve())
    parts = Path(rel).parts
    if not parts or parts[0] not in MANAGED_PREFIXES:
        raise RuntimeError(f"binding path must live under evidence/ or qualification/: {rel}")
    return p


def _remove_empty_dirs(root: Path) -> None:
    if not root.exists():
        return
    for p in sorted((x for x in root.rglob("*") if x.is_dir()), key=lambda x: len(x.parts), reverse=True):
        try:
            p.rmdir()
        except OSError:
            pass


def apply_bound_evidence(case_dir: Path, unit_dir: Path, manifest: dict, *, root: Path = ROOT) -> dict:
    """Make the compiled evidence surface equal to the explicit envelope bindings.

    EVIDENCE bytes must map one-to-one by SHA-256 to a frozen path in the primary
    manifest. QUALIFICATION bytes must already exist in retained case infrastructure
    and match their sealed digest. Unbound inherited evidence/qualification files are
    removed. Semantic adapter/source-contract bytes are asserted unchanged.
    """
    case_dir = case_dir.resolve()
    unit_dir = unit_dir.resolve()
    assurance = case_dir / "assurance"
    adapter_path = assurance / "adapter.json"
    source_path = assurance / "source-contract.json"
    if not adapter_path.is_file() or not source_path.is_file():
        raise RuntimeError("compiled case lacks adapter.json or source-contract.json")

    adapter_sha = sha256_file(adapter_path)
    source_sha = sha256_file(source_path)

    instance_path = root / str(manifest.get("instance_path") or "")
    if not instance_path.is_file():
        raise RuntimeError("manifest instance_path is missing")
    instance = read_json(instance_path)
    envelope_path = (instance_path.parent / str(instance.get("carrier_envelope") or "")).resolve()
    envelope = read_json(envelope_path)
    bindings = ((envelope.get("adapter_base") or {}).get("bindings") or [])
    if not bindings:
        raise RuntimeError("carrier envelope has no explicit bindings")

    seen_ids: set[str] = set()
    seen_paths: set[str] = set()
    explicit_paths: set[str] = set()
    by_sha: dict[str, list[str]] = {}
    for item in manifest.get("frozen_paths") or []:
        rel, digest = item.get("path"), item.get("sha256")
        if rel and digest:
            by_sha.setdefault(str(digest), []).append(str(rel))

    normalized = []
    for b in bindings:
        bid = str(b.get("id") or "")
        kind = str(b.get("kind") or "")
        role = str(b.get("role") or "")
        rel = str(b.get("path") or "")
        digest = str(b.get("sha256") or "")
        if not bid or not rel or not digest:
            raise RuntimeError("each binding requires id, path, and sha256")
        if bid in seen_ids:
            raise RuntimeError(f"duplicate binding id: {bid}")
        if rel in seen_paths:
            raise RuntimeError(f"duplicate binding destination: {rel}")
        seen_ids.add(bid)
        seen_paths.add(rel)
        dest = safe_bound_path(assurance, rel)
        explicit_paths.add(rel.replace("\\", "/"))
        normalized.append((bid, kind, role, rel, digest, dest))

    # Remove inherited evidence/qualification bytes that are not explicitly bound.
    removed_unbound: list[str] = []
    for prefix in sorted(MANAGED_PREFIXES):
        managed = assurance / prefix
        if not managed.exists():
            continue
        for p in sorted((x for x in managed.rglob("*") if x.is_file()), key=lambda x: str(x)):
            rel = str(p.relative_to(assurance)).replace("\\", "/")
            if rel not in explicit_paths:
                removed_unbound.append(rel)
                p.unlink()
        _remove_empty_dirs(managed)

    records = []
    for bid, kind, role, rel, digest, dest in normalized:
        if kind == "EVIDENCE":
            candidates = sorted(set(by_sha.get(digest) or []))
            if len(candidates) != 1:
                raise RuntimeError(
                    f"EVIDENCE binding {bid} must map one-to-one by SHA-256 to frozen bytes; got {candidates}"
                )
            src = (root / candidates[0]).resolve()
            src.relative_to(root.resolve())
            if not src.is_file() or sha256_file(src) != digest:
                raise RuntimeError(f"frozen EVIDENCE source digest mismatch for {bid}")
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, dest)
            source_record = {"mode": "FROZEN_PATH_BY_SHA256", "path": candidates[0]}
        elif kind == "QUALIFICATION":
            if not role.startswith("SEALED_"):
                raise RuntimeError(f"QUALIFICATION role must be explicitly sealed: {bid}")
            if not dest.is_file():
                raise RuntimeError(f"sealed QUALIFICATION missing from retained infrastructure: {rel}")
            source_record = {"mode": "RETAINED_SEALED_QUALIFICATION"}
        else:
            raise RuntimeError(f"unsupported binding kind for v0.8 bound compiler: {kind}")

        actual = sha256_file(dest)
        if actual != digest:
            raise RuntimeError(f"bound digest mismatch for {bid}: expected={digest} actual={actual}")
        records.append(
            {
                "binding_id": bid,
                "kind": kind,
                "role": role,
                "path": rel.replace("\\", "/"),
                "sha256": digest,
                "source": source_record,
            }
        )

    # There must be no managed bytes outside the explicit binding surface.
    unexpected = []
    for prefix in sorted(MANAGED_PREFIXES):
        managed = assurance / prefix
        if not managed.exists():
            continue
        for p in managed.rglob("*"):
            if p.is_file():
                rel = str(p.relative_to(assurance)).replace("\\", "/")
                if rel not in explicit_paths:
                    unexpected.append(rel)
    if unexpected:
        raise RuntimeError(f"unbound evidence bytes survived compilation: {sorted(unexpected)}")

    if sha256_file(adapter_path) != adapter_sha:
        raise RuntimeError("bound-evidence compilation changed assurance/adapter.json")
    if sha256_file(source_path) != source_sha:
        raise RuntimeError("bound-evidence compilation changed assurance/source-contract.json")

    out = {
        "schema": SCHEMA,
        "mode": "EXPLICIT_BINDINGS_ONLY",
        "unit_id": manifest.get("unit_id"),
        "binding_count": len(records),
        "bindings": sorted(records, key=lambda x: x["binding_id"]),
        "removed_unbound_paths": sorted(removed_unbound),
        "unbound_managed_file_count_after": 0,
        "adapter_sha256_unchanged": adapter_sha,
        "source_contract_sha256_unchanged": source_sha,
        "scientific_semantics_modified": False,
    }
    write_json(case_dir / "BOUND_EVIDENCE_MANIFEST.json", out)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Compile a Corpus case to the explicit evidence-binding surface only")
    ap.add_argument("case_dir")
    ap.add_argument("unit_dir")
    ap.add_argument("manifest")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    try:
        case_dir = Path(args.case_dir).resolve()
        unit_dir = Path(args.unit_dir).resolve()
        manifest_path = Path(args.manifest)
        if not manifest_path.is_absolute():
            manifest_path = (ROOT / manifest_path).resolve()
        manifest = read_json(manifest_path)
        result = apply_bound_evidence(case_dir, unit_dir, manifest)
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print(f"BOUND EVIDENCE: PASS bindings={result['binding_count']} removed_unbound={len(result['removed_unbound_paths'])}")
        return 0
    except Exception as exc:
        print(f"BOUND EVIDENCE: FAIL: {exc}", file=__import__('sys').stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
