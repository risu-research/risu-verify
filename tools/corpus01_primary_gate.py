#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def git(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    p = subprocess.run(
        ["git", *args],
        cwd=str(ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if check and p.returncode != 0:
        raise RuntimeError(
            f"git {' '.join(args)} failed: {p.stderr.decode('utf-8', errors='replace').strip()}"
        )
    return p


def tracked_at(ref: str, path: str) -> bytes:
    p = git("show", f"{ref}:{path}", check=False)
    if p.returncode != 0:
        raise ValueError(f"frozen path is not present at authoring freeze commit: {path}")
    return p.stdout


def fail(errors: list[str], message: str) -> None:
    errors.append(message)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Refuse a Corpus 0.1 primary run if AUTHOR_ACCEPTED inputs changed after freeze"
    )
    ap.add_argument("manifest", help="PRIMARY_RUN_MANIFEST.json path")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    manifest_path = (ROOT / args.manifest).resolve()
    errors: list[str] = []
    try:
        manifest_path.relative_to(ROOT)
    except ValueError:
        print("manifest escapes repository root", file=sys.stderr)
        return 2

    if not manifest_path.is_file():
        print(f"manifest missing: {manifest_path}", file=sys.stderr)
        return 2

    m = read_json(manifest_path)
    if m.get("schema") != "risu.corpus-primary-run-manifest/v0.1alpha1":
        fail(errors, "unsupported primary-run manifest schema")
    if m.get("status") != "READY_FOR_FIRST_PRIMARY_EXECUTION":
        fail(errors, "manifest is not READY_FOR_FIRST_PRIMARY_EXECUTION")
    if m.get("primary_verdict_observed_before_manifest") is not False:
        fail(errors, "manifest does not explicitly record zero prior primary verdict observation")

    freeze = str(m.get("authoring_freeze_commit") or "")
    if not freeze:
        fail(errors, "authoring_freeze_commit missing")
    else:
        if git("rev-parse", "--verify", f"{freeze}^{{commit}}", check=False).returncode != 0:
            fail(errors, "authoring_freeze_commit is not an available commit")
        elif git("merge-base", "--is-ancestor", freeze, "HEAD", check=False).returncode != 0:
            fail(errors, "authoring freeze commit is not an ancestor of HEAD")

    frozen_paths = m.get("frozen_paths") or []
    if not frozen_paths:
        fail(errors, "frozen_paths is empty")
    seen = set()
    for item in frozen_paths:
        path = item.get("path")
        expected = item.get("sha256")
        if not path or not expected:
            fail(errors, "each frozen path requires path and sha256")
            continue
        if path in seen:
            fail(errors, f"duplicate frozen path: {path}")
            continue
        seen.add(path)
        current = ROOT / path
        if not current.is_file():
            fail(errors, f"current frozen path missing: {path}")
            continue
        current_bytes = current.read_bytes()
        current_sha = sha256_bytes(current_bytes)
        if current_sha != expected:
            fail(errors, f"current frozen path hash mismatch: {path}")
        if freeze:
            try:
                frozen_bytes = tracked_at(freeze, path)
            except Exception as exc:
                fail(errors, str(exc))
                continue
            frozen_sha = sha256_bytes(frozen_bytes)
            if frozen_sha != expected:
                fail(errors, f"authoring-freeze bytes do not match declared hash: {path}")
            if frozen_bytes != current_bytes:
                fail(errors, f"frozen input changed after author acceptance: {path}")

    acceptance_path = str(m.get("author_acceptance_path") or "")
    instance_path = str(m.get("instance_path") or "")
    if acceptance_path not in seen:
        fail(errors, "author acceptance record is not included in frozen_paths")
    if instance_path not in seen:
        fail(errors, "VBE instance is not included in frozen_paths")

    if acceptance_path:
        p = ROOT / acceptance_path
        if p.is_file():
            acceptance = read_json(p)
            if acceptance.get("status") != "AUTHOR_ACCEPTED":
                fail(errors, "author acceptance status is not AUTHOR_ACCEPTED")
            if acceptance.get("primary_verdict_observed_before_acceptance") is not False:
                fail(errors, "author acceptance does not record verdict blindness")
            if acceptance.get("unit_id") != m.get("unit_id"):
                fail(errors, "author acceptance unit_id mismatch")

    if instance_path:
        p = ROOT / instance_path
        if p.is_file():
            instance = read_json(p)
            if instance.get("status") != "AUTHOR_ACCEPTED":
                fail(errors, "VBE instance is not AUTHOR_ACCEPTED")
            if instance.get("instance_id") != m.get("instance_id"):
                fail(errors, "VBE instance_id mismatch")

    if freeze:
        changed = git("diff", "--name-only", f"{freeze}..HEAD").stdout.decode("utf-8").splitlines()
        allowed = set(m.get("post_freeze_allowed_paths") or [])
        manifest_rel = str(manifest_path.relative_to(ROOT)).replace("\\", "/")
        allowed.add(manifest_rel)
        unexpected = sorted(set(changed) - allowed)
        if unexpected:
            fail(errors, f"unexpected post-freeze changes: {unexpected}")

    result_path = m.get("tracked_primary_result_path")
    if result_path:
        if (ROOT / result_path).exists():
            fail(errors, "tracked primary result already exists before first primary execution")
        if git("cat-file", "-e", f"HEAD:{result_path}", check=False).returncode == 0:
            fail(errors, "primary result is already tracked at HEAD")

    result = {
        "status": "PASS" if not errors else "FAIL",
        "unit_id": m.get("unit_id"),
        "instance_id": m.get("instance_id"),
        "authoring_freeze_commit": freeze,
        "frozen_path_count": len(frozen_paths),
        "errors": errors,
    }
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"Corpus 0.1 primary freeze gate: {result['status']}")
        print(f"  unit={result['unit_id']} frozen_paths={result['frozen_path_count']}")
        for e in errors:
            print(f"  ERROR: {e}", file=sys.stderr)
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
