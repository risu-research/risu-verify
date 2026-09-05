#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from vbe_compile import compile_instance


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, obj) -> None:
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Compile one AUTHOR_ACCEPTED Corpus 0.1 VBE instance without changing scientific semantics"
    )
    ap.add_argument("instance")
    ap.add_argument("--output", required=True)
    args = ap.parse_args()

    instance_path = Path(args.instance).resolve()
    out = Path(args.output).resolve()
    inst = read_json(instance_path)
    if inst.get("status") != "AUTHOR_ACCEPTED":
        raise SystemExit("Corpus primary compilation requires status=AUTHOR_ACCEPTED")
    corpus = inst.get("corpus") or {}
    if corpus.get("id") != "PROSPECTIVE_CORPUS_0.1":
        raise SystemExit("instance is not bound to PROSPECTIVE_CORPUS_0.1")
    if not corpus.get("unit_id"):
        raise SystemExit("prospective corpus instance lacks unit_id")

    compile_instance(instance_path, out)

    case_path = out / "case.json"
    case = read_json(case_path)
    case["title"] = f"Prospective Corpus 0.1 - {corpus['unit_id']} - {inst['instance_id']}"
    case["kind"] = "VBE_PROFILE_COMPILED_PROSPECTIVE"
    case["corpus"] = {
        "id": corpus["id"],
        "unit_id": corpus["unit_id"],
        "enrollment_position": corpus.get("enrollment_position"),
        "authoring_status": inst["status"],
    }
    write_json(case_path, case)

    manifest_path = out / "VBE_COMPILE_MANIFEST.json"
    manifest = read_json(manifest_path)
    manifest["compilation_mode"] = "PROSPECTIVE_CORPUS_PRIMARY"
    manifest["corpus"] = case["corpus"]
    manifest["note"] = (
        "This wrapper changes generated case metadata only. Source-contract and adapter semantics are produced by tools/vbe_compile.py unchanged."
    )
    write_json(manifest_path, manifest)

    print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
