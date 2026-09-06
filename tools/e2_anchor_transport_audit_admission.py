from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

CASE_DOMAIN = b"risu-e2-transport-case/v0.1\0"
FROZEN_CELLS_TREE = "34a30574c7420728bff57958c815194979a622ab"
SEED_RE = re.compile(r"^(SYN-(?:PY|GO|TS)-0[12])\.(py|go|mjs|js|ts)$")
LANG = {"py":"python","go":"go","mjs":"typescript_javascript","js":"typescript_javascript","ts":"typescript_javascript"}
EXPECTED_TOP = {"schema","semantic_authority","case_count","cases","manifest_digest_sha256"}
EXPECTED_CASE = {"transport_case_id","seed_id","language","candidate_source_sha256"}
FORBIDDEN_STRINGS = (
    "expected_truth", "expected_e2_primary", "expected_e2_secondary",
    "mutation_operator", "operator_id", "operator_name", "operator_class",
    "repair", "verdict", "M_PLUS", "M_ZERO", "M_QUESTION",
    "CELL.json", "/materialized/", "source_path", "cell_id", "q_id",
)

def canonical(obj: object) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def h(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def case_id(seed: str, source_hash: str) -> str:
    return h(CASE_DOMAIN + seed.encode("ascii") + b"\0" + source_hash.encode("ascii"))

def main() -> int:
    ap=argparse.ArgumentParser()
    ap.add_argument("--root", required=True)
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--output", required=True)
    args=ap.parse_args()
    root=Path(args.root).resolve()
    rel="experiments/risu-diff-e2/qualification/materialized/cells"
    cells=root/rel
    tree=subprocess.check_output(["git","-C",str(root),"rev-parse",f"HEAD:{rel}"],text=True).strip()
    if tree != FROZEN_CELLS_TREE:
        raise SystemExit("cells tree mismatch")

    raw=Path(args.manifest).read_bytes()
    obj=json.loads(raw)
    errors=[]
    if raw != canonical(obj):
        errors.append("manifest_not_canonical_json")
    if set(obj) != EXPECTED_TOP:
        errors.append("top_level_key_set")
    if obj.get("schema") != "risu.e2-sanitized-opaque-58-admission-manifest/v0.1":
        errors.append("schema")
    if obj.get("semantic_authority") is not False:
        errors.append("semantic_authority")
    if obj.get("case_count") != 58 or len(obj.get("cases",[])) != 58:
        errors.append("case_count")

    tmp=dict(obj); got_digest=tmp.pop("manifest_digest_sha256", None)
    if got_digest != h(canonical(tmp)):
        errors.append("manifest_digest")

    text=raw.decode("utf-8")
    for token in FORBIDDEN_STRINGS:
        if token in text:
            errors.append("forbidden_string:"+token)
    if re.search(r'"Q[0-9]{3}"', text):
        errors.append("cell_identifier_leak")

    expected=[]
    for p in cells.rglob("*"):
        if not p.is_file():
            continue
        m=SEED_RE.fullmatch(p.name)
        if not m:
            continue
        seed,ext=m.group(1),m.group(2)
        sh=h(p.read_bytes())
        expected.append({
            "candidate_source_sha256":sh,
            "language":LANG[ext],
            "seed_id":seed,
            "transport_case_id":case_id(seed,sh),
        })
    expected.sort(key=lambda r:r["transport_case_id"])
    if len(expected) != 58:
        errors.append("source_count")
    if len({r["transport_case_id"] for r in expected}) != 58:
        errors.append("duplicate_expected_case_id")

    cases=obj.get("cases",[])
    for row in cases:
        if set(row) != EXPECTED_CASE:
            errors.append("case_key_set")
            break
    if cases != expected:
        errors.append("manifest_does_not_exactly_bind_frozen_source_bytes")

    receipt={
        "case_count":58,
        "cells_tree_git_sha":tree,
        "errors":sorted(set(errors)),
        "manifest_sha256":h(raw),
        "metadata_json_opened":False,
        "recomputed_all_candidate_source_hashes":True,
        "recomputed_all_transport_case_ids":True,
        "schema":"risu.e2-sanitized-opaque-admission-independent-audit/v0.1",
        "status":"PASS" if not errors else "FAIL",
    }
    out=canonical(receipt)
    Path(args.output).write_bytes(out)
    print(json.dumps({"status":receipt["status"],"errors":receipt["errors"],"manifest_sha256":receipt["manifest_sha256"]},separators=(",",":")))
    return 0 if not errors else 1

if __name__=="__main__":
    raise SystemExit(main())
