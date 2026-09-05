#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import urllib.parse
import urllib.request
import zlib
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterable, List

EXAM_ID = "UNIT003_BLIND_MACHINE_FIRST_E0_001"
UNIT_ID = "corpus01-unit-003"
REPOSITORY = "kubernetes/kubectl"
TARGET_REVISION = "04f459470f58642063b0374361bee0011278f6d8"
TARGET_TREE_SHA = "d1eb526feea2a1815554db775a343d751f4892b1"
SCREENED_OPERATION = "kubectl annotate --resource-version"
ENGINE_IDENTITY_DIGEST = "7979ff811765cf1617602b2ef9ed89935f24da2c1f32eceb417dfd209e335c60"
EFFECTIVE_PROTOCOL_BLOB = "95a72c1857fe797be11d4f5a21d23156a69711d4"
CORRECTION_BLOB = "90bb97f4ca37461398eb8f00cd479756ae2d10e9"
MAX_FILES = 24
INCLUDE_EXTENSIONS = (".go", ".md", ".yaml", ".yml", ".json", ".txt")
EXCLUDE_FRAGMENTS = ("vendor/", "third_party/", "translations/")
SELECTION_SCHEMA = "risu.unit003-round0-selection/v0.1"
FIRST_SEAL_SCHEMA = "risu.unit003-first-seal-record/v0.1"

POLICY = {
    "maximum_first_round_files": MAX_FILES,
    "include_extensions": list(INCLUDE_EXTENSIONS),
    "exclude_path_fragments": list(EXCLUDE_FRAGMENTS),
    "ranking": [
        "exact basename/token match to annotate",
        "path contains kubectl and annotate",
        "path contains resource-version/resourceversion/resource_version/resourceVersion",
        "path contains command or cmd near annotate",
        "lexicographic path as final tie-break",
    ],
    "formalization": {
        "tokenization": "lowercase ASCII alphanumeric runs from the full repository-relative path",
        "exact_annotate": "basename stem equals annotate OR annotate is one token",
        "kubectl_and_annotate": "both kubectl and annotate occur as tokens",
        "resource_version": "lowercase path contains resource-version or resource_version OR punctuation-stripped lowercase path contains resourceversion",
        "cmd_or_command_near_annotate": "annotate token and either cmd or command token occur in the same path",
        "order": "descending booleans in the listed ranking order, then Unicode codepoint lexicographic path",
        "cut": "first 24 eligible paths; no score threshold",
    },
}


class AcquisitionError(RuntimeError):
    pass


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_blob_sha1(data: bytes) -> str:
    header = f"blob {len(data)}\0".encode("ascii")
    return hashlib.sha1(header + data).hexdigest()


def policy_sha256() -> str:
    return sha256_bytes(canonical_bytes(POLICY))


def _safe_path(path: str) -> str:
    if not isinstance(path, str) or not path:
        raise AcquisitionError("empty path")
    p = PurePosixPath(path)
    if p.is_absolute() or "." in p.parts or ".." in p.parts or "\\" in path:
        raise AcquisitionError(f"unsafe target path: {path!r}")
    return p.as_posix()


def path_features(path: str) -> Dict[str, bool]:
    safe = _safe_path(path)
    low = safe.lower()
    tokens = re.findall(r"[a-z0-9]+", low)
    stem = PurePosixPath(low).stem
    compact = re.sub(r"[^a-z0-9]+", "", low)
    annotate = stem == "annotate" or "annotate" in tokens
    return {
        "exact_annotate": annotate,
        "kubectl_and_annotate": "kubectl" in tokens and "annotate" in tokens,
        "resource_version": (
            "resource-version" in low
            or "resource_version" in low
            or "resourceversion" in compact
        ),
        "cmd_or_command_near_annotate": annotate and ("cmd" in tokens or "command" in tokens),
    }


def ranking_key(row: Dict[str, Any]) -> tuple:
    f = row["features"]
    return (
        -int(f["exact_annotate"]),
        -int(f["kubectl_and_annotate"]),
        -int(f["resource_version"]),
        -int(f["cmd_or_command_near_annotate"]),
        row["path"],
    )


def eligible_path(path: str) -> bool:
    safe = _safe_path(path)
    low = safe.lower()
    if any(fragment in low for fragment in EXCLUDE_FRAGMENTS):
        return False
    return any(low.endswith(ext) for ext in INCLUDE_EXTENSIONS)


def parse_ls_tree(raw: bytes) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    for record in raw.split(b"\0"):
        if not record:
            continue
        try:
            meta, path_b = record.split(b"\t", 1)
            mode_b, type_b, sha_b = meta.split(b" ", 2)
            path = path_b.decode("utf-8", errors="strict")
        except Exception as exc:
            raise AcquisitionError(f"cannot parse ls-tree record: {exc}") from exc
        if type_b != b"blob":
            continue
        rows.append({
            "mode": mode_b.decode("ascii"),
            "type": "blob",
            "git_blob_sha": sha_b.decode("ascii"),
            "path": _safe_path(path),
        })
    return rows


def _git(repo: Path, *args: str) -> bytes:
    try:
        return subprocess.check_output(["git", "-C", str(repo), *args], stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as exc:
        raise AcquisitionError(f"git {' '.join(args)} failed: {exc.output.decode('utf-8', errors='replace')}") from exc


def local_object_types(repo: Path) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    git_dir = Path(_git(repo, "rev-parse", "--git-dir").decode().strip())
    if not git_dir.is_absolute():
        git_dir = (repo / git_dir).resolve()

    pack_dir = git_dir / "objects" / "pack"
    if pack_dir.is_dir():
        for idx in sorted(pack_dir.glob("*.idx")):
            out = subprocess.check_output(["git", "verify-pack", "-v", str(idx)], stderr=subprocess.STDOUT)
            for line in out.decode("utf-8", errors="replace").splitlines():
                parts = line.split()
                if len(parts) >= 2 and re.fullmatch(r"[0-9a-f]{40,64}", parts[0]) and parts[1] in {"blob", "tree", "commit", "tag"}:
                    counts[parts[1]] = counts.get(parts[1], 0) + 1

    obj_dir = git_dir / "objects"
    if obj_dir.is_dir():
        for prefix in sorted(obj_dir.iterdir()):
            if not prefix.is_dir() or not re.fullmatch(r"[0-9a-f]{2}", prefix.name):
                continue
            for obj in sorted(prefix.iterdir()):
                if not re.fullmatch(r"[0-9a-f]{38,62}", obj.name):
                    continue
                try:
                    decoded = zlib.decompress(obj.read_bytes())
                except Exception:
                    continue
                kind = decoded.split(b" ", 1)[0].decode("ascii", errors="ignore")
                if kind in {"blob", "tree", "commit", "tag"}:
                    counts[kind] = counts.get(kind, 0) + 1
    return counts


def build_selection(repo: Path) -> Dict[str, Any]:
    commit = _git(repo, "rev-parse", TARGET_REVISION).decode().strip()
    if commit != TARGET_REVISION:
        raise AcquisitionError(f"target commit mismatch: {commit}")
    tree = _git(repo, "rev-parse", f"{TARGET_REVISION}^{{tree}}").decode().strip()
    if tree != TARGET_TREE_SHA:
        raise AcquisitionError(f"target tree mismatch: {tree}")
    object_types = local_object_types(repo)
    if object_types.get("blob", 0) != 0:
        raise AcquisitionError(f"selection repository already contains target blobs: {object_types}")

    all_rows = parse_ls_tree(_git(repo, "ls-tree", "-r", "-z", TARGET_REVISION))
    eligible: List[Dict[str, Any]] = []
    for row in all_rows:
        if eligible_path(row["path"]):
            eligible.append({
                "path": row["path"],
                "git_blob_sha": row["git_blob_sha"],
                "features": path_features(row["path"]),
            })
    eligible.sort(key=ranking_key)
    selected = []
    for index, row in enumerate(eligible[:MAX_FILES], start=1):
        selected.append({"rank": index, **row})

    basis = {
        "exam_id": EXAM_ID,
        "unit_id": UNIT_ID,
        "repository": REPOSITORY,
        "target_revision": TARGET_REVISION,
        "target_tree_sha": TARGET_TREE_SHA,
        "screened_operation": SCREENED_OPERATION,
        "policy_sha256": policy_sha256(),
        "selected": selected,
    }
    return {
        "schema": SELECTION_SCHEMA,
        **basis,
        "selection_sha256": sha256_bytes(canonical_bytes(basis)),
        "path_metadata_only": True,
        "target_file_contents_read_for_selection": False,
        "local_target_blob_objects_before_selection": object_types.get("blob", 0),
        "tree_blob_entries": len(all_rows),
        "eligible_entries": len(eligible),
        "selected_count": len(selected),
        "selection_policy": POLICY,
        "strict_zero_byte_blindness_claimed": False,
        "preseal_incident_001_disclosed": True,
    }


def verify_selection(manifest: Dict[str, Any]) -> None:
    if manifest.get("schema") != SELECTION_SCHEMA:
        raise AcquisitionError("selection schema mismatch")
    if manifest.get("exam_id") != EXAM_ID or manifest.get("unit_id") != UNIT_ID:
        raise AcquisitionError("selection exam/unit mismatch")
    if manifest.get("repository") != REPOSITORY:
        raise AcquisitionError("selection repository mismatch")
    if manifest.get("target_revision") != TARGET_REVISION or manifest.get("target_tree_sha") != TARGET_TREE_SHA:
        raise AcquisitionError("selection target identity mismatch")
    if manifest.get("screened_operation") != SCREENED_OPERATION:
        raise AcquisitionError("selection operation mismatch")
    if manifest.get("policy_sha256") != policy_sha256() or manifest.get("selection_policy") != POLICY:
        raise AcquisitionError("selection policy mismatch")
    selected = manifest.get("selected")
    if not isinstance(selected, list) or len(selected) > MAX_FILES:
        raise AcquisitionError("invalid selected list")
    for i, row in enumerate(selected, start=1):
        if row.get("rank") != i:
            raise AcquisitionError("selection rank sequence mismatch")
        if not eligible_path(row.get("path", "")):
            raise AcquisitionError(f"ineligible selected path: {row.get('path')!r}")
        if row.get("features") != path_features(row["path"]):
            raise AcquisitionError(f"feature mismatch: {row['path']}")
        if not re.fullmatch(r"[0-9a-f]{40}", str(row.get("git_blob_sha", ""))):
            raise AcquisitionError(f"invalid Git blob SHA: {row.get('git_blob_sha')!r}")
    if selected != sorted(selected, key=ranking_key):
        raise AcquisitionError("selected rows are not in frozen rank order")
    basis = {
        "exam_id": EXAM_ID,
        "unit_id": UNIT_ID,
        "repository": REPOSITORY,
        "target_revision": TARGET_REVISION,
        "target_tree_sha": TARGET_TREE_SHA,
        "screened_operation": SCREENED_OPERATION,
        "policy_sha256": policy_sha256(),
        "selected": selected,
    }
    if manifest.get("selection_sha256") != sha256_bytes(canonical_bytes(basis)):
        raise AcquisitionError("selection digest mismatch")
    if manifest.get("path_metadata_only") is not True or manifest.get("target_file_contents_read_for_selection") is not False:
        raise AcquisitionError("selection blindness flags invalid")
    if manifest.get("local_target_blob_objects_before_selection") != 0:
        raise AcquisitionError("selection was not tree-only")


def surface_from_screened_operation(value: str) -> Dict[str, Any]:
    parts = shlex.split(value)
    if not parts:
        raise AcquisitionError("empty screened operation")
    first_flag = next((i for i, token in enumerate(parts) if token.startswith("--")), len(parts))
    name = " ".join(parts[:first_flag])
    args = []
    for token in parts[first_flag:]:
        if token.startswith("--"):
            arg = token[2:].split("=", 1)[0]
            if arg:
                args.append(arg)
    return {"name": name, "arguments": sorted(set(args))}


def _raw_url(path: str) -> str:
    quoted = urllib.parse.quote(_safe_path(path), safe="/")
    return f"https://raw.githubusercontent.com/{REPOSITORY}/{TARGET_REVISION}/{quoted}"


def fetch_exact_selected_blob(row: Dict[str, Any]) -> bytes:
    request = urllib.request.Request(
        _raw_url(row["path"]),
        headers={"User-Agent": "RISU-Unit003-Blind-Machine-First/0.1"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read()
    except Exception as exc:
        raise AcquisitionError(f"selected blob fetch failed for {row['path']}: {type(exc).__name__}:{exc}") from exc
    actual_git = git_blob_sha1(raw)
    if actual_git != row["git_blob_sha"]:
        raise AcquisitionError(
            f"Git blob identity mismatch for {row['path']}: expected {row['git_blob_sha']} actual {actual_git}"
        )
    return raw


def language_for(path: str) -> str:
    low = path.lower()
    if low.endswith(".go"):
        return "go"
    if low.endswith(".md"):
        return "markdown"
    if low.endswith((".yaml", ".yml")):
        return "yaml"
    if low.endswith(".json"):
        return "json"
    if low.endswith(".txt"):
        return "text"
    return "unknown"


def acquire_packet(selection: Dict[str, Any], packet_dir: Path, run_id: str) -> Dict[str, Any]:
    verify_selection(selection)
    if packet_dir.exists() and any(packet_dir.iterdir()):
        raise AcquisitionError("packet directory must be absent or empty")
    packet_dir.mkdir(parents=True, exist_ok=True)
    evidence_rows = []
    for row in selection["selected"]:
        raw = fetch_exact_selected_blob(row)
        rel = f"evidence/target/{row['path']}"
        out = packet_dir / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(raw)
        evidence_rows.append({
            "path": rel,
            "sha256": sha256_bytes(raw),
            "kind": "TARGET_TEXT",
            "language": language_for(row["path"]),
        })

    root = {
        "schema": "risu.diff-e0-machine-input/v0.1",
        "run_id": run_id,
        "unit_id": UNIT_ID,
        "target_revision": TARGET_REVISION,
        "screened_operation": SCREENED_OPERATION,
        "surface": surface_from_screened_operation(SCREENED_OPERATION),
        "evidence_files": evidence_rows,
        "acquisition": {
            "exam_id": EXAM_ID,
            "method": "TREE_ONLY_SELECTION_THEN_SELECTED_RAW_EXACT_REVISION_FETCH",
            "repository": REPOSITORY,
            "target_tree_sha": TARGET_TREE_SHA,
            "selection_sha256": selection["selection_sha256"],
            "selection_policy_sha256": policy_sha256(),
            "engine_identity_digest": ENGINE_IDENTITY_DIGEST,
            "effective_protocol_git_blob": EFFECTIVE_PROTOCOL_BLOB,
            "correction_git_blob": CORRECTION_BLOB,
            "preseal_incident_001_disclosed": True,
        },
    }
    (packet_dir / "MACHINE_INPUT.json").write_bytes(canonical_bytes(root))
    return {
        "evidence_count": len(evidence_rows),
        "machine_input_sha256": sha256_bytes((packet_dir / "MACHINE_INPUT.json").read_bytes()),
        "selection_sha256": selection["selection_sha256"],
    }


def write_first_seal_record(selection_path: Path, packet_dir: Path, output_dir: Path, out_path: Path) -> Dict[str, Any]:
    from risu_e0.machine_first import load_machine_packet, verify_output_dir

    selection = json.loads(selection_path.read_text(encoding="utf-8"))
    verify_selection(selection)
    packet = load_machine_packet(packet_dir)
    verified = verify_output_dir(output_dir)
    prediction_bytes = (output_dir / "E0_PREDICTION.json").read_bytes()
    probe_bytes = (output_dir / "PROBE_PLAN.json").read_bytes()
    request_bytes = (output_dir / "REFINEMENT_REQUESTS.json").read_bytes()
    record = {
        "schema": FIRST_SEAL_SCHEMA,
        "exam_id": EXAM_ID,
        "unit_id": UNIT_ID,
        "repository": REPOSITORY,
        "target_revision": TARGET_REVISION,
        "target_tree_sha": TARGET_TREE_SHA,
        "engine_identity_digest": ENGINE_IDENTITY_DIGEST,
        "selection_sha256": selection["selection_sha256"],
        "input_packet_digest": packet["packet_digest"],
        "machine_input_sha256": packet["packet_identity"]["machine_input_sha256"],
        "evidence_sha256": packet["packet_identity"]["evidence_sha256"],
        "seal_digest": verified["seal_digest"],
        "semantic_artifact_sha256": verified["semantic_artifact_sha256"],
        "prediction_artifact_sha256": sha256_bytes(prediction_bytes),
        "probe_plan_sha256": sha256_bytes(probe_bytes),
        "refinement_requests_sha256": sha256_bytes(request_bytes),
        "prediction_value_intentionally_not_copied_into_record": True,
        "screened_operation_semantic_contents_not_logged_before_seal": True,
        "strict_zero_byte_blindness_claimed": False,
        "preseal_incident_001_disclosed": True,
        "canonical_scientific_authority": False,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(canonical_bytes(record))
    return record


def cmd_select(args: argparse.Namespace) -> int:
    manifest = build_selection(args.repo_dir)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_bytes(canonical_bytes(manifest))
    print(json.dumps({
        "status": "PASS",
        "selection_sha256": manifest["selection_sha256"],
        "selected_count": manifest["selected_count"],
        "eligible_entries": manifest["eligible_entries"],
        "tree_blob_entries": manifest["tree_blob_entries"],
        "local_target_blob_objects_before_selection": manifest["local_target_blob_objects_before_selection"],
    }, sort_keys=True))
    return 0


def cmd_verify_selection(args: argparse.Namespace) -> int:
    manifest = json.loads(args.selection.read_text(encoding="utf-8"))
    verify_selection(manifest)
    print(json.dumps({
        "status": "PASS",
        "selection_sha256": manifest["selection_sha256"],
        "selected_count": len(manifest["selected"]),
    }, sort_keys=True))
    return 0


def cmd_acquire(args: argparse.Namespace) -> int:
    selection = json.loads(args.selection.read_text(encoding="utf-8"))
    info = acquire_packet(selection, args.packet_dir, args.run_id)
    print(json.dumps({"status": "PASS", **info}, sort_keys=True))
    return 0


def cmd_record(args: argparse.Namespace) -> int:
    record = write_first_seal_record(args.selection, args.packet_dir, args.output_dir, args.out)
    print(json.dumps({
        "status": "PASS",
        "seal_digest": record["seal_digest"],
        "selection_sha256": record["selection_sha256"],
        "prediction_artifact_sha256": record["prediction_artifact_sha256"],
    }, sort_keys=True))
    return 0


def make_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Frozen Unit003 machine-first acquisition harness.")
    sub = p.add_subparsers(dest="command", required=True)
    s = sub.add_parser("select")
    s.add_argument("--repo-dir", type=Path, required=True)
    s.add_argument("--out", type=Path, required=True)
    s.set_defaults(func=cmd_select)
    v = sub.add_parser("verify-selection")
    v.add_argument("--selection", type=Path, required=True)
    v.set_defaults(func=cmd_verify_selection)
    a = sub.add_parser("acquire")
    a.add_argument("--selection", type=Path, required=True)
    a.add_argument("--packet-dir", type=Path, required=True)
    a.add_argument("--run-id", required=True)
    a.set_defaults(func=cmd_acquire)
    r = sub.add_parser("record")
    r.add_argument("--selection", type=Path, required=True)
    r.add_argument("--packet-dir", type=Path, required=True)
    r.add_argument("--output-dir", type=Path, required=True)
    r.add_argument("--out", type=Path, required=True)
    r.set_defaults(func=cmd_record)
    return p


def main() -> int:
    try:
        args = make_parser().parse_args()
        return int(args.func(args))
    except (AcquisitionError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({
            "status": "UNIT003_ACQUISITION_INFRASTRUCTURE_FAILURE",
            "scientific_prediction": False,
            "error_type": type(exc).__name__,
            "error": str(exc),
        }, sort_keys=True), file=sys.stderr)
        return 20


if __name__ == "__main__":
    raise SystemExit(main())
