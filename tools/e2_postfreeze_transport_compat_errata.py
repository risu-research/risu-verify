#!/usr/bin/env python3
from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import os
import re
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, Callable

PARENT_PROTOCOL_BLOB = "8d1860312d259e628e86070416a4757c570ba05f"
ERRATUM_001_BLOB = "a226d19994b55e7668658a94604db2d1ce07cb05"
ERRATUM_002_BLOB = "663673cc3b1b4fdad07541dc0113b15de3e00fa2"
FROZEN_QUALIFIER_BLOB = "3b5cbe1bac55503e135426ccaab5ed73b65e5480"
FROZEN_AUDITOR_BLOB = "9bae752a306c762576c2b10f8cafbf400674566b"
FROZEN_BUNDLE_BLOB = "95f7338e6f21bc3e0a8fc3209296d2e98c1c6f12"
FROZEN_BUNDLE_SHA256 = "78c5f024c1af7a353844120879d3ec4487b5f56fb443bc6e063530f836a9f74c"
ADMISSION_BLOB = "f2fc78439d4bfadce5941bf71aadd15ec292bcb1"
ADMISSION_SHA256 = "847d85c2274cd6b94a83eefe0f6153a8fb183dbad758efa75118a4fd368623e4"
RECEIPT_SCHEMA_BLOB = "09a35d3c505b7ceaa0ecdefc682945fd61adfe37"
MATRIX_SHA256 = "afd681d308a6f4ec8c183edd9b139c6b914fe501936cf84e5845a6a1c0d6b7cb"
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def canon(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_blob_sha1(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()


def load_jsonl(path: Path) -> tuple[list[dict[str, Any]], bytes]:
    raw = path.read_bytes()
    rows = [json.loads(line) for line in raw.decode("utf-8").splitlines() if line.strip()]
    return rows, raw


def require_blob(path: Path, expected: str) -> bytes:
    raw = path.read_bytes()
    got = git_blob_sha1(raw)
    if got != expected:
        raise AssertionError(f"git blob mismatch for {path}: {got} != {expected}")
    return raw


def _is_type(value: Any, kind: str) -> bool:
    if kind == "object":
        return isinstance(value, dict)
    if kind == "array":
        return isinstance(value, list)
    if kind == "string":
        return isinstance(value, str)
    if kind == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if kind == "null":
        return value is None
    if kind == "boolean":
        return isinstance(value, bool)
    raise AssertionError(f"unsupported schema type: {kind}")


def _resolve_ref(root: dict[str, Any], ref: str) -> dict[str, Any]:
    if not ref.startswith("#/"):
        raise AssertionError(f"unsupported schema ref: {ref}")
    node: Any = root
    for token in ref[2:].split("/"):
        token = token.replace("~1", "/").replace("~0", "~")
        node = node[token]
    if not isinstance(node, dict):
        raise AssertionError("schema ref did not resolve to object")
    return node


def validate_schema(value: Any, schema: dict[str, Any], root: dict[str, Any], path: str = "$") -> None:
    if "$ref" in schema:
        validate_schema(value, _resolve_ref(root, str(schema["$ref"])), root, path)
        return
    if "anyOf" in schema:
        successes = 0
        for option in schema["anyOf"]:
            try:
                validate_schema(value, option, root, path)
                successes += 1
            except AssertionError:
                pass
        if successes == 0:
            raise AssertionError(f"{path}: no anyOf branch matched")
        return
    if "const" in schema and value != schema["const"]:
        raise AssertionError(f"{path}: const mismatch")
    if "enum" in schema and value not in schema["enum"]:
        raise AssertionError(f"{path}: enum mismatch")
    if "type" in schema:
        kind = str(schema["type"])
        if not _is_type(value, kind):
            raise AssertionError(f"{path}: expected {kind}")
    if isinstance(value, str):
        if "minLength" in schema and len(value) < int(schema["minLength"]):
            raise AssertionError(f"{path}: minLength")
        if "pattern" in schema and re.search(str(schema["pattern"]), value) is None:
            raise AssertionError(f"{path}: pattern")
    if isinstance(value, int) and not isinstance(value, bool):
        if "minimum" in schema and value < int(schema["minimum"]):
            raise AssertionError(f"{path}: minimum")
    if isinstance(value, list):
        if "minItems" in schema and len(value) < int(schema["minItems"]):
            raise AssertionError(f"{path}: minItems")
        if "maxItems" in schema and len(value) > int(schema["maxItems"]):
            raise AssertionError(f"{path}: maxItems")
        if "prefixItems" in schema:
            for i, sub in enumerate(schema["prefixItems"]):
                if i >= len(value):
                    break
                validate_schema(value[i], sub, root, f"{path}[{i}]")
        if "items" in schema and isinstance(schema["items"], dict):
            for i, item in enumerate(value):
                validate_schema(item, schema["items"], root, f"{path}[{i}]")
    if isinstance(value, dict):
        props = schema.get("properties", {})
        for key in schema.get("required", []):
            if key not in value:
                raise AssertionError(f"{path}: missing required key {key}")
        if schema.get("additionalProperties") is False:
            extras = set(value) - set(props)
            if extras:
                raise AssertionError(f"{path}: additional properties {sorted(extras)}")
        for key, sub in props.items():
            if key in value:
                validate_schema(value[key], sub, root, f"{path}.{key}")


def import_exact(path: Path, expected_blob: str, module_name: str) -> ModuleType:
    require_blob(path, expected_blob)
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Views:
    def __init__(
        self,
        protocol_path: Path,
        erratum1_path: Path,
        erratum2_path: Path,
        bundle_path: Path,
        admission_path: Path,
        schema_path: Path,
        matrix_path: Path,
    ) -> None:
        self.protocol_path = protocol_path.resolve()
        self.bundle_path = bundle_path.resolve()

        parent_raw = require_blob(protocol_path, PARENT_PROTOCOL_BLOB)
        err1_raw = require_blob(erratum1_path, ERRATUM_001_BLOB)
        err2_raw = require_blob(erratum2_path, ERRATUM_002_BLOB)
        bundle_raw = require_blob(bundle_path, FROZEN_BUNDLE_BLOB)
        admission_raw = require_blob(admission_path, ADMISSION_BLOB)
        schema_raw = require_blob(schema_path, RECEIPT_SCHEMA_BLOB)

        if sha256(bundle_raw) != FROZEN_BUNDLE_SHA256:
            raise AssertionError("frozen bundle sha256 mismatch")
        if sha256(admission_raw) != ADMISSION_SHA256:
            raise AssertionError("admission sha256 mismatch")

        parent = json.loads(parent_raw)
        err1 = json.loads(err1_raw)
        err2 = json.loads(err2_raw)
        bundle = json.loads(bundle_raw)
        admission = json.loads(admission_raw)
        receipt_schema = json.loads(schema_raw)
        matrix_rows, matrix_raw = load_jsonl(matrix_path)
        if sha256(matrix_raw) != MATRIX_SHA256:
            raise AssertionError("matrix sha256 mismatch")

        if err1.get("erratum_id") != "ERRATUM_001_OPERATOR_ID_REPRESENTATION":
            raise AssertionError("ERRATUM_001 identity mismatch")
        if err1.get("status") != "FROZEN_AFTER_LABEL_SCHEMA_UNBLINDING_BEFORE_ANY_TRUTH_TRANSPORT_JOIN":
            raise AssertionError("ERRATUM_001 status mismatch")
        if err1["parent_protocol"]["git_blob"] != PARENT_PROTOCOL_BLOB:
            raise AssertionError("ERRATUM_001 parent mismatch")
        if err1["frozen_evidence"]["qualifier_git_blob_at_failure"] != FROZEN_QUALIFIER_BLOB:
            raise AssertionError("ERRATUM_001 qualifier mismatch")
        if err1["frozen_evidence"]["independent_auditor_git_blob_at_failure"] != FROZEN_AUDITOR_BLOB:
            raise AssertionError("ERRATUM_001 auditor mismatch")
        if err1["representation_correction"]["transport_join_key_unchanged"] != [
            "seed_id", "language", "candidate_source_sha256"
        ]:
            raise AssertionError("ERRATUM_001 join key mismatch")

        if err2.get("erratum_id") != "ERRATUM_002_TRANSPORT_RECEIPT_REPRESENTATION":
            raise AssertionError("ERRATUM_002 identity mismatch")
        if err2.get("status") != "FROZEN_AFTER_TRANSPORT_RECEIPT_SCHEMA_UNBLINDING_BEFORE_ANY_TRUTH_TRANSPORT_JOIN_OUTPUT":
            raise AssertionError("ERRATUM_002 status mismatch")
        if err2["parent_chain"]["parent_protocol"]["git_blob"] != PARENT_PROTOCOL_BLOB:
            raise AssertionError("ERRATUM_002 parent mismatch")
        if err2["parent_chain"]["erratum_001"]["git_blob"] != ERRATUM_001_BLOB:
            raise AssertionError("ERRATUM_002 ERRATUM_001 mismatch")
        fa = err2["frozen_authorities"]
        expected_fa = {
            "blind_transport_bundle_git_blob": FROZEN_BUNDLE_BLOB,
            "blind_transport_bundle_sha256": FROZEN_BUNDLE_SHA256,
            "sanitized_admission_manifest_git_blob": ADMISSION_BLOB,
            "sanitized_admission_manifest_sha256": ADMISSION_SHA256,
            "frozen_transport_receipt_schema_git_blob": RECEIPT_SCHEMA_BLOB,
            "original_postfreeze_qualifier_git_blob": FROZEN_QUALIFIER_BLOB,
            "independent_postfreeze_auditor_git_blob": FROZEN_AUDITOR_BLOB,
            "expanded_truth_matrix_sha256": MATRIX_SHA256,
        }
        for key, expected in expected_fa.items():
            if fa.get(key) != expected:
                raise AssertionError(f"ERRATUM_002 authority mismatch: {key}")

        diffs = err2["schema_comparison"]["representation_differences_exhaustive_for_frozen_qualifier"]
        if len(diffs) != 2:
            raise AssertionError("ERRATUM_002 must authorize exactly two representation differences")
        if {d["qualifier_field"] for d in diffs} != {"language", "receipt_digest_sha256"}:
            raise AssertionError("ERRATUM_002 field set mismatch")
        if err2["schema_comparison"]["no_other_field_alias_or_structural_conversion_authorized"] is not True:
            raise AssertionError("ERRATUM_002 non-expansion boundary mismatch")

        short_allowed = {
            cls: set(str(x) for x in vals)
            for cls, vals in parent["truth_contract"]["allowed_operator_ids"].items()
        }
        full_by_class: dict[str, set[str]] = {cls: set() for cls in short_allowed}
        codes_by_class: dict[str, set[str]] = {cls: set() for cls in short_allowed}
        for row in matrix_rows:
            cls = str(row["operator_class"])
            opid = str(row["operator_id"])
            if cls not in short_allowed or "_" not in opid:
                raise AssertionError("matrix operator representation mismatch")
            code = opid.split("_", 1)[0]
            if code not in short_allowed[cls]:
                raise AssertionError("matrix operator code outside preregistered class allowlist")
            full_by_class[cls].add(opid)
            codes_by_class[cls].add(code)
        for cls in short_allowed:
            if codes_by_class[cls] != short_allowed[cls]:
                raise AssertionError("matrix short-code universe mismatch")
        effective_protocol = copy.deepcopy(parent)
        effective_protocol["truth_contract"]["allowed_operator_ids"] = {
            cls: sorted(full_by_class[cls]) for cls in sorted(full_by_class)
        }

        if admission.get("case_count") != 58 or len(admission.get("cases", [])) != 58:
            raise AssertionError("admission cardinality mismatch")
        by_tid: dict[str, dict[str, Any]] = {}
        allowed_admission_fields = {"transport_case_id", "seed_id", "language", "candidate_source_sha256"}
        for row in admission["cases"]:
            if set(row) != allowed_admission_fields:
                raise AssertionError("admission field set mismatch")
            tid = str(row["transport_case_id"])
            if tid in by_tid:
                raise AssertionError("duplicate admission transport_case_id")
            by_tid[tid] = row

        if bundle.get("case_count") != 58 or len(bundle.get("receipts", [])) != 58:
            raise AssertionError("bundle cardinality mismatch")
        projected_bundle = copy.deepcopy(bundle)
        projected_receipts: list[dict[str, Any]] = []
        seen_tids: set[str] = set()
        for i, receipt in enumerate(bundle["receipts"]):
            validate_schema(receipt, receipt_schema, receipt_schema, f"$.receipts[{i}]")
            tid = str(receipt["transport_case_id"])
            if tid in seen_tids:
                raise AssertionError("duplicate receipt transport_case_id")
            seen_tids.add(tid)
            row = by_tid.get(tid)
            if row is None:
                raise AssertionError("admission lookup failed")
            seed_id = str(receipt["seed_id"])
            if str(row["seed_id"]) != seed_id:
                raise AssertionError("admission/receipt seed mismatch")
            if str(row["candidate_source_sha256"]) != str(receipt["candidate_source_sha256"]):
                raise AssertionError("admission/receipt candidate sha mismatch")
            source_spec = parent["primary_source_contract"].get(seed_id)
            if not isinstance(source_spec, dict):
                raise AssertionError("unknown seed in parent source contract")
            if str(row["language"]) != str(source_spec["language"]):
                raise AssertionError("admission/parent language mismatch")
            digest = str(receipt["transport_digest_sha256"])
            if HEX64.fullmatch(digest) is None:
                raise AssertionError("transport digest representation mismatch")

            projected = copy.deepcopy(receipt)
            if "language" in projected and projected["language"] != row["language"]:
                raise AssertionError("language projection conflict")
            projected["language"] = str(row["language"])
            if "receipt_digest_sha256" in projected and projected["receipt_digest_sha256"] != digest:
                raise AssertionError("digest alias projection conflict")
            projected["receipt_digest_sha256"] = digest
            if set(projected) != set(receipt) | {"language", "receipt_digest_sha256"}:
                raise AssertionError("unauthorized projected receipt field")
            for key in receipt:
                if projected[key] != receipt[key]:
                    raise AssertionError("frozen receipt field changed by projection")
            projected_receipts.append(projected)

        if seen_tids != set(by_tid):
            raise AssertionError("receipt/admission transport_case_id bijection mismatch")
        projected_bundle["receipts"] = projected_receipts

        self.parent_raw = parent_raw
        self.bundle_raw = bundle_raw
        self.effective_protocol = effective_protocol
        self.projected_bundle = projected_bundle
        self.attestation_base = {
            "schema": "risu.e2-postfreeze-transport-compatibility-view-attestation/v0.1",
            "status": "PASS",
            "semantic_authority": False,
            "errata": {
                "ERRATUM_001_OPERATOR_ID_REPRESENTATION": ERRATUM_001_BLOB,
                "ERRATUM_002_TRANSPORT_RECEIPT_REPRESENTATION": ERRATUM_002_BLOB,
            },
            "frozen_tools": {
                "qualifier_git_blob": FROZEN_QUALIFIER_BLOB,
                "independent_auditor_git_blob": FROZEN_AUDITOR_BLOB,
            },
            "raw_authorities": {
                "parent_protocol_git_blob": PARENT_PROTOCOL_BLOB,
                "blind_transport_bundle_git_blob": FROZEN_BUNDLE_BLOB,
                "blind_transport_bundle_sha256": FROZEN_BUNDLE_SHA256,
                "sanitized_admission_manifest_git_blob": ADMISSION_BLOB,
                "sanitized_admission_manifest_sha256": ADMISSION_SHA256,
                "frozen_receipt_schema_git_blob": RECEIPT_SCHEMA_BLOB,
                "expanded_truth_matrix_sha256": MATRIX_SHA256,
            },
            "view_digests": {
                "effective_protocol_object_sha256": sha256(canon(effective_protocol)),
                "projected_bundle_object_sha256": sha256(canon(projected_bundle)),
            },
            "projection_counts": {
                "receipt_count": 58,
                "language_fields_projected": 58,
                "receipt_digest_aliases_projected": 58,
                "other_receipt_fields_projected": 0,
            },
            "method": {
                "file_read_boundary_in_memory_view": True,
                "raw_protocol_bytes_returned_to_frozen_tool_unchanged": True,
                "raw_bundle_bytes_returned_to_frozen_tool_unchanged": True,
                "protocol_authority_sha_check_preserved": True,
                "bundle_authority_sha_check_preserved": True,
                "frozen_tool_source_modified": False,
                "frozen_transport_bytes_modified": False,
                "join_key_semantics_modified": False,
                "metrics_modified": False,
                "strata_modified": False,
                "a3_a4_verdict_logic_executed": False,
                "fresh_target_evaluation_executed": False,
            },
        }

    def projected_loader(self, original: Callable[[Path], tuple[Any, bytes]]) -> Callable[[Path], tuple[Any, bytes]]:
        protocol_path = self.protocol_path
        bundle_path = self.bundle_path
        effective_protocol = self.effective_protocol
        projected_bundle = self.projected_bundle

        def load(path: Path) -> tuple[Any, bytes]:
            resolved = Path(path).resolve()
            obj, raw = original(path)
            if resolved == protocol_path:
                if raw != self.parent_raw:
                    raise AssertionError("parent protocol raw bytes changed")
                return copy.deepcopy(effective_protocol), raw
            if resolved == bundle_path:
                if raw != self.bundle_raw:
                    raise AssertionError("frozen bundle raw bytes changed")
                return copy.deepcopy(projected_bundle), raw
            return obj, raw

        return load


def invoke_tool(module: ModuleType, argv: list[str]) -> int:
    old_argv = sys.argv[:]
    try:
        sys.argv = argv
        rc = module.main()
    finally:
        sys.argv = old_argv
    if rc not in (None, 0):
        raise SystemExit(int(rc))
    return 0


def write_attestation(path: Path, base: dict[str, Any], role: str, scientific_output: Path) -> None:
    raw = scientific_output.read_bytes()
    obj = json.loads(raw.decode("utf-8"))
    att = copy.deepcopy(base)
    att["execution"] = {
        "role": role,
        "head_sha": os.environ.get("GITHUB_SHA"),
        "scientific_output_sha256": sha256(raw),
        "scientific_output_status": obj.get("status"),
        "scientific_output_case_count": (
            obj.get("integrity", {}).get("cell_count") if role == "qualifier" else obj.get("case_count")
        ),
        "scientific_output_modified_after_frozen_tool_return": False,
    }
    pre = canon(att)
    att["attestation_digest_sha256"] = sha256(pre)
    path.write_bytes(canon(att))


def common_paths(args: argparse.Namespace) -> Views:
    return Views(
        Path(args.protocol),
        Path(args.erratum1),
        Path(args.erratum2),
        Path(args.transport_bundle),
        Path(args.admission),
        Path(args.receipt_schema),
        Path(args.matrix),
    )


def run_qualifier(args: argparse.Namespace) -> int:
    views = common_paths(args)
    module = import_exact(Path(args.qualifier), FROZEN_QUALIFIER_BLOB, "risu_frozen_postfreeze_qualifier")
    module.read_json = views.projected_loader(module.read_json)
    argv = [
        str(Path(args.qualifier)),
        "--root", args.root,
        "--protocol", args.protocol,
        "--transport-bundle", args.transport_bundle,
        "--matrix", args.matrix,
        "--cells", args.cells,
        "--output", args.output,
    ]
    invoke_tool(module, argv)
    write_attestation(Path(args.attestation), views.attestation_base, "qualifier", Path(args.output))
    return 0


def run_auditor(args: argparse.Namespace) -> int:
    views = common_paths(args)
    module = import_exact(Path(args.auditor), FROZEN_AUDITOR_BLOB, "risu_frozen_postfreeze_auditor")
    module.load_json = views.projected_loader(module.load_json)
    argv = [
        str(Path(args.auditor)),
        "--protocol", args.protocol,
        "--transport-bundle", args.transport_bundle,
        "--matrix", args.matrix,
        "--cells", args.cells,
        "--qualification", args.qualification,
        "--output", args.output,
    ]
    invoke_tool(module, argv)
    write_attestation(Path(args.attestation), views.attestation_base, "auditor", Path(args.output))
    return 0


def add_common(ap: argparse.ArgumentParser) -> None:
    ap.add_argument("--protocol", required=True)
    ap.add_argument("--erratum1", required=True)
    ap.add_argument("--erratum2", required=True)
    ap.add_argument("--transport-bundle", required=True)
    ap.add_argument("--admission", required=True)
    ap.add_argument("--receipt-schema", required=True)
    ap.add_argument("--matrix", required=True)
    ap.add_argument("--cells", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--attestation", required=True)


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="mode", required=True)

    q = sub.add_parser("qualify")
    add_common(q)
    q.add_argument("--qualifier", required=True)
    q.add_argument("--root", required=True)

    a = sub.add_parser("audit")
    add_common(a)
    a.add_argument("--auditor", required=True)
    a.add_argument("--qualification", required=True)

    args = ap.parse_args()
    if args.mode == "qualify":
        return run_qualifier(args)
    if args.mode == "audit":
        return run_auditor(args)
    raise AssertionError("unreachable")


if __name__ == "__main__":
    raise SystemExit(main())
