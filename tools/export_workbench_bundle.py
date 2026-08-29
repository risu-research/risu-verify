#!/usr/bin/env python3
"""Create portable, content-addressed RISU Verify -> Browser Workbench handoff bundles.

This is a packaging/transport utility outside the scientific trust boundary. It does
not issue assurance, change a RISU verdict, or rerun the frozen producer/checker.
It refuses to package a run when the already-produced report, certificate, and
run-manifest do not agree on their recorded digests and identities.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
from pathlib import Path

TOOL_VERSION = "0.1"
RUN_SCHEMA = "risu.workbench-run/v0.1"
COMPARE_SCHEMA = "risu.workbench-comparison/v0.1"

PREFERRED = [
    ("report.json", "report", "application/json"),
    ("certificate.json", "certificate", "application/json"),
    ("run-manifest.json", "run-manifest", "application/json"),
    ("report.md", "report-markdown", "text/markdown"),
    ("producer.log", "producer-log", "text/plain"),
    ("consumer.log", "consumer-log", "text/plain"),
]


def fail(message: str, code: int = 30) -> "NoReturn":
    print(f"RISU Workbench handoff: {message}", file=sys.stderr)
    raise SystemExit(code)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_bytes(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def canonical_sha(value) -> str:
    return sha256_bytes(canonical_bytes(value))


def read_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        fail(f"invalid JSON: {path}: {exc}")


def safe_name(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip()).strip("-.")
    return value or "risu-run"


def get_source_digest(report: dict) -> str | None:
    return (report.get("commitments") or {}).get("source_semantic_digest")


def validate_run_dir(run_dir: Path) -> tuple[dict, dict, dict, list[dict]]:
    run_dir = run_dir.resolve()
    if not run_dir.is_dir():
        fail(f"run directory not found: {run_dir}")
    required = [run_dir / "report.json", run_dir / "certificate.json", run_dir / "run-manifest.json"]
    missing = [p.name for p in required if not p.is_file()]
    if missing:
        fail("missing required run artifact(s): " + ", ".join(missing))

    report = read_json(required[0])
    cert = read_json(required[1])
    manifest = read_json(required[2])
    if manifest.get("manifest_version") != "0.2":
        fail(f"unsupported run-manifest version: {manifest.get('manifest_version')!r}")
    if not report.get("product_status") or not isinstance(report.get("worlds"), list):
        fail("report.json does not look like a RISU Verify report")
    if not cert.get("results") or not cert.get("inner_certificate"):
        fail("certificate.json does not look like a RISU proof-carrying certificate")

    rb = required[0].read_bytes()
    cb = required[1].read_bytes()
    if sha256_bytes(rb) != manifest.get("report_json_sha256"):
        fail("run-manifest report_json_sha256 does not match report.json")
    if sha256_bytes(cb) != manifest.get("certificate_sha256"):
        fail("run-manifest certificate_sha256 does not match certificate.json")
    if (report.get("certificate") or {}).get("sha256") != sha256_bytes(cb):
        fail("report certificate SHA-256 does not match certificate.json")
    if manifest.get("case_id") != report.get("case_id"):
        fail("run-manifest case_id does not match report.json")
    if manifest.get("core_archive_sha256") != (report.get("core") or {}).get("archive_sha256"):
        fail("run-manifest core archive SHA-256 does not match report.json")

    digest_fields = {
        "report.md": "report_md_sha256",
        "producer.log": "producer_log_sha256",
        "consumer.log": "consumer_log_sha256",
    }
    for name, field in digest_fields.items():
        path = run_dir / name
        if path.is_file() and manifest.get(field) and sha256_bytes(path.read_bytes()) != manifest[field]:
            fail(f"run-manifest {field} does not match {name}")

    artifacts = []
    for name, kind, media_type in PREFERRED:
        path = run_dir / name
        if not path.is_file():
            continue
        data = path.read_bytes()
        artifacts.append({
            "name": name,
            "kind": kind,
            "media_type": media_type,
            "size": len(data),
            "sha256": sha256_bytes(data),
            "encoding": "base64",
            "content": base64.b64encode(data).decode("ascii"),
        })
    return report, cert, manifest, artifacts


def build_run_bundle(run_dir: Path) -> dict:
    report, _cert, manifest, artifacts = validate_run_dir(run_dir)
    descriptors = [
        {k: a[k] for k in ("name", "kind", "media_type", "size", "sha256", "encoding")}
        for a in artifacts
    ]
    run = {
        "case_id": report.get("case_id"),
        "title": report.get("title"),
        "risu_verify_version": report.get("risu_verify_version"),
        "product_status": report.get("product_status"),
        "semantic_exit_code": report.get("semantic_exit_code"),
        "source_semantic_digest": get_source_digest(report),
        "core_version": (report.get("core") or {}).get("version"),
        "core_archive_sha256": (report.get("core") or {}).get("archive_sha256"),
        "run_manifest_version": manifest.get("manifest_version"),
    }
    return {
        "bundle_schema": RUN_SCHEMA,
        "bundle_kind": "RISU_VERIFY_RUN_HANDOFF",
        "created_by": {"tool": "tools/export_workbench_bundle.py", "version": TOOL_VERSION},
        "boundary": "Transport and local-consumer handoff only. This bundle does not issue or modify a RISU assurance verdict.",
        "run": run,
        "artifact_manifest_sha256": canonical_sha(descriptors),
        "artifacts": artifacts,
    }


def validate_run_bundle(bundle: dict) -> dict:
    if bundle.get("bundle_schema") != RUN_SCHEMA:
        fail(f"not a {RUN_SCHEMA} bundle")
    artifacts = bundle.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        fail("run bundle contains no artifacts")
    descriptors = []
    decoded: dict[str, bytes] = {}
    for art in artifacts:
        for key in ("name", "kind", "media_type", "size", "sha256", "encoding", "content"):
            if key not in art:
                fail(f"run bundle artifact missing {key}")
        if art["encoding"] != "base64":
            fail("unsupported run bundle artifact encoding")
        try:
            data = base64.b64decode(art["content"], validate=True)
        except Exception:
            fail(f"invalid base64 content for {art['name']}")
        if len(data) != art["size"]:
            fail(f"size mismatch for embedded {art['name']}")
        if sha256_bytes(data) != art["sha256"]:
            fail(f"SHA-256 mismatch for embedded {art['name']}")
        decoded[art["name"]] = data
        descriptors.append({k: art[k] for k in ("name", "kind", "media_type", "size", "sha256", "encoding")})
    if canonical_sha(descriptors) != bundle.get("artifact_manifest_sha256"):
        fail("run bundle artifact manifest digest mismatch")
    for name in ("report.json", "certificate.json", "run-manifest.json"):
        if name not in decoded:
            fail(f"run bundle missing embedded {name}")
    report = json.loads(decoded["report.json"].decode("utf-8"))
    manifest = json.loads(decoded["run-manifest.json"].decode("utf-8"))
    if bundle.get("run", {}).get("case_id") != report.get("case_id"):
        fail("run bundle metadata case_id does not match embedded report")
    if bundle.get("run", {}).get("product_status") != report.get("product_status"):
        fail("run bundle metadata product_status does not match embedded report")
    if bundle.get("run", {}).get("source_semantic_digest") != get_source_digest(report):
        fail("run bundle metadata source semantic digest does not match embedded report")
    if manifest.get("report_json_sha256") != sha256_bytes(decoded["report.json"]):
        fail("embedded run-manifest does not bind embedded report.json")
    if manifest.get("certificate_sha256") != sha256_bytes(decoded["certificate.json"]):
        fail("embedded run-manifest does not bind embedded certificate.json")
    return report


def load_run_input(path: Path) -> dict:
    path = path.resolve()
    if path.is_dir():
        return build_run_bundle(path)
    if path.is_file():
        bundle = read_json(path)
        validate_run_bundle(bundle)
        return bundle
    fail(f"run input not found: {path}")


def comparison_summary(base_report: dict, current_report: dict) -> dict:
    bdig = get_source_digest(base_report)
    cdig = get_source_digest(current_report)
    same_semantics = bool(bdig and cdig and bdig == cdig)
    bs = base_report.get("structural") or {}
    cs = current_report.get("structural") or {}
    return {
        "comparison_scope": "SAME_DECLARED_SOURCE_SEMANTICS" if same_semantics else "SOURCE_SEMANTIC_COMMITMENT_CHANGED",
        "source_semantic_digest_same": same_semantics,
        "case_id_same": base_report.get("case_id") == current_report.get("case_id"),
        "baseline": {
            "case_id": base_report.get("case_id"),
            "product_status": base_report.get("product_status"),
            "source_semantic_digest": bdig,
            "structural": {"C": bs.get("C"), "D": bs.get("D"), "O": bs.get("O")},
            "exact_status": (base_report.get("exact_realization") or {}).get("status"),
        },
        "current": {
            "case_id": current_report.get("case_id"),
            "product_status": current_report.get("product_status"),
            "source_semantic_digest": cdig,
            "structural": {"C": cs.get("C"), "D": cs.get("D"), "O": cs.get("O")},
            "exact_status": (current_report.get("exact_realization") or {}).get("status"),
        },
    }


def build_comparison_bundle(base_input: Path, current_input: Path) -> dict:
    base = load_run_input(base_input)
    current = load_run_input(current_input)
    base_report = validate_run_bundle(base)
    current_report = validate_run_bundle(current)
    summary = comparison_summary(base_report, current_report)
    return {
        "bundle_schema": COMPARE_SCHEMA,
        "bundle_kind": "RISU_VERIFY_COMPARISON_HANDOFF",
        "created_by": {"tool": "tools/export_workbench_bundle.py", "version": TOOL_VERSION},
        "boundary": "Comparison transport only. Same-source interpretation is permitted only when source_semantic_digest_same is true.",
        "comparison": summary,
        "baseline_run": base,
        "current_run": current,
    }


def write_bundle(bundle: dict, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "status": "PASS",
        "bundle_schema": bundle["bundle_schema"],
        "output": str(output),
        "sha256": sha256_bytes(output.read_bytes()),
        "workbench_url": "https://risuinstitute.org/tools/#workbench",
        "next_step": "Open the Workbench and drop this handoff file.",
    }, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="package one RISU Verify output directory")
    run.add_argument("run_dir", type=Path)
    run.add_argument("--output", "-o", type=Path)

    comp = sub.add_parser("compare", help="package two runs for browser comparison")
    comp.add_argument("baseline", type=Path)
    comp.add_argument("current", type=Path)
    comp.add_argument("--output", "-o", type=Path)

    args = parser.parse_args()
    if args.command == "run":
        bundle = build_run_bundle(args.run_dir)
        default = Path(f"{safe_name(bundle['run'].get('case_id') or 'risu-run')}.risu.json")
        write_bundle(bundle, args.output or default)
    else:
        bundle = build_comparison_bundle(args.baseline, args.current)
        b = safe_name(bundle["comparison"]["baseline"].get("case_id") or "baseline")
        c = safe_name(bundle["comparison"]["current"].get("case_id") or "current")
        write_bundle(bundle, args.output or Path(f"{b}--vs--{c}.risu-compare.json"))


if __name__ == "__main__":
    main()
