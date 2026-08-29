#!/usr/bin/env python3
"""RISU Verify vertical slice.

This file is an untrusted convenience layer over the frozen Consequence-Preserving
Projections v0.7.0 scientific core. It does not implement C/D/O, Exact Realization,
source compilation, evidence verification, certificate issuance, or proof checking.

Trust flow:
  pinned core archive -> producer certificate -> independent core consumer checker
  -> derived human/machine report -> optional semantic lock comparison
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import platform
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import textwrap
import zipfile

TOOL_VERSION = "0.4.0-rc1"
EXIT_OK = 0
EXIT_REGRESSION = 10
EXIT_INCOMPLETE = 20
EXIT_INVALID = 30
EXIT_LOCK_MISMATCH = 40


def root_dir() -> Path:
    return Path(__file__).resolve().parents[1]


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def canonical_sha(obj) -> str:
    b = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(b).hexdigest()


def fail(msg: str, code: int = EXIT_INVALID):
    print(f"RISU Verify: {msg}", file=sys.stderr)
    raise SystemExit(code)


def verify_core_pin(project: Path) -> dict:
    pin_path = project / "CORE_PIN.json"
    pin = read_json(pin_path)
    archive = project / pin["archive"]
    if not archive.is_file():
        fail(f"frozen core archive missing: {archive}")
    actual = sha256_file(archive)
    if actual != pin["archive_sha256"]:
        fail(
            "frozen core pin mismatch; refusing to execute\n"
            f"  expected {pin['archive_sha256']}\n"
            f"  actual   {actual}"
        )
    return {**pin, "archive_path": str(archive), "pin_status": "PASS"}


def _safe_extract(zf: zipfile.ZipFile, dest: Path) -> None:
    dest_resolved = dest.resolve()
    for member in zf.infolist():
        target = (dest / member.filename).resolve()
        try:
            target.relative_to(dest_resolved)
        except ValueError:
            fail(f"unsafe path in frozen core archive: {member.filename}")
    zf.extractall(dest)


@contextlib.contextmanager
def core_runtime(project: Path, pin: dict):
    archive = Path(pin["archive_path"])
    with tempfile.TemporaryDirectory(prefix="risu-verify-core-") as td:
        td_path = Path(td)
        with zipfile.ZipFile(archive, "r") as zf:
            _safe_extract(zf, td_path)
        core = td_path / pin["expected_root"]
        if not core.is_dir():
            fail(f"frozen core root not found after extraction: {pin['expected_root']}")
        seal = read_json(core / "PACKAGE_SEAL.json")
        if seal.get("release_version") != pin["core_version"]:
            fail("frozen core package seal version does not match CORE_PIN.json")
        if seal.get("release_status") != pin["release_state"]:
            fail("frozen core package seal state does not match CORE_PIN.json")
        yield core


def resolve_case(case_arg: str, project: Path) -> tuple[Path, dict, Path]:
    p = Path(case_arg)
    if not p.is_absolute():
        p = (Path.cwd() / p).resolve()
        if not p.exists():
            alt = (project / case_arg).resolve()
            if alt.exists():
                p = alt
    if p.is_file() and p.name == "case.json":
        case_dir = p.parent
    elif p.is_dir():
        case_dir = p
    else:
        fail(f"case not found: {case_arg}")
    meta_path = case_dir / "case.json"
    if not meta_path.is_file():
        fail(f"case.json not found in {case_dir}")
    meta = read_json(meta_path)
    assurance = (case_dir / meta.get("assurance_dir", "assurance")).resolve()
    adapter = assurance / meta.get("adapter", "adapter.json")
    if not adapter.is_file():
        fail(f"projection adapter not found: {adapter}")
    return case_dir.resolve(), meta, adapter


def verify_predeclaration(case_dir: Path, case_meta: dict) -> dict | None:
    spec = case_meta.get("predeclaration")
    if not spec:
        return None
    rel = spec.get("path")
    expected = spec.get("sha256")
    if not rel or not expected:
        fail("predeclaration metadata requires both path and sha256")
    path = (case_dir / rel).resolve()
    try:
        path.relative_to(case_dir.resolve())
    except ValueError:
        fail("predeclaration path escapes case directory")
    if not path.is_file():
        fail(f"predeclaration missing: {path}")
    actual = sha256_file(path)
    if actual != expected:
        fail(
            "predeclaration pin mismatch; refusing to execute\n"
            f"  expected {expected}\n"
            f"  actual   {actual}"
        )
    return {"path": rel, "sha256": actual, "pin_status": "PASS"}




def verify_case_provenance(case_dir: Path, case_meta: dict, project: Path) -> dict | None:
    spec = case_meta.get("provenance")
    if not spec:
        return None
    rel = spec.get("manifest")
    expected = spec.get("sha256")
    if not rel or not expected:
        fail("provenance metadata requires both manifest and sha256")
    mpath = (case_dir / rel).resolve()
    try:
        mpath.relative_to(case_dir.resolve())
    except ValueError:
        fail("provenance manifest path escapes case directory")
    if not mpath.is_file():
        fail(f"provenance manifest missing: {mpath}")
    actual = sha256_file(mpath)
    if actual != expected:
        fail(
            "provenance manifest pin mismatch; refusing to execute\n"
            f"  expected {expected}\n"
            f"  actual   {actual}"
        )
    tool = project / "tools" / "provenance_verify.py"
    proc = subprocess.run(
        [sys.executable, str(tool), str(case_dir)],
        cwd=str(project), text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    )
    if proc.returncode != 0:
        fail("provenance verification failed; refusing to execute\n" + proc.stdout)
    try:
        result = json.loads(proc.stdout)
    except Exception:
        fail("provenance verifier returned non-JSON output")
    if result.get("status") != "PASS":
        fail("provenance verification did not PASS")
    return {"manifest": rel, "sha256": actual, "status": "PASS", "derived_fact_count": result.get("derived_fact_count")}

def run_cmd(cmd: list[str], cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=str(cwd), text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)


def core_verify(core: Path, adapter: Path, assurance_root: Path, certificate: Path) -> tuple[str, str]:
    producer = run_cmd(
        [
            sys.executable,
            str(core / "cli" / "risu_projection.py"),
            "verify",
            str(adapter),
            "--require-source-contract",
            "--require-blind",
            "--require-evidence",
            "--certificate",
            str(certificate),
        ],
        core,
    )
    if producer.returncode != 0 or not certificate.is_file():
        raise RuntimeError("producer verification failed", producer.stdout)

    consumer = run_cmd(
        [
            sys.executable,
            str(core / "checker" / "risu_contract_pcc_check.py"),
            str(certificate),
            "--root",
            str(assurance_root),
        ],
        core,
    )
    if consumer.returncode != 0:
        raise RuntimeError("independent certificate check failed", producer.stdout, consumer.stdout)
    return producer.stdout, consumer.stdout


def _world_map(cert: dict) -> dict[str, dict]:
    records = cert["inner_certificate"]["bundle_snapshot"]["semantic"]["derivation"]["world_records"]
    return {r["id"]: r["coordinates"] for r in records}


def _required_map(cert: dict) -> dict[str, object]:
    return cert["inner_certificate"]["bundle_snapshot"]["semantic"]["structural_template"]["consequence"]["source_by_world"]


def _actual_map(cert: dict) -> dict[str, object]:
    return cert["inner_certificate"]["proof"]["blind_compilation"]["derived"]["mechanism_consequence_by_world"]


def classify(cert: dict) -> tuple[str, int]:
    structural = cert["results"]["structural"]
    exact = cert["results"]["exact_realization"]
    exact_status = exact.get("status")
    if exact_status == "REALIZATION_CONTRADICTED":
        return "CONSEQUENCE_REGRESSION", EXIT_REGRESSION
    if (
        exact_status == "REALIZATION_ESTABLISHED"
        and structural.get("C") == "C1"
        and structural.get("D") == "D1"
        and structural.get("O") == "O1"
    ):
        if structural.get("coverage_complete") is True:
            return "PRESERVED", EXIT_OK
        return "PRESERVED_IN_DECLARED_SCOPE", EXIT_OK
    return "INCOMPLETE_ASSURANCE", EXIT_INCOMPLETE


def technical_commitments(cert: dict, core_pin: dict, status: str) -> dict:
    s = cert["results"]["structural"]
    e = cert["results"]["exact_realization"]
    inner = cert["inner_certificate"]
    return {
        "core_archive_sha256": core_pin["archive_sha256"],
        "core_version": core_pin["core_version"],
        "source_contract_file_sha256": cert["source_contract_file_sha256"],
        "source_semantic_digest": cert["source_compilation"]["source_semantic_digest"],
        "adapter_digest": cert["adapter_digest"],
        "normalized_bundle_digest": cert["normalized_bundle_digest"],
        "proof_digest": inner["proof_digest"],
        "product_status": status,
        "structural": {"C": s.get("C"), "D": s.get("D"), "O": s.get("O")},
        "coverage_complete": s.get("coverage_complete"),
        "structural_classification": s.get("structural_classification"),
        "exact_status": e.get("status"),
        "exact_failure_mode": e.get("failure_mode"),
    }


def build_summary(cert: dict, case_meta: dict, core_pin: dict, certificate_sha: str) -> dict:
    status, exit_code = classify(cert)
    structural = cert["results"]["structural"]
    exact = cert["results"]["exact_realization"]
    worlds = _world_map(cert)
    required = _required_map(cert)
    actual = _actual_map(cert)
    rows = []
    for wid in sorted(worlds):
        rows.append({
            "world": wid,
            "coordinates": worlds[wid],
            "required_consequence": required.get(wid),
            "projected_effect": actual.get(wid),
            "matches": _consequence_matches(required.get(wid), actual.get(wid)),
        })
    witness = exact.get("minimal_counterexample")
    witness_world = None
    if witness and isinstance(witness, dict):
        witness_world = (witness.get("detail") or {}).get("world")
    return {
        "risu_verify_version": TOOL_VERSION,
        "case_id": case_meta["case_id"],
        "title": case_meta["title"],
        "product_status": status,
        "semantic_exit_code": exit_code,
        "assurance_integrity": "PASS",
        "core": {
            "name": core_pin["core_name"],
            "version": core_pin["core_version"],
            "archive_sha256": core_pin["archive_sha256"],
            "pin_status": "PASS",
        },
        "certificate": {
            "sha256": certificate_sha,
            "version": cert.get("certificate_version"),
            "consumer_check": "PASS",
        },
        "structural": {
            "C": structural.get("C"),
            "D": structural.get("D"),
            "O": structural.get("O"),
            "classification": structural.get("structural_classification"),
            "coverage_complete": structural.get("coverage_complete"),
            "operative_basis": structural.get("O_basis"),
        },
        "exact_realization": {
            "status": exact.get("status"),
            "failure_mode": exact.get("failure_mode"),
            "minimal_counterexample": exact.get("minimal_counterexample"),
            "repair_obligations": exact.get("repair_obligations", []),
        },
        "worlds": rows,
        "minimal_witness_world": witness_world,
        "display": case_meta.get("display", {}),
        "external_system": case_meta.get("external_system", {}),
        "claim_boundary": case_meta.get("claim_boundary", {}),
        "commitments": technical_commitments(cert, core_pin, status),
    }


def _consequence_matches(required, actual) -> bool:
    if isinstance(actual, dict) and actual.get("space") == "C" and "label" in actual:
        return actual["label"] == required
    return False


def _fmt_value(v) -> str:
    if v is True:
        return "true"
    if v is False:
        return "false"
    if v is None:
        return "null"
    if isinstance(v, dict):
        if v.get("space") == "C" and "label" in v:
            return str(v["label"])
        native = v.get("native")
        if isinstance(native, dict):
            kind = native.get("kind", "native")
            rest = {k: val for k, val in native.items() if k != "kind"}
            if rest:
                return f"{kind} " + json.dumps(rest, sort_keys=True, separators=(",", ":"))
            return str(kind)
        return json.dumps(v, sort_keys=True, separators=(",", ":"))
    return str(v)


def render_markdown(summary: dict) -> str:
    d = summary.get("display", {})
    labels = d.get("coordinate_labels", {})
    s = summary["structural"]
    e = summary["exact_realization"]
    status = summary["product_status"]
    lines = []
    lines.append(f"# RISU Verify — {status.replace('_', ' ').title()}")
    lines.append("")
    lines.append(f"**Case:** {summary['title']}  ")
    if d.get("action"):
        lines.append(f"**Action:** {d['action']}  ")
    lines.append(f"**Assurance integrity:** {summary['assurance_integrity']}  ")
    lines.append(f"**Frozen core:** v{summary['core']['version']} · pin verified  ")
    lines.append(f"**Certificate:** independently checked · `{summary['certificate']['sha256']}`")
    lines.append("")

    if d.get("declared_consequence"):
        lines.append("## Declared consequence")
        lines.append("")
        lines.append(d["declared_consequence"])
        lines.append("")
    if d.get("why_it_matters"):
        lines.append("## Why this matters")
        lines.append("")
        lines.append(d["why_it_matters"])
        lines.append("")

    lines.append("## Minimal human witness" if status == "CONSEQUENCE_REGRESSION" else "## Bounded consequence check")
    lines.append("")
    coord_keys = []
    for row in summary["worlds"]:
        for k in row["coordinates"]:
            if k not in coord_keys:
                coord_keys.append(k)
    headers = [labels.get(k, k.replace("_", " ").title()) for k in coord_keys] + ["Required", "Projected effect", "Match"]
    lines.append("| " + " | ".join(headers) + " |")
    lines.append("| " + " | ".join(["---"] * len(headers)) + " |")
    for row in summary["worlds"]:
        vals = [_fmt_value(row["coordinates"].get(k)) for k in coord_keys]
        vals += [_fmt_value(row["required_consequence"]), _fmt_value(row["projected_effect"]), "yes" if row["matches"] else "**no**"]
        lines.append("| " + " | ".join(vals) + " |")
    lines.append("")

    if status == "CONSEQUENCE_REGRESSION":
        mismatch = next((r for r in summary["worlds"] if not r["matches"]), None)
        if mismatch:
            lines.append("**Verified finding.** At least one admitted realization requires a different declared consequence than the grounded projected effect. The certificate classifies this as `REALIZATION_CONTRADICTED`.")
            lines.append("")
    elif status in {"PRESERVED", "PRESERVED_IN_DECLARED_SCOPE"}:
        lines.append("**Verified finding.** Every admitted realization in the declared profile maps to the required consequence, with `C1 / D1 / O1` and Exact Realization established.")
        lines.append("")

    lines.append("## Technical proof surface")
    lines.append("")
    lines.append(f"- Structural: `{s['C']} / {s['D']} / {s['O']}` — `{s['classification']}`")
    lines.append(f"- Exact Realization: `{e['status']}`" + (f" — `{e['failure_mode']}`" if e.get("failure_mode") else ""))
    lines.append(f"- Coverage complete in declared profile: `{str(s['coverage_complete']).lower()}`")
    lines.append(f"- Core archive SHA-256: `{summary['core']['archive_sha256']}`")
    lines.append(f"- Source contract SHA-256: `{summary['commitments']['source_contract_file_sha256']}`")
    lines.append(f"- Adapter digest: `{summary['commitments']['adapter_digest']}`")
    lines.append(f"- Proof digest: `{summary['commitments']['proof_digest']}`")
    lines.append("")

    repairs = e.get("repair_obligations") or []
    if repairs or d.get("suggested_repair"):
        lines.append("## Repair")
        lines.append("")
        if repairs:
            for r in repairs:
                lines.append(f"**Certified obligation:** {r.get('necessary_condition', _fmt_value(r))}")
                lines.append("")
        if d.get("suggested_repair"):
            lines.append(f"**Suggested implementation direction (not certified):** {d['suggested_repair']}")
            lines.append("")

    lines.append("## Claim boundary")
    lines.append("")
    lines.append("The human report is a derived convenience artifact. The proof-carrying certificate and independent consumer check are authoritative for the model-relative v0.7 result. This run does not establish live-runtime conformance, real-system model completeness, or independent reproduction unless separately evidenced.")
    lines.append("")
    return "\n".join(lines)


def render_terminal(summary: dict) -> str:
    d = summary.get("display", {})
    s = summary["structural"]
    e = summary["exact_realization"]
    title = summary["product_status"].replace("_", " ")
    bar = "=" * 72
    lines = [
        f"RISU Verify {TOOL_VERSION}",
        bar,
        f"{title}",
        f"Case: {summary['title']}",
    ]
    if d.get("action"):
        lines.append(f"Action: {d['action']}")
    lines += [
        "",
        "Integrity",
        f"  frozen core pin       PASS  v{summary['core']['version']}",
        "  producer verification PASS",
        "  consumer proof check   PASS",
    ]
    if summary.get("predeclaration"):
        lines.append("  predeclaration pin     PASS")
    lines += [
        f"  certificate sha256     {summary['certificate']['sha256']}",
        "",
    ]
    if d.get("declared_consequence"):
        lines += ["Declared consequence", textwrap.fill(d["declared_consequence"], width=70, subsequent_indent="  "), ""]
    lines.append("Minimal witness" if summary["product_status"] == "CONSEQUENCE_REGRESSION" else "Bounded consequence check")
    labels = d.get("coordinate_labels", {})
    for i, row in enumerate(summary["worlds"], 1):
        marker = "OK" if row["matches"] else "MISMATCH"
        lines.append(f"  World {i} [{marker}]")
        for k, v in row["coordinates"].items():
            lines.append(f"    {labels.get(k, k)}: {_fmt_value(v)}")
        lines.append(f"    required:         {_fmt_value(row['required_consequence'])}")
        lines.append(f"    projected effect: {_fmt_value(row['projected_effect'])}")
    lines += [
        "",
        "Technical proof",
        f"  Structural           {s['C']} / {s['D']} / {s['O']}  {s['classification']}",
        f"  Exact Realization    {e['status']}" + (f"  {e['failure_mode']}" if e.get("failure_mode") else ""),
    ]
    repairs = e.get("repair_obligations") or []
    if repairs:
        lines += ["", "Certified repair obligation"]
        for r in repairs:
            lines.append("  " + textwrap.fill(r.get("necessary_condition", _fmt_value(r)), width=68, subsequent_indent="  "))
    if d.get("suggested_repair"):
        lines += ["", "Suggested direction (not certified)", "  " + textwrap.fill(d["suggested_repair"], width=68, subsequent_indent="  ")]
    lines += [
        "",
        "Boundary",
        "  Model-relative result. Live-runtime conformance and model adequacy are",
        "  not established by this convenience layer.",
        bar,
    ]
    return "\n".join(lines)


def default_output(project: Path, case_meta: dict) -> Path:
    slug = case_meta.get("output_slug") or case_meta["case_id"].lower().replace("_", "-")
    return project / ".risu" / "out" / slug


def perform_verify(case_arg: str, output_arg: str | None) -> tuple[dict, Path]:
    project = root_dir()
    pin = verify_core_pin(project)
    case_dir, case_meta, adapter = resolve_case(case_arg, project)
    provenance = verify_case_provenance(case_dir, case_meta, project)
    predeclaration = verify_predeclaration(case_dir, case_meta)
    assurance_root = adapter.parent
    out = Path(output_arg).resolve() if output_arg else default_output(project, case_meta)
    out.mkdir(parents=True, exist_ok=True)
    certificate = out / "certificate.json"

    try:
        with core_runtime(project, pin) as core:
            producer_log, consumer_log = core_verify(core, adapter, assurance_root, certificate)
    except RuntimeError as err:
        details = "\n\n".join(str(x) for x in err.args[1:])
        (out / "failure.log").write_text(details + "\n", encoding="utf-8")
        fail(f"assurance pipeline failed; see {out / 'failure.log'}")

    (out / "producer.log").write_text(producer_log, encoding="utf-8")
    (out / "consumer.log").write_text(consumer_log, encoding="utf-8")
    cert = read_json(certificate)
    cert_sha = sha256_file(certificate)
    summary = build_summary(cert, case_meta, pin, cert_sha)
    summary["predeclaration"] = predeclaration
    summary["provenance"] = provenance
    write_json(out / "report.json", summary)
    (out / "report.md").write_text(render_markdown(summary), encoding="utf-8")
    tool_paths = {
        "risu_verify": project / "src" / "risu_verify.py",
        "provenance_verify": project / "tools" / "provenance_verify.py",
        "historical_transition": project / "tools" / "historical_transition.py",
    }
    manifest = {
        "manifest_version": "0.2",
        "risu_verify_version": TOOL_VERSION,
        "case_id": case_meta["case_id"],
        "case_metadata_sha256": sha256_file(case_dir / "case.json"),
        "adapter_sha256": sha256_file(adapter),
        "source_contract_sha256": sha256_file(assurance_root / "source-contract.json"),
        "predeclaration_sha256": predeclaration["sha256"] if predeclaration else None,
        "provenance_manifest_sha256": provenance["sha256"] if provenance else None,
        "core_archive_sha256": pin["archive_sha256"],
        "certificate_sha256": cert_sha,
        "report_json_sha256": sha256_file(out / "report.json"),
        "report_md_sha256": sha256_file(out / "report.md"),
        "producer_log_sha256": sha256_file(out / "producer.log"),
        "consumer_log_sha256": sha256_file(out / "consumer.log"),
        "toolchain": {k: sha256_file(v) for k, v in tool_paths.items() if v.is_file()},
        "runtime": {"python": platform.python_version(), "implementation": platform.python_implementation(), "platform": platform.platform()},
        "package_manifest_sha256": sha256_file(project / "FULL_PACKAGE_MANIFEST.sha256") if (project / "FULL_PACKAGE_MANIFEST.sha256").is_file() else None,
    }
    write_json(out / "run-manifest.json", manifest)
    return summary, out


def make_lock(summary: dict, *, allow_regression: bool = False) -> dict:
    status = summary["product_status"]
    preserving = status in {"PRESERVED", "PRESERVED_IN_DECLARED_SCOPE"}
    policy = "PRESERVATION_GATE" if preserving else "RESEARCH_REPRODUCTION"
    if not preserving and not allow_regression:
        fail("refusing to create a non-preserving baseline without explicit research acceptance", EXIT_REGRESSION)
    provenance = {}
    if summary.get("predeclaration"):
        provenance["predeclaration_sha256"] = summary["predeclaration"]["sha256"]
    if summary.get("provenance"):
        provenance["evidence_provenance_sha256"] = summary["provenance"]["sha256"]
    return {
        "lock_version": "0.2",
        "semantics": "RISU_VERIFY_SEMANTIC_BASELINE",
        "case_id": summary["case_id"],
        "baseline_policy": policy,
        "commitments": summary["commitments"],
        "commitments_sha256": canonical_sha(summary["commitments"]),
        "provenance_commitments": provenance,
        "provenance_commitments_sha256": canonical_sha(provenance),
        "policy_note": (
            "PRESERVATION_GATE is a CI baseline for an already certificate-backed preserving result. "
            "RESEARCH_REPRODUCTION records a known non-preserving observation only when explicitly accepted. "
            "Neither mode is a safety approval or a mechanism for upgrading assurance."
        ),
    }


def compare_lock(summary: dict, lock: dict) -> list[str]:
    problems = []
    version = lock.get("lock_version")
    if version not in {"0.1", "0.2"}:
        problems.append("unsupported lock version")
    if lock.get("case_id") != summary["case_id"]:
        problems.append(f"case_id: lock={lock.get('case_id')} current={summary['case_id']}")
    current = summary["commitments"]
    expected = lock.get("commitments", {})
    keys = sorted(set(current) | set(expected))
    for k in keys:
        if current.get(k) != expected.get(k):
            problems.append(f"{k}: lock={expected.get(k)!r} current={current.get(k)!r}")
    digest = canonical_sha(expected)
    if lock.get("commitments_sha256") != digest:
        problems.append("lock commitments_sha256 is internally inconsistent")
    if version == "0.2":
        policy = lock.get("baseline_policy")
        locked_status = expected.get("product_status")
        if policy == "PRESERVATION_GATE" and locked_status not in {"PRESERVED", "PRESERVED_IN_DECLARED_SCOPE"}:
            problems.append("PRESERVATION_GATE lock contains a non-preserving baseline")
        elif policy not in {"PRESERVATION_GATE", "RESEARCH_REPRODUCTION"}:
            problems.append("unsupported baseline_policy")
        expected_prov = lock.get("provenance_commitments", {})
        current_prov = {}
        if summary.get("predeclaration"):
            current_prov["predeclaration_sha256"] = summary["predeclaration"]["sha256"]
        if summary.get("provenance"):
            current_prov["evidence_provenance_sha256"] = summary["provenance"]["sha256"]
        if expected_prov != current_prov:
            problems.append(f"provenance_commitments: lock={expected_prov!r} current={current_prov!r}")
        if lock.get("provenance_commitments_sha256") != canonical_sha(expected_prov):
            problems.append("lock provenance_commitments_sha256 is internally inconsistent")
    return problems


def cmd_verify(args):
    summary, out = perform_verify(args.case, args.output)
    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print(render_terminal(summary))
        print(f"\nArtifacts: {out}")
    raise SystemExit(summary["semantic_exit_code"])


def cmd_lock(args):
    summary, out = perform_verify(args.case, args.output)
    if summary["product_status"] == "CONSEQUENCE_REGRESSION" and not args.accept_regression:
        print(render_terminal(summary))
        fail("refusing to approve a consequence regression without --accept-regression", EXIT_REGRESSION)
    lock = make_lock(summary, allow_regression=args.accept_regression)
    project = root_dir()
    case_dir, _, _ = resolve_case(args.case, project)
    path = Path(args.write).resolve() if args.write else case_dir / "risu.lock.json"
    write_json(path, lock)
    print(f"RISU semantic lock written: {path}")
    print(f"Baseline status: {summary['product_status']}")
    print(f"Commitments: {lock['commitments_sha256']}")
    print(f"Artifacts: {out}")


def cmd_check(args):
    summary, out = perform_verify(args.case, args.output)
    project = root_dir()
    case_dir, _, _ = resolve_case(args.case, project)
    lock_path = Path(args.lock).resolve() if args.lock else (case_dir / "risu.lock.json")
    if not lock_path.is_file():
        fail(f"semantic lock not found: {lock_path}", EXIT_LOCK_MISMATCH)
    lock = read_json(lock_path)
    problems = compare_lock(summary, lock)
    if problems:
        print(render_terminal(summary))
        print("\nSEMANTIC LOCK MISMATCH")
        for p in problems:
            print(f"  - {p}")
        print(f"\nArtifacts: {out}")
        raise SystemExit(EXIT_LOCK_MISMATCH)
    print(render_terminal(summary))
    print("\nSEMANTIC LOCK: MATCH")
    print(f"Locked commitments: {lock['commitments_sha256']}")
    print(f"Artifacts: {out}")


def cmd_self_test(args):
    project = root_dir()
    checks = []
    try:
        pin = verify_core_pin(project)
        checks.append(("frozen core archive pin", True, pin["archive_sha256"]))
    except SystemExit:
        checks.append(("frozen core archive pin", False, ""))

    index_path = project / "cases" / "INDEX.json"
    index = read_json(index_path) if index_path.is_file() else {"cases": []}
    for entry in index.get("cases", []):
        case = project / entry["path"]
        try:
            summary, out = perform_verify(str(case), args.output)
            expected = entry["expected_status"]
            checks.append((f"{entry['id']} executes", True, str(out)))
            checks.append((f"{entry['id']} semantic status", summary["product_status"] == expected, summary["product_status"]))
            checks.append((f"{entry['id']} consumer check", summary["certificate"]["consumer_check"] == "PASS", summary["certificate"]["sha256"]))
            lock_path = case / "risu.lock.json"
            if lock_path.is_file():
                problems = compare_lock(summary, read_json(lock_path))
                checks.append((f"{entry['id']} semantic lock", not problems, "; ".join(problems)))
        except SystemExit as exc:
            checks.append((f"{entry['id']} executes", False, f"exit={exc.code}"))

    for entry in index.get("mutations", []):
        case = project / entry["path"]
        baseline_lock = project / entry["baseline_lock"]
        try:
            summary, out = perform_verify(str(case), args.output)
            checks.append((f"{entry['id']} executes", True, str(out)))
            checks.append((f"{entry['id']} regression detected", summary["product_status"] == entry.get("expected_status", "CONSEQUENCE_REGRESSION"), summary["product_status"]))
            if baseline_lock.is_file():
                problems = compare_lock(summary, read_json(baseline_lock))
                checks.append((f"{entry['id']} breaks preserving lock", bool(problems), "; ".join(problems[:4])))
        except SystemExit as exc:
            checks.append((f"{entry['id']} executes", False, f"exit={exc.code}"))

    print(f"RISU Verify {TOOL_VERSION} self-test")
    print("=" * 72)
    ok = True
    for name, passed, detail in checks:
        ok &= passed
        print(f"{'PASS' if passed else 'FAIL':4}  {name}")
        if detail:
            print(f"      {detail}")
    raise SystemExit(EXIT_OK if ok else EXIT_INVALID)



def cmd_init(args):
    if args.profile != "version-bound-effect":
        fail(f"unsupported init profile: {args.profile}")
    out = Path(args.output).resolve()
    if out.exists() and any(out.iterdir()):
        fail(f"init output directory is not empty: {out}")
    out.mkdir(parents=True, exist_ok=True)
    name = args.name or out.name
    instance = {
        "instance_schema": "risu.vbe.instance/v0.1alpha1",
        "profile": "version-bound-effect",
        "profile_version": "0.1-development",
        "status": "DRAFT_UNVERIFIED",
        "instance_id": name,
        "carrier_envelope": "carrier-envelope.json",
        "authoring_state": {
            "verdict_eligible": False,
            "required_before_compile": [
                "replace all TODO values",
                "bind carrier-specific evidence facts",
                "review declared source consequence and boundary",
                "set status to AUTHOR_ACCEPTED"
            ]
        },
        "source": {
            "contract_id": f"SRC-VBE-{name}",
            "metadata": {"title": "TODO", "kind": "VBE_PROFILE_GENERATED_SOURCE_CONTRACT"},
            "constants": {},
            "current_coordinate": "current_version",
            "current_domain": ["V0", "V1"],
            "reviewed": {"mode": "literal", "anchor": "V0"},
            "extra_coordinates": {},
            "lens": "L_VERSION_BOUND_EFFECT",
            "success_consequence": "EFFECT_COMMITTED",
            "stale_consequence": "STALE_EFFECT_REJECTED",
            "boundary": {
                "declaration": "TODO: declare how current version may change before the effect cut.",
                "post_check_material_transition_possible": True
            },
            "source_family": ["TODO_VERSION_BOUND_EFFECT_FAMILY"],
            "claim_boundary": {
                "model_relative": True,
                "domain_adequacy": "DECLARED_PREMISE",
                "source_semantic_adequacy": "DECLARED_PREMISE"
            },
            "admissibility": {"expr": {"op": "literal", "value": True}}
        },
        "target": {
            "pattern": "PRESERVED_COMPARE",
            "scope_id": "TODO_VERSION_BOUND_EFFECT_FAMILY",
            "reviewed_anchor_constant": "reviewed_version_anchor",
            "program_version": "0.1",
            "discriminator_visibility": "TODO",
            "discharge_mode": "TODO",
            "signature_current_field": "current_version",
            "signature_reviewed_field": "reviewed_version",
            "mechanism_current_field": "current_version",
            "mechanism_reviewed_field": "reviewed_version",
            "native_accept_kind": "EFFECT_ACCEPTED",
            "native_stale_kind": "STALE_REJECTED",
            "facts": {
                "discriminator": ["TODO_FACT_VERSION_AVAILABLE"],
                "operative_signature": ["TODO_FACT_VERSION_BOUND"],
                "mechanism": ["TODO_FACT_VERSION_GATES_EFFECT"],
                "interpreter": ["TODO_FACT_EFFECT_INTERPRETATION"]
            }
        }
    }
    envelope = {
        "envelope_version": "0.1-development",
        "role": "CARRIER_SPECIFIC_EVIDENCE_ENVELOPE",
        "status": "DRAFT_UNVERIFIED",
        "adapter_base": {
            "adapter_id": f"VBE-{name}",
            "adapter_version": "0.7",
            "bindings": [],
            "claim_boundary": {
                "model_relative": True,
                "live_runtime_conformance": "NOT_CLAIMED",
                "independent_reproduction": "NOT_CLAIMED"
            },
            "metadata": {
                "architecture": "SOURCE_CONTRACT_SEPARATED",
                "kind": "VBE_PROFILE_AUTHORED_CASE",
                "title": "TODO"
            },
            "provenance": {
                "mode": "EVIDENCE_LINKED",
                "claim_roots": {"C": ["CLAIM-C"], "D": ["CLAIM-D"], "O": ["CLAIM-O"], "EXACT": ["CLAIM-EXACT"], "COVERAGE": ["CLAIM-COVERAGE"]},
                "nodes": [],
                "edges": []
            }
        },
        "derivation_facts": [],
        "structural_base": {
            "case_id": f"VBE-{name}",
            "evidence": {"items": [], "strength": "TODO"},
            "target_model_status": {
                "kind": "DECLARED_ANALYTICAL_MODEL",
                "purpose": "Cross-check only; does not independently establish C, D, or O.",
                "empirical_runtime_validation": "NOT_CLAIMED"
            }
        }
    }
    write_json(out / "vbe-instance.json", instance)
    write_json(out / "carrier-envelope.json", envelope)
    (out / "AUTHORING.md").write_text(
        "# RISU VBE authoring scaffold\n\n"
        "This directory is intentionally **not verdict-eligible**. Complete the semantic declaration and carrier evidence envelope, review them, then change `status` to `AUTHOR_ACCEPTED`. The VBE compiler may generate artifacts, but only the frozen v0.7 producer and independent consumer can establish the assurance result.\n",
        encoding="utf-8"
    )
    print(f"RISU VBE scaffold created: {out}")
    print("Status: DRAFT_UNVERIFIED (not verdict-eligible)")


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="risu-verify",
        description="Thin consequence-assurance product surface over the frozen RISU v0.7.0 scientific core.",
    )
    p.add_argument("--version", action="version", version=f"RISU Verify {TOOL_VERSION}")
    sub = p.add_subparsers(dest="command", required=True)

    v = sub.add_parser("verify", help="verify one projection, issue/check certificate, and render a human witness")
    v.add_argument("case", help="case directory containing case.json")
    v.add_argument("--output", help="artifact output directory")
    v.add_argument("--json", action="store_true", help="print machine report JSON")
    v.set_defaults(func=cmd_verify)

    l = sub.add_parser("lock", help="write an explicit semantic baseline from a checked certificate")
    l.add_argument("case")
    l.add_argument("--output")
    l.add_argument("--write", help="lockfile path (default: <case>/risu.lock.json)")
    l.add_argument("--accept-regression", action="store_true", help="explicitly allow locking a known regression (commissioning/research use)")
    l.set_defaults(func=cmd_lock)

    c = sub.add_parser("check", help="rerun verification and compare proof commitments to a semantic lock")
    c.add_argument("case")
    c.add_argument("--lock", help="lockfile path (default: <case>/risu.lock.json)")
    c.add_argument("--output")
    c.set_defaults(func=cmd_check)

    i = sub.add_parser("init", help="scaffold a narrow human-reviewed authoring profile; does not issue a verdict")
    i.add_argument("--profile", required=True, choices=["version-bound-effect"])
    i.add_argument("--output", required=True)
    i.add_argument("--name")
    i.set_defaults(func=cmd_init)

    t = sub.add_parser("self-test", help="run the pinned external commissioning path and lock reproduction test")
    t.add_argument("--output")
    t.set_defaults(func=cmd_self_test)
    return p


def main():
    args = parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
