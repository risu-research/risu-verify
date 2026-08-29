#!/usr/bin/env python3
from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("risu_verify", ROOT / "src" / "risu_verify.py")
rv = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(rv)

PASS: list[tuple[str, str]] = []
FAIL: list[tuple[str, str]] = []


def record(name: str, ok: bool, detail: str = "") -> None:
    (PASS if ok else FAIL).append((name, detail))
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f" — {detail}" if detail else ""), flush=True)


def run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([str(ROOT / "risu-verify"), *args], cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)


def load(path: Path):
    return json.loads(path.read_text())


def file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


with tempfile.TemporaryDirectory(prefix="risu-verify-v020-tests-") as td_raw:
    td = Path(td_raw)
    case1 = ROOT / "cases" / "github-guarded-merge"
    case2 = ROOT / "cases" / "azure-devops-wiki-etag"
    mutant = case2 / "mutations" / "ignore-supplied-etag"

    # Three primary end-to-end product paths. Each independently rechecks the frozen core pin,
    # producer, and consumer; all other attacks reuse one extracted core to keep qualification fast.
    c1out = td / "case1"
    p1 = run("verify", str(case1), "--output", str(c1out))
    s1 = load(c1out / "report.json")
    record("case001 negative control remains regression", p1.returncode == 10 and s1["product_status"] == "CONSEQUENCE_REGRESSION", f"exit={p1.returncode}")
    record("case001 formal result remains C1/D1/O0 contradiction", s1["structural"]["C"] == "C1" and s1["structural"]["D"] == "D1" and s1["structural"]["O"] == "O0" and s1["exact_realization"]["status"] == "REALIZATION_CONTRADICTED")
    record("case001 consumer check passes", s1["certificate"]["consumer_check"] == "PASS")

    bout = td / "baseline"
    pb = run("verify", str(case2), "--output", str(bout))
    b = load(bout / "report.json")
    record("fresh case002 positive control is PRESERVED", pb.returncode == 0 and b["product_status"] == "PRESERVED", f"exit={pb.returncode}")
    record("case002 formal result is C1/D1/O1", (b["structural"]["C"], b["structural"]["D"], b["structural"]["O"]) == ("C1", "D1", "O1"))
    record("case002 Exact Realization is established", b["exact_realization"]["status"] == "REALIZATION_ESTABLISHED" and b["exact_realization"]["failure_mode"] == "NONE")
    record("case002 consumer check passes", b["certificate"]["consumer_check"] == "PASS")
    record("case002 predeclaration pin is enforced", b["predeclaration"]["pin_status"] == "PASS" and b["predeclaration"]["sha256"] == "42bac8308b45bee1d628f9492fd2f8212aee4c243f9b1d83e8ac5585a4881565")
    record("both bounded baseline worlds match", len(b["worlds"]) == 2 and all(w["matches"] for w in b["worlds"]))

    mout = td / "mutant"
    pm = run("verify", str(mutant), "--output", str(mout))
    m = load(mout / "report.json")
    record("schema-preserving ignore-etag mutation is regression", pm.returncode == 10 and m["product_status"] == "CONSEQUENCE_REGRESSION", f"exit={pm.returncode}")
    record("mutation isolates operativity loss C1/D1/O0", (m["structural"]["C"], m["structural"]["D"], m["structural"]["O"]) == ("C1", "D1", "O0"))
    record("mutation Exact result is mechanism misalignment", m["exact_realization"]["status"] == "REALIZATION_CONTRADICTED" and m["exact_realization"]["failure_mode"] == "MECHANISM_MISALIGNMENT")
    record("negative mutation certificate still passes independent consumer", m["certificate"]["consumer_check"] == "PASS")
    mismatch = [w for w in m["worlds"] if not w["matches"]]
    record("mutation witness is stale E1 accepted as update", len(mismatch) == 1 and mismatch[0]["coordinates"]["current_etag"] == "E1" and mismatch[0]["required_consequence"] == "STALE_EDIT_REJECTED" and isinstance(mismatch[0]["projected_effect"], dict) and mismatch[0]["projected_effect"].get("label") == "UPDATE_COMMITTED")

    # Lock policies are checked from certificate-backed summaries without rerunning the core.
    c1lock = load(case1 / "risu.lock.json")
    b_lock = load(case2 / "risu.lock.json")
    record("case001 lock is explicit research reproduction", c1lock["baseline_policy"] == "RESEARCH_REPRODUCTION")
    record("case002 lock is preservation gate", b_lock["baseline_policy"] == "PRESERVATION_GATE" and b_lock["commitments"]["product_status"] == "PRESERVED")
    record("case001 lock commitments reproduce", not rv.compare_lock(s1, c1lock))
    record("case002 preserving lock commitments reproduce", not rv.compare_lock(b, b_lock))
    mut_lock_problems = rv.compare_lock(m, b_lock)
    record("preserving lock rejects semantic mutation", bool(mut_lock_problems))
    joined = "\n".join(mut_lock_problems)
    record("lock mismatch exposes product/O/exact changes", all(x in joined for x in ["product_status", "structural", "exact_status", "exact_failure_mode"]))
    try:
        rv.make_lock(s1)
        refused = False
    except SystemExit as exc:
        refused = exc.code == 10
    record("known regression cannot become lock without explicit research acceptance", refused)
    record("case.json path resolves to correct case directory", rv.resolve_case(str(case2 / "case.json"), ROOT)[0] == case2.resolve())

    # Source claim is unchanged across the mutation; the projection binding is what changes.
    ba = load(case2 / "assurance" / "adapter.json")
    ma = load(mutant / "assurance" / "adapter.json")
    record("mutation preserves exact source consequence contract", ba["source_contract"]["sha256"] == ma["source_contract"]["sha256"] == file_sha(case2 / "assurance" / "source-contract.json"))
    record("mutation retains exact pinned upstream source evidence", file_sha(case2 / "assurance" / "evidence" / "microsoft_wiki_upsert_pinned.json") == file_sha(mutant / "assurance" / "evidence" / "microsoft_wiki_upsert_pinned.json"))
    mut_ev = load(mutant / "assurance" / "evidence" / "mutation_ignore_supplied_etag.json")
    record("mutation is explicitly non-upstream", mut_ev["not_upstream_code"] is True and m["claim_boundary"]["upstream_defect"] == "NOT_CLAIMED")
    record("baseline and mutation share same sealed predeclaration", b["predeclaration"]["sha256"] == m["predeclaration"]["sha256"])

    # Narrative metadata is unable to vote on semantic status: build_summary derives status from cert.
    pin = rv.verify_core_pin(ROOT)
    bcert = load(bout / "certificate.json")
    mcert = load(mout / "certificate.json")
    fake_meta = load(case2 / "case.json"); fake_meta["product_status"] = "CONSEQUENCE_REGRESSION"
    derived = rv.build_summary(bcert, fake_meta, pin, file_sha(bout / "certificate.json"))
    record("narrative metadata cannot downgrade certificate-backed preserved status", derived["product_status"] == "PRESERVED")
    fake_meta = load(mutant / "case.json"); fake_meta["product_status"] = "PRESERVED"
    derived = rv.build_summary(mcert, fake_meta, pin, file_sha(mout / "certificate.json"))
    record("narrative metadata cannot upgrade mutation regression", derived["product_status"] == "CONSEQUENCE_REGRESSION")

    # Predeclaration tampering is rejected before core execution.
    predecl_copy = td / "predecl"
    shutil.copytree(case2, predecl_copy)
    pd = predecl_copy / "PREDECLARATION.json"; pd.chmod(0o644); pd.write_bytes(pd.read_bytes() + b"\n")
    try:
        with contextlib.redirect_stderr(io.StringIO()): rv.verify_predeclaration(predecl_copy, load(predecl_copy / "case.json"))
        predecl_rejected = False
    except SystemExit as exc:
        predecl_rejected = exc.code == 30
    record("predeclaration byte mutation fails closed", predecl_rejected)

    # One extracted frozen core is reused for deterministic replay and lower-level attacks.
    with rv.core_runtime(ROOT, pin) as core:
        # One fresh direct-core replay per case is compared with the already-produced end-to-end
        # certificate. This preserves the determinism assertion without duplicating two extra
        # expensive core executions in the release qualification path.
        r1 = td / "direct-baseline-replay.json"
        rv.core_verify(core, case2 / "assurance" / "adapter.json", case2 / "assurance", r1)
        record("case002 certificate generation is deterministic", file_sha(r1) == file_sha(bout / "certificate.json"))
        q1 = td / "direct-mutant-replay.json"
        rv.core_verify(core, mutant / "assurance" / "adapter.json", mutant / "assurance", q1)
        record("mutation certificate generation is deterministic", file_sha(q1) == file_sha(mout / "certificate.json"))

        evidence_tamper = td / "evidence-tamper"; shutil.copytree(case2 / "assurance", evidence_tamper)
        ev = evidence_tamper / "evidence" / "microsoft_wiki_upsert_pinned.json"; ev.write_bytes(ev.read_bytes() + b"\n")
        try:
            rv.core_verify(core, evidence_tamper / "adapter.json", evidence_tamper, td / "bad-evidence-cert.json")
            rejected = False
        except RuntimeError:
            rejected = True
        record("case002 evidence byte mutation is rejected by frozen core", rejected)

        source_tamper = td / "source-tamper"; shutil.copytree(case2 / "assurance", source_tamper)
        sc = source_tamper / "source-contract.json"; sc.write_bytes(sc.read_bytes() + b"\n")
        try:
            rv.core_verify(core, source_tamper / "adapter.json", source_tamper, td / "bad-source-cert.json")
            rejected = False
        except RuntimeError:
            rejected = True
        record("source consequence contract mutation is rejected by adapter pin", rejected)

        tampered_cert = td / "tampered-cert.json"
        cert = load(r1); cert["results"]["structural"]["O"] = "O0"; tampered_cert.write_text(json.dumps(cert, indent=2, sort_keys=True) + "\n")
        c = rv.run_cmd([sys.executable, str(core / "checker" / "risu_contract_pcc_check.py"), str(tampered_cert), "--root", str(case2 / "assurance")], core)
        record("certificate result tampering is rejected by independent consumer", c.returncode != 0, f"exit={c.returncode}")

    # Frozen archive integrity.
    fake_project = td / "fake-project"; fake_project.mkdir(); shutil.copy(ROOT / "CORE_PIN.json", fake_project / "CORE_PIN.json")
    vendor = fake_project / "vendor"; vendor.mkdir()
    archive_name = Path(load(ROOT / "CORE_PIN.json")["archive"]).name
    fake_archive = vendor / archive_name; shutil.copy(ROOT / "vendor" / archive_name, fake_archive); fake_archive.write_bytes(fake_archive.read_bytes() + b"mutation")
    try:
        with contextlib.redirect_stderr(io.StringIO()): rv.verify_core_pin(fake_project)
        core_rejected = False
    except SystemExit as exc:
        core_rejected = exc.code == 30
    record("frozen v0.7 archive mutation fails before execution", core_rejected)

    # Lock-policy tampering even if attacker recomputes the commitment digest.
    bad = json.loads(json.dumps(b_lock)); bad["commitments"]["product_status"] = "CONSEQUENCE_REGRESSION"; bad["commitments_sha256"] = rv.canonical_sha(bad["commitments"])
    problems = rv.compare_lock(b, bad)
    record("PRESERVATION_GATE cannot contain a non-preserving baseline", "PRESERVATION_GATE lock contains a non-preserving baseline" in problems)
    bad = json.loads(json.dumps(c1lock)); bad["baseline_policy"] = "PRESERVATION_GATE"
    problems = rv.compare_lock(s1, bad)
    record("research regression cannot masquerade as preservation gate", "PRESERVATION_GATE lock contains a non-preserving baseline" in problems)

    # Human output boundaries.
    preserved_report = (bout / "report.md").read_text(); mutant_report = (mout / "report.md").read_text()
    record("preserved report states bounded positive finding", "Every admitted realization in the declared profile" in preserved_report and "does not establish live-runtime conformance" in preserved_report)
    record("mutation report separates certified obligation from suggested repair", "Certified obligation" in mutant_report and "Suggested implementation direction (not certified)" in mutant_report)

print("\nSummary")
print("=" * 72)
print(f"PASS: {len(PASS)}")
print(f"FAIL: {len(FAIL)}")
if FAIL:
    for name, detail in FAIL:
        print(f"  - {name}: {detail}")
    raise SystemExit(1)
