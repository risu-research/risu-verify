#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
EXPORTER = ROOT / "tools" / "export_workbench_bundle.py"

EXPECTED_PINNED = {
    "src/risu_verify.py": "431f73a8df146470a97b57270b676447b0b5c3381d46708f80fed2b40f9e1210",
    "tools/vbe_compile.py": "ad5fb723a0758807ad79ec0b1cdc91f97ea489a550607d0c26e1e47b2962587b",
    "tools/vbe_differential.py": "94a62340d9e25ae85efac4c87a72ead1efc79c1cdad65111405feec0a7c0674c",
}


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(cmd, *, expect=0):
    p = subprocess.run(cmd, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if p.returncode != expect:
        raise AssertionError(f"command returned {p.returncode}, expected {expect}: {' '.join(map(str, cmd))}\n{p.stdout}")
    return p


def ensure_runs():
    if not (ROOT / "cases/github-create-update-sha-transition/before/case.json").exists():
        run([sys.executable, "tools/materialize_case_bundles.py"])
    run([str(ROOT / "risu-verify"), "verify", "cases/github-create-update-sha-transition/before"], expect=10)
    run([str(ROOT / "risu-verify"), "verify", "cases/github-create-update-sha-transition/after"], expect=0)
    return (
        ROOT / ".risu/out/hist-github-create-update-sha-003-before",
        ROOT / ".risu/out/hist-github-create-update-sha-003-after",
    )


def check(name, fn):
    try:
        fn()
        print(f"PASS {name}")
        return 1
    except Exception as exc:
        print(f"FAIL {name}: {exc}")
        raise


def main():
    before, after = ensure_runs()
    passed = 0
    with tempfile.TemporaryDirectory(prefix="risu-handoff-test-") as td:
        td = Path(td)
        after_bundle = td / "after.risu.json"
        compare_bundle = td / "transition.risu-compare.json"

        def run_bundle_roundtrip():
            run([sys.executable, str(EXPORTER), "run", str(after), "-o", str(after_bundle)])
            b = json.loads(after_bundle.read_text())
            assert b["bundle_schema"] == "risu.workbench-run/v0.1"
            assert b["run"]["product_status"] == "PRESERVED"
            arts = {a["name"]: a for a in b["artifacts"]}
            for required in ("report.json", "certificate.json", "run-manifest.json"):
                assert required in arts
                raw = base64.b64decode(arts[required]["content"], validate=True)
                assert hashlib.sha256(raw).hexdigest() == arts[required]["sha256"]
            assert b["run"]["source_semantic_digest"]
        passed_nonlocal[0] += check("single-run bundle preserves exact content-addressed run artifacts", run_bundle_roundtrip)

        def tamper_rejected():
            bad = td / "bad-run"
            shutil.copytree(after, bad)
            report = json.loads((bad / "report.json").read_text())
            report["product_status"] = "INCOMPLETE_ASSURANCE"
            (bad / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
            p = subprocess.run([sys.executable, str(EXPORTER), "run", str(bad), "-o", str(td / "bad.risu.json")], cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            assert p.returncode == 30
            assert "report_json_sha256" in p.stdout
        passed_nonlocal[0] += check("exporter rejects a self-inconsistent tampered run", tamper_rejected)

        def comparison_scope():
            run([sys.executable, str(EXPORTER), "compare", str(before), str(after), "-o", str(compare_bundle)])
            b = json.loads(compare_bundle.read_text())
            assert b["bundle_schema"] == "risu.workbench-comparison/v0.1"
            c = b["comparison"]
            assert c["source_semantic_digest_same"] is True
            assert c["comparison_scope"] == "SAME_DECLARED_SOURCE_SEMANTICS"
            assert c["baseline"]["product_status"] == "CONSEQUENCE_REGRESSION"
            assert c["current"]["product_status"] == "PRESERVED"
            assert c["baseline"]["structural"] == {"C": "C0", "D": "NA", "O": "NA"}
            assert c["current"]["structural"] == {"C": "C1", "D": "D1", "O": "O1"}
        passed_nonlocal[0] += check("comparison bundle preserves the historical before/after semantic boundary", comparison_scope)

        def comparison_tamper_rejected():
            run([sys.executable, str(EXPORTER), "run", str(after), "-o", str(after_bundle)])
            b = json.loads(after_bundle.read_text())
            b["run"]["source_semantic_digest"] = "0" * 64
            tampered = td / "tampered-bundle.risu.json"
            tampered.write_text(json.dumps(b, indent=2, sort_keys=True) + "\n")
            p = subprocess.run([sys.executable, str(EXPORTER), "compare", str(tampered), str(after_bundle), "-o", str(td / "x.json")], cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            assert p.returncode == 30
            assert "source semantic digest" in p.stdout
        passed_nonlocal[0] += check("comparison refuses a bundle whose metadata diverges from embedded report", comparison_tamper_rejected)

        def pinned_semantics_unchanged():
            for rel, expected in EXPECTED_PINNED.items():
                actual = sha(ROOT / rel)
                assert actual == expected, (rel, actual, expected)
        passed_nonlocal[0] += check("handoff layer does not modify protocol-pinned verifier/profile implementations", pinned_semantics_unchanged)

    print(f"WORKBENCH_HANDOFF_QUALIFICATION: PASS {passed_nonlocal[0]}/5")


passed_nonlocal = [0]
if __name__ == "__main__":
    main()
