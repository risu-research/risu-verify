#!/usr/bin/env python3
"""Adversarial qualification harness for K1 Implementation Binding B0."""

import argparse
import ast
import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

EXPECTED = {
    "B0-01": "NO_AUTHORITY",
    "B0-02": "BOUND_REGRESSION",
    "B0-03": "NO_AUTHORITY",
    "B0-04": "BOUND_REGRESSION",
    "B0-05": "BOUND_REGRESSION",
    "B0-06": "NO_AUTHORITY",
    "B0-07": "NO_AUTHORITY",
    "B0-08": "BOUND_REGRESSION",
    "B0-09": "REJECT_BINDING_EVIDENCE",
    "B0-10": "REJECT_BINDING_EVIDENCE",
    "B0-11": "REJECT_BINDING_EVIDENCE",
    "B0-12": "IMPOSSIBLE_BY_INTERFACE",
    "B0-13": "UNSUPPORTED_NO_AUTHORITY",
}


def run_json(cmd, expect_rc=None):
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    try:
        data = json.loads(proc.stdout.decode("utf-8"))
    except Exception as exc:
        raise AssertionError(f"non-JSON output rc={proc.returncode}: {proc.stdout!r} {proc.stderr!r}") from exc
    if expect_rc is not None and proc.returncode != expect_rc:
        raise AssertionError(f"unexpected rc {proc.returncode}, expected {expect_rc}: {data}")
    return proc.returncode, data


def binding_run(args, implementation, output):
    cmd = [
        sys.executable,
        args.binder,
        "run",
        "--implementation", implementation,
        "--world", args.world,
        "--claim", args.claim,
        "--w1", args.w1,
        "--w2", args.w2,
        "--timeout-ms", "250",
        "--output", output,
    ]
    rc, data = run_json(cmd, 0)
    assert rc == 0
    return data


def verify_report(args, report, implementation, world, expect_rc):
    return run_json([
        sys.executable,
        args.binder,
        "verify-report",
        "--report", report,
        "--implementation", implementation,
        "--world", world,
    ], expect_rc)


def record(rows, vector_id, actual, detail=None):
    expected = EXPECTED[vector_id]
    ok = actual == expected
    rows.append({
        "id": vector_id,
        "expected": expected,
        "actual": actual,
        "pass": ok,
        "detail": detail,
    })
    if not ok:
        raise AssertionError(f"{vector_id}: expected {expected}, got {actual}: {detail}")


def audit_binder_independence(path):
    source = Path(path).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imports = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.append(node.module or "")
    forbidden = [x for x in imports if "k1_checker" in x or x.startswith("kernel")]
    return {
        "imports": sorted(imports),
        "forbidden_checker_imports": forbidden,
        "imports_checker_implementation": bool(forbidden),
        "pass": not forbidden,
    }


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--binder", required=True)
    parser.add_argument("--w1", required=True)
    parser.add_argument("--w2", required=True)
    parser.add_argument("--world", required=True)
    parser.add_argument("--claim", required=True)
    parser.add_argument("--bin-dir", required=True)
    parser.add_argument("--output")
    args = parser.parse_args(argv)

    bins = {name: os.path.join(args.bin_dir, "b0-" + name) for name in [
        "good", "bad", "stdout-lie", "nonzero-forbidden", "timeout-after-forbidden",
        "timeout-before-effect", "malformed", "multi",
    ]}
    for name, path in bins.items():
        if not os.path.isfile(path):
            raise AssertionError(f"missing target variant {name}: {path}")

    independence = audit_binder_independence(args.binder)
    if not independence["pass"]:
        raise AssertionError("B0 binder imports checker implementation")

    rows = []
    with tempfile.TemporaryDirectory(prefix="risu-k1-b0-verify-") as td:
        root = Path(td)

        good_path = str(root / "good.json")
        good = binding_run(args, bins["good"], good_path)
        record(rows, "B0-01", good["authority"], good)
        assert good["preservation_authority"] is False
        assert good["implementation_binding"] is False

        bad_path = str(root / "bad.json")
        bad = binding_run(args, bins["bad"], bad_path)
        record(rows, "B0-02", bad["authority"], bad)
        assert bad["implementation_binding"] is True
        assert bad["w1_class"] == "ACCEPTED/REGRESSION"
        assert bad["w2_class"] == "ACCEPTED/REGRESSION"
        assert bad["selected_forbidden_pair"][1] in bad["forbidden_consequences"]
        verify_report(args, bad_path, bins["bad"], args.world, 0)

        stdout_lie = binding_run(args, bins["stdout-lie"], str(root / "stdout-lie.json"))
        record(rows, "B0-03", stdout_lie["authority"], stdout_lie)
        assert stdout_lie["stdout_sha256"] != hashlib.sha256(b"").hexdigest()
        assert stdout_lie["forbidden_consequences"] == []

        nonzero = binding_run(args, bins["nonzero-forbidden"], str(root / "nonzero.json"))
        record(rows, "B0-04", nonzero["authority"], nonzero)
        assert nonzero["exit_code"] == 9

        timeout_after = binding_run(args, bins["timeout-after-forbidden"], str(root / "timeout-after.json"))
        record(rows, "B0-05", timeout_after["authority"], timeout_after)
        assert timeout_after["timed_out"] is True

        timeout_before = binding_run(args, bins["timeout-before-effect"], str(root / "timeout-before.json"))
        record(rows, "B0-06", timeout_before["authority"], timeout_before)
        assert timeout_before["timed_out"] is True
        assert timeout_before["observed_consequences"] == []

        malformed = binding_run(args, bins["malformed"], str(root / "malformed.json"))
        record(rows, "B0-07", malformed["authority"], malformed)
        assert malformed["observation_status"] == "MALFORMED_OBSERVATION"

        multi = binding_run(args, bins["multi"], str(root / "multi.json"))
        record(rows, "B0-08", multi["authority"], multi)
        assert len(multi["observed_consequences"]) == 2
        assert len(multi["forbidden_consequences"]) == 1

        rc, substituted = verify_report(args, bad_path, bins["good"], args.world, 1)
        record(rows, "B0-09", "REJECT_BINDING_EVIDENCE" if rc == 1 and "implementation substitution" in substituted.get("reason", "") else "FAILED", substituted)

        altered_world = root / "altered-world.txt"
        altered_world.write_text("request=transfer\nsubject=mallory\nvalue=100\n", encoding="utf-8")
        rc, substituted_world = verify_report(args, bad_path, bins["bad"], str(altered_world), 1)
        record(rows, "B0-10", "REJECT_BINDING_EVIDENCE" if rc == 1 and "world-input substitution" in substituted_world.get("reason", "") else "FAILED", substituted_world)

        tampered = json.loads(Path(bad_path).read_text(encoding="utf-8"))
        tampered["effect_log_b64"] = base64.b64encode(b"E1|kind=transfer|subject=alice|value=100\n").decode("ascii")
        tampered_path = root / "tampered.json"
        tampered_path.write_text(json.dumps(tampered, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        rc, tamper_result = verify_report(args, str(tampered_path), bins["bad"], args.world, 1)
        record(rows, "B0-11", "REJECT_BINDING_EVIDENCE" if rc == 1 and "binding_id mismatch" in tamper_result.get("reason", "") else "FAILED", tamper_result)

        impossible = (
            good["authority"] == "NO_AUTHORITY"
            and good["preservation_authority"] is False
            and "certificate_id" not in good
            and good.get("w1_class") is None
            and good.get("w2_class") is None
        )
        record(rows, "B0-12", "IMPOSSIBLE_BY_INTERFACE" if impossible else "FAILED", good)

        claim = json.loads(Path(args.claim).read_text(encoding="utf-8"))
        claim["worlds"] = claim["worlds"] + ["w:sha256:" + "0" * 64]
        multi_claim_path = root / "multi-claim.json"
        multi_claim_path.write_text(json.dumps(claim, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        cmd = [
            sys.executable, args.binder, "run",
            "--implementation", bins["bad"],
            "--world", args.world,
            "--claim", str(multi_claim_path),
            "--w1", args.w1,
            "--w2", args.w2,
            "--timeout-ms", "250",
        ]
        _, multi_claim = run_json(cmd, 0)
        actual = "UNSUPPORTED_NO_AUTHORITY" if multi_claim["authority"] == "NO_AUTHORITY" and multi_claim["observation_status"] == "UNSUPPORTED" else "FAILED"
        record(rows, "B0-13", actual, multi_claim)

    result = {
        "gate": "RISU_KERNEL_K1_IMPLEMENTATION_BINDING_B0",
        "status": "PASS" if all(x["pass"] for x in rows) else "FAIL",
        "vector_count": len(rows),
        "passed": sum(1 for x in rows if x["pass"]),
        "failed": [x["id"] for x in rows if not x["pass"]],
        "binder_independence": independence,
        "binding_scope": "OBSERVED_EXECUTION_REGRESSION_WITNESS_ONLY",
        "preservation_authority": False,
        "implementation_binding_claim": "SCOPED_ONE_SIDED_REGRESSION_ONLY",
        "rows": rows,
    }
    if args.output:
        Path(args.output).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
