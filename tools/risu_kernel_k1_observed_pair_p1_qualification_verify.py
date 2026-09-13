#!/usr/bin/env python3
"""Fail-closed composite qualification replay for K1 observed-pair P1."""

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

MANIFEST_PATH = "protocols/RISU_KERNEL_K1_OBSERVED_PAIR_P1_QUALIFICATION.json"
BOOTSTRAP_TOOLING = {
    "tools/risu_kernel_k1_observed_pair_p1_qualification_verify.py",
    ".github/workflows/k1-observed-pair-p1-qualification.yml",
}


def run(cmd, *, capture=False):
    proc = subprocess.run(cmd, stdout=subprocess.PIPE if capture else None, stderr=subprocess.PIPE if capture else None, text=True, check=False)
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip() if capture else ""
        raise SystemExit(f"qualification command failed ({proc.returncode}): {' '.join(cmd)}\n{detail}")
    return proc.stdout if capture else ""


def git_blob(path, ref=None):
    spec = f"{ref}:{path}" if ref else path
    if ref:
        return run(["git", "rev-parse", spec], capture=True).strip()
    return run(["git", "hash-object", spec], capture=True).strip()


def verify_delta(base, expected):
    run(["git", "merge-base", "--is-ancestor", base, "HEAD"])
    raw = run(["git", "diff", "--name-status", base, "HEAD"], capture=True)
    actual = set()
    for line in raw.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) != 2 or parts[0] != "A":
            raise SystemExit("P1 qualification requires exact add-only delta; found: " + line)
        actual.add(parts[1])
    if actual != expected:
        raise SystemExit("P1 delta file set mismatch\nmissing=" + repr(sorted(expected-actual)) + "\nextra=" + repr(sorted(actual-expected)))
    return sorted(actual)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", default=MANIFEST_PATH)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    base = manifest["frozen_base"]["commit"]
    tooling = manifest.get("qualification_tooling_blobs", {})
    tooling_paths = set(tooling) if tooling else set(BOOTSTRAP_TOOLING)
    expected_delta = set(manifest["pinned_p1_blobs"]) | tooling_paths | {args.manifest}
    delta = verify_delta(base, expected_delta)

    verified_blobs = {}
    for path, expected in manifest["frozen_base_blobs"].items():
        actual = git_blob(path, base)
        if actual != expected:
            raise SystemExit(f"frozen-base blob mismatch: {path}: {actual} != {expected}")
        verified_blobs[path] = actual
    for path, expected in manifest["pinned_p1_blobs"].items():
        actual = git_blob(path)
        if actual != expected:
            raise SystemExit(f"P1 blob mismatch: {path}: {actual} != {expected}")
        verified_blobs[path] = actual
    for path, expected in tooling.items():
        actual = git_blob(path)
        if actual != expected:
            raise SystemExit(f"qualification tooling blob mismatch: {path}: {actual} != {expected}")
        verified_blobs[path] = actual

    run(["git", "diff", "--check"])
    run([sys.executable, "-m", "py_compile", "kernel/k1_checker_w3.py", "tools/risu_kernel_k1_observed_pair_p1_verify.py", __file__])
    gofmt = run(["gofmt", "-d", "kernel/k1_checker_w4.go"], capture=True)
    if gofmt:
        raise SystemExit("W4 is not gofmt-canonical:\n" + gofmt)
    run(["go", "vet", "kernel/k1_checker_w4.go"])
    run(["go", "vet", "tools/specimens/k1_binding_b0_target.go"])

    with tempfile.TemporaryDirectory(prefix="risu-p1-qual-") as td:
        root = Path(td)
        w4 = root / "w4"
        implementation = root / "target"
        gate_out = root / "gate.json"
        run(["go", "build", "-trimpath", "-o", str(w4), "kernel/k1_checker_w4.go"])
        run(["go", "build", "-trimpath", "-ldflags", "-s -w -X main.variant=bad", "-o", str(implementation), "tools/specimens/k1_binding_b0_target.go"])
        run([
            sys.executable, "tools/risu_kernel_k1_observed_pair_p1_verify.py",
            "--w3", "kernel/k1_checker_w3.py",
            "--w4", str(w4),
            "--w4-source", "kernel/k1_checker_w4.go",
            "--claim", "fixtures/k1_observed_pair_p1/claim_multi.json",
            "--implementation", str(implementation),
            "--output", str(gate_out),
        ])
        gate = json.loads(gate_out.read_text(encoding="utf-8"))

    checks = {
        "gate_status": gate.get("status") == "PASS",
        "vector_count": gate.get("vector_count") == 18,
        "passed": gate.get("passed") == 18,
        "failed_empty": gate.get("failed") == [],
        "checker_independence": gate.get("checker_independence", {}).get("pass") is True,
        "preservation_authority_false": gate.get("preservation_authority") is False,
        "semantic_kernel_unchanged": gate.get("semantic_kernel_changed") is False,
    }
    status = "PASS" if all(checks.values()) else "FAIL"
    result = {
        "qualification": "RISU_KERNEL_K1_OBSERVED_PAIR_P1_QUALIFICATION",
        "status": status,
        "base_commit": base,
        "head_commit": run(["git", "rev-parse", "HEAD"], capture=True).strip(),
        "delta_files": delta,
        "verified_blob_count": len(verified_blobs),
        "bootstrap_tooling_mode": not bool(tooling),
        "checks": checks,
        "p1_gate": {"status": gate.get("status"), "passed": gate.get("passed"), "vector_count": gate.get("vector_count"), "failed": gate.get("failed")},
    }
    Path(args.output).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
