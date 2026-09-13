#!/usr/bin/env python3
"""Fail-closed composite qualification replay for K1 Binding B1."""

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

MANIFEST_PATH = "protocols/RISU_KERNEL_K1_BINDING_B1_QUALIFICATION.json"
BOOTSTRAP_TOOLING = {
    "tools/risu_kernel_k1_binding_b1_qualification_verify.py",
    ".github/workflows/k1-binding-b1-qualification.yml",
}


def run(cmd, *, capture=False, env=None):
    proc = subprocess.run(
        cmd,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
        text=True,
        check=False,
        env=env,
    )
    if proc.returncode != 0:
        detail = ((proc.stderr or "") + (proc.stdout or "")).strip() if capture else ""
        raise SystemExit(f"qualification command failed ({proc.returncode}): {' '.join(cmd)}\n{detail}")
    return proc.stdout if capture else ""


def git_blob(path, ref=None):
    if ref:
        return run(["git", "rev-parse", f"{ref}:{path}"], capture=True).strip()
    return run(["git", "hash-object", path], capture=True).strip()


def verify_delta(base, expected):
    run(["git", "merge-base", "--is-ancestor", base, "HEAD"])
    raw = run(["git", "diff", "--name-status", base, "HEAD"], capture=True)
    actual = set()
    for line in raw.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) != 2 or parts[0] != "A":
            raise SystemExit("B1 qualification requires exact add-only delta; found: " + line)
        actual.add(parts[1])
    if actual != expected:
        raise SystemExit(
            "B1 delta file set mismatch\nmissing=" + repr(sorted(expected - actual)) +
            "\nextra=" + repr(sorted(actual - expected))
        )
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
    expected_delta = set(manifest["pinned_b1_blobs"]) | tooling_paths | {args.manifest}
    delta_files = verify_delta(base, expected_delta)

    verified = {}
    for path, expected in manifest["frozen_base_blobs"].items():
        actual = git_blob(path, base)
        if actual != expected:
            raise SystemExit(f"frozen-base blob mismatch: {path}: {actual} != {expected}")
        verified[path] = actual
    for path, expected in manifest["pinned_b1_blobs"].items():
        actual = git_blob(path)
        if actual != expected:
            raise SystemExit(f"B1 blob mismatch: {path}: {actual} != {expected}")
        verified[path] = actual
    for path, expected in tooling.items():
        actual = git_blob(path)
        if actual != expected:
            raise SystemExit(f"qualification tooling blob mismatch: {path}: {actual} != {expected}")
        verified[path] = actual

    run(["git", "diff", "--check"])
    py_sources = [
        "kernel/k1_checker_w3.py",
        "tools/risu_kernel_k1_binding_b1.py",
        "tools/risu_kernel_k1_binding_b1_report_verify.py",
        "tools/risu_kernel_k1_binding_b1_verify.py",
        "tools/risu_kernel_k1_binding_b1_observer_d2_verify.py",
        __file__,
    ]
    run([sys.executable, "-m", "py_compile", *py_sources])
    for path in ["kernel/k1_checker_w4.go", "tools/risu_kernel_k1_binding_b1_observer.go", "tools/specimens/k1_binding_b0_target.go"]:
        diff = run(["gofmt", "-d", path], capture=True)
        if diff:
            raise SystemExit(f"noncanonical gofmt source: {path}\n{diff}")
        run(["go", "vet", path])

    env = dict(os.environ)
    env["CGO_ENABLED"] = "0"
    with tempfile.TemporaryDirectory(prefix="risu-b1-qualification-") as td:
        root = Path(td)
        w4 = root / "risu-k1-w4"
        observer = root / "risu-k1-b1-observer"
        bindir = root / "b1-bin"
        bindir.mkdir()
        b1_out = root / "b1.json"
        d2_out = root / "d2.json"

        run(["go", "build", "-trimpath", "-o", str(w4), "kernel/k1_checker_w4.go"], env=env)
        run(["go", "build", "-trimpath", "-o", str(observer), "tools/risu_kernel_k1_binding_b1_observer.go"], env=env)
        variants = ["good", "bad", "stdout-lie", "nonzero-forbidden", "timeout-after-forbidden", "timeout-before-effect", "malformed", "multi"]
        for variant in variants:
            run([
                "go", "build", "-trimpath", "-ldflags", f"-s -w -X main.variant={variant}",
                "-o", str(bindir / f"b1-{variant}"), "tools/specimens/k1_binding_b0_target.go"
            ], env=env)

        run([
            sys.executable, "tools/risu_kernel_k1_binding_b1_verify.py",
            "--binder", "tools/risu_kernel_k1_binding_b1.py",
            "--report-verifier", "tools/risu_kernel_k1_binding_b1_report_verify.py",
            "--w3", "kernel/k1_checker_w3.py",
            "--w4", str(w4),
            "--claim", "fixtures/k1_observed_pair_p1/claim_multi.json",
            "--world", "fixtures/k1_binding_b0/world_input.txt",
            "--bin-dir", str(bindir),
            "--output", str(b1_out),
        ], env=env)
        run([
            sys.executable, "tools/risu_kernel_k1_binding_b1_observer_d2_verify.py",
            "--binder", "tools/risu_kernel_k1_binding_b1.py",
            "--observer", str(observer),
            "--observer-source", "tools/risu_kernel_k1_binding_b1_observer.go",
            "--w3", "kernel/k1_checker_w3.py",
            "--w4", str(w4),
            "--claim", "fixtures/k1_observed_pair_p1/claim_multi.json",
            "--world", "fixtures/k1_binding_b0/world_input.txt",
            "--bin-dir", str(bindir),
            "--output", str(d2_out),
        ], env=env)
        b1 = json.loads(b1_out.read_text(encoding="utf-8"))
        d2 = json.loads(d2_out.read_text(encoding="utf-8"))

    checks = {
        "b1_status": b1.get("status") == "PASS",
        "b1_vector_count": b1.get("vector_count") == 16,
        "b1_passed": b1.get("passed") == 16,
        "b1_failed_empty": b1.get("failed") == [],
        "b1_preservation_false": b1.get("preservation_authority") is False,
        "b1_scope": b1.get("binding_scope") == "CONTROLLED_LOCAL_EXECUTION_REGRESSION_ONLY",
        "d2_status": d2.get("status") == "PASS",
        "d2_vector_count": d2.get("runtime_vector_count") == 8,
        "d2_passed": d2.get("passed") == 8,
        "d2_failed_empty": d2.get("failed") == [],
        "d2_independent": d2.get("observer_independence", {}).get("pass") is True,
        "d2_preservation_false": d2.get("preservation_authority") is False,
        "manifest_preservation_false": manifest.get("scope", {}).get("preservation_authority") is False,
        "manifest_transferable_attestation_false": manifest.get("scope", {}).get("transferable_attestation") is False,
        "manifest_kernel_unchanged": manifest.get("scope", {}).get("semantic_kernel_changed") is False,
    }
    status = "PASS" if all(checks.values()) else "FAIL"
    result = {
        "qualification": "RISU_KERNEL_K1_BINDING_B1_QUALIFICATION",
        "status": status,
        "base_commit": base,
        "head_commit": run(["git", "rev-parse", "HEAD"], capture=True).strip(),
        "delta_files": delta_files,
        "verified_blob_count": len(verified),
        "bootstrap_tooling_mode": not bool(tooling),
        "checks": checks,
        "b1_gate": {"status": b1.get("status"), "passed": b1.get("passed"), "vector_count": b1.get("vector_count"), "failed": b1.get("failed")},
        "d2_gate": {"status": d2.get("status"), "passed": d2.get("passed"), "vector_count": d2.get("runtime_vector_count"), "failed": d2.get("failed")},
    }
    Path(args.output).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
