#!/usr/bin/env python3
"""Composite, fail-closed qualification verifier for K1 Implementation Binding B0.

The verifier replays provenance, exact Git blob pins, source hygiene/builds,
the 13-vector B0 gate, and the 8-vector independent-observer D1 gate.
It deliberately establishes only scoped one-sided observed regression binding.
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

BASE = "3f3e6b9071d7fe1cd447f2bbbba9addbbe509533"
MANIFEST = "protocols/RISU_KERNEL_K1_IMPLEMENTATION_BINDING_B0_QUALIFICATION.json"
SELF_PATH = "tools/risu_kernel_k1_binding_b0_qualification_verify.py"
WORKFLOW_PATH = ".github/workflows/k1-implementation-binding-b0-qualification.yml"


class QualificationError(Exception):
    pass


def run(cmd, *, env=None, capture=True, check=True):
    proc = subprocess.run(
        cmd,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
        env=env,
        check=False,
        text=True,
    )
    if check and proc.returncode != 0:
        raise QualificationError(
            f"command failed rc={proc.returncode}: {cmd}\nstdout={proc.stdout}\nstderr={proc.stderr}"
        )
    return proc


def git_blob(path):
    return run(["git", "hash-object", "--", path]).stdout.strip()


def verify_ancestry_and_delta(manifest):
    run(["git", "merge-base", "--is-ancestor", BASE, "HEAD"])
    rows = []
    proc = run(["git", "diff", "--name-status", BASE, "HEAD"])
    for line in proc.stdout.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        status = parts[0]
        paths = parts[1:]
        rows.append((status, paths))
    if not rows:
        raise QualificationError("qualification delta unexpectedly empty")
    non_add = [(s, p) for s, p in rows if s != "A"]
    if non_add:
        raise QualificationError(f"non-additive delta relative to qualified base: {non_add}")

    delta_paths = {p[0] for _, p in rows}
    expected = set(manifest["pinned_b0_blobs"])
    expected.update(manifest.get("qualification_tooling_blobs", {}))
    expected.add(MANIFEST)
    # Before the tooling pins are filled, permit exactly these two prospective
    # qualification artifacts. The final frozen manifest pins both and the same
    # equality then holds without this bootstrap allowance.
    if not manifest.get("qualification_tooling_blobs"):
        expected.update({SELF_PATH, WORKFLOW_PATH})
    if delta_paths != expected:
        missing = sorted(expected - delta_paths)
        extra = sorted(delta_paths - expected)
        raise QualificationError(f"delta file-set mismatch; missing={missing}, extra={extra}")
    return {
        "base_commit": BASE,
        "base_is_ancestor": True,
        "add_only": True,
        "delta_file_count": len(delta_paths),
        "delta_paths": sorted(delta_paths),
    }


def verify_pins(manifest):
    failures = []
    checked = {}
    for section in ("frozen_base_blobs", "pinned_b0_blobs", "qualification_tooling_blobs"):
        for path, expected in manifest.get(section, {}).items():
            if not Path(path).is_file():
                failures.append({"path": path, "reason": "missing"})
                continue
            actual = git_blob(path)
            checked[path] = actual
            if actual != expected:
                failures.append({"path": path, "expected": expected, "actual": actual})
    if failures:
        raise QualificationError(f"pinned blob mismatch: {failures}")
    return checked


def source_hygiene_and_builds(workdir):
    run(["git", "diff", "--check"])
    run([
        sys.executable,
        "-m",
        "py_compile",
        "tools/risu_kernel_k1_binding_b0.py",
        "tools/risu_kernel_k1_binding_b0_verify.py",
        "tools/risu_kernel_k1_binding_b0_observer_d1_verify.py",
    ])

    for path in (
        "tools/specimens/k1_binding_b0_target.go",
        "tools/risu_kernel_k1_binding_b0_observer.go",
    ):
        diff = run(["gofmt", "-d", path]).stdout
        if diff:
            raise QualificationError(f"non-gofmt-canonical Go source: {path}\n{diff}")

    env = os.environ.copy()
    env["CGO_ENABLED"] = "0"
    run(["go", "vet", "tools/specimens/k1_binding_b0_target.go"], env=env)
    run(["go", "vet", "tools/risu_kernel_k1_binding_b0_observer.go"], env=env)
    run(["go", "vet", "kernel/k1_checker_w2.go"], env=env)

    w2 = str(Path(workdir) / "risu-k1-w2")
    observer = str(Path(workdir) / "risu-k1-b0-observer")
    bin_dir = Path(workdir) / "b0-bin"
    bin_dir.mkdir()
    run(["go", "build", "-trimpath", "-o", w2, "kernel/k1_checker_w2.go"], env=env)
    run(["go", "build", "-trimpath", "-o", observer, "tools/risu_kernel_k1_binding_b0_observer.go"], env=env)

    variants = [
        "good",
        "bad",
        "stdout-lie",
        "nonzero-forbidden",
        "timeout-after-forbidden",
        "timeout-before-effect",
        "malformed",
        "multi",
    ]
    for variant in variants:
        target = str(bin_dir / ("b0-" + variant))
        run([
            "go",
            "build",
            "-trimpath",
            "-ldflags",
            f"-s -w -X main.variant={variant}",
            "-o",
            target,
            "tools/specimens/k1_binding_b0_target.go",
        ], env=env)
    return {"w2": w2, "observer": observer, "bin_dir": str(bin_dir)}


def load_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def replay_b0(paths, workdir):
    out = str(Path(workdir) / "b0.json")
    proc = run([
        sys.executable,
        "tools/risu_kernel_k1_binding_b0_verify.py",
        "--binder", "tools/risu_kernel_k1_binding_b0.py",
        "--w1", "kernel/k1_checker_w1.py",
        "--w2", paths["w2"],
        "--world", "fixtures/k1_binding_b0/world_input.txt",
        "--claim", "fixtures/k1_binding_b0/claim.json",
        "--bin-dir", paths["bin_dir"],
        "--output", out,
    ])
    data = load_json(out)
    if data.get("status") != "PASS" or data.get("vector_count") != 13 or data.get("passed") != 13:
        raise QualificationError(f"B0 13-vector replay failed: {data}\nstdout={proc.stdout}")
    if data.get("failed") != [] or data.get("preservation_authority") is not False:
        raise QualificationError(f"B0 authority invariant failed: {data}")
    if data.get("implementation_binding_claim") != "SCOPED_ONE_SIDED_REGRESSION_ONLY":
        raise QualificationError("B0 claim scope drift")
    if not data.get("binder_independence", {}).get("pass"):
        raise QualificationError("B0 binder independence failed")
    return data


def replay_d1(paths, workdir):
    out = str(Path(workdir) / "d1.json")
    proc = run([
        sys.executable,
        "tools/risu_kernel_k1_binding_b0_observer_d1_verify.py",
        "--binder", "tools/risu_kernel_k1_binding_b0.py",
        "--observer", paths["observer"],
        "--observer-source", "tools/risu_kernel_k1_binding_b0_observer.go",
        "--w1", "kernel/k1_checker_w1.py",
        "--w2", paths["w2"],
        "--world", "fixtures/k1_binding_b0/world_input.txt",
        "--claim", "fixtures/k1_binding_b0/claim.json",
        "--bin-dir", paths["bin_dir"],
        "--output", out,
    ])
    data = load_json(out)
    if data.get("status") != "PASS" or data.get("runtime_vector_count") != 8 or data.get("passed") != 8:
        raise QualificationError(f"D1 8-vector replay failed: {data}\nstdout={proc.stdout}")
    if data.get("failed") != [] or data.get("preservation_authority") is not False:
        raise QualificationError(f"D1 authority invariant failed: {data}")
    if not data.get("observer_independence", {}).get("pass"):
        raise QualificationError("D1 observer independence failed")
    return data


def verify_oracles(manifest, b0, d1):
    q = manifest["qualification_results"]
    if q["b0_adversarial_vectors"] != {"required": 13, "passed": 13, "failed": 0}:
        raise QualificationError("manifest B0 count drift")
    if q["d1_independent_observer_vectors"] != {"required": 8, "passed": 8, "failed": 0}:
        raise QualificationError("manifest D1 count drift")
    fixture = q["exact_fixture_oracles"]
    if d1.get("exact_fixture_oracles", {}).get("world_id") != fixture["world_id"]:
        raise QualificationError("D1 world oracle drift")
    if d1["exact_fixture_oracles"].get("allowed_consequence_id") != fixture["allowed_consequence_id"]:
        raise QualificationError("D1 allowed consequence oracle drift")
    if d1["exact_fixture_oracles"].get("forbidden_consequence_id") != fixture["forbidden_consequence_id"]:
        raise QualificationError("D1 forbidden consequence oracle drift")

    bad = next(row for row in b0["rows"] if row["id"] == "B0-02")
    detail = bad["detail"]
    if detail.get("authority") != "BOUND_REGRESSION":
        raise QualificationError("simple forbidden run is not BOUND_REGRESSION")
    if detail.get("w1_class") != "ACCEPTED/REGRESSION" or detail.get("w2_class") != "ACCEPTED/REGRESSION":
        raise QualificationError("W1/W2 regression corroboration drift")
    simple = q["simple_forbidden_run"]
    for key in ("target_id", "proof_artifact_id", "witness_id"):
        if detail.get(key) != simple[key]:
            raise QualificationError(f"simple forbidden run {key} drift")


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", default=MANIFEST)
    parser.add_argument("--output")
    args = parser.parse_args(argv)

    try:
        manifest = load_json(args.manifest)
        if manifest.get("qualification_id") != "RISU_KERNEL_K1_IMPLEMENTATION_BINDING_B0_QUALIFICATION":
            raise QualificationError("wrong qualification manifest")
        if manifest.get("frozen_base", {}).get("commit") != BASE:
            raise QualificationError("frozen base drift")
        if manifest.get("scope", {}).get("preservation_authority") is not False:
            raise QualificationError("manifest attempts preservation authority")

        provenance = verify_ancestry_and_delta(manifest)
        pins = verify_pins(manifest)
        with tempfile.TemporaryDirectory(prefix="risu-k1-b0-qualification-") as td:
            paths = source_hygiene_and_builds(td)
            b0 = replay_b0(paths, td)
            d1 = replay_d1(paths, td)
            verify_oracles(manifest, b0, d1)

        result = {
            "qualification": "RISU_KERNEL_K1_IMPLEMENTATION_BINDING_B0_QUALIFICATION",
            "status": "PASS",
            "frozen_base": BASE,
            "base_is_ancestor": provenance["base_is_ancestor"],
            "add_only": provenance["add_only"],
            "delta_file_count": provenance["delta_file_count"],
            "pinned_blob_count": len(pins),
            "pinned_blobs": True,
            "source_hygiene": "PASS",
            "b0_adversarial": "13/13 PASS",
            "d1_observer_differential": "8/8 PASS",
            "w1_w2_forbidden_witness": "ACCEPTED/REGRESSION + ACCEPTED/REGRESSION",
            "implementation_binding_claim": "SCOPED_ONE_SIDED_REGRESSION_ONLY",
            "preservation_authority": False,
        }
        if args.output:
            Path(args.output).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (QualificationError, KeyError, ValueError, StopIteration) as exc:
        result = {
            "qualification": "RISU_KERNEL_K1_IMPLEMENTATION_BINDING_B0_QUALIFICATION",
            "status": "FAIL",
            "reason": str(exc),
            "preservation_authority": False,
        }
        if args.output:
            Path(args.output).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps(result, indent=2, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
