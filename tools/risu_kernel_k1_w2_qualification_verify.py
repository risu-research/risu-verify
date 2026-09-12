#!/usr/bin/env python3
"""Composite qualification verifier for independent K1 checker W2.

This verifier does not redefine K1 semantics. It verifies provenance/isolation,
exact Git blobs, source hygiene, and reproducibly reruns the frozen D0/D1
checker-differential evidence against K1 RC1.
"""

import argparse
import json
import os
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "protocols" / "RISU_KERNEL_K1_W2_QUALIFICATION.json"


class QualificationFailure(Exception):
    pass


def run(cmd, *, env=None, check=True, capture=True):
    cp = subprocess.run(
        cmd,
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=capture,
    )
    if check and cp.returncode != 0:
        raise QualificationFailure(
            f"command failed rc={cp.returncode}: {cmd!r}\nstdout={cp.stdout}\nstderr={cp.stderr}"
        )
    return cp


def git(*args, check=True):
    return run(["git", *args], check=check).stdout.strip()


def verify_ancestry_and_isolation(manifest):
    base = manifest["base_release_candidate"]["commit"]
    head = git("rev-parse", "HEAD")
    if git("rev-parse", base) != base:
        raise QualificationFailure("exact RC1 base commit is not available in checkout")
    cp = run(["git", "merge-base", "--is-ancestor", base, head], check=False)
    if cp.returncode != 0:
        raise QualificationFailure("current head does not descend from exact K1 RC1 base")

    diff = git("diff", "--name-status", f"{base}..{head}")
    changed = []
    forbidden = []
    if diff:
        for line in diff.splitlines():
            parts = line.split("\t")
            status = parts[0]
            paths = parts[1:]
            changed.append({"status": status, "paths": paths})
            if status != "A":
                forbidden.append({"status": status, "paths": paths})
    if forbidden:
        raise QualificationFailure("RC1 isolation violated; non-additive changes: " + repr(forbidden))
    return {"base": base, "head": head, "add_only": True, "changed": changed}


def hash_blob(path):
    p = ROOT / path
    if not p.is_file():
        raise QualificationFailure(f"pinned file missing: {path}")
    return git("hash-object", path)


def verify_blob_map(label, mapping):
    rows = []
    for path, expected in sorted(mapping.items()):
        actual = hash_blob(path)
        if actual != expected:
            raise QualificationFailure(
                f"{label} blob drift: {path}: expected {expected}, got {actual}"
            )
        rows.append({"path": path, "git_blob_sha1": actual})
    return rows


def verify_go_source(binary_path):
    source = "kernel/k1_checker_w2.go"
    fmt = run(["gofmt", "-d", source])
    if fmt.stdout:
        raise QualificationFailure("W2 source is not gofmt canonical:\n" + fmt.stdout)

    env = dict(os.environ)
    env["CGO_ENABLED"] = "0"
    run(["go", "vet", source], env=env)
    run(["go", "build", "-trimpath", "-o", str(binary_path), source], env=env)
    if not binary_path.is_file():
        raise QualificationFailure("W2 binary was not produced")
    version = run(["go", "version"], env=env).stdout.strip()
    return {
        "gofmt_canonical": True,
        "go_vet": "PASS",
        "cgo_enabled": False,
        "build": "PASS",
        "go_version": version,
    }


def load_json(path):
    return json.loads(pathlib.Path(path).read_text(encoding="utf-8"))


def verify_d0(x, req):
    checks = {
        "qualification_vector_count": x.get("qualification_vector_count"),
        "semantic_differential_equivalence": x.get("semantic_differential_equivalence"),
        "qualification_disagreements": x.get("qualification_disagreements"),
        "oracle_failures": x.get("oracle_failures"),
        "independence_audit_pass": x.get("independence_audit", {}).get("pass"),
        "full_wire_parser_equivalence": x.get("full_wire_parser_equivalence"),
        "boundary_divergences": x.get("boundary_divergences"),
    }
    if x.get("status") != "PASS":
        raise QualificationFailure("D0 status is not PASS")
    if checks != req:
        raise QualificationFailure(f"D0 required result mismatch: expected={req!r} got={checks!r}")
    if x.get("implementation_binding") is not False:
        raise QualificationFailure("D0 assurance boundary drift: implementation_binding")
    return checks


def verify_d1(x, req):
    checks = {
        "seed_decimal": x.get("seed_decimal"),
        "trial_count": x.get("trial_count"),
        "comparison_count": x.get("comparison_count"),
        "w1_w2_disagreements": x.get("w1_w2_disagreements"),
        "oracle_failures": x.get("oracle_failures"),
        "semantic_identity_failures": x.get("semantic_identity_failures"),
        "all_comparisons_agree": x.get("all_comparisons_agree"),
        "all_oracles_match": x.get("all_oracles_match"),
        "claim_target_permutation_invariance": x.get("claim_target_permutation_invariance"),
    }
    if x.get("status") != "PASS":
        raise QualificationFailure("D1 status is not PASS")
    if checks != req:
        raise QualificationFailure(f"D1 required result mismatch: expected={req!r} got={checks!r}")
    if x.get("implementation_binding") is not False:
        raise QualificationFailure("D1 assurance boundary drift: implementation_binding")
    return checks


def rerun_differentials(binary_path, manifest, tempdir):
    d0_out = tempdir / "d0.json"
    d1_out = tempdir / "d1.json"
    run([
        sys.executable,
        "tools/risu_kernel_k1_w1_w2_differential.py",
        "--w2", str(binary_path),
        "--output", str(d0_out),
    ])
    d0 = load_json(d0_out)
    d0_summary = verify_d0(d0, manifest["required_results"]["d0"])

    run([
        sys.executable,
        "tools/risu_kernel_k1_w1_w2_generative_d1.py",
        "--w2", str(binary_path),
        "--output", str(d1_out),
    ])
    d1 = load_json(d1_out)
    d1_summary = verify_d1(d1, manifest["required_results"]["d1"])
    return d0_summary, d1_summary


def verify_classified_divergence(manifest, d0_summary):
    rows = manifest["classified_divergences"]
    if len(rows) != 1:
        raise QualificationFailure("unexpected classified-divergence cardinality")
    row = rows[0]
    if row.get("classification") != "FAIL_CLOSED_STRUCTURAL_DIVERGENCE":
        raise QualificationFailure("parser divergence is not classified fail-closed")
    if row.get("authority_effect") != "NONE":
        raise QualificationFailure("parser divergence would change semantic authority")
    if d0_summary["boundary_divergences"] != ["sentinel_proof_kind_schema_pattern"]:
        raise QualificationFailure("classified divergence does not match rerun D0")
    return row


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--output")
    args = ap.parse_args()

    try:
        manifest = load_json(MANIFEST)
        ancestry = verify_ancestry_and_isolation(manifest)
        rc1_blobs = verify_blob_map("RC1 anchor", manifest["frozen_rc1_anchors"])
        w2_blobs = verify_blob_map("W2 evidence", manifest["w2_evidence_blobs"])
        tooling_blobs = verify_blob_map(
            "qualification tooling", manifest.get("qualification_tooling_blobs", {})
        )

        with tempfile.TemporaryDirectory(prefix="k1-w2-qualification-") as td:
            tempdir = pathlib.Path(td)
            binary = tempdir / "risu-k1-w2"
            go_summary = verify_go_source(binary)
            d0_summary, d1_summary = rerun_differentials(binary, manifest, tempdir)

        divergence = verify_classified_divergence(manifest, d0_summary)
        result = {
            "qualification_id": manifest["qualification_id"],
            "status": "PASS",
            "qualification_status": "QUALIFIED_INDEPENDENT_CORROBORATING_CHECKER",
            "base_rc1_commit": ancestry["base"],
            "qualified_head": ancestry["head"],
            "rc1_add_only_isolation": True,
            "added_file_count": len(ancestry["changed"]),
            "pinned_rc1_anchor_count": len(rc1_blobs),
            "pinned_w2_evidence_count": len(w2_blobs),
            "pinned_qualification_tooling_count": len(tooling_blobs),
            "go_source": go_summary,
            "d0": d0_summary,
            "d1": d1_summary,
            "classified_divergence": divergence,
            "semantic_differential_equivalence": "QUALIFIED",
            "full_wire_parser_equivalence": "NOT_QUALIFIED",
            "assurance_scope": manifest["assurance_boundary"]["assurance_scope"],
            "implementation_binding": False,
            "universal_correctness_claim": False,
        }
    except QualificationFailure as exc:
        result = {
            "qualification_id": "RISU_KERNEL_K1_W2_QUALIFICATION",
            "status": "FAIL",
            "reason": str(exc),
        }

    text = json.dumps(result, indent=2, sort_keys=True)
    print(text)
    if args.output:
        pathlib.Path(args.output).write_text(text + "\n", encoding="utf-8")
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
