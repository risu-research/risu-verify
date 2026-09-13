#!/usr/bin/env python3
"""Differentially qualify Python B0 observation against independent Go observer."""

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

WORLD = "w:sha256:13cc08218b3578873c7cb0438f32f4bc9ad8f732e4d810193bb15e89214ad314"
ALLOWED = "c:sha256:238c9f640b79314187064c6f722f726ec981c980229233cb5c1a5453b37f6ee0"
FORBIDDEN = "c:sha256:e9d1d1a276a1c50b31187d32763d4584a6b9f5b92a7c4aa7e53d71adfed9455e"

ORACLE = {
    "good": ("OBSERVED", [ALLOWED], []),
    "bad": ("OBSERVED", [FORBIDDEN], [FORBIDDEN]),
    "stdout-lie": ("OBSERVED", [ALLOWED], []),
    "nonzero-forbidden": ("OBSERVED", [FORBIDDEN], [FORBIDDEN]),
    "timeout-after-forbidden": ("OBSERVED", [FORBIDDEN], [FORBIDDEN]),
    "timeout-before-effect": ("OBSERVED", [], []),
    "malformed": ("MALFORMED_OBSERVATION", [], []),
    "multi": ("OBSERVED", sorted([ALLOWED, FORBIDDEN]), [FORBIDDEN]),
}


def run_json(cmd):
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if p.returncode != 0:
        raise AssertionError(f"command failed rc={p.returncode}: {cmd}\nstdout={p.stdout!r}\nstderr={p.stderr!r}")
    try:
        return json.loads(p.stdout.decode("utf-8"))
    except Exception as exc:
        raise AssertionError(f"non-JSON output: {p.stdout!r}") from exc


def normalize_binder(report):
    status = report["observation_status"]
    if status in {"OBSERVED_NO_FORBIDDEN_CONSEQUENCE", "OBSERVED_FORBIDDEN_CONSEQUENCE"}:
        status = "OBSERVED"
    return (
        status,
        sorted(report.get("observed_consequences") or []),
        sorted(report.get("forbidden_consequences") or []),
    )


def normalize_observer(report):
    return (
        report["observation_status"],
        sorted(report.get("observed_consequences") or []),
        sorted(report.get("forbidden_consequences") or []),
    )


def audit_observer_source(path):
    text = Path(path).read_text(encoding="utf-8")
    imports = sorted(re.findall(r'^\s*"([^"\n]+)"\s*$', text, flags=re.MULTILINE))
    forbidden_refs = [
        needle for needle in [
            "risu_kernel_k1_binding_b0.py",
            "risu_kernel_k1_binding_b0_verify.py",
            "k1_checker_w1.py",
            "k1_checker_w2.go",
            "subprocess",
            '"python"',
            '"python3"',
        ]
        if needle in text
    ]
    nonstdlib = [x for x in imports if "." in x.split("/")[0]]
    return {
        "imports": imports,
        "nonstdlib_imports": nonstdlib,
        "forbidden_references": forbidden_refs,
        "pass": not nonstdlib and not forbidden_refs,
    }


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--binder", required=True)
    p.add_argument("--observer", required=True)
    p.add_argument("--observer-source", required=True)
    p.add_argument("--w1", required=True)
    p.add_argument("--w2", required=True)
    p.add_argument("--world", required=True)
    p.add_argument("--claim", required=True)
    p.add_argument("--bin-dir", required=True)
    p.add_argument("--output")
    args = p.parse_args(argv)

    audit = audit_observer_source(args.observer_source)
    if not audit["pass"]:
        raise AssertionError(f"observer independence audit failed: {audit}")

    rows = []
    with tempfile.TemporaryDirectory(prefix="risu-k1-b0-d1-") as td:
        for variant, expected in ORACLE.items():
            target = os.path.join(args.bin_dir, "b0-" + variant)
            binder_out = os.path.join(td, variant + "-binder.json")
            binder = run_json([
                sys.executable, args.binder, "run",
                "--implementation", target,
                "--world", args.world,
                "--claim", args.claim,
                "--w1", args.w1,
                "--w2", args.w2,
                "--timeout-ms", "250",
                "--output", binder_out,
            ])
            observer = run_json([
                args.observer,
                "--implementation", target,
                "--world", args.world,
                "--claim", args.claim,
                "--timeout-ms", "250",
            ])
            b = normalize_binder(binder)
            g = normalize_observer(observer)
            ok = (
                b == expected
                and g == expected
                and b == g
                and binder["world_id"] == WORLD
                and observer["world_id"] == WORLD
                and binder["world_id"] == observer["world_id"]
                and binder["implementation_id"] == observer["implementation_id"]
                and binder["effect_log_sha256"] == observer["effect_log_sha256"]
                and binder["preservation_authority"] is False
                and observer["preservation_authority"] is False
            )
            rows.append({
                "variant": variant,
                "expected": {
                    "status": expected[0],
                    "observed": expected[1],
                    "forbidden": expected[2],
                },
                "binder": {"normalized": b, "authority": binder["authority"]},
                "observer": {"normalized": g, "authority_candidate": observer["authority_candidate"]},
                "pass": ok,
            })
            if not ok:
                raise AssertionError(f"D1 mismatch for {variant}: binder={binder}, observer={observer}, expected={expected}")

    fixture_oracles = {
        "world_id": WORLD,
        "allowed_consequence_id": ALLOWED,
        "forbidden_consequence_id": FORBIDDEN,
    }
    all_observed = set()
    for row in rows:
        all_observed.update(row["expected"]["observed"])
    if ALLOWED not in all_observed or FORBIDDEN not in all_observed:
        raise AssertionError("fixture consequence oracle coverage missing")

    result = {
        "gate": "RISU_KERNEL_K1_IMPLEMENTATION_BINDING_B0_D1",
        "status": "PASS" if all(x["pass"] for x in rows) else "FAIL",
        "runtime_vector_count": len(rows),
        "passed": sum(1 for x in rows if x["pass"]),
        "failed": [x["variant"] for x in rows if not x["pass"]],
        "exact_fixture_oracles": fixture_oracles,
        "observer_independence": audit,
        "preservation_authority": False,
        "rows": rows,
    }
    if args.output:
        Path(args.output).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
