#!/usr/bin/env python3
"""Differentially qualify B1 Python runner against independent Go D2 observer."""

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

VARIANTS = ["good", "bad", "stdout-lie", "nonzero-forbidden", "timeout-after-forbidden", "timeout-before-effect", "malformed", "multi"]


def run_json(cmd):
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    try:
        obj = json.loads(proc.stdout.decode("utf-8"))
    except Exception:
        obj = {"_decode_error": proc.stderr.decode("utf-8", errors="replace")}
    return proc.returncode, obj


def binder_normalized(report):
    status = report.get("observation_status")
    observed = report.get("observed_consequences") or []
    pair = report.get("selected_forbidden_pair")
    return {
        "observation_status": status,
        "observed_consequences": observed,
        "first_forbidden_pair": pair,
        "world_id": report.get("world_id"),
        "implementation_id": report.get("implementation_id"),
        "effect_log_sha256": report.get("effect_log_sha256"),
        "stdout_sha256": report.get("stdout_sha256"),
        "stderr_sha256": report.get("stderr_sha256"),
        "timed_out": report.get("timed_out"),
        "authority_candidate": "FORBIDDEN_OBSERVED" if pair is not None and report.get("authority") in {"BOUND_REGRESSION", "REJECT_BINDING_EVIDENCE"} else "NO_AUTHORITY",
    }


def observer_normalized(obj):
    return {
        "observation_status": obj.get("observation_status"),
        "observed_consequences": obj.get("observed_consequences") or [],
        "first_forbidden_pair": obj.get("first_forbidden_pair"),
        "world_id": obj.get("world_id"),
        "implementation_id": obj.get("implementation_id"),
        "effect_log_sha256": obj.get("effect_log_sha256"),
        "stdout_sha256": obj.get("stdout_sha256"),
        "stderr_sha256": obj.get("stderr_sha256"),
        "timed_out": obj.get("timed_out"),
        "authority_candidate": obj.get("authority_candidate"),
    }


def observer_independence(path):
    source = Path(path).read_text(encoding="utf-8")
    imports_match = re.search(r'import \((.*?)\n\)', source, flags=re.S)
    imports = []
    if imports_match:
        imports = sorted(re.findall(r'"([^"]+)"', imports_match.group(1)))
    forbidden_refs = [needle for needle in ("k1_checker_w3", "k1_checker_w4", "risu_kernel_k1_binding_b1.py") if needle in source]
    nonstdlib_prefixes = [x for x in imports if "." in x.split("/")[0]]
    return {"imports": imports, "forbidden_references": forbidden_refs, "nonstdlib_imports": nonstdlib_prefixes, "pass": not forbidden_refs and not nonstdlib_prefixes}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--binder", required=True); p.add_argument("--observer", required=True); p.add_argument("--observer-source", required=True)
    p.add_argument("--w3", required=True); p.add_argument("--w4", required=True)
    p.add_argument("--claim", required=True); p.add_argument("--world", required=True); p.add_argument("--bin-dir", required=True); p.add_argument("--output", required=True)
    args = p.parse_args()
    rows = []
    for variant in VARIANTS:
        binary = Path(args.bin_dir) / ("b1-" + variant)
        with tempfile.TemporaryDirectory(prefix="risu-b1-d2-binder-") as td:
            report_path = Path(td) / "report.json"
            brc, binder = run_json([
                sys.executable, args.binder, "--claim", args.claim, "--world", args.world, "--implementation", str(binary),
                "--w3", args.w3, "--w4", args.w4, "--timeout-seconds", "0.25", "--output", str(report_path)
            ])
        orc, observer = run_json([
            args.observer, "--claim", args.claim, "--world", args.world, "--implementation", str(binary), "--timeout-ms", "250"
        ])
        bn = binder_normalized(binder); on = observer_normalized(observer)
        ok = brc == 0 and orc == 0 and bn == on
        rows.append({"variant": variant, "pass": ok, "binder": bn, "observer": on, "binder_rc": brc, "observer_rc": orc})
    indep = observer_independence(args.observer_source)
    failed = [r["variant"] for r in rows if not r["pass"]]
    result = {
        "gate": "RISU_KERNEL_K1_BINDING_B1_D2",
        "status": "PASS" if not failed and indep["pass"] else "FAIL",
        "runtime_vector_count": len(rows), "passed": sum(r["pass"] for r in rows), "failed": failed,
        "observer_independence": indep, "preservation_authority": False, "rows": rows,
    }
    Path(args.output).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1

if __name__ == "__main__": raise SystemExit(main())
