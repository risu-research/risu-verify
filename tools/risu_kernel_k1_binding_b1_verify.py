#!/usr/bin/env python3
"""Adversarial qualification harness for K1 B1 multi-world local binding."""

import argparse
import base64
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

WORLD_DOMAIN = b"RISU-K1-BINDING-B0-WORLD\0"
CONSEQUENCE_DOMAIN = b"RISU-K1-BINDING-B0-CONSEQUENCE\0"


def net_bytes(raw): return str(len(raw)).encode("ascii") + b":" + raw + b","
def net(text): return net_bytes(text.encode("utf-8"))
def vals(tag, xs):
    out = tag.encode("ascii") + net(str(len(xs)))
    for value in xs: out += b"V" + net(value)
    return out

def pairs(tag, xs):
    out = tag.encode("ascii") + net(str(len(xs)))
    for w, c in xs: out += b"P" + net(w) + net(c)
    return out

def digest(prefix, raw): return prefix + hashlib.sha256(raw).hexdigest()
def world_id(raw): return digest("w:sha256:", WORLD_DOMAIN + b"B" + net_bytes(raw))
def consequence_id(kind, subject, value):
    return digest("c:sha256:", CONSEQUENCE_DOMAIN + b"K" + net(kind) + b"S" + net(subject) + b"V" + net(value))
def claim_id(doc):
    pre = b"RISU-K1-CLAIM-W0\0" + b"S" + net(doc["semantics"])
    pre += vals("W", sorted(doc["worlds"])) + pairs("A", sorted((r[0], r[1]) for r in doc["allow"]))
    return digest("claim:sha256:", pre)


def run_binder(binder, claim, world, implementation, w3, w4, timeout="0.25"):
    with tempfile.TemporaryDirectory(prefix="risu-b1-harness-") as td:
        out = Path(td) / "report.json"
        proc = subprocess.run([
            sys.executable, binder, "--claim", str(claim), "--world", str(world),
            "--implementation", str(implementation), "--w3", str(w3), "--w4", str(w4),
            "--timeout-seconds", timeout, "--output", str(out)
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        report = json.loads(proc.stdout.decode("utf-8"))
        return proc.returncode, report


def write_report_verify(verifier, report, claim, world, implementation, w3, w4):
    with tempfile.TemporaryDirectory(prefix="risu-b1-report-harness-") as td:
        rp = Path(td) / "report.json"
        rp.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        proc = subprocess.run([
            sys.executable, verifier, "--report", str(rp), "--claim", str(claim), "--world", str(world),
            "--implementation", str(implementation), "--w3", str(w3), "--w4", str(w4)
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        obj = json.loads(proc.stdout.decode("utf-8"))
        return proc.returncode, obj


def classify_binder(rc, report):
    if rc == 1 and report.get("authority") == "REJECTED": return "REJECTED"
    if rc == 0 and report.get("authority") in {"NO_AUTHORITY", "BOUND_REGRESSION", "REJECT_BINDING_EVIDENCE"}:
        return report["authority"]
    return "UNEXPECTED"


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--binder", required=True); p.add_argument("--report-verifier", required=True)
    p.add_argument("--w3", required=True); p.add_argument("--w4", required=True)
    p.add_argument("--claim", required=True); p.add_argument("--world", required=True)
    p.add_argument("--bin-dir", required=True); p.add_argument("--output", required=True)
    args = p.parse_args()
    claim_path = Path(args.claim); world_path = Path(args.world); bin_dir = Path(args.bin_dir)
    claim = json.loads(claim_path.read_text(encoding="utf-8"))
    rows = []
    reports = {}

    def check(vector_id, expected, actual, detail=None):
        rows.append({"id": vector_id, "expected": expected, "actual": actual, "pass": actual == expected, "detail": detail})

    mapping = [
        ("B1-01", "good", "NO_AUTHORITY"),
        ("B1-02", "bad", "BOUND_REGRESSION"),
        ("B1-03", "stdout-lie", "NO_AUTHORITY"),
        ("B1-04", "nonzero-forbidden", "BOUND_REGRESSION"),
        ("B1-05", "timeout-after-forbidden", "BOUND_REGRESSION"),
        ("B1-06", "timeout-before-effect", "NO_AUTHORITY"),
        ("B1-07", "malformed", "NO_AUTHORITY"),
        ("B1-08", "multi", "BOUND_REGRESSION"),
    ]
    for vid, variant, expected in mapping:
        rc, report = run_binder(args.binder, claim_path, world_path, bin_dir / ("b1-" + variant), args.w3, args.w4)
        reports[variant] = report
        actual = classify_binder(rc, report)
        detail = {"status": report.get("observation_status"), "w3": report.get("w3_class"), "w4": report.get("w4_class"), "preservation": report.get("preservation_authority")}
        if expected == "BOUND_REGRESSION" and actual == expected:
            vrc, verified = write_report_verify(args.report_verifier, report, claim_path, world_path, bin_dir / ("b1-" + variant), args.w3, args.w4)
            detail["posthoc_verifier"] = verified.get("status")
            if vrc != 0 or verified.get("status") != "VERIFIED_BOUND_REGRESSION": actual = "POSTHOC_VERIFY_FAILURE"
        check(vid, expected, actual, detail)

    # B1-09: add seven unrelated worlds without supplying observations for them.
    expanded = json.loads(json.dumps(claim))
    for i in range(7):
        raw = f"b1-unobserved-{i}\n".encode("ascii")
        wid = world_id(raw); cid = consequence_id("noop", f"u{i}", "ok")
        expanded["worlds"].append(wid); expanded["allow"].append([wid, cid])
    expanded["claim_id"] = claim_id(expanded)
    with tempfile.TemporaryDirectory(prefix="risu-b1-expanded-") as td:
        cp = Path(td) / "claim.json"; cp.write_text(json.dumps(expanded, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        rc, report = run_binder(args.binder, cp, world_path, bin_dir / "b1-bad", args.w3, args.w4)
        check("B1-09", "BOUND_REGRESSION", classify_binder(rc, report), {"claim_world_count": len(expanded["worlds"])})

    # B1-10: semantic representation reordering must not change claim identity/authority.
    reordered = json.loads(json.dumps(claim)); reordered["worlds"] = list(reversed(reordered["worlds"])); reordered["allow"] = list(reversed(reordered["allow"]))
    assert claim_id(reordered) == claim["claim_id"]
    with tempfile.TemporaryDirectory(prefix="risu-b1-reorder-") as td:
        cp = Path(td) / "claim.json"; cp.write_text(json.dumps(reordered, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        rc, report = run_binder(args.binder, cp, world_path, bin_dir / "b1-bad", args.w3, args.w4)
        check("B1-10", "BOUND_REGRESSION", classify_binder(rc, report))

    # B1-11: selected world is not admitted.
    with tempfile.TemporaryDirectory(prefix="risu-b1-world-") as td:
        wp = Path(td) / "other.world"; wp.write_bytes(b"request=transfer\nsubject=mallory\nvalue=999\n")
        rc, report = run_binder(args.binder, claim_path, wp, bin_dir / "b1-bad", args.w3, args.w4)
        check("B1-11", "REJECTED", classify_binder(rc, report), report.get("reason"))

    bound = reports["bad"]
    # B1-12: verify exact report against substituted executable.
    rc, obj = write_report_verify(args.report_verifier, bound, claim_path, world_path, bin_dir / "b1-good", args.w3, args.w4)
    check("B1-12", "REJECT_BINDING_EVIDENCE", obj.get("status") if rc else "UNEXPECTED_ACCEPT", obj.get("reason"))

    # B1-13: verify exact report against substituted world bytes.
    with tempfile.TemporaryDirectory(prefix="risu-b1-subworld-") as td:
        wp = Path(td) / "other.world"; wp.write_bytes(b"request=transfer\nsubject=mallory\nvalue=999\n")
        rc, obj = write_report_verify(args.report_verifier, bound, claim_path, wp, bin_dir / "b1-bad", args.w3, args.w4)
        check("B1-13", "REJECT_BINDING_EVIDENCE", obj.get("status") if rc else "UNEXPECTED_ACCEPT", obj.get("reason"))

    # B1-14: mutate saved effect/artifact evidence.
    tampered = json.loads(json.dumps(bound))
    tampered["effect_log_b64"] = base64.b64encode(b"E1|kind=transfer|subject=alice|value=100\n").decode("ascii")
    rc, obj = write_report_verify(args.report_verifier, tampered, claim_path, world_path, bin_dir / "b1-bad", args.w3, args.w4)
    check("B1-14", "REJECT_BINDING_EVIDENCE", obj.get("status") if rc else "UNEXPECTED_ACCEPT", obj.get("reason"))

    # B1-15: a clean run has no preservation-producing interface or object.
    clean = reports["good"]
    impossible = clean.get("authority") == "NO_AUTHORITY" and clean.get("preservation_authority") is False and clean.get("p1_witness") is None and clean.get("proof_artifact_id") is None
    check("B1-15", "IMPOSSIBLE_BY_INTERFACE", "IMPOSSIBLE_BY_INTERFACE" if impossible else "INTERFACE_LEAK")

    # B1-16: checker disagreement/rejection is fail-closed even after a real forbidden effect.
    rc, report = run_binder(args.binder, claim_path, world_path, bin_dir / "b1-bad", args.w3, "/bin/false")
    check("B1-16", "REJECT_BINDING_EVIDENCE", classify_binder(rc, report), {"w3": report.get("w3_class"), "w4": report.get("w4_class")})

    failed = [r["id"] for r in rows if not r["pass"]]
    result = {
        "gate": "RISU_KERNEL_K1_BINDING_B1",
        "status": "PASS" if not failed else "FAIL",
        "vector_count": len(rows), "passed": sum(r["pass"] for r in rows), "failed": failed,
        "preservation_authority": False,
        "binding_scope": "CONTROLLED_LOCAL_EXECUTION_REGRESSION_ONLY",
        "rows": rows,
    }
    Path(args.output).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1

if __name__ == "__main__": raise SystemExit(main())
