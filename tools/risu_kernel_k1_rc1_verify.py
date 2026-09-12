#!/usr/bin/env python3
"""Composite verifier for the scoped K1 RC1 freeze.

The verifier is intentionally boring: exact Git blob pins first, then rerun the
entire local qualification chain.  It does not fetch the network and it cannot
turn a proof-kind gap into a semantic-kernel success.
"""

import argparse
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
DEFAULT_FREEZE = ROOT / "protocols" / "RISU_KERNEL_K1_RC1_FREEZE.json"


class FreezeFailure(Exception):
    pass


def load(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def git_blob(path):
    try:
        out = subprocess.check_output(
            ["git", "hash-object", str(path)], cwd=ROOT, text=True, stderr=subprocess.STDOUT
        )
    except subprocess.CalledProcessError as exc:
        raise FreezeFailure(f"git hash-object failed for {path}: {exc.output}") from exc
    return out.strip()


def verify_pins(freeze):
    pins = dict(freeze["frozen_dependency_git_blobs"])
    pins[freeze["constitution"]["path"]] = freeze["constitution"]["git_blob_sha1"]
    checked = []
    for rel, expected in sorted(pins.items()):
        path = ROOT / rel
        if not path.is_file():
            raise FreezeFailure(f"missing pinned dependency: {rel}")
        actual = git_blob(path)
        if actual != expected:
            raise FreezeFailure(f"pinned dependency drift: {rel}: expected {expected}, got {actual}")
        checked.append({"path": rel, "git_blob_sha1": actual})
    return checked


def verify_constitution(freeze):
    constitution = load(ROOT / freeze["constitution"]["path"])
    if constitution.get("constitution_id") != "RISU_KERNEL_K1_RC1":
        raise FreezeFailure("unexpected RC constitution identity")
    if constitution.get("status") != "RELEASE_CANDIDATE_NOT_FINAL":
        raise FreezeFailure("RC constitution status drift")
    if set(constitution.get("semantic_objects", {})) != {"W", "U", "ALLOW", "REALIZE"}:
        raise FreezeFailure("RC semantic object set drift")
    rules = constitution.get("verdict_rules", {})
    if set(rules) != {"REGRESSION", "PRESERVATION", "UNKNOWN"}:
        raise FreezeFailure("RC verdict rule set drift")
    gap_ids = {x["id"] for x in constitution.get("known_non_kernel_gaps", [])}
    if gap_ids != set(freeze["known_proof_gaps"]):
        raise FreezeFailure("known proof-gap set drift")
    if "temporal logic" not in constitution.get("not_kernel_primitives", []):
        raise FreezeFailure("temporal logic unexpectedly promoted into RC1 kernel")
    return {
        "constitution_id": constitution["constitution_id"],
        "semantic_scope": constitution["semantic_scope"],
        "known_non_kernel_gaps": sorted(gap_ids),
    }


def run_command(argv):
    cmd = list(argv)
    if cmd and cmd[0] in {"python", "python3"}:
        cmd[0] = sys.executable
    proc = subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True)
    if proc.returncode != 0:
        raise FreezeFailure(
            "qualification command failed: " + " ".join(argv) + "\nSTDOUT:\n" + proc.stdout + "\nSTDERR:\n" + proc.stderr
        )
    return proc.stdout


def verify_qualification(freeze):
    runs = []
    a1 = None
    for argv in freeze["qualification_commands"]:
        stdout = run_command(argv)
        row = {"command": argv, "status": "PASS"}
        if argv[-1].endswith("risu_kernel_k1_adversarial_gate_a1.py"):
            try:
                a1 = json.loads(stdout)
            except Exception as exc:
                raise FreezeFailure("A1 output is not a single JSON object") from exc
            row["a1_kernel_verdict"] = a1.get("kernel_verdict")
        runs.append(row)

    if a1 is None:
        raise FreezeFailure("A1 qualification command missing")
    required = freeze["required_a1_summary"]
    for key, expected in required.items():
        if a1.get(key) != expected:
            raise FreezeFailure(f"A1 freeze summary mismatch for {key}: expected {expected!r}, got {a1.get(key)!r}")
    if a1.get("status") != "PASS":
        raise FreezeFailure("A1 did not PASS during RC qualification")
    return runs, {key: a1[key] for key in required}


def run(freeze):
    if freeze.get("freeze_id") != "RISU_KERNEL_K1_RC1_FREEZE":
        raise FreezeFailure("unexpected freeze manifest identity")
    pins = verify_pins(freeze)
    constitution = verify_constitution(freeze)
    commands, a1_summary = verify_qualification(freeze)
    return {
        "status": "PASS",
        "freeze_id": freeze["freeze_id"],
        "rc_status": "QUALIFIED_FOR_BRANCH_FREEZE",
        "semantic_scope": constitution["semantic_scope"],
        "pinned_blob_count": len(pins),
        "qualification_command_count": len(commands),
        "qualification_commands": commands,
        "a1_summary": a1_summary,
        "known_non_kernel_gaps": constitution["known_non_kernel_gaps"],
        "interpretation": "Exact pinned dependencies and the full local K1 qualification chain agree with the scoped RC1 constitution. This is not a universal completeness claim."
    }


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--freeze", default=str(DEFAULT_FREEZE))
    parser.add_argument("--output")
    args = parser.parse_args(argv)
    try:
        result = run(load(args.freeze))
    except FreezeFailure as exc:
        print(json.dumps({"status": "FAIL", "reason": str(exc)}, indent=2, sort_keys=True))
        return 1
    text = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        pathlib.Path(args.output).write_text(text, encoding="utf-8")
    print(text, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
