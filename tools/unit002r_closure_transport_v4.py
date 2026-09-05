#!/usr/bin/env python3
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = Path(os.environ["SCIENTIFIC_REPO"]).resolve()
BASE = "b52bde0d0fdef0a2be7d5973e564daccd12296c9"
CANDIDATE = "unit002-r-premerge-closure-candidate"
FULL = {
    ".github/workflows/unit002-r-preprimary-seal.yml",
    ".github/workflows/unit002-r-target-qualification.yml",
    ".github/workflows/unit002-r-closure.yml",
    "corpus/0.1/ENROLLMENT.json",
    "corpus/0.1/units/002-octokit-pulls-merge/friction.json",
    "corpus/0.1/units/002-octokit-pulls-merge/post-result/COVERAGE_DIAGNOSTIC.json",
    "corpus/0.1/units/002-octokit-pulls-merge/PREMERGE_CLOSURE.json",
    "tools/unit002r_closure_verify.py",
}
WORKFLOWS = {
    ".github/workflows/unit002-r-preprimary-seal.yml",
    ".github/workflows/unit002-r-target-qualification.yml",
    ".github/workflows/unit002-r-closure.yml",
}
NON_WORKFLOW = FULL - WORKFLOWS


def run(cmd: list[str], cwd: Path = ROOT, check: bool = True) -> subprocess.CompletedProcess:
    p = subprocess.run(cmd, cwd=cwd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if check and p.returncode:
        raise RuntimeError(f"command failed: {cmd}\nstdout={p.stdout}\nstderr={p.stderr}")
    return p


def git(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return run(["git", *args], check=check)


def names(base: str = BASE) -> set[str]:
    return {x for x in git("diff", "--name-only", f"{base}..HEAD").stdout.splitlines() if x}


def main() -> int:
    if git("rev-parse", "HEAD").stdout.strip() != BASE:
        raise RuntimeError("scientific checkout did not start at result-freeze base")
    if git("status", "--porcelain").stdout.strip():
        raise RuntimeError("scientific checkout not pristine before v3")

    # v3 is required to validate the complete eight-path candidate twice and form its local commit.
    p = run([sys.executable, str(HERE / "unit002r_closure_apply_v3.py")], cwd=HERE.parents[1], check=False)
    combined = (p.stdout or "") + "\n" + (p.stderr or "")
    if p.returncode == 0:
        raise RuntimeError("v3 unexpectedly pushed scientific branch; transport fallback must not run")
    required = "refusing to allow a GitHub App to create or update workflow `.github/workflows/unit002-r-closure.yml` without `workflows` permission"
    if required not in combined:
        raise RuntimeError("v3 failed for a reason other than the expected workflow-permission transport stop:\n" + combined)

    validated_head = git("rev-parse", "HEAD").stdout.strip()
    if validated_head == BASE:
        raise RuntimeError("v3 did not form a validated local closure commit")
    if names() != FULL:
        raise RuntimeError(f"validated v3 local surface mismatch: {sorted(names())}")
    # Primary archive must still be untouched in the fully validated local commit.
    primary_rel = "corpus/0.1/units/002-octokit-pulls-merge/primary-result"
    if git("diff", "--quiet", BASE, "--", primary_rel, check=False).returncode != 0:
        raise RuntimeError("validated local closure commit changed primary-result")

    # Re-materialize only the five non-workflow bytes as a transport commit.
    git("reset", BASE)
    for rel in sorted(WORKFLOWS):
        path = ROOT / rel
        if git("cat-file", "-e", f"{BASE}:{rel}", check=False).returncode == 0:
            git("restore", "--source", BASE, "--worktree", "--", rel)
        elif path.exists():
            path.unlink()
    actual_working = {x for x in git("status", "--porcelain").stdout.splitlines() if x}
    # Use path-aware git output for exact comparison rather than porcelain prefixes.
    working_names = set(git("diff", "--name-only", "--").stdout.splitlines()) | set(git("ls-files", "--others", "--exclude-standard").stdout.splitlines())
    working_names.discard("")
    if working_names != NON_WORKFLOW:
        raise RuntimeError(f"five-path transport surface mismatch: expected={sorted(NON_WORKFLOW)} actual={sorted(working_names)}")
    git("add", "--", *sorted(NON_WORKFLOW))
    staged = set(git("diff", "--cached", "--name-only").stdout.splitlines())
    if staged != NON_WORKFLOW:
        raise RuntimeError(f"staged transport surface mismatch: {sorted(staged)}")
    git("config", "user.name", "RISU Protocol Bot")
    git("config", "user.email", "protocol-bot@users.noreply.github.com")
    git("commit", "-m", "Stage Unit 002-R non-workflow closure bytes for verified transport")
    transport_head = git("rev-parse", "HEAD").stdout.strip()
    if names() != NON_WORKFLOW:
        raise RuntimeError("transport commit contains paths outside five non-workflow closure bytes")
    if git("status", "--porcelain").stdout.strip():
        raise RuntimeError("transport commit left a dirty tree")
    remote = git("ls-remote", "origin", f"refs/heads/{CANDIDATE}").stdout.strip()
    if remote:
        raise RuntimeError(f"candidate branch already exists unexpectedly: {remote}")
    git("push", "origin", f"HEAD:refs/heads/{CANDIDATE}")
    print(f"VALIDATED_FULL_LOCAL_HEAD={validated_head}")
    print(f"TRANSPORT_HEAD={transport_head}")
    print("NON_WORKFLOW_PATHS=" + ",".join(sorted(NON_WORKFLOW)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
