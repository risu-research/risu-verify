#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from e2_mutation_verifier_engine import verify


def main() -> int:
    ap = argparse.ArgumentParser(description="Independently verify deterministic E2 synthetic mutant materialization.")
    ap.add_argument("--repo-root", type=Path, default=Path("."))
    ap.add_argument("--corpus", type=Path)
    ap.add_argument("--replay-materializer", action="store_true")
    ap.add_argument("--runtime-timeout", type=int, default=30)
    ap.add_argument("--receipt", type=Path)
    return verify(ap.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
