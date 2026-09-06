#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from risu_e2.acquisition import AcquisitionConfig, acquire
from risu_e2.ir import build_ir
from risu_e2.model import canonical_bytes

def main() -> int:
    p = argparse.ArgumentParser(description="RISU Diff E2 A1/A2 carrier-neutral acquisition + normalized semantic-flow IR.")
    p.add_argument("root", type=Path)
    p.add_argument("--entrypoint", action="append", default=[])
    p.add_argument("--operation", default="")
    p.add_argument("--surface-argument", action="append", default=[])
    p.add_argument("--max-files", type=int, default=64)
    p.add_argument("--max-rounds", type=int, default=4)
    p.add_argument("--max-file-bytes", type=int, default=512000)
    p.add_argument("--max-total-bytes", type=int, default=4000000)
    p.add_argument("--out", type=Path)
    args = p.parse_args()

    cfg = AcquisitionConfig(args.max_files, args.max_rounds, args.max_file_bytes, args.max_total_bytes)
    acq, rows = acquire(
        args.root,
        entrypoints=args.entrypoint,
        operation=args.operation,
        surface_arguments=args.surface_argument,
        config=cfg,
    )
    helper = ROOT / "tools" / "e2_go_ir_extract.go"
    ir, status = build_ir(rows, acquisition_doc=acq, go_helper_path=helper)
    doc = {"schema":"risu.e2-a1-a2-run/v0.1","status":status,"acquisition":acq,"ir":ir}
    data = canonical_bytes(doc)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_bytes(data)
    sys.stdout.buffer.write(data)
    return 0 if status["status"] == "PASS" else (20 if status["status"] == "INFRASTRUCTURE_INVALID_BEFORE_PREDICTION" else 10)

if __name__ == "__main__":
    raise SystemExit(main())
