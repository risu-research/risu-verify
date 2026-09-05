#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import platform
import sys
import time
from pathlib import Path

from risu_e0.machine_first import (
    MachineInputError,
    execution_observation,
    load_machine_packet,
    verify_output_dir,
    write_semantic_outputs,
)

ROOT = Path(__file__).resolve().parents[1]
QUALIFICATION = ROOT / "experiments" / "risu-diff-e0" / "MACHINE_FIRST_FREEZE_QUALIFICATION.json"


def engine_identity() -> dict:
    q = json.loads(QUALIFICATION.read_text(encoding="utf-8"))
    return {
        "freeze_id": q["freeze_id"],
        "freeze_protocol_id": q["freeze_protocol_id"],
        "foundation_qualification_id": q["foundation_qualification_id"],
        "engine_identity_digest": q["engine_identity_digest"],
        "identity_authority": q["file_identity"]["authority"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the frozen target-agnostic RISU Diff E0 machine-first core.")
    parser.add_argument("packet_dir", type=Path)
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("--no-observation", action="store_true", help="Do not emit the nonsemantic timing sidecar.")
    args = parser.parse_args()

    started = time.perf_counter()
    try:
        packet = load_machine_packet(args.packet_dir)
        write_semantic_outputs(args.packet_dir, args.output_dir, engine_identity())
        verified = verify_output_dir(args.output_dir)
    except (MachineInputError, ValueError, OSError, json.JSONDecodeError) as exc:
        print(json.dumps({
            "status": "E0_INFRASTRUCTURE_FAILURE",
            "consequence_authority": False,
            "error_type": type(exc).__name__,
            "error": str(exc),
        }, sort_keys=True), file=sys.stderr)
        return 20

    elapsed = time.perf_counter() - started
    if not args.no_observation:
        (args.output_dir / "E0_EXECUTION_OBSERVATION.json").write_bytes(
            execution_observation(
                run_id=packet["input"]["run_id"],
                elapsed_seconds=elapsed,
                host=f"{platform.system()}-{platform.machine()}",
            )
        )

    print(json.dumps({
        "status": "PASS",
        "run_id": packet["input"]["run_id"],
        "prediction_artifact": "E0_PREDICTION.json",
        "seal_digest": verified["seal_digest"],
        "observation_in_semantic_seal": False,
    }, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
