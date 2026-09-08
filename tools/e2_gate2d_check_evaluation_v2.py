#!/usr/bin/env python3
from __future__ import annotations
import importlib.util
from pathlib import Path

LEGACY = Path(__file__).with_name("e2_gate2d_check_evaluation.py")
EXPECTED = {
    "B0_STRUCTURAL_SCHEMA_DIFF",
    "B1_AST_SYNTACTIC_DATAFLOW",
    "B2_STRONG_STATIC_DATAFLOW",
    "B3A_GPT56_SOL_COPILOT",
    "B3B_CLAUDE_OPUS5_COPILOT",
    "B4_EXECUTION_ONLY_DIFFERENTIAL",
}

def load():
    spec = importlib.util.spec_from_file_location("risu_gate2d_legacy_checker", LEGACY)
    if spec is None or spec.loader is None:
        raise RuntimeError("LEGACY_CHECKER_LOAD")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    if getattr(mod, "EXPECTED_BASELINES", None) != {
        "B0_STRUCTURAL_SCHEMA_DIFF","B1_AST_SYNTACTIC_DATAFLOW","B2_STRONG_STATIC_DATAFLOW",
        "B3A_GPT56_SOL_FRONTIER","B3B_CLAUDE_OPUS45_DATED","B4_EXECUTION_ONLY_DIFFERENTIAL"
    }:
        raise RuntimeError("LEGACY_BASELINE_SET_IDENTITY")
    mod.EXPECTED_BASELINES = set(EXPECTED)
    return mod

if __name__ == "__main__":
    load().main()
