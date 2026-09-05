from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict

ROOT = Path(__file__).resolve().parents[1]
CAL = ROOT / "profiles" / "version-bound-effect" / "calibration"
CHECKER = ROOT / "tools" / "risu_e0_witness_check.py"


def load(name: str) -> Dict[str, Any]:
    return json.loads((CAL / name).read_text(encoding="utf-8"))


def run_checker(witness: Dict[str, Any]) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "witness.json"
        path.write_text(json.dumps(witness, sort_keys=True), encoding="utf-8")
        return subprocess.run(
            [sys.executable, str(CHECKER), str(path)],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
