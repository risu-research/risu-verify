from __future__ import annotations

import base64
import json
from pathlib import Path
import subprocess
from typing import Any, Dict, Sequence

from .model import canonical_bytes

def extract_many(rows: Sequence[dict[str, Any]], helper_path: Path) -> Dict[str, Dict[str, Any]]:
    if not rows:
        return {}
    payload = {
        "files": [
            {"path": r["path"], "source_b64": base64.b64encode(r["data"]).decode("ascii")}
            for r in sorted(rows, key=lambda x: x["path"])
        ]
    }
    proc = subprocess.run(
        ["go", "run", str(helper_path)],
        input=canonical_bytes(payload),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", errors="replace")[:4000]
        return {
            r["path"]: {
                "status": "MATERIAL_PARSE_FAILURE",
                "parser": "go/parser+go/ast",
                "error": f"GO_FRONTEND_FAILURE:{err}",
                "facts": [],
            }
            for r in rows
        }
    try:
        data = json.loads(proc.stdout.decode("utf-8"))
    except Exception as exc:
        return {
            r["path"]: {
                "status": "MATERIAL_PARSE_FAILURE",
                "parser": "go/parser+go/ast",
                "error": f"GO_FRONTEND_BAD_JSON:{type(exc).__name__}:{exc}",
                "facts": [],
            }
            for r in rows
        }
    out = {}
    for f in data.get("files", []):
        out[f["path"]] = {
            "status": f.get("status", "MATERIAL_PARSE_FAILURE"),
            "parser": f.get("parser", "go/parser+go/ast"),
            "error": f.get("error"),
            "facts": f.get("facts", []),
        }
    for r in rows:
        out.setdefault(r["path"], {
            "status":"MATERIAL_PARSE_FAILURE","parser":"go/parser+go/ast",
            "error":"GO_FRONTEND_RESULT_MISSING","facts":[]
        })
    return out
