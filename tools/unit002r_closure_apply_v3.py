#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

SRC = Path(__file__).with_name("unit002r_closure_apply_v2.py")
source = SRC.read_text(encoding="utf-8")
old_print = 'print(json.dumps({"status":"PASS","unit_id":"corpus01-unit-002","phase":phase,"primary_result":"PRESERVED_IN_DECLARED_SCOPE","coverage_complete":False,"primary_bytes_immutable":True,"changed_paths":sorted(changed)},indent=2,sort_keys=True))'
new_print = 'print(json.dumps({{"status":"PASS","unit_id":"corpus01-unit-002","phase":phase,"primary_result":"PRESERVED_IN_DECLARED_SCOPE","coverage_complete":False,"primary_bytes_immutable":True,"changed_paths":sorted(changed)}},indent=2,sort_keys=True))'
old_exc = 'except Exception as e: die(f"{type(e).__name__}: {e}")'
new_exc = 'except Exception as e: die(f"{{type(e).__name__}}: {{e}}")'
if source.count(old_print) != 1 or source.count(old_exc) != 1:
    raise SystemExit("closure-v3 patch anchors are not unique")
source = source.replace(old_print, new_print, 1).replace(old_exc, new_exc, 1)
namespace = {"__name__": "unit002r_closure_apply_v2_checked", "__file__": str(SRC)}
compiled = compile(source, str(SRC), "exec")
exec(compiled, namespace)
original = namespace["make_closure_verifier"]

def checked_make_closure_verifier() -> str:
    text = original()
    compile(text, "<generated-unit002r-closure-verifier>", "exec")
    return text

namespace["make_closure_verifier"] = checked_make_closure_verifier
raise SystemExit(namespace["main"]())
