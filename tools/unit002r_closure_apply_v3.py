#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

SRC = Path(__file__).with_name("unit002r_closure_apply_v2.py")
source = SRC.read_text(encoding="utf-8")
patches = [
    (
        'print(json.dumps({"status":"PASS","unit_id":"corpus01-unit-002","phase":phase,"primary_result":"PRESERVED_IN_DECLARED_SCOPE","coverage_complete":False,"primary_bytes_immutable":True,"changed_paths":sorted(changed)},indent=2,sort_keys=True))',
        'print(json.dumps({{"status":"PASS","unit_id":"corpus01-unit-002","phase":phase,"primary_result":"PRESERVED_IN_DECLARED_SCOPE","coverage_complete":False,"primary_bytes_immutable":True,"changed_paths":sorted(changed)}},indent=2,sort_keys=True))',
        "generated status dict braces",
    ),
    (
        'except Exception as e: die(f"{type(e).__name__}: {e}")',
        'except Exception as e: die(f"{{type(e).__name__}}: {{e}}")',
        "generated exception f-string braces",
    ),
    (
        'f"{{BASE}}^{{commit}}"',
        'BASE+"^{{commit}}"',
        "literal Git ^{commit} object suffix",
    ),
]
for old, new, label in patches:
    count = source.count(old)
    if count != 1:
        raise SystemExit(f"closure-v3 patch anchor {label!r} expected once, found {count}")
    source = source.replace(old, new, 1)

namespace = {"__name__": "unit002r_closure_apply_v2_checked", "__file__": str(SRC)}
compiled = compile(source, str(SRC), "exec")
exec(compiled, namespace)
original = namespace["make_closure_verifier"]

def checked_make_closure_verifier() -> str:
    text = original()
    # Gate both syntax and the exact literal Git object expression before scientific-tree write.
    compile(text, "<generated-unit002r-closure-verifier>", "exec")
    if 'BASE+"^{commit}"' not in text:
        raise RuntimeError("generated verifier lost literal Git ^{commit} object expression")
    return text

namespace["make_closure_verifier"] = checked_make_closure_verifier
raise SystemExit(namespace["main"]())
