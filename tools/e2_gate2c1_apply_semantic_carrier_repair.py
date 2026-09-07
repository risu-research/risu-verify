#!/usr/bin/env python3
from __future__ import annotations

import hashlib
from pathlib import Path

EXPECTED_OLD_GIT_BLOBS = {
    "risu_e2/observability_overlay.py": "77be5ea1dad30aa6daa889e0753ce7d1aaa6f07a",
    "risu_e2_semantic/adapter_support.py": "5558d4bc91a0e51c4f836b4ae6db69bcf6abafe7",
    "risu_e2_semantic/primary_adapter.py": "c1b5d5e666bdd1b8f9bb1e041f76368f7f7a741c",
}


def git_blob(raw: bytes) -> str:
    header = f"blob {len(raw)}\0".encode()
    return hashlib.sha1(header + raw).hexdigest()


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected exactly one old snippet, found {count}")
    return text.replace(old, new, 1)


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    for rel, expected in EXPECTED_OLD_GIT_BLOBS.items():
        raw = (root / rel).read_bytes()
        actual = git_blob(raw)
        if actual != expected:
            raise RuntimeError(f"pre-repair blob mismatch:{rel}:{actual}:{expected}")

    overlay_path = root / "risu_e2/observability_overlay.py"
    overlay = overlay_path.read_text(encoding="utf-8")
    overlay = replace_once(
        overlay,
        'OVERLAY_SCHEMA = "risu.e2-observability-overlay/v0.1"\n\ndef build_overlay',
        'OVERLAY_SCHEMA = "risu.e2-observability-overlay/v0.1"\n\n\ndef _unique_anchor_scope(controls: Mapping[str,Mapping[str,Any]], span: Tuple[int,int,int,int]) -> str | None:\n    """Return structured-control scope authority only when exactly one scope contains the anchor."""\n    matches=sorted(str(name) for name,row in controls.items() if _contains(tuple(row["span"]),span))\n    return matches[0] if len(matches)==1 else None\n\ndef build_overlay',
        "overlay unique-scope helper",
    )
    overlay = replace_once(
        overlay,
        '            n=g.node(kind,f"anchor:{aname}:{role}",sp,anchor_name=aname,anchor_role=role,anchor_contract_sha256=anchor_contract_sha256,syntax_kind=a["syntax_kind"])\n            g.evidenced(n,sp,"frozen_consequence_anchor",**evattrs)',
        '            node_attrs={"anchor_name":aname,"anchor_role":role,"anchor_contract_sha256":anchor_contract_sha256,"syntax_kind":a["syntax_kind"]}\n            if role=="GUARD_COMPARISON":\n                scope=_unique_anchor_scope(controls,sp)\n                if scope is not None:\n                    node_attrs["scope"]=scope\n            n=g.node(kind,f"anchor:{aname}:{role}",sp,**node_attrs)\n            g.evidenced(n,sp,"frozen_consequence_anchor",**evattrs)',
        "overlay guard anchor carrier completion",
    )
    overlay_path.write_text(overlay, encoding="utf-8")

    support_path = root / "risu_e2_semantic/adapter_support.py"
    support = support_path.read_text(encoding="utf-8")
    old_guard = '''def _guard_operator(overlay: Mapping[str,Any], transported_guard_id: str) -> str | None:\n    rows=[]\n    for e in overlay.get("edges",[]) or []:\n        if e.get("kind")!="COMPARES" or str(e.get("target"))!=transported_guard_id:\n            continue\n        ops=e.get("attrs",{}).get("operators",[]) or []\n        if len(ops)!=1:\n            return None\n        op=_normalize_compare_operator(str(ops[0]))\n        if op is None:\n            return None\n        rows.append(op)\n    return rows[0] if rows and len(set(rows))==1 else None\n'''
    new_guard = '''def _guard_operator(overlay: Mapping[str,Any], transported_guard_id: str, expected_operand_indices: Sequence[int]) -> str | None:\n    """Resolve comparator authority only from canonical comparison-operand roles.\n\n    Negative or otherwise non-canonical operand indices remain valid graph evidence but\n    are non-authoritative for EQ/NE semantics. Missing canonical operands, malformed\n    authoritative rows, unsupported tokens, or disagreement all fail closed.\n    """\n    expected={int(x) for x in expected_operand_indices}\n    if not expected:\n        return None\n    rows=[]; seen=set()\n    for e in overlay.get("edges",[]) or []:\n        if e.get("kind")!="COMPARES" or str(e.get("target"))!=transported_guard_id:\n            continue\n        attrs=e.get("attrs",{}) or []; idx=attrs.get("operand_index") if isinstance(attrs,Mapping) else None\n        if type(idx) is not int or idx not in expected:\n            continue\n        seen.add(idx)\n        ops=attrs.get("operators",[]) or []\n        if not isinstance(ops,list) or len(ops)!=1:\n            return None\n        op=_normalize_compare_operator(str(ops[0]))\n        if op is None:\n            return None\n        rows.append(op)\n    if seen != expected:\n        return None\n    return rows[0] if rows and len(set(rows))==1 else None\n'''
    support = replace_once(support, old_guard, new_guard, "adapter operator authority narrowing")
    support_path.write_text(support, encoding="utf-8")

    primary_path = root / "risu_e2_semantic/primary_adapter.py"
    primary = primary_path.read_text(encoding="utf-8")
    primary = replace_once(
        primary,
        '    source_roles=canonical_profile.get("source_roles",{}) or {}\n    guard_operator=_guard_operator(overlay,anchors.get("GUARD_COMPARISON",""))\n    if guard_operator is None: unresolved.append("GUARD_OPERATOR_UNRESOLVED")',
        '    source_roles=canonical_profile.get("source_roles",{}) or {}\n    expected_guard_operand_indices=sorted({int(spec["operand_index"]) for spec in exec_sig["required_bindings"] if spec.get("kind")=="guard_operand"})\n    guard_operator=_guard_operator(overlay,anchors.get("GUARD_COMPARISON",""),expected_guard_operand_indices)\n    if guard_operator is None: unresolved.append("GUARD_OPERATOR_UNRESOLVED")',
        "primary adapter canonical operand authority",
    )
    primary_path.write_text(primary, encoding="utf-8")

    print("GATE2C1_REPAIR_APPLIED=PASS")
    for rel in EXPECTED_OLD_GIT_BLOBS:
        print(f"POST_BLOB {rel} {git_blob((root/rel).read_bytes())}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
