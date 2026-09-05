#!/usr/bin/env python3
"""Independent stdlib-only checker. Intentionally imports no risu_e0 module."""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict


def world_key(world: Dict[str, Any]) -> str:
    return repr(tuple(sorted(world.items())))


def check(w: Dict[str, Any]) -> bool:
    kind = w.get("witness_kind")
    model = w.get("model", {})
    if kind == "DETERMINISTIC_COLLAPSE":
        wa, wb = w.get("world_a"), w.get("world_b")
        if not isinstance(wa, dict) or not isinstance(wb, dict) or wa == wb:
            return False
        sm = model.get("source_consequence_by_world", {})
        tm = model.get("target_observation_by_world", {})
        ka, kb = world_key(wa), world_key(wb)
        if ka not in sm or kb not in sm or ka not in tm or kb not in tm:
            return False
        if w.get("source_a") != sm[ka] or w.get("source_b") != sm[kb]:
            return False
        if w.get("target_a") != tm[ka] or w.get("target_b") != tm[kb]:
            return False
        return sm[ka] != sm[kb] and tm[ka] == tm[kb]

    if kind == "RELATIONAL_EXTRA_CONSEQUENCE":
        world = w.get("world")
        if not isinstance(world, dict):
            return False
        sm = model.get("source_allowed_by_world", {})
        tm = model.get("target_consequences_by_world", {})
        key = world_key(world)
        if key not in sm or key not in tm:
            return False
        allowed = sorted(sm[key])
        observed = sorted(tm[key])
        extras = sorted(set(observed) - set(allowed))
        return (
            w.get("source_allowed") == allowed
            and w.get("observed_target") == observed
            and w.get("extra_consequences") == extras
            and bool(extras)
        )
    return False


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("witness")
    args = p.parse_args()
    with open(args.witness, "r", encoding="utf-8") as f:
        witness = json.load(f)
    ok = check(witness)
    print(json.dumps({"status": "PASS" if ok else "REJECT", "witness_kind": witness.get("witness_kind")}, sort_keys=True))
    return 0 if ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
