#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from collections import deque
from pathlib import Path


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def reachable(start: str, targets: set[str], adjacency: dict[str, set[str]]) -> bool:
    q = deque([start])
    seen = {start}
    while q:
        cur = q.popleft()
        if cur in targets:
            return True
        for nxt in adjacency.get(cur, set()):
            if nxt not in seen:
                seen.add(nxt)
                q.append(nxt)
    return False


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Preflight compiled Corpus provenance before invoking the frozen verifier"
    )
    ap.add_argument("adapter")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    adapter_path = Path(args.adapter).resolve()
    adapter = read_json(adapter_path)
    provenance = adapter.get("provenance") or {}
    nodes = {n.get("id") for n in provenance.get("nodes") or []}
    edges = provenance.get("edges") or []
    adjacency: dict[str, set[str]] = {}
    for edge in edges:
        src, dst = edge.get("from"), edge.get("to")
        if src not in nodes or dst not in nodes:
            raise SystemExit(f"provenance edge references missing node: {edge}")
        adjacency.setdefault(src, set()).add(dst)

    exact_roots = set((provenance.get("claim_roots") or {}).get("EXACT") or [])
    if not exact_roots or not exact_roots.issubset(nodes):
        raise SystemExit("EXACT claim root is missing from provenance graph")

    derivation = ((adapter.get("target") or {}).get("derivation") or {})
    facts = derivation.get("facts") or []
    failures = []
    checked = []
    for fact in facts:
        if fact.get("status") != "ESTABLISHED":
            continue
        fact_id = fact.get("id")
        node = fact.get("provenance_node")
        if node not in nodes:
            failures.append({"fact_id": fact_id, "reason": "PROVENANCE_NODE_MISSING", "node": node})
            continue
        ok = reachable(node, exact_roots, adjacency)
        checked.append({"fact_id": fact_id, "provenance_node": node, "upstream_of_exact": ok})
        if not ok:
            failures.append({"fact_id": fact_id, "reason": "NOT_UPSTREAM_OF_EXACT", "node": node})

    result = {
        "schema": "risu.corpus-provenance-preflight/v0.1alpha1",
        "status": "PASS" if not failures else "FAIL",
        "adapter": str(adapter_path),
        "exact_claim_roots": sorted(exact_roots),
        "established_fact_count": len(checked) + sum(1 for x in failures if x["reason"] == "PROVENANCE_NODE_MISSING"),
        "checked": checked,
        "failures": failures,
    }
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"Corpus provenance preflight: {result['status']}")
        for failure in failures:
            print(f"  ERROR {failure['fact_id']}: {failure['reason']} node={failure['node']}")
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
