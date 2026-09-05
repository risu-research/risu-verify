from __future__ import annotations

import ast
from typing import Any, Dict, List


VERSION_TOKENS = ("sha", "etag", "version", "revision", "generation", "resource_version", "resourceversion")


def extract_coordinate_candidates(source: str) -> Dict[str, Any]:
    """Syntactic candidate extractor. It deliberately never emits ESTABLISHED semantics."""
    tree = ast.parse(source)
    candidates: List[Dict[str, Any]] = []
    comparisons: List[Dict[str, Any]] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            lowered = node.id.lower()
            if any(tok in lowered for tok in VERSION_TOKENS):
                candidates.append({
                    "name": node.id,
                    "line": getattr(node, "lineno", None),
                    "status": "DECLARED",
                    "semantic_role": "UNRESOLVED",
                })
        elif isinstance(node, ast.Compare):
            names = [n.id for n in ast.walk(node) if isinstance(n, ast.Name)]
            if names:
                comparisons.append({
                    "names": sorted(set(names)),
                    "line": getattr(node, "lineno", None),
                    "status": "DECLARED",
                    "semantic_role": "UNRESOLVED",
                })

    unique = {(c["name"], c["line"]): c for c in candidates}
    return {
        "coordinate_candidates": [unique[k] for k in sorted(unique)],
        "comparison_candidates": sorted(comparisons, key=lambda x: (x["line"] or -1, x["names"])),
        "semantic_authority": False,
    }
