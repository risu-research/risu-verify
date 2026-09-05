"""RISU Diff E0: untrusted machine-first consequence-translation front-end."""

from .graph import ConsequenceGraph, GraphInvariantError
from .engine import evaluate_vbe, find_collapse_witness, find_relational_witness, shrink_witness

__all__ = [
    "ConsequenceGraph",
    "GraphInvariantError",
    "evaluate_vbe",
    "find_collapse_witness",
    "find_relational_witness",
    "shrink_witness",
]
