from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass
from typing import Any, Dict, List


MATERIAL_NODE_KINDS = {
    "SEMANTIC_COORDINATE",
    "GUARD",
    "EFFECT",
    "OUTCOME",
    "FAILURE",
    "INTERPRETER",
}
MATERIAL_EDGE_KINDS = {
    "BINDS_TO",
    "COMPARES",
    "GUARDS",
    "REJECTS_AS",
    "INTERPRETS_AS",
}
ALLOWED_STATUSES = {"ESTABLISHED", "UNRESOLVED", "DECLARED"}


class GraphInvariantError(ValueError):
    pass


def _normalize(value: Any) -> Any:
    if isinstance(value, dict):
        out = {k: _normalize(v) for k, v in sorted(value.items())}
        if "evidence_refs" in out and isinstance(out["evidence_refs"], list):
            out["evidence_refs"] = sorted(out["evidence_refs"])
        return out
    if isinstance(value, list):
        return [_normalize(v) for v in value]
    return value


def _evidence_refs(item: Dict[str, Any]) -> List[str]:
    refs = item.get("evidence_refs")
    if refs is None:
        refs = item.get("attributes", {}).get("evidence_refs", [])
    return list(refs or [])


@dataclass(frozen=True)
class ConsequenceGraph:
    ir_id: str
    evidence_boundary: str
    nodes: List[Dict[str, Any]]
    edges: List[Dict[str, Any]]
    cir_schema: str = "risu.consequence-ir/v0.1alpha1"
    cir_version: str = "0.1"

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "ConsequenceGraph":
        graph = ConsequenceGraph(
            ir_id=data["ir_id"],
            evidence_boundary=data["evidence_boundary"],
            nodes=copy.deepcopy(data.get("nodes", [])),
            edges=copy.deepcopy(data.get("edges", [])),
            cir_schema=data.get("cir_schema", "risu.consequence-ir/v0.1alpha1"),
            cir_version=data.get("cir_version", "0.1"),
        )
        graph.validate()
        return graph

    def validate(self) -> None:
        node_ids = [n.get("id") for n in self.nodes]
        edge_ids = [e.get("id") for e in self.edges]
        if None in node_ids or len(set(node_ids)) != len(node_ids):
            raise GraphInvariantError("node ids must be present and unique")
        if None in edge_ids or len(set(edge_ids)) != len(edge_ids):
            raise GraphInvariantError("edge ids must be present and unique")

        known = set(node_ids)
        for node in self.nodes:
            status = node.get("status")
            if status not in ALLOWED_STATUSES:
                raise GraphInvariantError(f"invalid node status: {status}")
            if (
                status == "ESTABLISHED"
                and node.get("kind") in MATERIAL_NODE_KINDS
                and not _evidence_refs(node)
            ):
                raise GraphInvariantError(
                    f"evidence-less ESTABLISHED material node: {node['id']}"
                )

        for edge in self.edges:
            status = edge.get("status")
            if status not in ALLOWED_STATUSES:
                raise GraphInvariantError(f"invalid edge status: {status}")
            if edge.get("from") not in known or edge.get("to") not in known:
                raise GraphInvariantError(f"dangling edge: {edge['id']}")
            if (
                status == "ESTABLISHED"
                and edge.get("kind") in MATERIAL_EDGE_KINDS
                and not _evidence_refs(edge)
            ):
                raise GraphInvariantError(
                    f"evidence-less ESTABLISHED material edge: {edge['id']}"
                )

    def canonical_dict(self) -> Dict[str, Any]:
        self.validate()
        nodes = sorted((_normalize(n) for n in self.nodes), key=lambda n: n["id"])
        edges = sorted((_normalize(e) for e in self.edges), key=lambda e: e["id"])
        return {
            "cir_schema": self.cir_schema,
            "cir_version": self.cir_version,
            "ir_id": self.ir_id,
            "nodes": nodes,
            "edges": edges,
            "evidence_boundary": self.evidence_boundary,
        }

    def digest(self) -> str:
        encoded = json.dumps(
            self.canonical_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def node(self, node_id: str) -> Dict[str, Any]:
        for node in self.nodes:
            if node["id"] == node_id:
                return node
        raise KeyError(node_id)

    def established_edge(self, kind: str, src: str, dst: str) -> bool:
        return any(
            e.get("kind") == kind
            and e.get("from") == src
            and e.get("to") == dst
            and e.get("status") == "ESTABLISHED"
            for e in self.edges
        )
