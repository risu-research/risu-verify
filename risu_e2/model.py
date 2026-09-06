from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Tuple

IR_SCHEMA = "risu.e2-normalized-semantic-flow-ir/v0.1"
NODE_KINDS = {
    "OPERATION", "RESOURCE", "INPUT", "SEMANTIC_COORDINATE",
    "GUARD", "EFFECT", "OUTCOME", "FAILURE", "INTERPRETER", "EVIDENCE",
}
EDGE_KINDS = {
    "CARRIES", "DERIVES", "BINDS_TO", "COMPARES", "GUARDS",
    "PRECEDES", "MUTATES", "REJECTS_AS", "INTERPRETS_AS", "EVIDENCED_BY",
}

def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")

def digest(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()

@dataclass(frozen=True)
class Span:
    path: str
    start_line: int
    start_col: int
    end_line: int
    end_col: int
    sha256: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "start_line": self.start_line,
            "start_col": self.start_col,
            "end_line": self.end_line,
            "end_col": self.end_col,
            "sha256": self.sha256,
        }

@dataclass(frozen=True)
class Node:
    id: str
    kind: str
    label: str
    span: Span
    attrs: Mapping[str, Any] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "kind": self.kind, "label": self.label,
            "span": self.span.as_dict(), "attrs": dict(self.attrs),
        }

@dataclass(frozen=True)
class Edge:
    id: str
    kind: str
    source: str
    target: str
    span: Span
    attrs: Mapping[str, Any] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "kind": self.kind, "source": self.source,
            "target": self.target, "span": self.span.as_dict(),
            "attrs": dict(self.attrs),
        }

class GraphBuilder:
    def __init__(self) -> None:
        self._nodes: Dict[str, Node] = {}
        self._edges: Dict[str, Edge] = {}

    @staticmethod
    def node_id(kind: str, label: str, span: Span, attrs: Mapping[str, Any]) -> str:
        basis = {"kind": kind, "label": label, "span": span.as_dict(), "attrs": dict(attrs)}
        return "n_" + digest(basis)[:24]

    @staticmethod
    def edge_id(kind: str, source: str, target: str, span: Span, attrs: Mapping[str, Any]) -> str:
        basis = {"kind": kind, "source": source, "target": target, "span": span.as_dict(), "attrs": dict(attrs)}
        return "e_" + digest(basis)[:24]

    def add_node(self, kind: str, label: str, span: Span, **attrs: Any) -> str:
        if kind not in NODE_KINDS:
            raise ValueError(f"unsupported node kind: {kind}")
        nid = self.node_id(kind, label, span, attrs)
        self._nodes[nid] = Node(nid, kind, label, span, dict(sorted(attrs.items())))
        return nid

    def add_edge(self, kind: str, source: str, target: str, span: Span, **attrs: Any) -> str:
        if kind not in EDGE_KINDS:
            raise ValueError(f"unsupported edge kind: {kind}")
        if source not in self._nodes or target not in self._nodes:
            raise ValueError(f"dangling edge: {source}->{target}")
        eid = self.edge_id(kind, source, target, span, attrs)
        self._edges[eid] = Edge(eid, kind, source, target, span, dict(sorted(attrs.items())))
        return eid

    def nodes(self) -> List[Node]:
        return sorted(self._nodes.values(), key=lambda n: (n.span.path, n.span.start_line, n.span.start_col, n.kind, n.label, n.id))

    def edges(self) -> List[Edge]:
        return sorted(self._edges.values(), key=lambda e: (e.span.path, e.span.start_line, e.span.start_col, e.kind, e.source, e.target, e.id))

    def as_document(self, *, files: Sequence[Mapping[str, Any]], acquisition: Mapping[str, Any], frontend_status: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
        nodes = [n.as_dict() for n in self.nodes()]
        edges = [e.as_dict() for e in self.edges()]
        doc = {
            "schema": IR_SCHEMA,
            "semantic_authority": False,
            "files": list(files),
            "acquisition": dict(acquisition),
            "frontend_status": list(frontend_status),
            "nodes": nodes,
            "edges": edges,
        }
        validate_ir(doc)
        doc["ir_digest_sha256"] = digest(doc)
        return doc

def validate_ir(doc: Mapping[str, Any]) -> None:
    if doc.get("schema") != IR_SCHEMA:
        raise ValueError("IR schema mismatch")
    nodes = list(doc.get("nodes", []))
    edges = list(doc.get("edges", []))
    ids = {n["id"] for n in nodes}
    if len(ids) != len(nodes):
        raise ValueError("duplicate node id")
    eids = {e["id"] for e in edges}
    if len(eids) != len(edges):
        raise ValueError("duplicate edge id")
    for n in nodes:
        if n["kind"] not in NODE_KINDS:
            raise ValueError(f"bad node kind {n['kind']}")
        s = n["span"]
        if not s["path"] or s["start_line"] < 1 or s["end_line"] < s["start_line"]:
            raise ValueError(f"invalid node span {n['id']}")
    for e in edges:
        if e["kind"] not in EDGE_KINDS:
            raise ValueError(f"bad edge kind {e['kind']}")
        if e["source"] not in ids or e["target"] not in ids:
            raise ValueError(f"dangling edge {e['id']}")
