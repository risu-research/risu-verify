from __future__ import annotations

import ast
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Sequence, Tuple

from .model import EDGE_KINDS, NODE_KINDS, canonical_bytes, digest

OVERLAY_SCHEMA = "risu.e2-observability-overlay/v0.1"


def _sha(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _span_tuple(raw: Mapping[str, Any]) -> Tuple[int, int, int, int]:
    if "span" in raw and isinstance(raw["span"], (list, tuple)):
        a = raw["span"]
        return (int(a[0]), int(a[1]), int(a[2]), int(a[3]))
    s = raw.get("span", raw)
    return (
        int(s.get("start_line", 1)), int(s.get("start_col", 0)),
        int(s.get("end_line", s.get("start_line", 1))),
        int(s.get("end_col", s.get("start_col", 0) + 1)),
    )


def _span_dict(path: str, source_sha256: str, span: Tuple[int, int, int, int]) -> Dict[str, Any]:
    return {
        "path": path,
        "start_line": span[0], "start_col": span[1],
        "end_line": span[2], "end_col": span[3],
        "sha256": source_sha256,
    }


def _leq_pos(a: Tuple[int, int], b: Tuple[int, int]) -> bool:
    return a <= b


def _contains(outer: Tuple[int, int, int, int], inner: Tuple[int, int, int, int]) -> bool:
    return _leq_pos((outer[0], outer[1]), (inner[0], inner[1])) and _leq_pos((inner[2], inner[3]), (outer[2], outer[3]))


def _same_span(a: Tuple[int, int, int, int], b: Tuple[int, int, int, int]) -> bool:
    return a == b


def _root_label(label: str) -> str:
    x = label.strip()
    for sep in (".", "["):
        if sep in x:
            x = x.split(sep, 1)[0]
    return x


def _slot_suffix(label: str) -> str | None:
    root = _root_label(label)
    rest = label[len(root):]
    return rest or None


def _specificity(label: str) -> Tuple[int, int, str]:
    return (1 if ("." in label or "[" in label) else 0, len(label), label)


class OverlayGraph:
    def __init__(self, path: str, source_sha256: str) -> None:
        self.path = path
        self.source_sha256 = source_sha256
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self.edges: Dict[str, Dict[str, Any]] = {}
        self._evidence: Dict[Tuple[Tuple[int,int,int,int], str], str] = {}

    def node(self, kind: str, label: str, span: Tuple[int,int,int,int], **attrs: Any) -> str:
        if kind not in NODE_KINDS:
            raise ValueError(f"unsupported node kind:{kind}")
        body = {"kind":kind,"label":label,"span":_span_dict(self.path,self.source_sha256,span),"attrs":dict(sorted(attrs.items()))}
        nid = "on_" + _sha(body)[:24]
        self.nodes[nid] = {"id":nid, **body}
        return nid

    def edge(self, kind: str, source: str, target: str, span: Tuple[int,int,int,int], **attrs: Any) -> str:
        if kind not in EDGE_KINDS:
            raise ValueError(f"unsupported edge kind:{kind}")
        if source not in self.nodes or target not in self.nodes:
            raise ValueError(f"dangling overlay edge:{source}->{target}")
        body = {"kind":kind,"source":source,"target":target,"span":_span_dict(self.path,self.source_sha256,span),"attrs":dict(sorted(attrs.items()))}
        eid = "oe_" + _sha(body)[:24]
        self.edges[eid] = {"id":eid, **body}
        return eid

    def evidence(self, span: Tuple[int,int,int,int], role: str, **attrs: Any) -> str:
        key = (span, role)
        if key not in self._evidence:
            ev = self.node("EVIDENCE", f"{self.path}:{span[0]}:{span[1]}-{span[2]}:{span[3]}", span,
                           evidence_role=role, source_sha256=self.source_sha256, **attrs)
            self._evidence[key] = ev
        return self._evidence[key]

    def evidenced(self, node_id: str, span: Tuple[int,int,int,int], role: str, **attrs: Any) -> None:
        ev = self.evidence(span, role, **attrs)
        self.edge("EVIDENCED_BY", node_id, ev, span, evidence_role=role)

    def sorted_nodes(self) -> List[Dict[str, Any]]:
        return sorted(self.nodes.values(), key=lambda n:(n["span"]["path"],n["span"]["start_line"],n["span"]["start_col"],n["kind"],n["label"],n["id"]))

    def sorted_edges(self) -> List[Dict[str, Any]]:
        return sorted(self.edges.values(), key=lambda e:(e["span"]["path"],e["span"]["start_line"],e["span"]["start_col"],e["kind"],e["source"],e["target"],e["id"]))
