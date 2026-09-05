from __future__ import annotations

from typing import Any, Dict, List, Tuple

from .engine import evaluate_vbe, find_collapse_witness
from .graph import ConsequenceGraph


def _node(node_id: str, kind: str, status: str = "ESTABLISHED") -> Dict[str, Any]:
    out = {"id": node_id, "kind": kind, "status": status}
    if status == "ESTABLISHED" and kind in {
        "SEMANTIC_COORDINATE", "GUARD", "EFFECT", "OUTCOME", "FAILURE", "INTERPRETER"
    }:
        out["attributes"] = {"evidence_refs": [f"fixture:{node_id}"]}
    return out


def _edge(edge_id: str, kind: str, src: str, dst: str, status: str = "ESTABLISHED") -> Dict[str, Any]:
    out = {"id": edge_id, "kind": kind, "from": src, "to": dst, "status": status}
    if status == "ESTABLISHED" and kind in {"BINDS_TO", "COMPARES", "GUARDS", "REJECTS_AS", "INTERPRETS_AS"}:
        out["evidence_refs"] = [f"fixture:{edge_id}"]
    return out


def graph_from_vbe_instance(instance: Dict[str, Any]) -> Tuple[ConsequenceGraph, Dict[str, str]]:
    pattern = instance["target"]["pattern"]
    source = instance["source"]
    ids = {
        "authoritative_coordinate": "coord.authoritative",
        "current_coordinate": "coord.current",
        "guard": "guard.version",
        "effect": "effect.material",
        "stale_outcome": "outcome.stale",
    }
    nodes = [
        _node(ids["authoritative_coordinate"], "SEMANTIC_COORDINATE"),
        _node(ids["current_coordinate"], "SEMANTIC_COORDINATE"),
        _node(ids["effect"], "EFFECT"),
        _node(ids["stale_outcome"], "FAILURE"),
    ]
    edges: List[Dict[str, Any]] = []

    if pattern == "PRESERVED_COMPARE":
        nodes.append(_node(ids["guard"], "GUARD"))
        edges.extend([
            _edge("e.bind", "BINDS_TO", ids["authoritative_coordinate"], ids["guard"]),
            _edge("e.compare", "COMPARES", ids["current_coordinate"], ids["guard"]),
            _edge("e.effect", "GUARDS", ids["guard"], ids["effect"]),
            _edge("e.stale", "REJECTS_AS", ids["guard"], ids["stale_outcome"]),
        ])
    elif pattern == "OMITTED_REVIEWED_GUARD":
        # Keep an explicitly unresolved guard placeholder; regression is established by concrete collapse.
        nodes.append(_node(ids["guard"], "GUARD", "UNRESOLVED"))
    elif pattern == "WRONG_VALIDATOR_REJECT_PATH":
        nodes.append(_node(ids["guard"], "GUARD", "UNRESOLVED"))
    else:
        nodes.append(_node(ids["guard"], "GUARD", "UNRESOLVED"))

    return ConsequenceGraph.from_dict({
        "ir_id": f"e0:{instance['instance_id']}",
        "evidence_boundary": "development-calibration-adapter",
        "nodes": nodes,
        "edges": edges,
    }), ids


def _reviewed_anchor(instance: Dict[str, Any]) -> Any:
    reviewed = instance["source"]["reviewed"]
    return reviewed.get("anchor")


def world_models(instance: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], Dict[str, str], Dict[str, str]]:
    source = instance["source"]
    cur_name = source["current_coordinate"]
    anchor = _reviewed_anchor(instance)
    worlds = [{cur_name: value} for value in source["current_domain"]]
    source_map = {}
    target_map = {}
    pattern = instance["target"]["pattern"]
    for world in worlds:
        key = repr(tuple(sorted(world.items())))
        is_match = world[cur_name] == anchor
        source_map[key] = source["success_consequence"] if is_match else source["stale_consequence"]
        if pattern == "PRESERVED_COMPARE":
            target_map[key] = source_map[key]
        elif pattern == "OMITTED_REVIEWED_GUARD":
            target_map[key] = instance["target"].get("native_accept_kind", "ACCEPTED")
        elif pattern == "WRONG_VALIDATOR_REJECT_PATH":
            target_map[key] = instance["target"].get("native_stale_kind", "PRECHECK_REJECTED")
        else:
            target_map[key] = "UNKNOWN"
    return worlds, source_map, target_map


def evaluate_calibration(instance: Dict[str, Any]) -> Dict[str, Any]:
    graph, roles = graph_from_vbe_instance(instance)
    worlds, source_map, target_map = world_models(instance)
    collapse = find_collapse_witness(worlds, source_map, target_map)
    return evaluate_vbe(
        graph,
        roles,
        refinement_complete=instance["target"]["pattern"] == "PRESERVED_COMPARE",
        material_interpretation_nonempty=True,
        collapse_witness=collapse,
    )


def discriminator_collapse_mutation(instance: Dict[str, Any]) -> Dict[str, Any]:
    graph, roles = graph_from_vbe_instance(instance)
    worlds, source_map, target_map = world_models(instance)
    fixed = next(iter(target_map.values()))
    target_map = {k: fixed for k in target_map}
    collapse = find_collapse_witness(worlds, source_map, target_map)
    return evaluate_vbe(
        graph,
        roles,
        refinement_complete=True,
        material_interpretation_nonempty=True,
        collapse_witness=collapse,
    )
