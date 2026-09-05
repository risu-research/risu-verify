from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .graph import ConsequenceGraph

PRED_REGRESSION = "E0_PREDICTED_CONSEQUENCE_REGRESSION"
PRED_STABLE = "E0_PREDICTED_CONSEQUENCE_STABLE_IN_DECLARED_SCOPE"
PRED_INCOMPLETE = "E0_PREDICTED_ASSURANCE_INCOMPLETE"
PRED_INFRA = "E0_INFRASTRUCTURE_FAILURE"


def _world_key(world: Dict[str, Any]) -> str:
    return repr(tuple(sorted(world.items())))


def _difference_count(a: Dict[str, Any], b: Dict[str, Any]) -> int:
    keys = set(a) | set(b)
    return sum(a.get(k) != b.get(k) for k in keys)


def find_collapse_witness(
    worlds: Sequence[Dict[str, Any]],
    source_consequence_by_world: Dict[str, str],
    target_observation_by_world: Dict[str, str],
) -> Optional[Dict[str, Any]]:
    candidates: List[Dict[str, Any]] = []
    for i, w1 in enumerate(worlds):
        k1 = _world_key(w1)
        for w2 in worlds[i + 1 :]:
            k2 = _world_key(w2)
            if (
                source_consequence_by_world[k1] != source_consequence_by_world[k2]
                and target_observation_by_world[k1] == target_observation_by_world[k2]
            ):
                candidates.append(
                    {
                        "witness_kind": "DETERMINISTIC_COLLAPSE",
                        "world_a": deepcopy(w1),
                        "world_b": deepcopy(w2),
                        "source_a": source_consequence_by_world[k1],
                        "source_b": source_consequence_by_world[k2],
                        "target_a": target_observation_by_world[k1],
                        "target_b": target_observation_by_world[k2],
                        "difference_count": _difference_count(w1, w2),
                        "model": {
                            "source_consequence_by_world": deepcopy(source_consequence_by_world),
                            "target_observation_by_world": deepcopy(target_observation_by_world),
                        },
                    }
                )
    if not candidates:
        return None
    candidates.sort(
        key=lambda w: (
            w["difference_count"],
            len(w["world_a"]) + len(w["world_b"]),
            repr(w["world_a"]),
            repr(w["world_b"]),
        )
    )
    return candidates[0]


def find_relational_witness(
    worlds: Sequence[Dict[str, Any]],
    source_allowed_by_world: Dict[str, List[str]],
    target_consequences_by_world: Dict[str, List[str]],
) -> Optional[Dict[str, Any]]:
    candidates = []
    for world in worlds:
        key = _world_key(world)
        allowed = list(source_allowed_by_world[key])
        observed = list(target_consequences_by_world[key])
        extras = sorted(set(observed) - set(allowed))
        if extras:
            candidates.append(
                {
                    "witness_kind": "RELATIONAL_EXTRA_CONSEQUENCE",
                    "world": deepcopy(world),
                    "source_allowed": sorted(allowed),
                    "observed_target": sorted(observed),
                    "extra_consequences": extras,
                    "model": {
                        "source_allowed_by_world": deepcopy(source_allowed_by_world),
                        "target_consequences_by_world": deepcopy(target_consequences_by_world),
                    },
                }
            )
    if not candidates:
        return None
    candidates.sort(key=lambda w: (len(w["world"]), repr(w["world"]), w["extra_consequences"]))
    return candidates[0]


def shrink_witness(witness: Dict[str, Any]) -> Dict[str, Any]:
    """Validity-first deterministic shrinker over irrelevant equal coordinates."""
    out = deepcopy(witness)
    if out.get("witness_kind") == "DETERMINISTIC_COLLAPSE":
        wa, wb = out["world_a"], out["world_b"]
        common_equal = [k for k in sorted(set(wa) & set(wb)) if wa[k] == wb[k]]
        for key in common_equal:
            wa.pop(key, None)
            wb.pop(key, None)
        out["difference_count"] = _difference_count(wa, wb)
        # Re-key only the two witness worlds so the independent checker can
        # re-evaluate the shrunken witness without trusting producer internals.
        out["model"] = {
            "source_consequence_by_world": {
                _world_key(wa): out["source_a"],
                _world_key(wb): out["source_b"],
            },
            "target_observation_by_world": {
                _world_key(wa): out["target_a"],
                _world_key(wb): out["target_b"],
            },
        }
    return out


def vbe_obligations(graph: ConsequenceGraph, roles: Dict[str, str]) -> Dict[str, bool]:
    a = roles["authoritative_coordinate"]
    c = roles["current_coordinate"]
    g = roles["guard"]
    e = roles["effect"]
    s = roles["stale_outcome"]
    return {
        "authoritative_coordinate_established": graph.node(a).get("status") == "ESTABLISHED",
        "current_coordinate_established": graph.node(c).get("status") == "ESTABLISHED",
        "guard_established": graph.node(g).get("status") == "ESTABLISHED",
        "effect_established": graph.node(e).get("status") == "ESTABLISHED",
        "stale_outcome_established": graph.node(s).get("status") == "ESTABLISHED",
        "authoritative_bound_to_guard": graph.established_edge("BINDS_TO", a, g),
        "current_compared_by_guard": graph.established_edge("COMPARES", c, g),
        "guard_guards_effect": graph.established_edge("GUARDS", g, e),
        "guard_rejects_as_stale": graph.established_edge("REJECTS_AS", g, s),
    }


def evaluate_vbe(
    graph: ConsequenceGraph,
    roles: Dict[str, str],
    *,
    refinement_complete: bool,
    material_interpretation_nonempty: bool,
    collapse_witness: Optional[Dict[str, Any]] = None,
    relational_witness: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    graph.validate()
    obligations = vbe_obligations(graph, roles)

    # Concrete counterexample dominates any positive structural evidence.
    witness = relational_witness or collapse_witness
    if witness is not None:
        return {
            "prediction": PRED_REGRESSION,
            "authority": "E0_CTV_FRONTEND",
            "consequence_authority": False,
            "obligations": obligations,
            "witness": shrink_witness(witness),
        }

    if not material_interpretation_nonempty:
        return {
            "prediction": PRED_INCOMPLETE,
            "authority": "E0_CTV_FRONTEND",
            "consequence_authority": False,
            "obligations": obligations,
            "hard_stop": "EMPTY_OR_UNESTABLISHED_MATERIAL_INTERPRETATION",
        }

    if not refinement_complete or not all(obligations.values()):
        return {
            "prediction": PRED_INCOMPLETE,
            "authority": "E0_CTV_FRONTEND",
            "consequence_authority": False,
            "obligations": obligations,
            "hard_stop": "UNRESOLVED_MATERIAL_OBLIGATION",
        }

    return {
        "prediction": PRED_STABLE,
        "authority": "E0_CTV_FRONTEND",
        "consequence_authority": False,
        "obligations": obligations,
    }
