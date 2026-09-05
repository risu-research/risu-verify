#!/usr/bin/env python3
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path

from vbe_compile import compile_instance


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, obj) -> None:
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def edge_key(edge: dict) -> tuple[str, str, str]:
    return (str(edge.get("from")), str(edge.get("relation")), str(edge.get("to")))


def apply_provenance_overlay(instance_path: Path, out: Path, inst: dict, overlay_path: Path) -> dict:
    overlay = read_json(overlay_path)
    if overlay.get("schema") != "risu.corpus-provenance-overlay/v0.1alpha1":
        raise SystemExit("unsupported Corpus provenance overlay schema")
    corpus = inst.get("corpus") or {}
    if overlay.get("unit_id") != corpus.get("unit_id"):
        raise SystemExit("provenance overlay unit_id mismatch")
    if overlay.get("primary_verdict_observed_before_overlay") is not False:
        raise SystemExit("provenance overlay is not explicitly pre-verdict")
    if overlay.get("mode") != "ADD_EXISTING_FACT_PROVENANCE_EDGES_ONLY":
        raise SystemExit("unsupported provenance overlay mode")

    original = overlay.get("original_envelope") or {}
    envelope_path = (instance_path.parent / inst["carrier_envelope"]).resolve()
    if original.get("path") and not str(envelope_path).replace("\\", "/").endswith(str(original["path"])):
        raise SystemExit("provenance overlay original envelope path mismatch")
    if sha256_file(envelope_path) != original.get("sha256"):
        raise SystemExit("provenance overlay original envelope SHA-256 mismatch")

    adapter_path = out / "assurance" / "adapter.json"
    adapter = read_json(adapter_path)
    before = copy.deepcopy(adapter)
    provenance = adapter.get("provenance") or {}
    nodes = {n.get("id") for n in provenance.get("nodes") or []}
    edges = provenance.get("edges")
    if not isinstance(edges, list):
        raise SystemExit("compiled adapter provenance edges missing")

    exact_node = overlay.get("exact_derivation_node")
    exact_root = overlay.get("exact_claim_root")
    if exact_node not in nodes or exact_root not in nodes:
        raise SystemExit("provenance overlay exact derivation/root node missing")
    if (exact_node, "DERIVES", exact_root) not in {edge_key(e) for e in edges}:
        raise SystemExit("provenance overlay exact derivation is not connected to the EXACT claim root")

    derivation = ((adapter.get("target") or {}).get("derivation") or {})
    facts = {f.get("id"): f for f in derivation.get("facts") or []}
    program = derivation.get("program") or {}
    required_fact_ids = set()
    for component in ("discriminator", "operative_signature", "mechanism", "interpreter"):
        required_fact_ids.update((program.get(component) or {}).get("required_fact_ids") or [])

    additions = []
    existing = {edge_key(e) for e in edges}
    for fact_id in overlay.get("add_exact_provenance_for_fact_ids") or []:
        fact = facts.get(fact_id)
        if not fact:
            raise SystemExit(f"overlay fact is not present in compiled derivation facts: {fact_id}")
        if fact.get("status") != "ESTABLISHED":
            raise SystemExit(f"overlay fact is not ESTABLISHED: {fact_id}")
        if fact_id not in required_fact_ids:
            raise SystemExit(f"overlay fact is not required by the frozen target program: {fact_id}")
        provenance_node = fact.get("provenance_node")
        if provenance_node not in nodes:
            raise SystemExit(f"overlay fact provenance node is missing: {fact_id}")
        edge = {"from": provenance_node, "relation": "USES", "to": exact_node}
        key = edge_key(edge)
        if key not in existing:
            edges.append(edge)
            existing.add(key)
            additions.append(edge)

    expected = overlay.get("expected_added_edges") or []
    if sorted(map(edge_key, additions)) != sorted(map(edge_key, expected)):
        raise SystemExit(
            f"provenance overlay added edges differ from predeclared expectation: actual={additions} expected={expected}"
        )

    before_without_edges = copy.deepcopy(before)
    after_without_edges = copy.deepcopy(adapter)
    before_without_edges["provenance"]["edges"] = []
    after_without_edges["provenance"]["edges"] = []
    if before_without_edges != after_without_edges:
        raise SystemExit("provenance overlay changed adapter content outside provenance.edges")

    before_edges = {edge_key(e) for e in before["provenance"]["edges"]}
    after_edges = {edge_key(e) for e in adapter["provenance"]["edges"]}
    if after_edges - before_edges != set(map(edge_key, expected)):
        raise SystemExit("provenance overlay edge delta is not exactly the predeclared edge set")
    if before_edges - after_edges:
        raise SystemExit("provenance overlay removed existing edges")

    before_sha = sha256_file(adapter_path)
    write_json(adapter_path, adapter)
    after_sha = sha256_file(adapter_path)
    application = {
        "schema": "risu.corpus-provenance-overlay-application/v0.1alpha1",
        "overlay_path": str(overlay_path),
        "overlay_sha256": sha256_file(overlay_path),
        "unit_id": corpus.get("unit_id"),
        "original_adapter_sha256": before_sha,
        "amended_adapter_sha256": after_sha,
        "added_edges": additions,
        "non_edge_adapter_content_identical": True,
        "source_contract_unchanged": True,
        "frozen_vbe_compiler_unchanged": True,
    }
    write_json(out / "PROVENANCE_OVERLAY_APPLICATION.json", application)
    return application


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Compile one AUTHOR_ACCEPTED Corpus 0.1 VBE instance without changing frozen scientific semantics"
    )
    ap.add_argument("instance")
    ap.add_argument("--output", required=True)
    ap.add_argument("--provenance-overlay")
    args = ap.parse_args()

    instance_path = Path(args.instance).resolve()
    out = Path(args.output).resolve()
    inst = read_json(instance_path)
    if inst.get("status") != "AUTHOR_ACCEPTED":
        raise SystemExit("Corpus primary compilation requires status=AUTHOR_ACCEPTED")
    corpus = inst.get("corpus") or {}
    if corpus.get("id") != "PROSPECTIVE_CORPUS_0.1":
        raise SystemExit("instance is not bound to PROSPECTIVE_CORPUS_0.1")
    if not corpus.get("unit_id"):
        raise SystemExit("prospective corpus instance lacks unit_id")

    compile_instance(instance_path, out)

    overlay_application = None
    if args.provenance_overlay:
        overlay_application = apply_provenance_overlay(
            instance_path, out, inst, Path(args.provenance_overlay).resolve()
        )

    case_path = out / "case.json"
    case = read_json(case_path)
    case["title"] = f"Prospective Corpus 0.1 - {corpus['unit_id']} - {inst['instance_id']}"
    case["kind"] = "VBE_PROFILE_COMPILED_PROSPECTIVE"
    case["corpus"] = {
        "id": corpus["id"],
        "unit_id": corpus["unit_id"],
        "enrollment_position": corpus.get("enrollment_position"),
        "authoring_status": inst["status"],
    }
    write_json(case_path, case)

    manifest_path = out / "VBE_COMPILE_MANIFEST.json"
    manifest = read_json(manifest_path)
    manifest["compilation_mode"] = "PROSPECTIVE_CORPUS_PRIMARY"
    manifest["corpus"] = case["corpus"]
    manifest["note"] = (
        "Source-contract and target semantic program are produced by tools/vbe_compile.py unchanged. "
        "When a pinned post-freeze provenance overlay is supplied, the Corpus wrapper may add only "
        "predeclared provenance edges between already-frozen established facts and an existing claim derivation."
    )
    if overlay_application:
        manifest["provenance_overlay"] = overlay_application
    write_json(manifest_path, manifest)

    print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
