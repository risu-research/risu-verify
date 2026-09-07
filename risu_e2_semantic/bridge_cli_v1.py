#!/usr/bin/env python3
from __future__ import annotations

"""Production Gate1B/1C bridge driver.

Both modes bootstrap from an externally pinned read-policy digest.  Scientific
reads after bootstrap are content-addressed and guarded by ClosedReadSet.
Neither mode executes A3/A4 verdict logic.
"""

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from risu_e2_semantic.adapter_support import _digest
from risu_e2_semantic.canonical_bridge import canonical_bytes, derive
from risu_e2_semantic.canonical_worlds import derive_worlds
from risu_e2_semantic.closed_read_set import ClosedReadSet, load_bootstrap_policy
from risu_e2_semantic.primary_adapter import adapt_primary


def _json(raw: bytes) -> Any:
    return json.loads(raw.decode("utf-8"))


def _write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_bytes(value))


def _select(rows: list[Mapping[str,Any]], seed_id: str) -> Mapping[str,Any]:
    found=[x for x in rows if str(x.get("seed_id"))==seed_id]
    if len(found)!=1:
        raise ValueError(f"seed cardinality:{seed_id}:{len(found)}")
    return found[0]


def canonical_mode(a: argparse.Namespace) -> int:
    root=Path(a.repo_root)
    policy,_=load_bootstrap_policy(Path(a.read_policy),a.read_policy_sha256)
    guard=ClosedReadSet(root,policy)
    guard.install_audit_guard()
    anchor_raw=guard.read_bytes(a.anchor_path,purpose="canonical_anchor_bundle")
    overlay_raw=guard.read_bytes(a.overlay_path,purpose="canonical_overlay_bundle")
    frozen_raw=guard.read_bytes(a.frozen_signature_path,purpose="frozen_canonical_signature")
    anchor=_json(anchor_raw); overlay=_json(overlay_raw); frozen=_json(frozen_raw)
    sources={}
    for row in anchor.get("contracts",[]):
        sid=str(row["seed_id"]); p=str(row["declaration"]["source"]["path"])
        sources[sid]=guard.read_bytes(p,purpose="canonical_seed_source")
    sig,profiles=derive(anchor_bundle=anchor,anchor_bundle_raw=anchor_raw,overlay_bundle=overlay,overlay_bundle_raw=overlay_raw)
    sig_bytes=canonical_bytes(sig)
    if sig_bytes!=frozen_raw:
        raise ValueError("canonical signature byte identity mismatch")
    worlds=derive_worlds(anchor_bundle=anchor,overlay_bundle=overlay,signature_bundle=sig,sources=sources)
    out=Path(a.output_dir); out.mkdir(parents=True,exist_ok=True)
    _write(out/"E2_GATE1B1C_CANONICAL_SIGNATURE_REPLAY.json",sig)
    _write(out/"E2_GATE1B1C_CANONICAL_EXECUTION_PROFILES.json",profiles)
    _write(out/"E2_GATE1B1C_DECLARED_FINITE_WORLDS.json",worlds)
    receipt=guard.receipt(source_paths=[])
    _write(out/"E2_GATE1B1C_CANONICAL_CLOSED_READ_SET_RECEIPT.json",receipt)
    helper=worlds.get("helper_polarity_receipts",[])
    py2=[x for x in helper if x.get("seed_id")=="SYN-PY-02"]
    checks={
        "public_signature_byte_identity":sig_bytes==frozen_raw,
        "seed_count":sig.get("seed_count")==6==profiles.get("seed_count")==worlds.get("seed_count"),
        "control_forms":sum(x.get("effective_guard_form")=="DIRECT_CONTROL" for x in sig.get("signatures",[]))==5 and sum(x.get("effective_guard_form")=="HELPER_CONTROL" for x in sig.get("signatures",[]))==1,
        "helper_py02_exact":len(py2)==1 and py2[0].get("status")=="PROVED" and py2[0].get("final_relation")=="INVERTED" and py2[0].get("flip_count")==1,
        "no_target_rho_stored":all("rho" not in w for d in worlds.get("world_documents",[]) for w in d.get("worlds",[])),
        "closed_read_set":receipt.get("closed") is True and not receipt.get("forbidden_reads"),
        "candidate_bytes_read":False,
        "a3_a4_verdict_executed":False,
    }
    result={
        "schema":"risu.e2-gate1b1c-canonical-bridge-qualification-result/v0.1",
        "status":"PASS" if all(checks.values()) else "FAIL",
        "checks":checks,
        "public_signature_sha256":hashlib.sha256(sig_bytes).hexdigest(),
        "public_signature_bundle_digest_sha256":sig["bundle_digest_sha256"],
        "execution_profile_sha256":hashlib.sha256(canonical_bytes(profiles)).hexdigest(),
        "world_bundle_sha256":hashlib.sha256(canonical_bytes(worlds)).hexdigest(),
        "read_set_receipt_sha256":hashlib.sha256(canonical_bytes(receipt)).hexdigest(),
        "scientific_firewall":{"candidate58_read":False,"truth_read":False,"operator_metadata_read":False,"fresh_target_read":False,"a3_a4_verdict_executed":False},
    }
    _write(out/"E2_GATE1B1C_CANONICAL_BRIDGE_RESULT.json",result)
    print(json.dumps(result,sort_keys=True,separators=(",",":")))
    return 0 if result["status"]=="PASS" else 1


def adapt_mode(a: argparse.Namespace) -> int:
    root=Path(a.repo_root)
    policy,_=load_bootstrap_policy(Path(a.read_policy),a.read_policy_sha256)
    guard=ClosedReadSet(root,policy)
    guard.install_audit_guard()
    overlay=_json(guard.read_bytes(a.overlay_path,purpose="primary_overlay"))
    pathdoc=_json(guard.read_bytes(a.path_observability_path,purpose="primary_path_observability"))
    sigbundle=_json(guard.read_bytes(a.signature_bundle_path,purpose="frozen_canonical_signature"))
    profiles=_json(guard.read_bytes(a.profile_bundle_path,purpose="canonical_execution_profile"))
    worlds=_json(guard.read_bytes(a.world_bundle_path,purpose="declared_finite_worlds"))
    source=guard.read_bytes(a.candidate_source_path,purpose="candidate_source")
    file_hashes={str(x.get("sha256")) for x in overlay.get("files",[]) if x.get("sha256")}
    observed=hashlib.sha256(source).hexdigest()
    if observed not in file_hashes:
        raise ValueError("candidate source/primary overlay hash mismatch")
    sig=_select(list(sigbundle.get("signatures",[])),a.seed_id)
    profile=_select(list(profiles.get("profiles",[])),a.seed_id)
    worlddoc=_select(list(worlds.get("world_documents",[])),a.seed_id)
    semantic_slice,adapter_receipt=adapt_primary(case_id=a.case_id,language=a.language,source_path=a.candidate_source_path,
        overlay=overlay,path_observability=pathdoc,canonical_signature=sig,canonical_profile=profile,worlds_document=worlddoc)
    out=Path(a.output_dir); out.mkdir(parents=True,exist_ok=True)
    _write(out/"semantic_slice.json",semantic_slice)
    _write(out/"adapter_receipt.json",adapter_receipt)
    read_receipt=guard.receipt(source_paths=[a.candidate_source_path])
    _write(out/"closed_read_set_receipt.json",read_receipt)
    result={"schema":"risu.e2-gate1b1c-production-bridge-result/v0.1","case_id":a.case_id,
            "semantic_slice_digest_sha256":_digest(semantic_slice),"adapter_receipt_digest_sha256":_digest(adapter_receipt),
            "candidate_source_sha256":observed,"read_set_receipt_digest_sha256":_digest(read_receipt),
            "scope_complete":semantic_slice.get("scope",{}).get("complete") is True,"unresolved":semantic_slice.get("scope",{}).get("unresolved",[]),
            "a3_a4_verdict_executed":False}
    _write(out/"bridge_result.json",result)
    print(json.dumps(result,sort_keys=True,separators=(",",":")))
    return 0


def main() -> int:
    ap=argparse.ArgumentParser(); sub=ap.add_subparsers(dest="mode",required=True)
    c=sub.add_parser("canonical")
    for p in (c,):
        p.add_argument("--repo-root",required=True); p.add_argument("--read-policy",required=True); p.add_argument("--read-policy-sha256",required=True)
    c.add_argument("--anchor-path",required=True); c.add_argument("--overlay-path",required=True); c.add_argument("--frozen-signature-path",required=True); c.add_argument("--output-dir",required=True)
    d=sub.add_parser("adapt-primary")
    d.add_argument("--repo-root",required=True); d.add_argument("--read-policy",required=True); d.add_argument("--read-policy-sha256",required=True)
    d.add_argument("--overlay-path",required=True); d.add_argument("--path-observability-path",required=True); d.add_argument("--signature-bundle-path",required=True)
    d.add_argument("--profile-bundle-path",required=True); d.add_argument("--world-bundle-path",required=True); d.add_argument("--candidate-source-path",required=True)
    d.add_argument("--seed-id",required=True); d.add_argument("--case-id",required=True); d.add_argument("--language",required=True); d.add_argument("--output-dir",required=True)
    a=ap.parse_args(); return canonical_mode(a) if a.mode=="canonical" else adapt_mode(a)

if __name__=="__main__": raise SystemExit(main())
