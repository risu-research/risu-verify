#!/usr/bin/env python3
from __future__ import annotations

"""Truth-free Candidate-58 preparation inside an already sealed source-only capsule.

The caller must stage candidates as <opaque transport_case_id>.<language suffix>
using the frozen blind-58 source-only staging boundary. This module never opens
the original materialized-cell tree, truth/operator metadata, or any gold join.
It prepares A2/D1/D2/D3 evidence only and writes an exact content-addressed
ClosedReadSet policy for the later semantic execution.
"""

import argparse, copy, hashlib, json, re
from pathlib import Path
from typing import Any, Mapping, Sequence

from risu_e2.acquisition import AcquiredFile
from risu_e2.frontend_go import extract_many as extract_go_many
from risu_e2.frontend_js_v3 import extract as extract_js
from risu_e2.frontend_python_v2 import extract as extract_python
from risu_e2.ir_v3 import build_ir
from risu_e2.model import canonical_bytes
from risu_e2.observability_overlay import build_overlay, validate_overlay
from risu_e2.path_observability import build_path_observability

PLAN_SCHEMA = "risu.e2-candidate58-prepared-execution-plan/v0.1"
PREP_SCHEMA = "risu.e2-candidate58-preparation-receipt/v0.1"
POLICY_SCHEMA = "risu.e2-closed-runtime-read-policy/v0.1"
PLACEHOLDER_SCHEMA = "risu.e2-candidate58-upstream-incomplete-placeholder/v0.1"
EXPECTED = 58
SUFFIX = {"python": ".py", "go": ".go", "typescript_javascript": ".mjs"}
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def canon(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def load(path: Path) -> tuple[Any, bytes]:
    raw = path.read_bytes(); return json.loads(raw), raw


def write(path: Path, value: Any) -> str:
    raw = canon(value); path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(raw); return sha(raw)


def rel(root: Path, path: Path) -> str:
    root = root.resolve(strict=True); path = path.resolve(strict=True)
    if path == root or root not in path.parents:
        raise ValueError("prepared path escapes capsule root")
    return path.relative_to(root).as_posix()


def validate_manifest(doc: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows = doc.get("cases")
    if doc.get("schema") != "risu.e2-sanitized-opaque-58-admission-manifest/v0.1" or doc.get("semantic_authority") is not False or doc.get("case_count") != EXPECTED or not isinstance(rows, list) or len(rows) != EXPECTED:
        raise ValueError("sanitized manifest mismatch")
    fields = {"transport_case_id", "candidate_source_sha256", "language", "seed_id"}
    out=[]; ids=set(); hashes=set()
    for row in rows:
        if not isinstance(row, Mapping) or set(row) != fields: raise ValueError("manifest field allowlist mismatch")
        cid=str(row["transport_case_id"]); digest=str(row["candidate_source_sha256"]); language=str(row["language"]); seed=str(row["seed_id"])
        if not HEX64.fullmatch(cid) or not HEX64.fullmatch(digest) or language not in SUFFIX or not re.fullmatch(r"SYN-(?:PY|GO|TS)-0[12]", seed): raise ValueError("manifest identity malformed")
        if cid in ids or digest in hashes: raise ValueError("manifest duplicate identity")
        ids.add(cid); hashes.add(digest); out.append(dict(row))
    out.sort(key=lambda x: x["transport_case_id"])
    if {k:sum(r["language"]==k for r in out) for k in sorted(SUFFIX)} != {"go":19,"python":20,"typescript_javascript":19}: raise ValueError("manifest language strata mismatch")
    return out


def transport_map(doc: Mapping[str, Any], rows: Sequence[Mapping[str, Any]]) -> dict[str, Mapping[str, Any]]:
    receipts=doc.get("receipts")
    if doc.get("schema") != "risu.e2-blind-58-anchor-transport-bundle/v0.1" or doc.get("semantic_authority") is not False or doc.get("case_count") != EXPECTED or not isinstance(receipts,list) or len(receipts)!=EXPECTED: raise ValueError("blind transport mismatch")
    out={str(r.get("transport_case_id")):r for r in receipts}
    if len(out)!=EXPECTED or set(out)!={str(r["transport_case_id"]) for r in rows}: raise ValueError("transport identity-set mismatch")
    return out


def source_slice(text: str, span: Sequence[int]) -> bytes:
    sl,sc,el,ec=map(int,span); lines=[x.encode() for x in text.splitlines(keepends=True)]
    if sl<1 or el<sl or el>len(lines): raise ValueError("bad transported span")
    if sl==el: return lines[sl-1][sc:ec]
    return b"".join([lines[sl-1][sc:]]+lines[sl:el-1]+[lines[el-1][:ec]])


def projected_contract(anchor: Mapping[str, Any], transport: Mapping[str, Any], logical_path: str, text: str, language: str) -> tuple[dict[str, Any],str]:
    declaration=copy.deepcopy(anchor["declaration"]); by_anchor={x["anchor_key"]:x for x in transport.get("anchors",[])}
    declaration["source"]={"git_blob_sha":"OPAQUE_RUNTIME_SOURCE","language":language,"path":logical_path,"sha256":transport["candidate_source_sha256"]}
    for key,item in declaration["anchors"].items():
        row=by_anchor.get(key)
        if row is None or row.get("realization_status")!="ROLE_COMPATIBLE" or not row.get("candidate_span"): raise ValueError("transport anchor not strictly usable")
        item["span"]=list(row["candidate_span"]); item["slice_sha256"]=row["candidate_slice_sha256"]; actual=source_slice(text,item["span"])
        if sha(actual)!=item["slice_sha256"]: raise ValueError("transport anchor slice mismatch")
        item["slice_bytes"]=len(actual); item["unique_in_source"]=True
    for slot in ("expected_coordinate","current_coordinate"):
        observed=transport["binding_slots"][slot]; declared=declaration["binding_slots"][slot]
        if observed.get("status")!="AVAILABLE" or int(observed["operand_index"])!=int(declared["operand_index"]): raise ValueError("transport binding not strictly usable")
    declaration["transport"]={"mutant_revision_authorized":True,"fresh_revision_authorized":False,"projection_authority":"FROZEN_BLIND58_TRANSPORT_RECEIPT"}; declaration["verdict_authority"]=False
    return declaration, sha(canonical_bytes(declaration))


def frontend(language: str, path: str, data: bytes, go_helper: Path) -> dict[str, Any]:
    text=data.decode("utf-8")
    if language=="python": return extract_python(text)
    if language=="typescript_javascript": return extract_js(text)
    if language=="go": return extract_go_many([{"path":path,"data":data}],go_helper)[path]
    raise ValueError("unsupported language")


def direct_ir(path: str, language: str, data: bytes, go_helper: Path):
    acquired=[AcquiredFile(path=path,language=language,sha256=sha(data),data=data,selection_round=0,selection_reasons=("CANDIDATE58_OPAQUE_HASH_BOUND_INPUT",))]
    acquisition={"status":"PASS","reason":"CANDIDATE58_EXACT_BOUND_SINGLE_FILE_INPUT","semantic_authority":False,"selected_file_count":1,"selected_total_bytes":len(data)}
    return build_ir(acquired,acquisition_doc=acquisition,go_helper_path=go_helper)


def select(rows: Sequence[Mapping[str, Any]], seed: str) -> Mapping[str, Any]:
    found=[r for r in rows if str(r.get("seed_id"))==seed]
    if len(found)!=1: raise ValueError("seed cardinality mismatch")
    return found[0]


def build_case(source: bytes, language: str, case_id: str, transport: Mapping[str, Any], anchor: Mapping[str, Any], signature: Mapping[str, Any], go_helper: Path):
    logical=f"opaque-candidate/{case_id}{SUFFIX[language]}"; text=source.decode("utf-8"); contract,contract_sha=projected_contract(anchor,transport,logical,text,language)
    ir,status=direct_ir(logical,language,source,go_helper)
    if status.get("status")!="PASS": raise ValueError("base IR failed")
    fdoc=frontend(language,logical,source,go_helper)
    if fdoc.get("status")!="PASS": raise ValueError("frontend failed")
    overlay=build_overlay(path=logical,source=text,source_sha256=sha(source),language=language,facts=fdoc["facts"],base_ir=ir,anchor_contract=contract,anchor_contract_sha256=contract_sha); validate_overlay(overlay)
    pathdoc=build_path_observability(path=logical,source=text,source_sha256=sha(source),language=language,facts=fdoc["facts"],overlay=overlay,canonical_signature=signature)
    return overlay,pathdoc,{"base_ir_digest_sha256":ir["ir_digest_sha256"],"overlay_digest_sha256":overlay["overlay_digest_sha256"],"path_observability_digest_sha256":pathdoc["path_observability_digest_sha256"],"projected_anchor_contract_sha256":contract_sha}


def add_policy_entry(entries: list[dict[str,str]], root: Path, path: Path, purpose: str, role: str) -> str:
    digest=sha(path.read_bytes()); entries.append({"path":rel(root,path),"sha256":digest,"purpose":purpose,"role":role}); return digest


def main() -> int:
    ap=argparse.ArgumentParser(); ap.add_argument("--capsule-root",required=True); ap.add_argument("--candidate-dir",required=True); ap.add_argument("--output-root",required=True); ap.add_argument("--execution-protocol-path",required=True); ap.add_argument("--implementation-freeze-path",required=True); ap.add_argument("--admission-manifest-path",required=True); ap.add_argument("--blind-transport-path",required=True); ap.add_argument("--anchor-bundle-path",required=True); ap.add_argument("--signature-bundle-path",required=True); ap.add_argument("--profile-bundle-path",required=True); ap.add_argument("--world-bundle-path",required=True); ap.add_argument("--go-helper",required=True); a=ap.parse_args()
    root=Path(a.capsule_root).resolve(strict=True); candidate_dir=Path(a.candidate_dir).resolve(strict=True); out=Path(a.output_root).resolve(); out.mkdir(parents=True,exist_ok=True)
    if root not in candidate_dir.parents or root not in out.parents: raise ValueError("candidate/output must be inside sealed capsule")
    protocol,praw=load(root/a.execution_protocol_path)
    if protocol.get("schema")!="risu.e2-candidate58-first-semantic-execution-protocol/v0.1" or protocol.get("status")!="PROSPECTIVE_SEALED_NOT_EXECUTED": raise ValueError("execution seal mismatch")
    manifest,mraw=load(root/a.admission_manifest_path); ms=protocol["candidate58_input_lock"]["admission_manifest"]
    if sha(mraw)!=ms["sha256"]: raise ValueError("manifest digest mismatch")
    rows=validate_manifest(manifest); transport,traw=load(root/a.blind_transport_path); ts=protocol["candidate58_input_lock"]["blind58_transport"]
    if sha(traw)!=ts["bundle_sha256"]: raise ValueError("transport digest mismatch")
    tmap=transport_map(transport,rows); anchors,_=load(root/a.anchor_bundle_path); signatures,_=load(root/a.signature_bundle_path)
    plan_rows=[]; prep_rows=[]; evdir=out/"evidence"
    for row in rows:
        cid=str(row["transport_case_id"]); language=str(row["language"]); seed=str(row["seed_id"]); source_path=candidate_dir/f"{cid}{SUFFIX[language]}"
        raw=source_path.read_bytes()
        if sha(raw)!=row["candidate_source_sha256"]: raise ValueError("opaque candidate/source hash mismatch")
        tr=tmap[cid]; prep_status="UPSTREAM_INCOMPLETE"; reason="FROZEN_TRANSPORT_INCOMPLETE"; intermediates={}
        if tr.get("case_transport_status")=="COMPLETE":
            try:
                overlay,pathdoc,intermediates=build_case(raw,language,cid,tr,select(anchors["contracts"],seed),select(signatures["signatures"],seed),root/a.go_helper); prep_status="PREPARED"; reason=None
            except Exception as exc:
                reason=f"PRIMARY_EVIDENCE_INCOMPLETE:{type(exc).__name__}"; overlay={"schema":PLACEHOLDER_SCHEMA,"case_id":cid,"reason":reason,"semantic_authority":False}; pathdoc=dict(overlay)
        else:
            overlay={"schema":PLACEHOLDER_SCHEMA,"case_id":cid,"reason":reason,"semantic_authority":False}; pathdoc=dict(overlay)
        op=evdir/f"{cid}.overlay.json"; pp=evdir/f"{cid}.path.json"; od=write(op,overlay); pd=write(pp,pathdoc)
        plan_rows.append({"case_id":cid,"seed_id":seed,"language":language,"candidate_source_path":rel(root,source_path),"candidate_source_sha256":sha(raw),"overlay_path":rel(root,op),"overlay_sha256":od,"path_observability_path":rel(root,pp),"path_observability_sha256":pd})
        prep_rows.append({"case_id":cid,"transport_status":tr.get("case_transport_status"),"preparation_status":prep_status,"incomplete_reason":reason,"candidate_source_sha256":sha(raw),"prepared_overlay_sha256":od,"prepared_path_observability_sha256":pd,"primary_intermediate_digests":intermediates})
    plan_rows.sort(key=lambda x:x["case_id"]); prep_rows.sort(key=lambda x:x["case_id"])
    plan={"schema":PLAN_SCHEMA,"semantic_authority":False,"case_count":EXPECTED,"cases":plan_rows}; plan_path=out/"prepared_execution_plan.json"; plan_sha=write(plan_path,plan)
    prep={"schema":PREP_SCHEMA,"status":"PREPARED_NO_SEMANTIC_VERDICT","case_count":EXPECTED,"plan_sha256":plan_sha,"cases":prep_rows,"scientific_firewall":{"candidate_source_bytes_read":True,"truth_or_gold_read":False,"expected_e2_prediction_read":False,"mutation_operator_metadata_read":False,"epistemic10_read":False,"fresh_heldout_read":False,"semantic_verdict_executed":False}}; prep_path=out/"preparation_receipt.json"; prep_sha=write(prep_path,prep)
    entries=[]
    for path,purpose,role in [(root/a.execution_protocol_path,"candidate58_execution_protocol","protocol"),(root/a.implementation_freeze_path,"gate1b1c_implementation_freeze","protocol"),(root/a.admission_manifest_path,"sanitized_candidate58_admission","candidate_identity"),(root/a.blind_transport_path,"frozen_blind58_transport","transport"),(root/a.signature_bundle_path,"frozen_canonical_signature","canonical"),(root/a.profile_bundle_path,"canonical_execution_profile","canonical"),(root/a.world_bundle_path,"declared_finite_worlds","canonical"),(plan_path,"candidate58_prepared_execution_plan","prepared"),(prep_path,"candidate58_preparation_receipt","prepared")]: add_policy_entry(entries,root,path,purpose,role)
    prep_by_id={r["case_id"]:r for r in prep_rows}
    for row in plan_rows:
        add_policy_entry(entries,root,root/row["candidate_source_path"],"candidate_source","candidate")
        if prep_by_id[row["case_id"]]["preparation_status"]=="PREPARED":
            add_policy_entry(entries,root,root/row["overlay_path"],"primary_overlay","prepared"); add_policy_entry(entries,root,root/row["path_observability_path"],"primary_path_observability","prepared")
    seen={}
    for entry in entries:
        if entry["path"] in seen and seen[entry["path"]]!=entry: raise ValueError("conflicting policy entry")
        seen[entry["path"]]=entry
    policy={"schema":POLICY_SCHEMA,"closed":True,"entries":[seen[k] for k in sorted(seen)]}; policy_path=out/"closed_read_policy.json"; policy_sha=write(policy_path,policy)
    print(json.dumps({"status":"PREPARED_NO_SEMANTIC_VERDICT","case_count":EXPECTED,"prepared_count":sum(r["preparation_status"]=="PREPARED" for r in prep_rows),"plan_sha256":plan_sha,"preparation_receipt_sha256":prep_sha,"closed_read_policy_sha256":policy_sha},sort_keys=True,separators=(",",":"))); return 0

if __name__=="__main__": raise SystemExit(main())
