#!/usr/bin/env python3
from __future__ import annotations
import argparse, copy, hashlib, json, tempfile
from collections import Counter
from pathlib import Path
from typing import Any

from risu_e2.acquisition import AcquisitionConfig, acquire
from risu_e2.frontend_python import extract as extract_python
from risu_e2.frontend_js import extract as extract_js
from risu_e2.frontend_go import extract_many as extract_go_many
from risu_e2.ir import build_ir
from risu_e2.model import canonical_bytes
from risu_e2.observability_overlay import build_overlay, validate_overlay
from risu_e2.path_observability import build_path_observability

PROTOCOL_BLOB="cdd6dd1329c5fb77318f2ecf7c04c53cb9797b33"
MANIFEST_SHA="847d85c2274cd6b94a83eefe0f6153a8fb183dbad758efa75118a4fd368623e4"
TRANSPORT_SHA="78c5f024c1af7a353844120879d3ec4487b5f56fb443bc6e063530f836a9f74c"
SIGNATURE_SHA="7a652a508d53960dc0fcdb8860b9d358165f6a6c96b050e6b962edccc2a4549f"
CASE_FIELDS={"transport_case_id","seed_id","language","candidate_source_sha256"}
FORBIDDEN=("expected_truth","expected_e2_primary","operator_id","operator_name","operator_class","M_PLUS","M_ZERO","M_QUESTION")

def canon(v): return canonical_bytes(v)
def sha(b): return hashlib.sha256(b).hexdigest()
def load(path):
    b=Path(path).read_bytes(); return json.loads(b),b

def suffix(lang): return {"python":".py","go":".go","typescript_javascript":".mjs"}[lang]

def source_slice(source,span):
    sl,sc,el,ec=map(int,span); lines=source.splitlines(keepends=True)
    if sl==el: return lines[sl-1].encode("utf-8")[sc:ec]
    out=lines[sl-1].encode("utf-8")[sc:]
    for line in lines[sl:el-1]: out += line.encode("utf-8")
    out += lines[el-1].encode("utf-8")[:ec]
    return out

def frontend(language,path,data,go_helper):
    text=data.decode("utf-8")
    if language=="python": return extract_python(text)
    if language=="go": return extract_go_many([{"path":path,"data":data}],Path(go_helper))[path]
    if language=="typescript_javascript": return extract_js(text)
    raise ValueError(language)

def projected_contract(canon_entry,receipt,candidate_path,source):
    decl=copy.deepcopy(canon_entry["declaration"]); amap={x["anchor_key"]:x for x in receipt["anchors"]}
    decl["source"]={"git_blob_sha":"OPAQUE_RUNTIME_SOURCE","language":receipt["seed_id"].split("-")[1].lower(),"path":candidate_path,"sha256":receipt["candidate_source_sha256"]}
    decl["source"]["language"]={"py":"python","go":"go","ts":"typescript_javascript"}[receipt["seed_id"].split("-")[1].lower()]
    for key,a in decl["anchors"].items():
        row=amap[key]
        if row["realization_status"]!="ROLE_COMPATIBLE" or not row.get("candidate_span"): raise ValueError("transport anchor ineligible")
        a["span"]=list(row["candidate_span"]); a["slice_sha256"]=row["candidate_slice_sha256"]
        actual=source_slice(source,a["span"])
        if sha(actual)!=a["slice_sha256"]: raise ValueError("candidate anchor slice mismatch")
        a["slice_bytes"]=len(actual); a["unique_in_source"]=True
    for slot in ("expected_coordinate","current_coordinate"):
        sr=receipt["binding_slots"][slot]
        if sr["status"]!="AVAILABLE": raise ValueError("transport slot ineligible")
        if int(sr["operand_index"])!=int(decl["binding_slots"][slot]["operand_index"]): raise ValueError("transport operand index mismatch")
    decl["transport"]={"mutant_revision_authorized":True,"fresh_revision_authorized":False,"projection_authority":"FROZEN_RAW_BLIND_TRANSPORT_RECEIPT"}
    decl["verdict_authority"]=False
    return decl,sha(canon(decl))

def case_status(pathdoc):
    reasons=[]
    if not pathdoc["material_control_complete"]: reasons.append("CONTROL_INCOMPLETE")
    eg=pathdoc["effective_guard_observability"]
    if eg["form"] not in {"DIRECT_CONTROL","HELPER_CONTROL"}: reasons.append(eg.get("reason") or "EFFECTIVE_GUARD_UNPROVEN")
    if pathdoc["path_dataflow_correlation"]!="COMPLETE": reasons.append("PATH_DATAFLOW_CORRELATION_UNPROVEN")
    if pathdoc["effect_binding_surface"]["status"]!="UNIQUE": reasons.append("EFFECT_INVOCATION_UNRESOLVED")
    return ("OBSERVABILITY_QUALIFIED_FOR_A3_A4_EXECUTION" if not reasons else "OBSERVABILITY_INCOMPLETE",sorted(set(reasons)))

def witness_preconditions(pathdoc):
    complete=pathdoc["path_dataflow_correlation"]=="COMPLETE" and pathdoc["material_control_complete"]
    effect=pathdoc["effect_binding_surface"]["status"]=="UNIQUE"
    guard=pathdoc["effective_guard_observability"]["form"] in {"DIRECT_CONTROL","HELPER_CONTROL"}
    return {
      "A3_R1_WRONG_BINDING_IDENTITY":{"evaluable":complete and guard,"reason":None if complete and guard else "PATH_OR_GUARD_UNPROVEN"},
      "A3_R2_DEFINITE_OVERWRITE_TO_WRONG_CARRIER":{"evaluable":complete,"reason":None if complete else "PATH_DATAFLOW_CORRELATION_UNPROVEN"},
      "A3_R3_EXPLICIT_CARRIER_SUBSTITUTION_OR_DROP":{"evaluable":complete and effect,"reason":None if complete and effect else "EFFECT_OR_PATH_UNPROVEN"},
      "A3_R4_CLOSED_REPRESENTATION_OMISSION":{"evaluable":False,"reason":"REPRESENTATION_CLOSURE_UNPROVEN"},
      "A4_CONTROL_ORDER_OUTCOME_FAMILY":{"evaluable":complete and guard and effect,"reason":None if complete and guard and effect else "CONTROL_GUARD_OR_EFFECT_UNPROVEN"}}

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--protocol",required=True); ap.add_argument("--manifest",required=True); ap.add_argument("--transport",required=True); ap.add_argument("--anchors",required=True); ap.add_argument("--signatures",required=True); ap.add_argument("--candidate-dir",required=True); ap.add_argument("--go-helper",required=True); ap.add_argument("--output",required=True); a=ap.parse_args()
    protocol,praw=load(a.protocol); manifest,mraw=load(a.manifest); transport,traw=load(a.transport); anchors,_=load(a.anchors); signatures,sraw=load(a.signatures)
    if sha(mraw)!=MANIFEST_SHA: raise SystemExit("manifest sha mismatch")
    if sha(traw)!=TRANSPORT_SHA: raise SystemExit("transport sha mismatch")
    if sha(sraw)!=SIGNATURE_SHA: raise SystemExit("signature sha mismatch")
    if manifest["case_count"]!=58 or len(manifest["cases"])!=58 or any(set(x)!=CASE_FIELDS for x in manifest["cases"]): raise SystemExit("manifest malformed")
    if transport["case_count"]!=58 or len(transport["receipts"])!=58: raise SystemExit("transport malformed")
    by_receipt={r["transport_case_id"]:r for r in transport["receipts"]}; by_anchor={x["seed_id"]:x for x in anchors["contracts"]}; by_sig={x["seed_id"]:x for x in signatures["signatures"]}; rows=[]
    for meta in sorted(manifest["cases"],key=lambda x:x["transport_case_id"]):
        tid=meta["transport_case_id"]; receipt=by_receipt.get(tid); base={"transport_case_id":tid,"seed_id":meta["seed_id"],"language":meta["language"],"candidate_source_sha256":meta["candidate_source_sha256"],"transport_status":receipt["case_transport_status"] if receipt else "MISSING","semantic_authority":False}
        if receipt is None or receipt["candidate_source_sha256"]!=meta["candidate_source_sha256"] or receipt["seed_id"]!=meta["seed_id"]:
            base.update({"qualification_status":"INFRASTRUCTURE_INVALID_BEFORE_PREDICTION","reasons":["TRANSPORT_IDENTITY_MISMATCH"]}); rows.append(base); continue
        if receipt["case_transport_status"]!="COMPLETE":
            base.update({"qualification_status":"OBSERVABILITY_INCOMPLETE","reasons":["OBSERVABILITY_INCOMPLETE_TRANSPORT"],"base_ir_status":"NOT_EVALUATED","overlay_status":"NOT_EVALUATED","path_observability_status":"NOT_EVALUATED","representation_closure_status":"REPRESENTATION_CLOSURE_UNPROVEN"}); rows.append(base); continue
        cpath=Path(a.candidate_dir)/(tid+suffix(meta["language"])); raw=cpath.read_bytes()
        if sha(raw)!=meta["candidate_source_sha256"]:
            base.update({"qualification_status":"INFRASTRUCTURE_INVALID_BEFORE_PREDICTION","reasons":["CANDIDATE_SOURCE_HASH_MISMATCH"]}); rows.append(base); continue
        source=raw.decode("utf-8")
        try:
            contract,contract_sha=projected_contract(by_anchor[meta["seed_id"]],receipt,cpath.name,source)
            with tempfile.TemporaryDirectory() as td:
                p=Path(td)/cpath.name; p.write_bytes(raw); acq,acquired=acquire(Path(td),entrypoints=[p.name],config=AcquisitionConfig()); base_ir,status=build_ir(acquired,acquisition_doc=acq,go_helper_path=Path(a.go_helper))
            if status.get("status")!="PASS":
                base.update({"qualification_status":"INFRASTRUCTURE_INVALID_BEFORE_PREDICTION","reasons":["BASE_IR_BUILD_FAILURE"],"base_ir_status":status.get("status")}); rows.append(base); continue
            fdoc=frontend(meta["language"],cpath.name,raw,a.go_helper)
            if fdoc.get("status")!="PASS":
                base.update({"qualification_status":"INFRASTRUCTURE_INVALID_BEFORE_PREDICTION","reasons":["FRONTEND_PARSE_FAILURE"],"base_ir_status":"PASS"}); rows.append(base); continue
            overlay=build_overlay(path=cpath.name,source=source,source_sha256=meta["candidate_source_sha256"],language=meta["language"],facts=fdoc["facts"],base_ir=base_ir,anchor_contract=contract,anchor_contract_sha256=contract_sha); validate_overlay(overlay)
            pathdoc=build_path_observability(path=cpath.name,source=source,source_sha256=meta["candidate_source_sha256"],language=meta["language"],facts=fdoc["facts"],overlay=overlay,canonical_signature=by_sig[meta["seed_id"]]); q,reasons=case_status(pathdoc)
            base.update({"qualification_status":q,"reasons":reasons,"base_ir_status":"PASS","base_ir_digest_sha256":base_ir["ir_digest_sha256"],"overlay_status":"PASS","overlay_digest_sha256":overlay["overlay_digest_sha256"],"path_observability_status":"PASS","path_observability_digest_sha256":pathdoc["path_observability_digest_sha256"],"anchor_usability":"COMPLETE","effective_guard_observability":pathdoc["effective_guard_observability"],"control_scope_completeness":pathdoc["control_scope_completeness"],"path_dataflow_correlation":pathdoc["path_dataflow_correlation"],"effect_surface_status":pathdoc["effect_binding_surface"]["status"],"ordering_outcome_observability":{"effect_path_count":len(pathdoc["entry_effect_paths"]),"rejection_path_count":len(pathdoc["rejection_paths"]),"success_path_count":len(pathdoc["success_paths"])},"representation_closure_status":pathdoc["representation_closure_status"],"witness_precondition_observability":witness_preconditions(pathdoc),"candidate_anchor_contract_sha256":contract_sha})
        except Exception as exc:
            base.update({"qualification_status":"INFRASTRUCTURE_INVALID_BEFORE_PREDICTION","reasons":["OVERLAY_OR_PATH_BUILD_FAILURE"],"diagnostic_type":type(exc).__name__})
        rows.append(base)
    counts=Counter(x["qualification_status"] for x in rows)
    out={"schema":"risu.e2-a3-a4-candidate-observability-qualification-bundle/v0.1","semantic_authority":False,"case_count":58,"rows":rows,"qualification_status_counts":{k:counts[k] for k in sorted(counts)},"authorities":{"candidate_observability_protocol_git_blob":PROTOCOL_BLOB,"manifest_sha256":MANIFEST_SHA,"transport_sha256":TRANSPORT_SHA,"canonical_signature_sha256":SIGNATURE_SHA},"read_set_attestation":{"candidate_source_bytes":True,"sanitized_manifest":True,"raw_blind_transport":True,"canonical_anchors":True,"canonical_signatures":True,"postfreeze_join_or_compatibility_view":False,"mutation_truth":False,"operator_metadata":False,"expected_e2_prediction":False,"fresh_target_bytes":False},"claim_boundary":{"observability_only":True,"a3_a4_semantic_verdicts_emitted":False,"selection_or_exclusion_applied":False}}
    text=json.dumps(out,sort_keys=True,separators=(",",":"),ensure_ascii=False)
    for token in FORBIDDEN:
        if token in text: raise SystemExit("forbidden output token:"+token)
    out["bundle_digest_sha256"]=sha(canon(out)); Path(a.output).write_bytes(canon(out)); print(json.dumps({"status":"PASS","case_count":58,"counts":out["qualification_status_counts"],"sha256":sha(Path(a.output).read_bytes())},sort_keys=True,separators=(",",":")))
if __name__=="__main__": main()
