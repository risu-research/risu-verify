#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json, re
from collections import Counter
from pathlib import Path
from typing import Any, Mapping

PROTOCOL_SCHEMA="risu.e2-candidate58-gate2b5-guard-operator-evidence-attribution-protocol/v0.1"
G2B4_SCHEMA="risu.e2-candidate58-gate2b4-counterfactual-obligation-sufficiency-ledger/v0.1"
OVERLAY_SCHEMA="risu.e2-observability-overlay/v0.1"
EXPECTED_G2B4_SHA256="ac1ad9acd7cb35decfd5d3dc3f03a92317d92653426bdef41787a17188233ae1"
EXPECTED_MANIFEST_SHA256="c5030f084936c186b1d320b02ad8bf1e1648bbc9e97ad78b33db81fb9a6bd217"
TARGET="GUARD_OPERATOR_UNRESOLVED"
PRIMARY_TAX="SCOPE_ONLY_INSUFFICIENT_SINGLE_RESIDUAL_FAMILY"
SECONDARY="OUTSIDE_GATE2B5_OPERATOR_FRONTIER"
TAXA=("TRACE_EVIDENCE_INCOMPLETE","FROZEN_CHAIN_INCONSISTENT","ANCHOR_COMPARE_LINKAGE_UNRESOLVED","OPERATOR_CARRIER_EMPTY_ALL_EDGES","OPERATOR_CARRIER_PARTIAL_OR_NONUNIQUE","OPERATOR_TOKEN_NORMALIZATION_UNSUPPORTED","OPERATOR_NORMALIZED_CONFLICT",SECONDARY)
HEX64=re.compile(r"^[0-9a-f]{64}$")
NORM={"Eq":"EQ","EQ":"EQ","==":"EQ","===":"EQ","EQL":"EQ","NotEq":"NE","NE":"NE","!=":"NE","!==":"NE","NEQ":"NE"}

def cbytes(v:Any)->bytes:return (json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=False)+"\n").encode()
def sha(raw:bytes)->str:return hashlib.sha256(raw).hexdigest()
def shafile(p:Path)->str:return sha(p.read_bytes())
def load(p:Path)->Any:return json.loads(p.read_text(encoding="utf-8"))
def write(p:Path,v:Any)->str:
    raw=cbytes(v);p.write_bytes(raw);return sha(raw)

def selected_cases(g4:Mapping[str,Any])->tuple[list[str],list[str]]:
    if g4.get("schema")!=G2B4_SCHEMA or g4.get("case_count")!=39:raise ValueError("Gate2B4 ledger authority mismatch")
    rows=g4.get("rows",[]) or []
    if len(rows)!=39:raise ValueError("Gate2B4 row count mismatch")
    ids=[];secondary=[];seen=set()
    for r in rows:
        if not isinstance(r,Mapping):raise ValueError("non-object Gate2B4 row")
        cid=str(r.get("case_id") or "")
        if not HEX64.fullmatch(cid) or cid in seen:raise ValueError("Gate2B4 case-id integrity failure")
        seen.add(cid)
        primary=(r.get("gate2b4_taxonomy_id")==PRIMARY_TAX and r.get("residual_primitive_atom_prefixes")==[TARGET] and r.get("residual_distinct_family_count")==1)
        (ids if primary else secondary).append(cid)
    if len(ids)!=30 or len(secondary)!=9:raise ValueError(f"Gate2B5 population mismatch:{len(ids)}:{len(secondary)}")
    return sorted(ids),sorted(secondary)

def manifest_map(m:Mapping[str,Any])->dict[str,Mapping[str,Any]]:
    rows=m.get("files",[]) or []
    if m.get("file_count")!=946 or len(rows)!=946:raise ValueError("bundle manifest cardinality mismatch")
    out={}
    for r in rows:
        if not isinstance(r,Mapping):raise ValueError("manifest row not object")
        p=str(r.get("path") or "")
        if not p or p in out or not HEX64.fullmatch(str(r.get("sha256") or "")):raise ValueError("manifest path/hash integrity failure")
        out[p]=r
    return out

def anchor_and_edges(overlay:Mapping[str,Any])->tuple[str,list[Mapping[str,Any]]]:
    if overlay.get("schema")!=OVERLAY_SCHEMA:raise ValueError("overlay schema mismatch")
    anchors=[]
    node_ids=set()
    for n in overlay.get("nodes",[]) or []:
        if not isinstance(n,Mapping) or not n.get("id"):raise ValueError("malformed overlay node")
        nid=str(n["id"]);node_ids.add(nid)
        if (n.get("attrs",{}) or {}).get("anchor_role")=="GUARD_COMPARISON":anchors.append(nid)
    if len(anchors)!=1:raise ValueError(f"unique GUARD_COMPARISON anchor required:{len(anchors)}")
    aid=anchors[0];edges=[]
    for e in overlay.get("edges",[]) or []:
        if not isinstance(e,Mapping):raise ValueError("malformed overlay edge")
        if e.get("kind")=="COMPARES" and str(e.get("target"))==aid:edges.append(e)
    return aid,sorted(edges,key=lambda e:(int((e.get("attrs",{}) or {}).get("operand_index",-1)),str(e.get("source")),str(e.get("id"))))

def reconstruct(edges:list[Mapping[str,Any]])->str|None:
    rows=[]
    for e in edges:
        attrs=e.get("attrs",{}) or {};ops=attrs.get("operators",[]) or []
        if not isinstance(ops,list) or len(ops)!=1:return None
        op=NORM.get(str(ops[0]))
        if op is None:return None
        rows.append(op)
    return rows[0] if rows and len(set(rows))==1 else None

def classify_overlay(overlay:Mapping[str,Any])->dict[str,Any]:
    try: aid,edges=anchor_and_edges(overlay)
    except Exception as exc:
        return {"taxonomy":"TRACE_EVIDENCE_INCOMPLETE","detail":type(exc).__name__,"anchor_id":None,"edge_count":None,"operator_lists":None,"reconstructed_operator":None}
    op_lists=[];presence=[];indices=[];raw=[];norm=[]
    malformed=False
    for e in edges:
        attrs=e.get("attrs",{}) or {};presence.append("operators" in attrs);ops=attrs.get("operators",[]) or []
        if not isinstance(ops,list):malformed=True;ops=[]
        op_lists.append([str(x) for x in ops]);indices.append(attrs.get("operand_index"))
        raw.extend(str(x) for x in ops);norm.extend(NORM.get(str(x)) for x in ops)
    resolved=reconstruct(edges)
    if resolved is not None:tax="FROZEN_CHAIN_INCONSISTENT"
    elif not edges:tax="ANCHOR_COMPARE_LINKAGE_UNRESOLVED"
    elif malformed:tax="TRACE_EVIDENCE_INCOMPLETE"
    elif all(len(x)==0 for x in op_lists):tax="OPERATOR_CARRIER_EMPTY_ALL_EDGES"
    elif any(len(x)!=1 for x in op_lists):tax="OPERATOR_CARRIER_PARTIAL_OR_NONUNIQUE"
    elif any(x is None for x in norm):tax="OPERATOR_TOKEN_NORMALIZATION_UNSUPPORTED"
    elif len(set(norm))>1:tax="OPERATOR_NORMALIZED_CONFLICT"
    else:tax="FROZEN_CHAIN_INCONSISTENT"
    return {"taxonomy":tax,"anchor_id":aid,"edge_count":len(edges),"operand_indexes":indices,"operator_field_present":presence,"operator_lists":op_lists,"raw_operator_tokens":raw,"normalized_operator_tokens":norm,"reconstructed_operator":resolved}

def analyze(protocol:Mapping[str,Any],g4:Mapping[str,Any],manifest:Mapping[str,Any],evidence_dir:Path)->tuple[dict[str,Any],dict[str,Any]]:
    if protocol.get("schema")!=PROTOCOL_SCHEMA:raise ValueError("Gate2B5 protocol schema mismatch")
    primary,secondary=selected_cases(g4);mm=manifest_map(manifest)
    expected={f"prepared/evidence/{cid}.overlay.json" for cid in primary}
    present={f"prepared/evidence/{p.name}" for p in evidence_dir.iterdir() if p.is_file()}
    if present!=expected:raise ValueError(f"evidence surface mismatch:{len(present)}:{len(expected)}")
    counts=Counter();buckets={k:[] for k in TAXA};edge_dist=Counter();card_sig=Counter();raw_tokens=Counter();operand_sig=Counter();rows=[]
    for cid in primary:
        rel=f"prepared/evidence/{cid}.overlay.json";row=mm.get(rel)
        if row is None:raise ValueError(f"manifest overlay missing:{cid}")
        p=evidence_dir/f"{cid}.overlay.json"
        if shafile(p)!=row.get("sha256"):raise ValueError(f"manifest overlay digest mismatch:{cid}")
        ov=load(p);res=classify_overlay(ov)
        if res["taxonomy"]=="TRACE_EVIDENCE_INCOMPLETE":raise ValueError(f"trace evidence incomplete:{cid}:{res.get('detail')}")
        if res["reconstructed_operator"] is not None:raise ValueError(f"frozen-chain inconsistency:{cid}:{res['reconstructed_operator']}")
        tax=res["taxonomy"];counts[tax]+=1;buckets[tax].append(cid);edge_dist[str(res["edge_count"])]+=1
        card_sig["+".join(str(len(x)) for x in res["operator_lists"]) if res["operator_lists"] else "<NO_EDGES>"]+=1
        for tok in res["raw_operator_tokens"]:raw_tokens[tok]+=1
        operand_sig["+".join(str(x) for x in sorted(res["operand_indexes"],key=lambda x:(str(type(x)),str(x)))) if res["operand_indexes"] else "<NO_EDGES>"]+=1
        rows.append({"case_id":cid,"gate2b5_taxonomy_id":tax,"manifest_bound_overlay":{"path":rel,"sha256":row["sha256"]},"anchored_guard_id":res["anchor_id"],"incoming_compares_edge_count":res["edge_count"],"operand_indexes":res["operand_indexes"],"operator_field_present":res["operator_field_present"],"raw_operator_lists":res["operator_lists"],"raw_operator_tokens":res["raw_operator_tokens"],"normalized_operator_tokens":res["normalized_operator_tokens"],"independent_frozen_adapter_operator":res["reconstructed_operator"]})
    counts[SECONDARY]=len(secondary);buckets[SECONDARY]=secondary
    summary={"schema":"risu.e2-candidate58-gate2b5-guard-operator-evidence-attribution-summary/v0.1","status":"GATE2B5_OPERATOR_EVIDENCE_BOUNDARY_PROFILE_NOT_UPSTREAM_ROOT_CAUSE","all_gate2b4_case_count":39,"primary_operator_frontier_case_count":30,"secondary_outside_frontier_case_count":9,"taxonomy_counts":{k:counts.get(k,0) for k in TAXA},"taxonomy_case_ids":{k:sorted(buckets[k]) for k in TAXA},"incoming_compares_edge_count_distribution":dict(sorted(edge_dist.items())),"operator_list_cardinality_signature_counts":dict(sorted(card_sig.items())),"raw_operator_token_counts":dict(sorted(raw_tokens.items())),"operand_index_signature_counts":dict(sorted(operand_sig.items())),"interpretation_boundary":{"boundary_attribution_not_upstream_semantic_root_cause":True,"definitive_verdict_gain_inferred":False,"remediation_priority_inferred":False,"truth_or_operator_metadata_used":False}}
    ledger={"schema":"risu.e2-candidate58-gate2b5-guard-operator-evidence-attribution-ledger/v0.1","status":"GATE2B5_FROZEN_OPERATOR_BOUNDARY_ATTRIBUTION_NOT_REMEDIATION","case_count":39,"primary_case_count":30,"secondary_case_count":9,"rows":rows,"secondary_case_ids":secondary}
    return ledger,summary

def main()->int:
    ap=argparse.ArgumentParser();ap.add_argument("--protocol",type=Path,required=True);ap.add_argument("--gate2b4-ledger",type=Path,required=True);ap.add_argument("--manifest",type=Path,required=True);ap.add_argument("--evidence-dir",type=Path,required=True);ap.add_argument("--output-dir",type=Path,required=True);a=ap.parse_args()
    if shafile(a.gate2b4_ledger)!=EXPECTED_G2B4_SHA256:raise ValueError("Gate2B4 ledger SHA256 mismatch")
    if shafile(a.manifest)!=EXPECTED_MANIFEST_SHA256:raise ValueError("bundle manifest SHA256 mismatch")
    ledger,summary=analyze(load(a.protocol),load(a.gate2b4_ledger),load(a.manifest),a.evidence_dir);a.output_dir.mkdir(parents=True,exist_ok=False)
    ls=write(a.output_dir/"E2_CANDIDATE58_GATE2B5_GUARD_OPERATOR_ATTRIBUTION_LEDGER.json",ledger);ss=write(a.output_dir/"E2_CANDIDATE58_GATE2B5_GUARD_OPERATOR_ATTRIBUTION_SUMMARY.json",summary)
    rec={"schema":"risu.e2-candidate58-gate2b5-diagnostic-receipt/v0.1","status":"FIRST_COMPLETE_GATE2B5_LOGICAL_OUTPUT","inputs":{"protocol_sha256":shafile(a.protocol),"gate2b4_ledger_sha256":shafile(a.gate2b4_ledger),"bundle_manifest_sha256":shafile(a.manifest)},"outputs":{"ledger_sha256":ls,"summary_sha256":ss},"scientific_firewall":{"candidate_source_read":False,"path_evidence_read":False,"semantic_slice_read":False,"adapter_receipt_read":False,"kernel_result_read":False,"certificate_or_c1_read":False,"truth_or_operator_metadata_read":False,"epistemic10_read":False,"fresh_heldout_read":False,"semantic_engine_kernel_adapter_or_c1_rerun":False,"semantic_rule_change":False,"remediation":False}}
    write(a.output_dir/"E2_CANDIDATE58_GATE2B5_DIAGNOSTIC_RECEIPT.json",rec);return 0
if __name__=="__main__":raise SystemExit(main())
