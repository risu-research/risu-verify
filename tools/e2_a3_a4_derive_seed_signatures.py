#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Mapping

FROZEN_OVERLAY_FILE_SHA256 = "2d231b9eae523d7fb84925c302398c4913670b765cb10e2c4f76dc988cc5ea36"
FROZEN_OVERLAY_INTERNAL_SHA256 = "2d3f6559845323b6821f18920b727a90e5520514f00308af59e6f55a67d683cd"
PREREG_COMMIT = "1efc11b4f5b3a3e51cc1168c076be67213f335e0"
FROZEN_ANCHOR_BUNDLE_SHA256 = "e88b1c91bc2006b262351f6ac6dff6733078589024cc20645795c1f352b69d8c"
ALLOWED_HELPER_DERIVATIONS = {"comparison_result_to_return", "function_return_to_call_result"}


def cbytes(v: Any) -> bytes:
    return (json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()

def digest(v: Any) -> str: return hashlib.sha256(cbytes(v)).hexdigest()
def file_sha(p: Path) -> str: return hashlib.sha256(p.read_bytes()).hexdigest()

def span_contains(a: Mapping[str,Any], b: Mapping[str,Any]) -> bool:
    A=a["span"]; B=b["span"]
    if A.get("path") != B.get("path"): return False
    return (A["start_line"],A["start_col"]) <= (B["start_line"],B["start_col"]) and (B["end_line"],B["end_col"]) <= (A["end_line"],A["end_col"])

def out_edges(o, src, kind=None):
    return [e for e in o["edges"] if e["source"]==src and (kind is None or e["kind"]==kind)]
def in_edges(o, tgt, kind=None):
    return [e for e in o["edges"] if e["target"]==tgt and (kind is None or e["kind"]==kind)]

def reachable_precedes(o, start: str) -> set[str]:
    adj=defaultdict(list)
    for e in o["edges"]:
        if e["kind"]=="PRECEDES": adj[e["source"]].append(e["target"])
    seen={start}; q=deque([start])
    while q:
        u=q.popleft()
        for v in adj[u]:
            if v not in seen: seen.add(v); q.append(v)
    return seen

def unique_anchor(o, role):
    xs=[n for n in o["nodes"] if n.get("attrs",{}).get("anchor_role")==role]
    if len(xs)!=1: raise ValueError(f"anchor {role}: expected 1 got {len(xs)}")
    return xs[0]

def branch_map(o, guard_id):
    rows=out_edges(o,guard_id,"GUARDS")
    by={e.get("attrs",{}).get("branch_polarity"):e["target"] for e in rows}
    if set(by)!={False,True} or len(rows)!=2: raise ValueError("effective guard lacks exact true/false branches")
    return by

def derive_effective_guard(o, anchor_guard):
    direct=out_edges(o,anchor_guard["id"],"GUARDS")
    if len(direct)==2 and {e.get("attrs",{}).get("branch_polarity") for e in direct}=={False,True}:
        return "DIRECT_CONTROL", anchor_guard, []
    chains=[]
    for e1 in out_edges(o,anchor_guard["id"],"DERIVES"):
        if e1.get("attrs",{}).get("derivation")!="comparison_result_to_return": continue
        ret=e1["target"]
        for e2 in out_edges(o,ret,"DERIVES"):
            if e2.get("attrs",{}).get("derivation")!="function_return_to_call_result": continue
            cres=e2["target"]
            for e3 in out_edges(o,cres,"COMPARES"):
                if "CONTROL_PREDICATE_RESULT" not in e3.get("attrs",{}).get("operators",[]): continue
                cg=e3["target"]
                try: branch_map(o,cg)
                except ValueError: continue
                chains.append((ret,cres,cg))
    if len(chains)!=1: raise ValueError(f"helper control: expected unique chain, got {len(chains)}")
    nm={n["id"]:n for n in o["nodes"]}; ret,cres,cg=chains[0]
    scopes={nm[x].get("attrs",{}).get("scope") for x in (ret,cres,cg) if nm[x].get("attrs",{}).get("scope")}
    complete={r["scope"] for r in o.get("control_completeness",[]) if r.get("status")=="COMPLETE"}
    if not scopes <= complete: raise ValueError("helper chain crosses non-COMPLETE scope")
    return "HELPER_CONTROL", nm[cg], ["GUARD_COMPARISON_RESULT","RETURN_BOUNDARY","CALL_RESULT","CONSUMER_GUARD"]

def derive_lineage_relations(o, slots):
    roles=sorted(slots)
    vals={r:tuple(slots[r]["value_instance_ids"]) for r in roles}
    if any(len(v)!=1 for v in vals.values()): raise ValueError("canonical slot must bind exactly one value")
    rel=[]
    for r in roles:
        rel.append({"relation":"REACHES","source_role":f"BOUND_VALUE:{r}","terminal_role":f"GUARD_SLOT:{r}","slot":{"anchor":slots[r]["anchor"],"operand_index":slots[r]["operand_index"]}})
    for i,a in enumerate(roles):
        for b in roles[i+1:]:
            rel.append({"relation":"SAME_ORIGIN" if vals[a][0]==vals[b][0] else "DISTINCT_ORIGIN","role_a":f"GUARD_SLOT:{a}","role_b":f"GUARD_SLOT:{b}"})
    return rel

def derive_one(item):
    sid=item["seed_id"]; o=item["overlay"]
    if o.get("semantic_authority") is not False: raise ValueError(f"{sid}: semantic_authority")
    if any(r.get("status")!="COMPLETE" for r in o.get("control_completeness",[])): raise ValueError(f"{sid}: canonical control incomplete")
    g=unique_anchor(o,"GUARD_COMPARISON"); eff=unique_anchor(o,"EFFECT_BOUNDARY"); suc=unique_anchor(o,"SUCCESS_OUTCOME"); rej=unique_anchor(o,"REJECTION_NO_EFFECT_OUTCOME")
    form,eg,helper_shape=derive_effective_guard(o,g)
    branches=branch_map(o,eg["id"])
    reach={p:reachable_precedes(o,b) for p,b in branches.items()}
    ep=[p for p,s in reach.items() if eff["id"] in s]
    rp=[p for p,s in reach.items() if rej["id"] in s]
    if len(ep)!=1 or len(rp)!=1 or ep[0]==rp[0]: raise ValueError(f"{sid}: non-unique consequence polarity")
    effect_polarity=ep[0]; rejection_polarity=rp[0]
    if suc["id"] not in reachable_precedes(o,eff["id"]): raise ValueError(f"{sid}: effect !-> success")
    if eff["id"] in reach[rejection_polarity]: raise ValueError(f"{sid}: rejection branch reaches effect")
    ops=[n for n in o["nodes"] if n["kind"]=="OPERATION" and span_contains(eff,n) and n.get("attrs",{}).get("operation_role") in {"call","representation_instance"}]
    if len(ops)!=1: raise ValueError(f"{sid}: effect structural operation count={len(ops)}")
    op=ops[0]
    coord_slots=[]
    for e in in_edges(o,op["id"]):
        if e["kind"]=="CARRIES": coord_slots.append({k:v for k,v in e.get("attrs",{}).items() if k in {"argument_index","field","receiver_role","resource_role","carrier_boundary"}})
    coord_slots=sorted(coord_slots,key=lambda z:json.dumps(z,sort_keys=True))
    bslots={k:{"anchor":v["anchor"],"operand_index":v["operand_index"],"cardinality":len(v.get("value_instance_ids",[]))} for k,v in sorted(o["binding_slots"].items())}
    lineage=derive_lineage_relations(o,o["binding_slots"])
    core={"seed_id":sid,"source_sha256":o["files"][0]["sha256"],"anchor_contract_sha256":item["contract_canonical_sha256"],"guard_anchor_role":"GUARD_COMPARISON","effective_guard_form":form,"helper_passthrough_shape":helper_shape,"effect_polarity":effect_polarity,"rejection_polarity":rejection_polarity,"required_binding_slot_roles":bslots,"required_lineage_obligations":lineage,"effect_invocation_binding_surface":{"resolution":"UNIQUE_STRUCTURAL_OPERATION_WITHIN_EFFECT_ANCHOR","operation_role":op.get("attrs",{}).get("operation_role"),"coordinate_carrier_slots":coord_slots,"noncoordinate_representation_fields_not_promoted_to_a3_roles":op.get("attrs",{}).get("operation_role")=="representation_instance"},"opaque_lineage_equivalence":{"role_universe":[f"GUARD_SLOT:{k}" for k in sorted(o["binding_slots"])],"relations":[r for r in lineage if r["relation"] in {"SAME_ORIGIN","DISTINCT_ORIGIN"}]},"ordering_obligations":["EFFECT_BOUNDARY PRECEDES SUCCESS_OUTCOME","EFFECTIVE_GUARD PRECEDES EFFECT_BOUNDARY on effect polarity"],"terminal_obligations":["rejection polarity reaches REJECTION_NO_EFFECT_OUTCOME without prior EFFECT_BOUNDARY","effect polarity reaches EFFECT_BOUNDARY then SUCCESS_OUTCOME"],"control_scope_status":"COMPLETE","semantic_authority":False}
    core["canonical_signature_digest_sha256"]=digest(core)
    return core

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--overlay-bundle',type=Path,required=True); ap.add_argument('--anchor-bundle',type=Path,required=True); ap.add_argument('--output',type=Path,required=True); ap.add_argument('--receipt',type=Path,required=True); a=ap.parse_args()
    if file_sha(a.anchor_bundle)!=FROZEN_ANCHOR_BUNDLE_SHA256: raise SystemExit('frozen anchor bundle sha mismatch')
    anchors=json.loads(a.anchor_bundle.read_text()); amap={r['seed_id']:r for r in anchors.get('contracts',[])}
    if len(amap)!=6: raise SystemExit('frozen anchor bundle seed count mismatch')
    if file_sha(a.overlay_bundle)!=FROZEN_OVERLAY_FILE_SHA256: raise SystemExit('frozen overlay file sha mismatch')
    b=json.loads(a.overlay_bundle.read_text())
    if b.get('bundle_digest_sha256')!=FROZEN_OVERLAY_INTERNAL_SHA256 or b.get('seed_count')!=6: raise SystemExit('frozen overlay identity mismatch')
    for i in b['overlays']:
        ar=amap.get(i['seed_id']); o=i['overlay']
        if not ar or ar.get('contract_canonical_sha256')!=i.get('contract_canonical_sha256'): raise SystemExit('anchor contract binding mismatch:'+i['seed_id'])
        if ar['declaration']['source']['sha256']!=o['files'][0]['sha256']: raise SystemExit('anchor source binding mismatch:'+i['seed_id'])
        for role,spec in ar['declaration']['binding_slots'].items():
            got=o['binding_slots'].get(role,{})
            if got.get('anchor')!=spec.get('anchor') or got.get('operand_index')!=spec.get('operand_index'): raise SystemExit('anchor slot binding mismatch:'+i['seed_id']+':'+role)
    sigs=[derive_one(i) for i in sorted(b['overlays'],key=lambda z:z['seed_id'])]
    bundle={"schema":"risu.e2-a3-a4-canonical-consequence-signature-bundle/v0.1","preregistration_commit":PREREG_COMMIT,"source_overlay_file_sha256":FROZEN_OVERLAY_FILE_SHA256,"source_anchor_bundle_sha256":FROZEN_ANCHOR_BUNDLE_SHA256,"source_overlay_internal_digest_sha256":FROZEN_OVERLAY_INTERNAL_SHA256,"seed_count":len(sigs),"semantic_authority":False,"signatures":sigs,"firewall":{"candidate_or_mutant_bytes_read":False,"mutation_truth_read":False,"operator_metadata_read":False,"fresh_target_bytes_read":False,"identifier_spelling_used_as_semantic_role_authority":False,"callee_spelling_used_as_effect_semantic_authority":False}}
    bundle["bundle_digest_sha256"]=digest(bundle)
    a.output.write_bytes(cbytes(bundle))
    rec={"schema":"risu.e2-a3-a4-canonical-signature-derivation-receipt/v0.1","status":"PASS","seed_count":6,"bundle_sha256":file_sha(a.output),"bundle_internal_digest_sha256":bundle['bundle_digest_sha256'],"control_forms":{"DIRECT_CONTROL":sum(s['effective_guard_form']=='DIRECT_CONTROL' for s in sigs),"HELPER_CONTROL":sum(s['effective_guard_form']=='HELPER_CONTROL' for s in sigs)},"polarities":[{"seed_id":s['seed_id'],"effect":s['effect_polarity'],"rejection":s['rejection_polarity']} for s in sigs],"firewall":bundle['firewall']}
    a.receipt.write_bytes(cbytes(rec)); print(json.dumps(rec,sort_keys=True,separators=(',',':')))
if __name__=='__main__': main()
