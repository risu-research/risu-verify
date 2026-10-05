#!/usr/bin/env python3
"""Q0 R0 selected independent-reference certificate replay."""
from __future__ import annotations
import hashlib,json,sys,tempfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1];TOOLS=ROOT/"tools";sys.path.insert(0,str(TOOLS))
import risu_kernel_k1_mfst_c3_cert_q0_common as q
import risu_kernel_k1_mfst_c3_r0_compiler as comp

W0="w:sha256:"+"1"*64;W1="w:sha256:"+"2"*64
ROOT_DIGEST="c731db89e79e75f4d22f38788aded1a9c9e70572467615da448b7e1c9ce93346"
IDS=['R0-00001','R0-06348','R0-12567','R0-00474','R0-06693','R0-13032','R0-06994','R0-13213','R0-01120','R0-07339','R0-13686','R0-01465','R0-13859','R0-01774','R0-07985','R0-14332','R0-02055','R0-08394','R0-02420','R0-08639','R0-14914','R0-02701','R0-09040','R0-15259','R0-09221','R0-15560','R0-03347','R0-09694','R0-15905','R0-03820','R0-16214','R0-03993','R0-10340','R0-16559','R0-04466','R0-10685','R0-04647','R0-10986','R0-17205','R0-05112','R0-11267','R0-17614','R0-11632','R0-17851','R0-05702','R0-11913','R0-18260','R0-06047']
VETO=[
 ("R0-VETO-PREDICATE-FLIP","R0-00001","predicate_flip"),
 ("R0-VETO-PREFIX-DROP","R0-00065","prefix_drop"),
 ("R0-VETO-EFFECT-ORDER","R0-00017","effect_order"),
 ("R0-VETO-TABLE-ROW","R0-11009","table_row"),
]

def load_ref(path):
    h=hashlib.sha256();rows=[]
    with open(path,"rb") as f:
        for line in f:
            if not line.endswith(b"\n"):raise AssertionError("W9 line LF")
            h.update(line);rows.append(json.loads(line))
    if len(rows)!=18432 or h.hexdigest()!=ROOT_DIGEST:raise AssertionError(("W9 root/count",len(rows),h.hexdigest()))
    for i,r in enumerate(rows):
        if r["descriptor_id"]!=f"R0-{i:05d}":raise AssertionError(("W9 id",i,r["descriptor_id"]))
    return rows

def expected(rec):
    out=[]
    for p in rec["point_traces"]:
        w=W0 if p["world_symbol"]=="W0" else W1
        x="v0" if p["x_symbol"]=="X0" else "v1"
        out.append({"point":{"@world":w,"x":x},"payloads":list(p["payloads"])})
    return out

def main():
    if len(sys.argv)!=2:raise SystemExit("usage: q0_r0.py W9_REFERENCE_JSONL")
    rows=load_ref(sys.argv[1]);by={r["descriptor_id"]:r for r in rows}
    if len(IDS)!=48 or len(set(IDS))!=48:raise AssertionError("R0 selection drift")
    with tempfile.TemporaryDirectory() as s:
        td=Path(s);ordinary={}
        for rid in IDS:
            rec=by[rid];raw=comp.compile_bytes(rec)
            b=q.derive_bundle(raw,td,"r0-"+rid)
            if b["r7"]["direct_trace_map"]!=expected(rec):raise AssertionError((rid,"W9 trace mismatch",expected(rec),b["r7"]["direct_trace_map"]))
            q.check_pair(b,"ACCEPTED","Q0-"+rid)
            ordinary[rid]=b
            print("Q0_R0_CERT_PASS",rid,b["doc"]["certificate_id"])
        veto=0
        for cid,rid,mutation in VETO:
            rec=by[rid]
            good=ordinary.get(rid)
            if good is None:good=q.derive_bundle(comp.compile_bytes(rec),td,cid+"-good")
            if good["r7"]["direct_trace_map"]!=expected(rec):raise AssertionError((cid,"good W9 mismatch"))
            bad_obj=comp.compile_descriptor(rec,mutation=mutation)
            bad_raw=json.dumps(bad_obj,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode()
            bad=q.derive_bundle(bad_raw,td,cid+"-mutated")
            # The certificate is valid for the actual mutated C3 source.
            q.check_pair(bad,"ACCEPTED",cid+"-certificate-valid")
            if bad["r7"]["direct_trace_map"]==expected(rec):raise AssertionError((cid,"W9 failed to veto"))
            same=bad["r7"]["projected_realize"]==good["r7"]["projected_realize"]
            if cid=="R0-VETO-EFFECT-ORDER" and not same:raise AssertionError((cid,"K1 set unexpectedly changed"))
            veto+=1
            print("Q0_R0_W9_VETO_PASS",cid,rid,mutation,"CERTIFICATE_VALID true","K1_SAME",str(same).lower())
        if veto!=4:raise AssertionError(("veto count",veto))
    print("Q0_R0_REFERENCE_CERTIFICATE_PASS 48 VETO 4")
    print("AUTHORITY_CREATED false")
if __name__=="__main__":main()
