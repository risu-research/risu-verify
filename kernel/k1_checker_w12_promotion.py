#!/usr/bin/env python3
"""P0 candidate production-promotion checker W12 (Python).

Non-production P0 checker. It validates the promotion composition around the
Q0-qualified W10/W11 pair and existing W0 certificate transcript. It creates
no production authority by itself.
"""
from __future__ import annotations
import argparse, hashlib, json, re, subprocess, sys
from pathlib import Path

PROOF_FORMAT="risu.k1.mediated-refinement-proof/v1"
PROOF_KIND="k1.mediated-refinement/v1"
SOURCE_SEM="risu.k1.c3.mfst/v1"
DOWNSTREAM="k1.capsule-closure/v1"
SCOPE="EXACT_MFST_SOURCE_TO_EXACT_QUALIFIED_C2_LOWERING"
Q0_CANDIDATE="A1"
Q0_ANCHOR_COMMIT="a857fe1f72b7341d549354e9ccc330dca22e9c0d"
Q0_ANCHOR_BLOB="592afac89231040280e9e29ba26292c18f90b9e6"
W10_BLOB="5eea6fa26bdb488d60743a4bf3470cd5bd28eab3"
W11_BLOB="1434a9255d42ad9e9b8d57f9e1c1fa1d47c6a8a0"
SOURCE_PINS={
 "w10_source":W10_BLOB,
 "w11_source":W11_BLOB,
 "w7_model_source":"3c351fd445b704d693e05ba01efe9cffa6a2801b",
 "w7_exec_source":"8b1529dfbd8367e20776f0ab8ec3f5fa6559ca2a",
 "w7_source":"c011532efbe9b6dcd6ae440705ce7b38c5dde93b",
 "w8_json_source":"4e770c8ef7882b23705bb7068bd877c2cd9c3543",
 "w8_model_source":"b53897a82255886d59b9dc05d7fbe8166aca1d35",
 "w8_exec_source":"64254a8537d3777848b1d3f8176260c5a1c312e7",
 "w8_source":"f3e1e0c42e8106615b0aeeb2a85ceae3046e74a2",
 "w5_source":"cf08aff1ce9f9506df37d597c2fc348bfefd6331",
 "w6_source":"33464fe4132d6490b1a68cc71ef803d584e597f9",
}
PROMO_KEYS={
 "proof_format","proof_kind","claim_id","source_semantics","downstream_proof_kind","authority_scope",
 "profile_sha256","c3_certificate_sha256","c3_certificate_id","c2_program_sha256","c2_artifact_id","c2_target_id",
 "q0_candidate_id","q0_qualification_anchor_commit","q0_qualification_anchor_blob","w10_blob","w11_blob"
}
OUTER_KEYS={"wire","kind","claim_id","target_id","realize","closure_proof","grounding_proofs","evidence_roots","certificate_id"}
PAT={
 "claim":re.compile(r"^claim:sha256:[0-9a-f]{64}$"),
 "c3cert":re.compile(r"^c3cert:sha256:[0-9a-f]{64}$"),
 "sha":re.compile(r"^[0-9a-f]{64}$"),
 "p":re.compile(r"^p:sha256:[0-9a-f]{64}$"),
 "t":re.compile(r"^t:sha256:[0-9a-f]{64}$"),
 "w":re.compile(r"^w:sha256:[0-9a-f]{64}$"),
 "c":re.compile(r"^c:sha256:[0-9a-f]{64}$"),
 "e":re.compile(r"^e:sha256:[0-9a-f]{64}$"),
 "cert":re.compile(r"^cert:sha256:[0-9a-f]{64}$"),
}
class Reject(Exception): pass

def pairs_hook(xs):
    d={}
    for k,v in xs:
        if k in d: raise Reject("duplicate JSON key:"+k)
        d[k]=v
    return d

def loads(raw,where):
    try:return json.loads(raw.decode("utf-8","strict"),object_pairs_hook=pairs_hook)
    except Reject:raise
    except Exception as e:raise Reject(where+": invalid JSON") from e

def net(s):
    b=s.encode();return str(len(b)).encode()+b":"+b+b","

def git_blob(raw):
    return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()

def relation(v,where):
    if not isinstance(v,list):raise Reject(where+": not array")
    out=[]
    seen=set()
    for i,row in enumerate(v):
        if not isinstance(row,list) or len(row)!=2:raise Reject(f"{where}[{i}]: not pair")
        w,c=row
        if not isinstance(w,str) or not PAT["w"].fullmatch(w):raise Reject(where+": bad world")
        if not isinstance(c,str) or not PAT["c"].fullmatch(c):raise Reject(where+": bad consequence")
        if (w,c) in seen:raise Reject(where+": duplicate pair")
        seen.add((w,c));out.append((w,c))
    return sorted(out)

def evidence_root(claim,artifact,c3id,target):
    pre=b"RISU-K1-MEDIATED-REFINEMENT-PROOF-V1\0"
    for tag,val in ((b"C",claim),(b"A",artifact),(b"R",c3id),(b"T",target),(b"Q",Q0_ANCHOR_COMMIT),(b"X",W10_BLOB),(b"Y",W11_BLOB)):
        pre+=tag+net(val)
    return "e:sha256:"+hashlib.sha256(pre).hexdigest()

def outer_cert_id(doc):
    real=relation(doc["realize"],"outer.realize")
    gp=doc["grounding_proofs"]
    if not isinstance(gp,list):raise Reject("outer grounding_proofs")
    ground=[]
    for i,x in enumerate(gp):
        if not isinstance(x,dict) or set(x)!={"pair","proof"}:raise Reject("outer grounding entry shape")
        pair=relation([x["pair"]],f"ground[{i}].pair")[0]
        pr=x["proof"]
        if not isinstance(pr,dict) or set(pr)!={"kind","artifact"}:raise Reject("outer grounding proof shape")
        ground.append((pair[0],pair[1],pr["kind"],pr["artifact"]))
    roots=doc["evidence_roots"]
    if not isinstance(roots,list) or any(not isinstance(x,str) or not PAT["e"].fullmatch(x) for x in roots):raise Reject("outer evidence roots")
    if len(set(roots))!=len(roots):raise Reject("outer duplicate evidence root")
    cp=doc["closure_proof"]
    if not isinstance(cp,dict) or set(cp)!={"kind","artifact"}:raise Reject("outer closure proof shape")
    pre=b"RISU-K1-CERT-W0\0"+b"C"+net(doc["claim_id"])+b"T"+net(doc["target_id"])
    pre+=b"R"+net(str(len(real)))
    for w,c in real:pre+=b"P"+net(w)+net(c)
    pre+=b"Q"+net(cp["kind"])+net(cp["artifact"])
    pre+=b"G"+net(str(len(ground)))
    for w,c,k,a in sorted(ground):pre+=b"g"+net(w)+net(c)+net(k)+net(a)
    pre+=b"E"+net(str(len(roots)))
    for x in sorted(roots):pre+=b"V"+net(x)
    return "cert:sha256:"+hashlib.sha256(pre).hexdigest()

def run_json(argv):
    try:p=subprocess.run([str(x) for x in argv],text=True,capture_output=True,check=True)
    except Exception as e:raise Reject("inner checker unavailable/non-success") from e
    try:return json.loads(p.stdout)
    except Exception as e:raise Reject("inner checker malformed output") from e

def check(a):
    # Transitive source closure first.
    for arg,expected in SOURCE_PINS.items():
        raw=Path(getattr(a,arg)).read_bytes()
        got=git_blob(raw)
        if got!=expected:raise Reject("source pin mismatch:"+arg)

    claim=loads(Path(a.claim).read_bytes(),"claim")
    if not isinstance(claim,dict) or not isinstance(claim.get("claim_id"),str) or not PAT["claim"].fullmatch(claim["claim_id"]):
        raise Reject("claim id")

    promo_raw=Path(a.promotion_artifact).read_bytes()
    promo=loads(promo_raw,"promotion")
    if not isinstance(promo,dict) or set(promo)!=PROMO_KEYS:raise Reject("promotion exact-key violation")
    expected_literals={
      "proof_format":PROOF_FORMAT,"proof_kind":PROOF_KIND,"source_semantics":SOURCE_SEM,
      "downstream_proof_kind":DOWNSTREAM,"authority_scope":SCOPE,"q0_candidate_id":Q0_CANDIDATE,
      "q0_qualification_anchor_commit":Q0_ANCHOR_COMMIT,"q0_qualification_anchor_blob":Q0_ANCHOR_BLOB,
      "w10_blob":W10_BLOB,"w11_blob":W11_BLOB,
    }
    for k,v in expected_literals.items():
        if promo.get(k)!=v:raise Reject("promotion policy mismatch:"+k)
    if promo.get("claim_id")!=claim["claim_id"]:raise Reject("promotion claim mismatch")
    for k,p in (("claim_id","claim"),("c3_certificate_id","c3cert"),("profile_sha256","sha"),
                ("c3_certificate_sha256","sha"),("c2_program_sha256","sha"),("c2_artifact_id","p"),("c2_target_id","t")):
        if not isinstance(promo.get(k),str) or not PAT[p].fullmatch(promo[k]):raise Reject("promotion malformed:"+k)

    profile_raw=Path(a.profile).read_bytes()
    cert_raw=Path(a.c3_certificate).read_bytes()
    prog_raw=Path(a.program).read_bytes()
    art_raw=Path(a.c2_artifact).read_bytes()
    if hashlib.sha256(profile_raw).hexdigest()!=promo["profile_sha256"]:raise Reject("profile exact-byte mismatch")
    if hashlib.sha256(cert_raw).hexdigest()!=promo["c3_certificate_sha256"]:raise Reject("C3 certificate exact-byte mismatch")
    if hashlib.sha256(prog_raw).hexdigest()!=promo["c2_program_sha256"]:raise Reject("C2 program digest mismatch")
    if "p:sha256:"+hashlib.sha256(art_raw).hexdigest()!=promo["c2_artifact_id"]:raise Reject("C2 artifact digest mismatch")

    inner=loads(cert_raw,"C3 certificate")
    if not isinstance(inner,dict):raise Reject("C3 certificate shape")
    for k in ("claim_id","certificate_id","c2_target_id","projected_realize"):
        if k not in inner:raise Reject("C3 certificate missing:"+k)
    if inner["claim_id"]!=claim["claim_id"]:raise Reject("inner claim mismatch")
    if inner["certificate_id"]!=promo["c3_certificate_id"]:raise Reject("promotion C3 certificate id mismatch")
    if inner["c2_target_id"]!=promo["c2_target_id"]:raise Reject("promotion target mismatch")
    inner_real=relation(inner["projected_realize"],"inner projected_realize")

    common=["--claim",a.claim,"--profile",a.profile,"--certificate",a.c3_certificate,
            "--program",a.program,"--artifact",a.c2_artifact,
            "--w7",a.w7,"--w8",a.w8,"--w5",a.w5,"--w6",a.w6]
    r10=run_json([sys.executable,a.w10]+common)
    r11=run_json([a.w11]+common)
    if r10.get("checker")!="risu-k1-c3-cert-w10" or r11.get("checker")!="risu-k1-c3-cert-w11":raise Reject("inner checker identity")
    if r10.get("proof_status")!="ACCEPTED" or r11.get("proof_status")!="ACCEPTED":raise Reject("dual Q0 acceptance required")
    for k in ("certificate_id","c2_certificate_id","c3_source_id","ordered_trace_map_id","c2_target_id","realize_pair_count"):
        if r10.get(k)!=r11.get(k):raise Reject("W10/W11 disagreement:"+k)
    if r10.get("certificate_id")!=promo["c3_certificate_id"]:raise Reject("accepted C3 id mismatch")
    if r10.get("c2_target_id")!=promo["c2_target_id"]:raise Reject("accepted target mismatch")
    if r10.get("realize_pair_count")!=len(inner_real):raise Reject("accepted REALIZE count mismatch")

    promo_art="p:sha256:"+hashlib.sha256(promo_raw).hexdigest()
    eroot=evidence_root(claim["claim_id"],promo_art,promo["c3_certificate_id"],promo["c2_target_id"])

    outer=loads(Path(a.outer_certificate).read_bytes(),"outer")
    if not isinstance(outer,dict) or set(outer)!=OUTER_KEYS:raise Reject("outer exact-key violation")
    if outer.get("wire")!="risu.k1.w0" or outer.get("kind")!="preservation_certificate":raise Reject("outer wire/kind")
    if outer.get("claim_id")!=claim["claim_id"]:raise Reject("outer claim mismatch")
    if outer.get("target_id")!=promo["c2_target_id"]:raise Reject("outer target mismatch")
    outer_real=relation(outer.get("realize"),"outer.realize")
    if outer_real!=inner_real:raise Reject("outer REALIZE mismatch")
    cp=outer.get("closure_proof")
    if not isinstance(cp,dict) or cp!={"kind":PROOF_KIND,"artifact":promo_art}:raise Reject("outer closure proof mismatch")
    gp=outer.get("grounding_proofs")
    if not isinstance(gp,list) or len(gp)!=len(inner_real):raise Reject("outer grounding completeness")
    seen=set()
    for x in gp:
        if not isinstance(x,dict) or set(x)!={"pair","proof"}:raise Reject("outer grounding entry")
        pair=relation([x["pair"]],"outer grounding pair")[0]
        if pair in seen:raise Reject("outer grounding duplicate")
        seen.add(pair)
        if x["proof"]!={"kind":PROOF_KIND,"artifact":promo_art}:raise Reject("outer grounding proof mismatch")
    if sorted(seen)!=inner_real:raise Reject("outer grounding coverage")
    if outer.get("evidence_roots")!=[eroot]:raise Reject("outer evidence root mismatch")
    cid=outer_cert_id(outer)
    if outer.get("certificate_id")!=cid:raise Reject("outer certificate_id mismatch")
    return {
      "checker":"risu-k1-c3-promotion-w12","proof_status":"ACCEPTED",
      "semantic_claim":"P0_CANDIDATE_MEDIATED_REFINEMENT_COMPOSITION",
      "authority_created":False,"promotion_artifact_id":promo_art,"outer_certificate_id":cid,
      "c3_certificate_id":promo["c3_certificate_id"],"c2_target_id":promo["c2_target_id"],
      "realize_pair_count":len(inner_real)
    }

def main():
    ap=argparse.ArgumentParser()
    for x in ("claim","profile","c3_certificate","program","c2_artifact","promotion_artifact","outer_certificate",
              "w10","w11","w7","w8","w5","w6",
              "w10_source","w11_source","w7_model_source","w7_exec_source","w7_source",
              "w8_json_source","w8_model_source","w8_exec_source","w8_source","w5_source","w6_source"):
        ap.add_argument("--"+x.replace("_","-"),dest=x,required=True)
    a=ap.parse_args()
    try:o=check(a)
    except (Reject,OSError,ValueError) as e:o={"checker":"risu-k1-c3-promotion-w12","proof_status":"REJECTED","semantic_claim":"NONE","authority_created":False,"reason":str(e)}
    print(json.dumps(o,sort_keys=True,separators=(",",":")))
    return 0
if __name__=="__main__":raise SystemExit(main())
