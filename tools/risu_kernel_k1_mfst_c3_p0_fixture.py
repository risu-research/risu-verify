#!/usr/bin/env python3
"""Non-authoritative P0 promotion fixture producer."""
from __future__ import annotations
import hashlib, json, sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
TOOLS=ROOT/"tools";sys.path.insert(0,str(TOOLS))
import risu_kernel_k1_mfst_c3_cert_q0_common as q

PROOF_FORMAT="risu.k1.mediated-refinement-proof/v1"
PROOF_KIND="k1.mediated-refinement/v1"
SOURCE_SEM="risu.k1.c3.mfst/v1"
DOWNSTREAM="k1.capsule-closure/v1"
SCOPE="EXACT_MFST_SOURCE_TO_EXACT_QUALIFIED_C2_LOWERING"
Q0_CANDIDATE="A1"
Q0_COMMIT="a857fe1f72b7341d549354e9ccc330dca22e9c0d"
Q0_BLOB="592afac89231040280e9e29ba26292c18f90b9e6"
W10_BLOB="5eea6fa26bdb488d60743a4bf3470cd5bd28eab3"
W11_BLOB="1434a9255d42ad9e9b8d57f9e1c1fa1d47c6a8a0"

def canon(x):return json.dumps(x,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode()
def net(s):
    b=s.encode();return str(len(b)).encode()+b":"+b+b","

def evidence_root(claim,artifact,c3id,target):
    pre=b"RISU-K1-MEDIATED-REFINEMENT-PROOF-V1\0"
    for t,v in ((b"C",claim),(b"A",artifact),(b"R",c3id),(b"T",target),(b"Q",Q0_COMMIT),(b"X",W10_BLOB),(b"Y",W11_BLOB)):
        pre+=t+net(v)
    return "e:sha256:"+hashlib.sha256(pre).hexdigest()

def relation(v):
    rows=[tuple(x) for x in v]
    if len(set(rows))!=len(rows):raise ValueError("duplicate relation")
    return sorted(rows)

def outer_id(d):
    real=relation(d["realize"])
    gp=sorted((x["pair"][0],x["pair"][1],x["proof"]["kind"],x["proof"]["artifact"]) for x in d["grounding_proofs"])
    roots=sorted(d["evidence_roots"]);cp=d["closure_proof"]
    pre=b"RISU-K1-CERT-W0\0"+b"C"+net(d["claim_id"])+b"T"+net(d["target_id"])
    pre+=b"R"+net(str(len(real)))
    for w,c in real:pre+=b"P"+net(w)+net(c)
    pre+=b"Q"+net(cp["kind"])+net(cp["artifact"])
    pre+=b"G"+net(str(len(gp)))
    for w,c,k,a in gp:pre+=b"g"+net(w)+net(c)+net(k)+net(a)
    pre+=b"E"+net(str(len(roots)))
    for x in roots:pre+=b"V"+net(x)
    return "cert:sha256:"+hashlib.sha256(pre).hexdigest()

def build(profile_raw,td,name,*,claim=q.CLAIM,promo_serializer=canon,c3_doc_mutator=None):
    td=Path(td)
    inner=q.derive_bundle(profile_raw,td,name+"-inner",claim=claim)
    c3doc=json.loads(Path(inner["cert"]).read_text())
    if c3_doc_mutator:
        c3_doc_mutator(c3doc)
        c3raw=canon(c3doc)
        c3path=q.write(td/(name+".c3cert.json"),c3raw)
    else:
        c3path=Path(inner["cert"]);c3raw=c3path.read_bytes()
    profile_bytes=Path(inner["profile"]).read_bytes()
    program_bytes=Path(inner["program"]).read_bytes()
    artifact_bytes=Path(inner["artifact"]).read_bytes()
    promo={
      "proof_format":PROOF_FORMAT,"proof_kind":PROOF_KIND,"claim_id":c3doc["claim_id"],
      "source_semantics":SOURCE_SEM,"downstream_proof_kind":DOWNSTREAM,"authority_scope":SCOPE,
      "profile_sha256":hashlib.sha256(profile_bytes).hexdigest(),
      "c3_certificate_sha256":hashlib.sha256(c3raw).hexdigest(),
      "c3_certificate_id":c3doc["certificate_id"],
      "c2_program_sha256":hashlib.sha256(program_bytes).hexdigest(),
      "c2_artifact_id":"p:sha256:"+hashlib.sha256(artifact_bytes).hexdigest(),
      "c2_target_id":c3doc["c2_target_id"],
      "q0_candidate_id":Q0_CANDIDATE,"q0_qualification_anchor_commit":Q0_COMMIT,
      "q0_qualification_anchor_blob":Q0_BLOB,"w10_blob":W10_BLOB,"w11_blob":W11_BLOB,
    }
    praw=promo_serializer(promo);pp=q.write(td/(name+".promotion.json"),praw)
    paid="p:sha256:"+hashlib.sha256(praw).hexdigest()
    rows=[list(x) for x in relation(c3doc["projected_realize"])]
    proof={"kind":PROOF_KIND,"artifact":paid}
    outer={
      "wire":"risu.k1.w0","kind":"preservation_certificate","claim_id":c3doc["claim_id"],
      "target_id":c3doc["c2_target_id"],"realize":rows,"closure_proof":proof,
      "grounding_proofs":[{"pair":r,"proof":dict(proof)} for r in rows],
      "evidence_roots":[evidence_root(c3doc["claim_id"],paid,c3doc["certificate_id"],c3doc["c2_target_id"])],
      "certificate_id":"cert:sha256:"+"0"*64,
    }
    outer["certificate_id"]=outer_id(outer)
    op=q.write(td/(name+".outer.json"),canon(outer))
    return {**inner,"c3_certificate":c3path,"promotion_artifact":pp,"outer_certificate":op,
            "promo":promo,"outer":outer,"promotion_artifact_id":paid}

def rebind(bundle,td,name,*,promo=None,promo_raw=None,outer_mutator=None):
    td=Path(td);p=json.loads(json.dumps(promo if promo is not None else bundle["promo"]))
    raw=promo_raw if promo_raw is not None else canon(p)
    pp=q.write(td/(name+".promotion.json"),raw);paid="p:sha256:"+hashlib.sha256(raw).hexdigest()
    c3=json.loads(Path(bundle["c3_certificate"]).read_text());rows=[list(x) for x in relation(c3["projected_realize"])]
    proof={"kind":PROOF_KIND,"artifact":paid}
    o={"wire":"risu.k1.w0","kind":"preservation_certificate","claim_id":p["claim_id"],"target_id":p["c2_target_id"],
       "realize":rows,"closure_proof":proof,"grounding_proofs":[{"pair":r,"proof":dict(proof)} for r in rows],
       "evidence_roots":[evidence_root(p["claim_id"],paid,p["c3_certificate_id"],p["c2_target_id"])],
       "certificate_id":"cert:sha256:"+"0"*64}
    if outer_mutator:outer_mutator(o)
    o["certificate_id"]=outer_id(o)
    op=q.write(td/(name+".outer.json"),canon(o))
    z=dict(bundle);z.update({"promotion_artifact":pp,"outer_certificate":op,"promo":p,"outer":o,"promotion_artifact_id":paid})
    return z
