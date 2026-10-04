#!/usr/bin/env python3
"""C3 C0 independent refinement-certificate checker W10.

W10 creates no preservation authority. It treats the submitted C3 certificate
only as transported assertions. All authority-relevant facts are rederived by
running the frozen W7/W8 and qualified W5/W6 evidence engines.
"""
from __future__ import annotations
import argparse, hashlib, json, os, re, subprocess, sys, tempfile
from pathlib import Path

WIRE="risu.k1.c3.refinement-certificate/v1"
KIND="mediated_refinement_preservation"
VERIFY="risu.k1.c3.refinement-verification/v1"
KEYS={"wire","kind","verification_profile","claim_id","c3_source_id","c3_semantic_id",
      "reachable_graph_id","ordered_trace_map_id","c2_program_sha256","c2_artifact_id",
      "c2_target_id","projected_realize","c2_certificate_id","certificate_id"}
PAT={
 "claim":re.compile(r"^claim:sha256:[0-9a-f]{64}$"),
 "src":re.compile(r"^c3src:sha256:[0-9a-f]{64}$"),
 "sem":re.compile(r"^c3sem:sha256:[0-9a-f]{64}$"),
 "graph":re.compile(r"^c3graph:sha256:[0-9a-f]{64}$"),
 "trace":re.compile(r"^c3trace:sha256:[0-9a-f]{64}$"),
 "sha":re.compile(r"^[0-9a-f]{64}$"),
 "p":re.compile(r"^p:sha256:[0-9a-f]{64}$"),
 "t":re.compile(r"^t:sha256:[0-9a-f]{64}$"),
 "c":re.compile(r"^c:sha256:[0-9a-f]{64}$"),
 "w":re.compile(r"^w:sha256:[0-9a-f]{64}$"),
 "cert":re.compile(r"^cert:sha256:[0-9a-f]{64}$"),
 "c3cert":re.compile(r"^c3cert:sha256:[0-9a-f]{64}$"),
}
class Reject(Exception): pass

def pairs_no_dups(pairs):
    seen=set()
    def hook(xs):
        d={}
        for k,v in xs:
            if k in d: raise Reject("duplicate JSON key:"+k)
            d[k]=v
        return d
    return hook

def loads_strict(raw:bytes,where:str):
    try:
        return json.loads(raw.decode("utf-8","strict"),object_pairs_hook=pairs_no_dups(None))
    except Reject: raise
    except Exception as e: raise Reject(where+": invalid JSON") from e

def net(s:str)->bytes:
    b=s.encode("utf-8"); return str(len(b)).encode()+b":"+b+b","

def relation(v,where):
    if not isinstance(v,list): raise Reject(where+": not array")
    out=[]
    for i,row in enumerate(v):
        if not isinstance(row,list) or len(row)!=2: raise Reject(f"{where}[{i}]: not pair")
        w,c=row
        if not isinstance(w,str) or not PAT["w"].fullmatch(w): raise Reject(where+": bad world")
        if not isinstance(c,str) or not PAT["c"].fullmatch(c): raise Reject(where+": bad consequence")
        if (w,c) in out: raise Reject(where+": duplicate pair")
        out.append((w,c))
    return sorted(out)

def c3_certificate_id(c):
    rows=relation(c["projected_realize"],"projected_realize")
    pre=b"RISU-K1-C3-REFINEMENT-CERT-V1\0"
    for tag,key in ((b"V","verification_profile"),(b"C","claim_id"),(b"S","c3_source_id"),
                    (b"M","c3_semantic_id"),(b"G","reachable_graph_id"),(b"H","ordered_trace_map_id"),
                    (b"P","c2_program_sha256"),(b"A","c2_artifact_id"),(b"T","c2_target_id")):
        pre+=tag+net(c[key])
    pre+=b"R"+net(str(len(rows)))
    for w,x in rows: pre+=b"r"+net(w)+net(x)
    pre+=b"D"+net(c["c2_certificate_id"])
    return "c3cert:sha256:"+hashlib.sha256(pre).hexdigest()

def evidence_root(src,trace,prog,aid):
    pre=b"RISU-K1-C3-REFINEMENT-C2-EVIDENCE-V1\0"+b"S"+net(src)+b"H"+net(trace)+b"P"+net(prog)+b"A"+net(aid)
    return "e:sha256:"+hashlib.sha256(pre).hexdigest()

def pairs_transcript(tag, rows):
    rows=sorted(rows); out=tag+net(str(len(rows)))
    for w,c in rows: out+=b"P"+net(w)+net(c)
    return out

def vals(tag,xs):
    xs=sorted(xs); out=tag+net(str(len(xs)))
    for x in xs: out+=b"V"+net(x)
    return out

def c2_certificate_id(doc):
    realize=sorted(tuple(x) for x in doc["realize"])
    ground=sorted((x["pair"][0],x["pair"][1],x["proof"]["kind"],x["proof"]["artifact"]) for x in doc["grounding_proofs"])
    roots=sorted(doc["evidence_roots"]); q=doc["closure_proof"]
    pre=b"RISU-K1-CERT-W0\0"+b"C"+net(doc["claim_id"])+b"T"+net(doc["target_id"])
    pre+=pairs_transcript(b"R",realize)+b"Q"+net(q["kind"])+net(q["artifact"])
    pre+=b"G"+net(str(len(ground)))
    for w,c,k,a in ground: pre+=b"g"+net(w)+net(c)+net(k)+net(a)
    pre+=vals(b"E",roots)
    return "cert:sha256:"+hashlib.sha256(pre).hexdigest()

def make_c2_cert(claim_id,src,trace,prog,aid,target,realize):
    rows=[list(x) for x in sorted(tuple(x) for x in realize)]
    proof={"kind":"k1.capsule-closure/v1","artifact":aid}
    d={"wire":"risu.k1.w0","kind":"preservation_certificate","claim_id":claim_id,"target_id":target,
       "realize":rows,"closure_proof":proof,
       "grounding_proofs":[{"pair":r,"proof":dict(proof)} for r in rows],
       "evidence_roots":[evidence_root(src,trace,prog,aid)],
       "certificate_id":"cert:sha256:"+"0"*64}
    d["certificate_id"]=c2_certificate_id(d); return d

def run_json(argv):
    try: cp=subprocess.run(argv,capture_output=True,text=True,check=True)
    except Exception as e: raise Reject("evidence engine unavailable/non-success: "+" ".join(argv)) from e
    try: return json.loads(cp.stdout)
    except Exception as e: raise Reject("evidence engine emitted invalid JSON") from e

def same(a,b,key):
    if a.get(key)!=b.get(key): raise Reject("W7/W8 disagreement:"+key)

def check(args):
    cert=loads_strict(Path(args.certificate).read_bytes(),"certificate")
    if not isinstance(cert,dict) or set(cert)!=KEYS: raise Reject("certificate: exact-key violation")
    if (cert.get("wire"),cert.get("kind"),cert.get("verification_profile"))!=(WIRE,KIND,VERIFY): raise Reject("certificate: wire/kind/version")
    ids=[("claim_id","claim"),("c3_source_id","src"),("c3_semantic_id","sem"),("reachable_graph_id","graph"),
         ("ordered_trace_map_id","trace"),("c2_program_sha256","sha"),("c2_artifact_id","p"),
         ("c2_target_id","t"),("c2_certificate_id","cert"),("certificate_id","c3cert")]
    for k,p in ids:
        if not isinstance(cert.get(k),str) or not PAT[p].fullmatch(cert[k]): raise Reject("certificate: malformed "+k)
    relation(cert["projected_realize"],"projected_realize")
    claim=loads_strict(Path(args.claim).read_bytes(),"claim")
    if not isinstance(claim,dict) or not isinstance(claim.get("claim_id"),str): raise Reject("claim: missing claim_id")
    with tempfile.TemporaryDirectory() as td0:
        td=Path(td0); o7=td/"w7";o8=td/"w8"
        r7=run_json([sys.executable,args.w7,"--claim",args.claim,"--profile",args.profile,"--out-dir",str(o7)])
        r8=run_json([args.w8,"--claim",args.claim,"--profile",args.profile,"--out-dir",str(o8)])
        if r7.get("proof_status")!="ACCEPTED" or r8.get("proof_status")!="ACCEPTED": raise Reject("C3 evidence engine did not accept")
        for k in ("c3_source_id","c3_semantic_id","graph_id","trace_map_id","direct_trace_map","projected_realize",
                  "c2_program_sha256","c2_derived_gas","c2_artifact_id","c2_target_id","k1_subset_allowed"):
            same(r7,r8,k)
        if r7.get("k1_subset_allowed") is not True: raise Reject("C3 projection not subset of ALLOW")
        p7=(o7/"c2_program.cap").read_bytes(); p8=(o8/"c2_program.cap").read_bytes()
        a7=(o7/"c2_artifact.json").read_bytes(); a8=(o8/"c2_artifact.json").read_bytes()
        supplied_p=Path(args.program).read_bytes(); supplied_a=Path(args.artifact).read_bytes()
        if p7!=p8 or a7!=a8: raise Reject("W7/W8 generated bytes disagree")
        if supplied_p!=p7: raise Reject("supplied C2 program is not exact source-derived CBTNF")
        if supplied_a!=a7: raise Reject("supplied C2 artifact is not exact source-derived artifact")
        if hashlib.sha256(supplied_p).hexdigest()!=r7["c2_program_sha256"]: raise Reject("program digest mismatch")
        if "p:sha256:"+hashlib.sha256(supplied_a).hexdigest()!=r7["c2_artifact_id"]: raise Reject("artifact digest mismatch")
        c2=make_c2_cert(claim["claim_id"],r7["c3_source_id"],r7["trace_map_id"],r7["c2_program_sha256"],
                        r7["c2_artifact_id"],r7["c2_target_id"],r7["projected_realize"])
        c2p=td/"c2-cert.json"; c2p.write_text(json.dumps(c2,sort_keys=True,separators=(",",":")),encoding="utf-8")
        r5=run_json([sys.executable,args.w5,"--claim",args.claim,"--certificate",str(c2p),"--artifact",args.artifact,"--program",args.program])
        r6=run_json([args.w6,"--claim",args.claim,"--certificate",str(c2p),"--artifact",args.artifact,"--program",args.program])
        for tag,r in (("W5",r5),("W6",r6)):
            if r.get("proof_status")!="ACCEPTED" or r.get("semantic_claim")!="PRESERVATION": raise Reject(tag+" downstream did not accept")
            if r.get("derived_realize")!=r7["projected_realize"]: raise Reject(tag+" downstream REALIZE mismatch")
            if r.get("target_id")!=r7["c2_target_id"]: raise Reject(tag+" downstream target mismatch")
            if r.get("certificate_id")!=c2["certificate_id"]: raise Reject(tag+" downstream C2 certificate mismatch")
        expected={"wire":WIRE,"kind":KIND,"verification_profile":VERIFY,"claim_id":claim["claim_id"],
          "c3_source_id":r7["c3_source_id"],"c3_semantic_id":r7["c3_semantic_id"],
          "reachable_graph_id":r7["graph_id"],"ordered_trace_map_id":r7["trace_map_id"],
          "c2_program_sha256":r7["c2_program_sha256"],"c2_artifact_id":r7["c2_artifact_id"],
          "c2_target_id":r7["c2_target_id"],"projected_realize":r7["projected_realize"],
          "c2_certificate_id":c2["certificate_id"],"certificate_id":cert["certificate_id"]}
        for k,v in expected.items():
            if k=="certificate_id": continue
            if cert.get(k)!=v: raise Reject("transported field mismatch:"+k)
        cid=c3_certificate_id(cert)
        if cert["certificate_id"]!=cid: raise Reject("C3 certificate_id mismatch")
        return {"checker":"risu-k1-c3-cert-w10","proof_status":"ACCEPTED","semantic_claim":"CANDIDATE_REFINEMENT_CERTIFICATE",
                "authority_created":False,"certificate_id":cid,"c2_certificate_id":c2["certificate_id"],
                "c3_source_id":r7["c3_source_id"],"ordered_trace_map_id":r7["trace_map_id"],
                "c2_target_id":r7["c2_target_id"],"realize_pair_count":len(r7["projected_realize"])}

def main():
    ap=argparse.ArgumentParser()
    for x in ("claim","profile","certificate","program","artifact","w7","w8","w5","w6"): ap.add_argument("--"+x,required=True)
    a=ap.parse_args()
    try: out=check(a)
    except (Reject,OSError,ValueError) as e:
        out={"checker":"risu-k1-c3-cert-w10","proof_status":"REJECTED","semantic_claim":"NONE","authority_created":False,"reason":str(e)}
    print(json.dumps(out,sort_keys=True,separators=(",",":")))
    return 0
if __name__=="__main__": sys.exit(main())
