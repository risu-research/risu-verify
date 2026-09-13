#!/usr/bin/env python3
"""Static adversarial differential qualification for K1 C2 W5/W6."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

PROOF_KIND = "k1.capsule-closure/v1"
SEM = "risu.k1.capsule/v1"


def net(s):
    b=s.encode(); return str(len(b)).encode()+b":"+b+b","

def vals(tag,xs):
    out=tag.encode()+net(str(len(xs)))
    for x in xs: out+=b"V"+net(x)
    return out

def pairs_t(tag, rows):
    rows=sorted(tuple(x) for x in rows);out=tag.encode()+net(str(len(rows)))
    for w,c in rows: out+=b"P"+net(w)+net(c)
    return out

def world(label): return "w:sha256:"+hashlib.sha256(("RISU-K1-C2-WORLD\0"+label).encode()).hexdigest()
def consequence(payload): return "c:sha256:"+hashlib.sha256(b"RISU-K1-CAPSULE-CONSEQUENCE-V1\0"+payload).hexdigest()
def evidence(label): return "e:sha256:"+hashlib.sha256(label.encode()).hexdigest()
def fake(prefix,label): return prefix+hashlib.sha256(label.encode()).hexdigest()

def claim_id(c):
    pre=b"RISU-K1-CLAIM-W0\0"+b"S"+net(c["semantics"])+vals("W",sorted(c["worlds"]))+pairs_t("A",c["allow"])
    return "claim:sha256:"+hashlib.sha256(pre).hexdigest()

def make_claim(worlds,allow):
    c={"wire":"risu.k1.w0","kind":"claim","semantics":"safety-subset-v1","worlds":list(worlds),"allow":[list(x) for x in allow],"claim_id":""}
    c["claim_id"]=claim_id(c);return c

def artifact_bytes(claim,program,boundary, *, override=None, extra=None, pretty=False):
    obj={"proof_format":PROOF_KIND,"claim_id":claim["claim_id"],"capsule_semantics":SEM,"program_sha256":hashlib.sha256(program).hexdigest(),"boundary":copy.deepcopy(boundary)}
    if override: obj.update(copy.deepcopy(override))
    if extra: obj.update(copy.deepcopy(extra))
    if pretty:
        return json.dumps(obj,indent=2,ensure_ascii=False).encode()+b"\n"
    return json.dumps(obj,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()

def p_id(raw): return "p:sha256:"+hashlib.sha256(raw).hexdigest()

def target_id(program_sha,boundary,relation):
    pre=b"RISU-K1-TARGET-CAPSULE-V1\0"+b"S"+net(SEM)+b"P"+net(program_sha)+b"G"+net(str(boundary["gas"]))
    ws=sorted(boundary["worlds"]);pre+=b"W"+net(str(len(ws)))
    for w in ws: pre+=b"w"+net(w)
    names=sorted(boundary["slots"]);pre+=b"D"+net(str(len(names)))
    for n in names:
        vs=sorted(boundary["slots"][n]);pre+=b"s"+net(n)+net(str(len(vs)))
        for v in vs: pre+=b"v"+net(v)
    rr=sorted(tuple(x) for x in relation);pre+=b"R"+net(str(len(rr)))
    for w,c in rr: pre+=b"r"+net(w)+net(c)
    return "t:sha256:"+hashlib.sha256(pre).hexdigest()

def cert_id(c):
    ground=sorted((x["pair"][0],x["pair"][1],x["proof"]["kind"],x["proof"]["artifact"]) for x in c["grounding_proofs"])
    pre=b"RISU-K1-CERT-W0\0"+b"C"+net(c["claim_id"])+b"T"+net(c["target_id"])+pairs_t("R",c["realize"])
    q=c["closure_proof"];pre+=b"Q"+net(q["kind"])+net(q["artifact"])+b"G"+net(str(len(ground)))
    for w,cc,k,a in ground: pre+=b"g"+net(w)+net(cc)+net(k)+net(a)
    pre+=vals("E",sorted(c["evidence_roots"]));return "cert:sha256:"+hashlib.sha256(pre).hexdigest()

def make_cert(claim,artifact_raw,program,boundary,derived, *, realize=None, grounding=None, closure_artifact=None, ground_artifact=None, target=None):
    aid=closure_artifact or p_id(artifact_raw);real=list(derived if realize is None else realize);grounds=list(real if grounding is None else grounding);ga=ground_artifact or aid
    c={"wire":"risu.k1.w0","kind":"preservation_certificate","claim_id":claim["claim_id"],"target_id":target or target_id(hashlib.sha256(program).hexdigest(),boundary,derived),"realize":[list(x) for x in real],"closure_proof":{"kind":PROOF_KIND,"artifact":aid},"grounding_proofs":[{"pair":list(x),"proof":{"kind":PROOF_KIND,"artifact":ga}} for x in grounds],"evidence_roots":[evidence("c2-static")],"certificate_id":""}
    c["certificate_id"]=cert_id(c);return c

def reroot_cert(c):
    c=copy.deepcopy(c);c["certificate_id"]=cert_id(c);return c

def run_checker(cmd,claim,cert,artifact,program,root):
    (root/"claim.json").write_text(json.dumps(claim,separators=(",",":")))
    (root/"cert.json").write_text(json.dumps(cert,separators=(",",":")))
    (root/"artifact.json").write_bytes(artifact);(root/"program.cap").write_bytes(program)
    p=subprocess.run(cmd+["--claim",str(root/"claim.json"),"--certificate",str(root/"cert.json"),"--artifact",str(root/"artifact.json"),"--program",str(root/"program.cap")],text=True,capture_output=True,check=True)
    return json.loads(p.stdout)

def both(w6,claim,cert,artifact,program):
    with tempfile.TemporaryDirectory() as td:
        root=Path(td);a=run_checker([sys.executable,"kernel/k1_checker_w5.py"],claim,cert,artifact,program,root);b=run_checker([w6],claim,cert,artifact,program,root)
    return a,b

def status_pair(a,b,expected,target=None,relation=None):
    ok=a.get("proof_status")==expected and b.get("proof_status")==expected and a.get("semantic_claim")==b.get("semantic_claim")
    if expected=="ACCEPTED":
        ok=ok and a.get("semantic_claim")=="PRESERVATION" and a.get("target_id")==b.get("target_id")==target
        ok=ok and a.get("derived_realize")==b.get("derived_realize")==[list(x) for x in sorted(relation)]
    return ok

def main():
    ap=argparse.ArgumentParser();ap.add_argument("--w6",required=True);ap.add_argument("--output",required=True);args=ap.parse_args()
    w0,w1,w2=world("w0"),world("w1"),world("w2");caa,cbb,ccc,cdd=consequence(bytes.fromhex("aa")),consequence(bytes.fromhex("bb")),consequence(bytes.fromhex("cc")),consequence(bytes.fromhex("dd"))
    program=f"IF_EQ @world {w0} left\nEMIT_HEX bb\nHALT\nLABEL left\nEMIT_HEX aa\nHALT\n".encode();boundary={"worlds":[w0,w1],"slots":{},"gas":16};derived=[(w0,caa),(w1,cbb)]
    exact_claim=make_claim([w0,w1],derived);wide_claim=make_claim([w0,w1],derived+[(w0,ccc),(w1,cdd)])
    art=artifact_bytes(exact_claim,program,boundary);cert=make_cert(exact_claim,art,program,boundary,derived);base_target=target_id(hashlib.sha256(program).hexdigest(),boundary,derived)
    rows=[]
    def add(i,name,ok,a=None,b=None): rows.append({"id":f"C2-{i:02d}","name":name,"pass":bool(ok),"w5":None if a is None else a.get("proof_status"),"w6":None if b is None else b.get("proof_status")})

    a,b=both(args.w6,exact_claim,cert,art,program);add(1,"valid exhaustive safe capsule",status_pair(a,b,"ACCEPTED",base_target,derived),a,b)
    add(2,"multi-world exact differential",a.get("world_count")==b.get("world_count")==2 and a.get("derived_realize")==b.get("derived_realize"),a,b)
    art_w=artifact_bytes(wide_claim,program,boundary);cert_w=make_cert(wide_claim,art_w,program,boundary,derived);a,b=both(args.w6,wide_claim,cert_w,art_w,program);add(3,"strict safe subset",status_pair(a,b,"ACCEPTED",base_target,derived),a,b)

    native=bytes.fromhex("deadbeef");cn=consequence(native);pn=b"EMIT_HEX deadbeef\nHALT\n";bn={"worlds":[w0],"slots":{},"gas":8};rn=[(w0,cn)];cln=make_claim([w0],rn);an=artifact_bytes(cln,pn,bn);cen=make_cert(cln,an,pn,bn,rn);a,b=both(args.w6,cln,cen,an,pn);add(4,"target-native open consequence",status_pair(a,b,"ACCEPTED",target_id(hashlib.sha256(pn).hexdigest(),bn,rn),rn),a,b)

    bad=make_cert(exact_claim,art,program,boundary,derived,realize=[derived[0]],grounding=[derived[0]]);a,b=both(args.w6,exact_claim,bad,art,program);add(5,"REALIZE omission",status_pair(a,b,"REJECTED"),a,b)
    fakec=consequence(b"surplus");sur=derived+[(w0,fakec)];bad=make_cert(exact_claim,art,program,boundary,derived,realize=sur,grounding=sur);a,b=both(args.w6,exact_claim,bad,art,program);add(6,"REALIZE surplus",status_pair(a,b,"REJECTED"),a,b)
    forbidden_claim=make_claim([w0,w1],[(w0,caa),(w1,cdd)]);af=artifact_bytes(forbidden_claim,program,boundary);cf=make_cert(forbidden_claim,af,program,boundary,derived);a,b=both(args.w6,forbidden_claim,cf,af,program);add(7,"forbidden derived consequence",status_pair(a,b,"REJECTED"),a,b)
    a,b=both(args.w6,exact_claim,cert,art+b"\n",program);add(8,"artifact byte tamper",status_pair(a,b,"REJECTED"),a,b)
    pm=program.replace(b"EMIT_HEX bb",b"EMIT_HEX bc");a,b=both(args.w6,exact_claim,cert,art,pm);add(9,"program byte tamper",status_pair(a,b,"REJECTED"),a,b)

    otherprog=b"EMIT_HEX cc\nHALT\n";art10=artifact_bytes(exact_claim,program,boundary,override={"program_sha256":hashlib.sha256(otherprog).hexdigest()});c10=make_cert(exact_claim,art10,program,boundary,derived);a,b=both(args.w6,exact_claim,c10,art10,program);add(10,"program digest substitution",status_pair(a,b,"REJECTED"),a,b)
    art11=artifact_bytes(exact_claim,program,boundary,override={"claim_id":fake("claim:sha256:","other-claim")});c11=make_cert(exact_claim,art11,program,boundary,derived);a,b=both(args.w6,exact_claim,c11,art11,program);add(11,"artifact claim substitution",status_pair(a,b,"REJECTED"),a,b)
    art12=artifact_bytes(exact_claim,program,{"worlds":[w0],"slots":{},"gas":16});c12=make_cert(exact_claim,art12,program,boundary,derived);a,b=both(args.w6,exact_claim,c12,art12,program);add(12,"boundary world shrink",status_pair(a,b,"REJECTED"),a,b)
    art13=artifact_bytes(exact_claim,program,{"worlds":[w0,w1,w2],"slots":{},"gas":16});c13=make_cert(exact_claim,art13,program,boundary,derived);a,b=both(args.w6,exact_claim,c13,art13,program);add(13,"boundary world surplus",status_pair(a,b,"REJECTED"),a,b)
    art14=artifact_bytes(exact_claim,program,{"worlds":[w0,w1],"slots":{"mode":[]},"gas":16});c14=make_cert(exact_claim,art14,program,boundary,derived);a,b=both(args.w6,exact_claim,c14,art14,program);add(14,"empty slot domain",status_pair(a,b,"REJECTED"),a,b)

    p15=b"IF_EQ secret yes bad\nEMIT_HEX aa\nHALT\nLABEL bad\nEMIT_HEX bb\nHALT\n";a15=artifact_bytes(exact_claim,p15,boundary);c15=make_cert(exact_claim,a15,p15,boundary,derived);a,b=both(args.w6,exact_claim,c15,a15,p15);add(15,"undeclared program input",status_pair(a,b,"REJECTED"),a,b)
    sub=[]
    for op in ["CLOCK","RNG","FILE","NET","HOSTCALL","SPAWN"]:
        pp=f"{op} x\nEMIT_HEX aa\nHALT\n".encode();aa=artifact_bytes(exact_claim,pp,boundary);ccert=make_cert(exact_claim,aa,pp,boundary,derived);x,y=both(args.w6,exact_claim,ccert,aa,pp);sub.append(status_pair(x,y,"REJECTED"))
    add(16,"ambient capabilities",all(sub))
    p17=b"MAGIC x\nEMIT_HEX aa\nHALT\n";a17=artifact_bytes(exact_claim,p17,boundary);c17=make_cert(exact_claim,a17,p17,boundary,derived);a,b=both(args.w6,exact_claim,c17,a17,p17);add(17,"unknown opcode",status_pair(a,b,"REJECTED"),a,b)
    sub=[]
    for pp in [b"EMIT_HEX aa\x00\nHALT\n",b"LABEL x\nEMIT_HEX aa\nLABEL x\nHALT\n"]:
        aa=artifact_bytes(exact_claim,pp,boundary);ccert=make_cert(exact_claim,aa,pp,boundary,derived);x,y=both(args.w6,exact_claim,ccert,aa,pp);sub.append(status_pair(x,y,"REJECTED"))
    add(18,"parser ambiguity and duplicate label",all(sub))
    p19=b"LABEL loop\nGOTO loop\n";b19={"worlds":[w0,w1],"slots":{},"gas":4};a19=artifact_bytes(exact_claim,p19,b19);c19=make_cert(exact_claim,a19,p19,b19,derived);a,b=both(args.w6,exact_claim,c19,a19,p19);add(19,"gas exhaustion",status_pair(a,b,"REJECTED"),a,b)
    p20=b"HALT\n";a20=artifact_bytes(exact_claim,p20,boundary);c20=make_cert(exact_claim,a20,p20,boundary,derived);a,b=both(args.w6,exact_claim,c20,a20,p20);add(20,"zero-effect halt",status_pair(a,b,"REJECTED"),a,b)

    pmulti=b"EMIT_HEX aa\nEMIT_HEX bb\nHALT\n";bm={"worlds":[w0],"slots":{},"gas":8};rm=[(w0,caa),(w0,cbb)];clm=make_claim([w0],rm);am=artifact_bytes(clm,pmulti,bm);cm=make_cert(clm,am,pmulti,bm,rm,realize=[rm[0]],grounding=[rm[0]]);a,b=both(args.w6,clm,cm,am,pmulti);add(21,"first-effect-only laundering",status_pair(a,b,"REJECTED"),a,b)
    bad=make_cert(exact_claim,art,program,boundary,derived,grounding=[derived[0]]);a,b=both(args.w6,exact_claim,bad,art,program);add(22,"grounding omission",status_pair(a,b,"REJECTED"),a,b)
    bad=make_cert(exact_claim,art,program,boundary,derived,grounding=derived+[(w0,fakec)]);a,b=both(args.w6,exact_claim,bad,art,program);add(23,"grounding surplus",status_pair(a,b,"REJECTED"),a,b)
    bad=make_cert(exact_claim,art,program,boundary,derived,ground_artifact=fake("p:sha256:","other-proof"));a,b=both(args.w6,exact_claim,bad,art,program);add(24,"grounding different artifact",status_pair(a,b,"REJECTED"),a,b)
    bad=make_cert(exact_claim,art,program,boundary,derived,target=fake("t:sha256:","wrong-target"));a,b=both(args.w6,exact_claim,bad,art,program);add(25,"target id mutation",status_pair(a,b,"REJECTED"),a,b)
    bad=copy.deepcopy(cert);bad["certificate_id"]=fake("cert:sha256:","wrong-cert");a,b=both(args.w6,exact_claim,bad,art,program);add(26,"certificate id mutation",status_pair(a,b,"REJECTED"),a,b)
    art27=artifact_bytes(exact_claim,program,boundary,extra={"closed":True});c27=make_cert(exact_claim,art27,program,boundary,derived);a,b=both(args.w6,exact_claim,c27,art27,program);add(27,"artifact self-certification field",status_pair(a,b,"REJECTED"),a,b)
    perm_boundary={"worlds":[w1,w0],"slots":{},"gas":16};art28=artifact_bytes(exact_claim,program,perm_boundary,pretty=True);c28=make_cert(exact_claim,art28,program,perm_boundary,derived);a,b=both(args.w6,exact_claim,c28,art28,program);add(28,"representation permutation",status_pair(a,b,"ACCEPTED",base_target,derived) and p_id(art28)!=p_id(art),a,b)

    failed=[r for r in rows if not r["pass"]];out={"gate":"RISU_KERNEL_K1_CAPSULE_CLOSURE_C2_STATIC","status":"PASS" if not failed and len(rows)==28 else "FAIL","vector_count":len(rows),"passed":len(rows)-len(failed),"failed":[r["id"] for r in failed],"rows":rows,"w5":"risu-k1-checker-w5","w6":"risu-k1-checker-w6","semantic_kernel_changed":False,"producer_supplied_realize_authority":False}
    Path(args.output).write_text(json.dumps(out,sort_keys=True,indent=2)+"\n")
    print(json.dumps(out,sort_keys=True))
    return 0 if out["status"]=="PASS" else 1

if __name__=="__main__": raise SystemExit(main())
