#!/usr/bin/env python3
"""Non-authoritative C0 fixture producer. Test input generator only."""
from __future__ import annotations
import argparse,hashlib,json,subprocess,sys,tempfile
from pathlib import Path

def net(s):
    b=s.encode();return str(len(b)).encode()+b":"+b+b","
def run(argv):
    cp=subprocess.run(argv,capture_output=True,text=True,check=True);return json.loads(cp.stdout)
def rel(rows): return [list(x) for x in sorted(tuple(x) for x in rows)]
def evidence(src,tr,prog,aid):
    b=b"RISU-K1-C3-REFINEMENT-C2-EVIDENCE-V1\0"+b"S"+net(src)+b"H"+net(tr)+b"P"+net(prog)+b"A"+net(aid)
    return "e:sha256:"+hashlib.sha256(b).hexdigest()
def c2id(claim,target,aid,root,rows):
    rows=rel(rows);b=b"RISU-K1-CERT-W0\0"+b"C"+net(claim)+b"T"+net(target)
    b+=b"R"+net(str(len(rows)))
    for w,c in rows:b+=b"P"+net(w)+net(c)
    b+=b"Q"+net("k1.capsule-closure/v1")+net(aid)+b"G"+net(str(len(rows)))
    for w,c in rows:b+=b"g"+net(w)+net(c)+net("k1.capsule-closure/v1")+net(aid)
    b+=b"E"+net("1")+b"V"+net(root)
    return "cert:sha256:"+hashlib.sha256(b).hexdigest()
def c3id(d):
    rows=rel(d["projected_realize"]);b=b"RISU-K1-C3-REFINEMENT-CERT-V1\0"
    for t,k in [(b"V","verification_profile"),(b"C","claim_id"),(b"S","c3_source_id"),(b"M","c3_semantic_id"),
                (b"G","reachable_graph_id"),(b"H","ordered_trace_map_id"),(b"P","c2_program_sha256"),
                (b"A","c2_artifact_id"),(b"T","c2_target_id")]:b+=t+net(d[k])
    b+=b"R"+net(str(len(rows)))
    for w,c in rows:b+=b"r"+net(w)+net(c)
    b+=b"D"+net(d["c2_certificate_id"])
    return "c3cert:sha256:"+hashlib.sha256(b).hexdigest()
def main():
    ap=argparse.ArgumentParser()
    for x in ("claim","profile","w7","w8","out","program_out","artifact_out"):ap.add_argument("--"+x,required=True)
    a=ap.parse_args();claim=json.loads(Path(a.claim).read_text())
    with tempfile.TemporaryDirectory() as s:
        td=Path(s);o7=td/"w7";o8=td/"w8"
        r7=run([sys.executable,a.w7,"--claim",a.claim,"--profile",a.profile,"--out-dir",str(o7)])
        r8=run([a.w8,"--claim",a.claim,"--profile",a.profile,"--out-dir",str(o8)])
        assert r7["proof_status"]==r8["proof_status"]=="ACCEPTED"
        for k in ("c3_source_id","c3_semantic_id","graph_id","trace_map_id","projected_realize","c2_program_sha256","c2_artifact_id","c2_target_id"):
            assert r7[k]==r8[k],k
        p7=(o7/"c2_program.cap").read_bytes();p8=(o8/"c2_program.cap").read_bytes()
        ar7=(o7/"c2_artifact.json").read_bytes();ar8=(o8/"c2_artifact.json").read_bytes()
        assert p7==p8 and ar7==ar8
        Path(a.program_out).write_bytes(p7);Path(a.artifact_out).write_bytes(ar7)
        root=evidence(r7["c3_source_id"],r7["trace_map_id"],r7["c2_program_sha256"],r7["c2_artifact_id"])
        cid2=c2id(claim["claim_id"],r7["c2_target_id"],r7["c2_artifact_id"],root,r7["projected_realize"])
        d={"wire":"risu.k1.c3.refinement-certificate/v1","kind":"mediated_refinement_preservation",
           "verification_profile":"risu.k1.c3.refinement-verification/v1","claim_id":claim["claim_id"],
           "c3_source_id":r7["c3_source_id"],"c3_semantic_id":r7["c3_semantic_id"],
           "reachable_graph_id":r7["graph_id"],"ordered_trace_map_id":r7["trace_map_id"],
           "c2_program_sha256":r7["c2_program_sha256"],"c2_artifact_id":r7["c2_artifact_id"],
           "c2_target_id":r7["c2_target_id"],"projected_realize":rel(r7["projected_realize"]),
           "c2_certificate_id":cid2,"certificate_id":"c3cert:sha256:"+"0"*64}
        d["certificate_id"]=c3id(d)
        Path(a.out).write_text(json.dumps(d,sort_keys=True,separators=(",",":")),encoding="utf-8")
        print("C0_FIXTURE_PASS",d["certificate_id"],cid2)
if __name__=="__main__":main()
