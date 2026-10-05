#!/usr/bin/env python3
"""Shared non-authoritative Q0 qualification harness helpers."""
from __future__ import annotations
import hashlib, json, subprocess, sys, tempfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
CLAIM=ROOT/"fixtures/k1_mfst_c3_f0/claim.json"
BASE=ROOT/"fixtures/k1_mfst_c3_f0/baseline.json"
W7=ROOT/"kernel/k1_checker_w7.py"
W8=ROOT/"build/k1_checker_w8"
W5=ROOT/"kernel/k1_checker_w5.py"
W6=ROOT/"build/k1_checker_w6"
W10=ROOT/"kernel/k1_checker_w10_refinement_cert.py"
W11=ROOT/"build/k1_checker_w11_refinement_cert"
TOOLS=ROOT/"tools"
sys.path.insert(0,str(TOOLS))
import risu_kernel_k1_mfst_c3_cert_c0_fixture as fx

def canon(o):
    return json.dumps(o,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode()

def run_json(argv):
    cp=subprocess.run([str(x) for x in argv],capture_output=True,text=True,check=True)
    try:return json.loads(cp.stdout)
    except Exception as e:raise AssertionError((argv,cp.stdout,cp.stderr)) from e

def write(path,raw):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw);return path

def derive_bundle(profile_raw, td, name, claim=CLAIM):
    td=Path(td); prof=write(td/(name+".profile.json"),profile_raw)
    o7=td/(name+".w7");o8=td/(name+".w8")
    r7=run_json([sys.executable,str(W7),"--claim",str(claim),"--profile",str(prof),"--out-dir",str(o7)])
    r8=run_json([str(W8),"--claim",str(claim),"--profile",str(prof),"--out-dir",str(o8)])
    if r7.get("proof_status")!="ACCEPTED" or r8.get("proof_status")!="ACCEPTED":
        raise AssertionError((name,"producer direct not accepted",r7,r8))
    for k in ("c3_source_id","c3_semantic_id","graph_id","trace_map_id","projected_realize",
              "c2_program_sha256","c2_artifact_id","c2_target_id","k1_subset_allowed","direct_trace_map"):
        if r7.get(k)!=r8.get(k):raise AssertionError((name,"producer disagreement",k,r7.get(k),r8.get(k)))
    if r7.get("k1_subset_allowed") is not True:raise AssertionError((name,"not allowed"))
    p7=(o7/"c2_program.cap").read_bytes();p8=(o8/"c2_program.cap").read_bytes()
    a7=(o7/"c2_artifact.json").read_bytes();a8=(o8/"c2_artifact.json").read_bytes()
    if p7!=p8 or a7!=a8:raise AssertionError((name,"derived bytes disagree"))
    program=write(td/(name+".program.cap"),p7);artifact=write(td/(name+".artifact.json"),a7)
    claim_obj=json.loads(Path(claim).read_text())
    root=fx.evidence(r7["c3_source_id"],r7["trace_map_id"],r7["c2_program_sha256"],r7["c2_artifact_id"])
    c2id=fx.c2id(claim_obj["claim_id"],r7["c2_target_id"],r7["c2_artifact_id"],root,r7["projected_realize"])
    doc={
      "wire":"risu.k1.c3.refinement-certificate/v1","kind":"mediated_refinement_preservation",
      "verification_profile":"risu.k1.c3.refinement-verification/v1","claim_id":claim_obj["claim_id"],
      "c3_source_id":r7["c3_source_id"],"c3_semantic_id":r7["c3_semantic_id"],
      "reachable_graph_id":r7["graph_id"],"ordered_trace_map_id":r7["trace_map_id"],
      "c2_program_sha256":r7["c2_program_sha256"],"c2_artifact_id":r7["c2_artifact_id"],
      "c2_target_id":r7["c2_target_id"],"projected_realize":[list(x) for x in sorted(tuple(x) for x in r7["projected_realize"])],
      "c2_certificate_id":c2id,"certificate_id":"c3cert:sha256:"+"0"*64
    }
    doc["certificate_id"]=fx.c3id(doc)
    cert=write(td/(name+".cert.json"),canon(doc))
    return {"profile":prof,"program":program,"artifact":artifact,"cert":cert,"doc":doc,"r7":r7,"r8":r8}

def check_pair(bundle, expected, label, claim=CLAIM, overrides=None):
    q=dict(bundle);q.update(overrides or {})
    common=["--claim",str(claim),"--profile",str(q["profile"]),"--certificate",str(q["cert"]),
            "--program",str(q["program"]),"--artifact",str(q["artifact"]),
            "--w7",str(q.get("w7",W7)),"--w8",str(q.get("w8",W8)),
            "--w5",str(q.get("w5",W5)),"--w6",str(q.get("w6",W6))]
    a=run_json([sys.executable,str(W10)]+common)
    b=run_json([str(W11)]+common)
    if a.get("proof_status")!=expected or b.get("proof_status")!=expected:
        raise AssertionError((label,expected,a,b))
    if expected=="ACCEPTED":
        for k in ("certificate_id","c2_certificate_id","c3_source_id","ordered_trace_map_id","c2_target_id","realize_pair_count"):
            if a.get(k)!=b.get(k):raise AssertionError((label,"checker disagreement",k,a.get(k),b.get(k)))
    return a,b

def mutate_cert(bundle,td,name,mutator,recompute=True,pretty=False):
    d=json.loads(json.dumps(bundle["doc"]))
    mutator(d)
    if recompute:
        try:d["certificate_id"]=fx.c3id(d)
        except Exception:pass
    p=Path(td)/(name+".cert.json")
    if pretty:p.write_text(json.dumps(d,indent=2),encoding="utf-8")
    else:p.write_bytes(canon(d))
    z=dict(bundle);z["cert"]=p;z["doc"]=d
    return z

def bundle_with(bundle,**kw):
    z=dict(bundle);z.update(kw);return z

def fake_id(prefix,ch="0"):
    return prefix+ch*64

def sha256_bytes(raw):
    return hashlib.sha256(raw).hexdigest()
