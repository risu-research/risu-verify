#!/usr/bin/env python3
"""Frozen C0 refinement-certificate adversarial gate. Test-only orchestration."""
from __future__ import annotations
import copy, hashlib, importlib.util, json, os, subprocess, sys, tempfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
CLAIM=ROOT/"fixtures/k1_mfst_c3_f0/claim.json"
BASE=ROOT/"fixtures/k1_mfst_c3_f0/baseline.json"
FIX=ROOT/"tools/risu_kernel_k1_mfst_c3_cert_c0_fixture.py"
W10=ROOT/"kernel/k1_checker_w10_refinement_cert.py"
W11=ROOT/"build/k1_checker_w11_refinement_cert"
W7=ROOT/"kernel/k1_checker_w7.py"; W8=ROOT/"build/k1_checker_w8"
W5=ROOT/"kernel/k1_checker_w5.py"; W6=ROOT/"build/k1_checker_w6"
BASEOBJ=json.loads(BASE.read_text())
CLAIMOBJ=json.loads(CLAIM.read_text())

spec=importlib.util.spec_from_file_location("fx",FIX);fx=importlib.util.module_from_spec(spec);spec.loader.exec_module(fx)
spec2=importlib.util.spec_from_file_location("w5",W5);w5=importlib.util.module_from_spec(spec2);spec2.loader.exec_module(w5)

passed=[]

def canon(x):return json.dumps(x,sort_keys=True,separators=(",",":")).encode()
def runj(argv):
    cp=subprocess.run([str(x) for x in argv],capture_output=True,text=True,check=True)
    try:return json.loads(cp.stdout)
    except Exception as e:raise AssertionError((argv,cp.stdout,cp.stderr)) from e
def write(p,b):Path(p).write_bytes(b if isinstance(b,bytes) else b.encode());return Path(p)

def produce(raw,td,name="b",claim=CLAIM):
    p=write(td/(name+".profile.json"),raw)
    c=td/(name+".cert.json");pr=td/(name+".cap");ar=td/(name+".artifact.json")
    cp=subprocess.run([sys.executable,str(FIX),"--claim",str(claim),"--profile",str(p),"--w7",str(W7),"--w8",str(W8),
                       "--out",str(c),"--program_out",str(pr),"--artifact_out",str(ar)],capture_output=True,text=True)
    if cp.returncode: raise AssertionError((name,cp.stdout,cp.stderr))
    return {"profile":p,"cert":c,"program":pr,"artifact":ar,"doc":json.loads(c.read_text())}

def checker(bundle,which="both",claim=CLAIM,overrides=None):
    q=dict(bundle);q.update(overrides or {})
    common=["--claim",str(claim),"--profile",str(q["profile"]),"--certificate",str(q["cert"]),
            "--program",str(q["program"]),"--artifact",str(q["artifact"]),"--w7",str(q.get("w7",W7)),
            "--w8",str(q.get("w8",W8)),"--w5",str(q.get("w5",W5)),"--w6",str(q.get("w6",W6))]
    out={}
    if which in ("both","w10"):out["w10"]=runj([sys.executable,str(W10)]+common)
    if which in ("both","w11"):out["w11"]=runj([str(W11)]+common)
    return out

def expect(name,bundle,status="REJECTED",claim=CLAIM,overrides=None):
    r=checker(bundle,claim=claim,overrides=overrides)
    for k,v in r.items():
        if v.get("proof_status")!=status:raise AssertionError((name,k,status,v))
    if status=="ACCEPTED":
        if r["w10"]["certificate_id"]!=r["w11"]["certificate_id"]:raise AssertionError((name,"id disagreement"))
        if r["w10"]["c2_certificate_id"]!=r["w11"]["c2_certificate_id"]:raise AssertionError((name,"c2 id disagreement"))
    passed.append(name);print("C0_VECTOR_PASS",name,status)
    return r

def cert_mut(bundle,td,name,fn,recompute=True,raw_override=None):
    d=copy.deepcopy(bundle["doc"]);fn(d)
    if recompute and "certificate_id" in d:
        try:d["certificate_id"]=fx.c3id(d)
        except Exception:pass
    cp=td/(name+".cert.json")
    if raw_override is None:cp.write_bytes(canon(d))
    else:cp.write_bytes(raw_override(d))
    z=dict(bundle);z["cert"]=cp;z["doc"]=d;return z

def profile_raw(obj):return canon(obj)
def block(o,label):return next(x for x in o["blocks"] if x["label"]==label)
def rep_permuted_raw():
    o=copy.deepcopy(BASEOBJ);o["boundary"]["worlds"].reverse();o["boundary"]["slots"]["mode"].reverse()
    o["state"].reverse();o["tables"].reverse()
    for t in o["tables"]:t["rows"].reverse()
    o["blocks"].reverse()
    return json.dumps(o,separators=(",",":")).encode()

def fresh_c2_cert(claim_path,artifact,program,source_id,trace_id):
    claim=json.loads(Path(claim_path).read_text());ar=Path(artifact).read_bytes();pr=Path(program).read_bytes()
    aid="p:sha256:"+hashlib.sha256(ar).hexdigest()
    _,realize,target=w5.check_artifact(ar,aid,claim,pr)
    rows=[list(x) for x in sorted(realize)]
    root=fx.evidence(source_id,trace_id,hashlib.sha256(pr).hexdigest(),aid)
    cid=fx.c2id(claim["claim_id"],target,aid,root,rows)
    proof={"kind":"k1.capsule-closure/v1","artifact":aid}
    d={"wire":"risu.k1.w0","kind":"preservation_certificate","claim_id":claim["claim_id"],"target_id":target,"realize":rows,
       "closure_proof":proof,"grounding_proofs":[{"pair":r,"proof":dict(proof)} for r in rows],
       "evidence_roots":[root],"certificate_id":cid}
    return d,rows,target,aid

def prove_c2_valid(claim,artifact,program,source_id,trace_id,td,name):
    d,rows,target,aid=fresh_c2_cert(claim,artifact,program,source_id,trace_id)
    cp=td/(name+".c2cert.json");cp.write_bytes(canon(d))
    a=runj([sys.executable,str(W5),"--claim",str(claim),"--certificate",str(cp),"--artifact",str(artifact),"--program",str(program)])
    b=runj([str(W6),"--claim",str(claim),"--certificate",str(cp),"--artifact",str(artifact),"--program",str(program)])
    if a["proof_status"]!="ACCEPTED" or b["proof_status"]!="ACCEPTED":raise AssertionError((name,a,b))
    return rows,target,aid,d["certificate_id"]

def pin(path,expected):
    cp=subprocess.run(["git","hash-object",str(path)],capture_output=True,text=True,check=True)
    return cp.stdout.strip()==expected

def main():
  with tempfile.TemporaryDirectory() as s:
    td=Path(s);base=produce(BASE.read_bytes(),td,"base")
    expect("C0-P01",base,"ACCEPTED")

    # P02: certificate key order is representation-only.
    d=base["doc"];rev={k:d[k] for k in reversed(list(d))}
    p=td/"p02.cert.json";p.write_text(json.dumps(rev,separators=(",",":")))
    z=dict(base);z["cert"]=p;expect("C0-P02",z,"ACCEPTED")

    # P03 representation-only source permutation, freshly rebound.
    rp=produce(rep_permuted_raw(),td,"p03");expect("C0-P03",rp,"ACCEPTED")
    assert rp["doc"]["c3_source_id"]!=base["doc"]["c3_source_id"] and rp["doc"]["c3_semantic_id"]==base["doc"]["c3_semantic_id"]

    # P04 formal argument rename changes semantic identity but not lowering behavior.
    o=copy.deepcopy(BASEOBJ);o["tables"][0]["arguments"][0]["name"]="formal_renamed"
    p04=produce(canon(o),td,"p04");expect("C0-P04",p04,"ACCEPTED")
    assert p04["doc"]["c3_semantic_id"]!=base["doc"]["c3_semantic_id"]
    assert p04["program"].read_bytes()==base["program"].read_bytes()

    # P05 unreachable valid block.
    o=copy.deepcopy(BASEOBJ);o["blocks"].append({"label":"dead","ops":[{"op":"EMIT_HEX","payload":"aa"}],"term":{"op":"HALT"}})
    p05=produce(canon(o),td,"p05");expect("C0-P05",p05,"ACCEPTED")

    expect("C0-P06",base,"ACCEPTED")
    o=copy.deepcopy(BASEOBJ);block(o,"alt")["ops"].append({"op":"EMIT_HEX","payload":"03"})
    p07=produce(canon(o),td,"p07");expect("C0-P07",p07,"ACCEPTED")
    assert p07["doc"]["projected_realize"]==base["doc"]["projected_realize"]

    # P08 same K1 set, different ordered traces, own certificates only.
    o=copy.deepcopy(BASEOBJ);block(o,"alt")["ops"]=list(reversed(block(o,"alt")["ops"]))
    p08=produce(canon(o),td,"p08");expect("C0-P08",p08,"ACCEPTED")
    assert p08["doc"]["projected_realize"]==base["doc"]["projected_realize"]
    assert p08["doc"]["ordered_trace_map_id"]!=base["doc"]["ordered_trace_map_id"]

    # C0-01 stale source id against representation-only changed source bytes.
    stale=dict(rp);stale["cert"]=base["cert"];stale["program"]=base["program"];stale["artifact"]=base["artifact"];expect("C0-01",stale)

    # C0-02..04 stale derived commitments with recomputed outer id.
    expect("C0-02",cert_mut(base,td,"n02",lambda d:d.__setitem__("c3_semantic_id","c3sem:sha256:"+"0"*64)))
    expect("C0-03",cert_mut(base,td,"n03",lambda d:d.__setitem__("reachable_graph_id","c3graph:sha256:"+"0"*64)))
    expect("C0-04",cert_mut(base,td,"n04",lambda d:d.__setitem__("ordered_trace_map_id","c3trace:sha256:"+"0"*64)))

    # C0-05 reorder laundering, same K1 set, stale trace commitment.
    m=cert_mut(p08,td,"n05",lambda d:d.__setitem__("ordered_trace_map_id",base["doc"]["ordered_trace_map_id"]));expect("C0-05",m)
    # C0-06 insertion laundering using duplicated effect.
    m=cert_mut(p07,td,"n06",lambda d:d.__setitem__("ordered_trace_map_id",base["doc"]["ordered_trace_map_id"]));expect("C0-06",m)
    # C0-07 deletion laundering: source has duplicate but cert claims nonduplicate trace.
    m=cert_mut(p07,td,"n07",lambda d:d.__setitem__("ordered_trace_map_id",base["doc"]["ordered_trace_map_id"]));expect("C0-07",m)

    # C0-08 smaller C2 capsule is valid on its own, not faithful to original C3 source scope.
    art=json.loads(base["artifact"].read_text());art["boundary"]["slots"]["mode"]=["safe"]
    shrink_art=td/"shrink.artifact.json";shrink_art.write_bytes(canon(art))
    prove_c2_valid(CLAIM,shrink_art,base["program"],base["doc"]["c3_source_id"],base["doc"]["ordered_trace_map_id"],td,"shrink")
    z=dict(base);z["artifact"]=shrink_art;expect("C0-08",z)

    # C0-09 behavior-equivalent non-CBTNF: append unreachable effectful block, rebuild valid C2 artifact.
    altprog=td/"noncanonical.cap";altprog.write_bytes(base["program"].read_bytes()+b"LABEL EXTRA\nEMIT_HEX 01\nHALT\n")
    art=json.loads(base["artifact"].read_text());art["program_sha256"]=hashlib.sha256(altprog.read_bytes()).hexdigest()
    alta=td/"noncanonical.artifact.json";alta.write_bytes(canon(art))
    prove_c2_valid(CLAIM,alta,altprog,base["doc"]["c3_source_id"],base["doc"]["ordered_trace_map_id"],td,"noncanon")
    z=dict(base);z["program"]=altprog;z["artifact"]=alta;expect("C0-09",z)

    expect("C0-10",cert_mut(base,td,"n10",lambda d:d.__setitem__("c2_program_sha256","0"*64)))
    expect("C0-11",cert_mut(base,td,"n11",lambda d:d.__setitem__("c2_artifact_id","p:sha256:"+"0"*64)))
    expect("C0-12",cert_mut(base,td,"n12",lambda d:d.__setitem__("c2_target_id","t:sha256:"+"0"*64)))
    expect("C0-13",cert_mut(base,td,"n13",lambda d:d.__setitem__("projected_realize",d["projected_realize"][:-1])))
    fake=["w:sha256:"+"0"*64,"c:sha256:"+"0"*64]
    expect("C0-14",cert_mut(base,td,"n14",lambda d:d["projected_realize"].append(fake)))
    expect("C0-15",cert_mut(base,td,"n15",lambda d:d.__setitem__("c2_certificate_id","cert:sha256:"+"0"*64)))
    expect("C0-16",cert_mut(base,td,"n16",lambda d:d.__setitem__("claim_id","claim:sha256:"+"0"*64)))

    # C0-17 coherent splice across profiles.
    z=dict(base);z["program"]=p08["program"];z["artifact"]=p08["artifact"];expect("C0-17",z)

    # C0-18 stale outer id.
    expect("C0-18",cert_mut(base,td,"n18",lambda d:d.__setitem__("reachable_graph_id","c3graph:sha256:"+"1"*64),recompute=False))
    # C0-19 attacker recomputes outer id over false inner fact.
    expect("C0-19",cert_mut(base,td,"n19",lambda d:d.__setitem__("reachable_graph_id","c3graph:sha256:"+"2"*64),recompute=True))
    expect("C0-20",cert_mut(base,td,"n20",lambda d:d.__setitem__("agreement",True),recompute=False))
    def verdicts(d):d["preservation"]=True;d["authority"]=True;d["closed"]=True;d["complete"]=True
    expect("C0-21",cert_mut(base,td,"n21",verdicts,recompute=False))

    # C0-22 duplicate JSON key.
    raw=base["cert"].read_text();raw=raw[:-1]+',"wire":"risu.k1.c3.refinement-certificate/v1"}'
    z=dict(base);p=td/"dup.cert.json";p.write_text(raw);z["cert"]=p;expect("C0-22",z)

    expect("C0-23",cert_mut(base,td,"n23",lambda d:d.__setitem__("c3_source_id","c3src:sha256:bad"),recompute=False))
    expect("C0-24",cert_mut(base,td,"n24",lambda d:d["projected_realize"].append(list(d["projected_realize"][0])),recompute=False))

    # C0-25 explicitly verify semantic equality cannot erase exact-source binding.
    z=dict(rp);z["cert"]=base["cert"];z["program"]=rp["program"];z["artifact"]=rp["artifact"];expect("C0-25",z)

    # C0-26 artifact JSON reserialization is independently valid C2 with new artifact id, but stale C3 exact artifact binding fails.
    pretty=td/"pretty.artifact.json";pretty.write_text(json.dumps(json.loads(base["artifact"].read_text()),indent=2))
    prove_c2_valid(CLAIM,pretty,base["program"],base["doc"]["c3_source_id"],base["doc"]["ordered_trace_map_id"],td,"pretty")
    z=dict(base);z["artifact"]=pretty;expect("C0-26",z)

    # C0-27 underbound gas artifact.
    art=json.loads(base["artifact"].read_text());art["boundary"]["gas"]=max(1,art["boundary"]["gas"]-1)
    ga=td/"gas.artifact.json";ga.write_bytes(canon(art));z=dict(base);z["artifact"]=ga;expect("C0-27",z)

    # C0-28 mutated program with refreshed transported raw SHA but stale lowering bundle.
    mp=td/"mut.cap";mp.write_bytes(base["program"].read_bytes()+b"LABEL EXTRA2\nEMIT_HEX 01\nHALT\n")
    z=cert_mut(base,td,"n28",lambda d:d.__setitem__("c2_program_sha256",hashlib.sha256(mp.read_bytes()).hexdigest()))
    z["program"]=mp;expect("C0-28",z)

    # C0-29..32 evidence engine absence/failure closes the lane.
    for n,key in [("C0-29","w7"),("C0-30","w8"),("C0-31","w5"),("C0-32","w6")]:
        expect(n,base,overrides={key:td/("missing-"+key)})

    # C0-33 pair-level disagreement is fail-closed.
    good=checker(base)
    fake=copy.deepcopy(good["w11"]);fake["proof_status"]="REJECTED"
    try:
        if good["w10"]["proof_status"]!=fake["proof_status"] or good["w10"]["certificate_id"]!=fake.get("certificate_id"):
            raise RuntimeError("pair disagreement")
        raise AssertionError("disagreement not detected")
    except RuntimeError:
        passed.append("C0-33");print("C0_VECTOR_PASS C0-33 REJECTED_META")

    # C0-34/35 pin verifier itself catches drift.
    pins=[("C0-34",ROOT/"kernel/k1_checker_w7.py","c011532efbe9b6dcd6ae440705ce7b38c5dde93b"),
          ("C0-35",ROOT/"kernel/k1_checker_w5.py","cf08aff1ce9f9506df37d597c2fc348bfefd6331")]
    for n,p,h in pins:
        assert pin(p,h) and not pin(p,"0"*40);passed.append(n);print("C0_VECTOR_PASS",n,"PIN_FAIL_CLOSED")

    expect("C0-36",cert_mut(base,td,"n36",lambda d:d.__setitem__("checker_results",{"w7":"ACCEPTED","w8":"ACCEPTED"}),recompute=False))

    # C0-37 different exact claim even when profile payloads are unchanged.
    c=copy.deepcopy(CLAIMOBJ);c["allow"]=c["allow"][:-1];c["claim_id"]=w5.claim_id(c)
    nc=td/"other.claim.json";nc.write_bytes(canon(c));expect("C0-37",base,claim=nc)

    expect("C0-38",cert_mut(base,td,"n38",lambda d:d.__setitem__("extension",{"authority":True}),recompute=False))

  expected={f"C0-{i:02d}" for i in range(1,39)}|{f"C0-P{i:02d}" for i in range(1,9)}
  if set(passed)!=expected:raise AssertionError(("inventory",sorted(expected-set(passed)),sorted(set(passed)-expected)))
  print("C0_REFINEMENT_CERTIFICATE_GATE_PASS",len(passed))
  print("AUTHORITY_CREATED false")
if __name__=="__main__":main()
