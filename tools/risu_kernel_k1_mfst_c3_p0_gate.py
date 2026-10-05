#!/usr/bin/env python3
"""P0 58-vector production-promotion composition attack gate."""
from __future__ import annotations
import copy, hashlib, json, os, subprocess, sys, tempfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
TOOLS=ROOT/"tools";sys.path.insert(0,str(TOOLS))
import risu_kernel_k1_mfst_c3_p0_fixture as fx
import risu_kernel_k1_mfst_c3_cert_q0_common as q
import risu_kernel_k1_mfst_c3_g1_generator as g1
import risu_kernel_k1_mfst_c3_r0_compiler as r0c

W12=ROOT/"kernel/k1_checker_w12_promotion.py"
W13=ROOT/"build/k1_checker_w13_promotion"
REAL_W10=ROOT/"kernel/k1_checker_w10_refinement_cert.py"
REAL_W11=ROOT/"build/k1_checker_w11_refinement_cert"
REAL_W7=ROOT/"kernel/k1_checker_w7.py";REAL_W8=ROOT/"build/k1_checker_w8"
REAL_W5=ROOT/"kernel/k1_checker_w5.py";REAL_W6=ROOT/"build/k1_checker_w6"

SOURCE_DEFAULTS={
 "w10_source":ROOT/"kernel/k1_checker_w10_refinement_cert.py",
 "w11_source":ROOT/"kernel/k1_checker_w11_refinement_cert.go",
 "w7_model_source":ROOT/"kernel/k1_w7_model.py",
 "w7_exec_source":ROOT/"kernel/k1_w7_exec.py",
 "w7_source":ROOT/"kernel/k1_checker_w7.py",
 "w8_json_source":ROOT/"kernel/k1_w8_json.go",
 "w8_model_source":ROOT/"kernel/k1_w8_model.go",
 "w8_exec_source":ROOT/"kernel/k1_w8_exec.go",
 "w8_source":ROOT/"kernel/k1_checker_w8.go",
 "w5_source":ROOT/"kernel/k1_checker_w5.py",
 "w6_source":ROOT/"kernel/k1_checker_w6.go",
}

def f0_defs():
    p=TOOLS/"risu_kernel_k1_mfst_c3_crossed_gate.py"
    src=p.read_text().split("# Inventory is authority data",1)[0]
    ns={"__file__":str(p),"__name__":"p0_f0_defs"};exec(compile(src,str(p),"exec"),ns);return ns
D=f0_defs()

def run_json(argv):
    p=subprocess.run([str(x) for x in argv],capture_output=True,text=True,check=True)
    try:return json.loads(p.stdout)
    except Exception as e:raise AssertionError((argv,p.stdout,p.stderr)) from e

def args_for(b,*,claim=q.CLAIM,exec_overrides=None,source_overrides=None):
    ex={"w10":REAL_W10,"w11":REAL_W11,"w7":REAL_W7,"w8":REAL_W8,"w5":REAL_W5,"w6":REAL_W6}
    ex.update(exec_overrides or {})
    src=dict(SOURCE_DEFAULTS);src.update(source_overrides or {})
    a=[
      "--claim",str(claim),"--profile",str(b["profile"]),"--c3-certificate",str(b["c3_certificate"]),
      "--program",str(b["program"]),"--c2-artifact",str(b["artifact"]),
      "--promotion-artifact",str(b["promotion_artifact"]),"--outer-certificate",str(b["outer_certificate"]),
      "--w10",str(ex["w10"]),"--w11",str(ex["w11"]),"--w7",str(ex["w7"]),"--w8",str(ex["w8"]),
      "--w5",str(ex["w5"]),"--w6",str(ex["w6"])
    ]
    for k in ("w10_source","w11_source","w7_model_source","w7_exec_source","w7_source",
              "w8_json_source","w8_model_source","w8_exec_source","w8_source","w5_source","w6_source"):
        a += ["--"+k.replace("_","-"),str(src[k])]
    return a

def check_pair(b,expected,label,**kw):
    a=run_json([sys.executable,str(W12),*args_for(b,**kw)])
    g=run_json([str(W13),*args_for(b,**kw)])
    if a.get("proof_status")!=expected or g.get("proof_status")!=expected:
        raise AssertionError((label,expected,a,g))
    if expected=="ACCEPTED":
        for k in ("promotion_artifact_id","outer_certificate_id","c3_certificate_id","c2_target_id","realize_pair_count"):
            if a.get(k)!=g.get(k):raise AssertionError((label,"W12/W13 disagreement",k,a.get(k),g.get(k)))
    if a.get("authority_created") is not False or g.get("authority_created") is not False:raise AssertionError((label,"authority"))
    print("P0_VECTOR_PASS",label,expected)
    return a,g

def clone_bundle(b):
    z=dict(b);z["promo"]=copy.deepcopy(b["promo"]);z["outer"]=copy.deepcopy(b["outer"]);return z

def write_json(td,name,obj,pretty=False):
    p=Path(td)/name
    p.write_text(json.dumps(obj,indent=2 if pretty else None,sort_keys=not pretty,separators=None if pretty else (",",":")),encoding="utf-8")
    return p

def rebuild_outer_file(z,td,name):
    z=dict(z);o=copy.deepcopy(z["outer"]);o["certificate_id"]=fx.outer_id(o)
    z["outer"]=o;z["outer_certificate"]=q.write(Path(td)/(name+".outer.json"),fx.canon(o));return z

def promo_mutated(base,td,name,mutator,*,rebind=True,outer_mutator=None):
    p=copy.deepcopy(base["promo"]);mutator(p)
    if rebind:return fx.rebind(base,td,name,promo=p,outer_mutator=outer_mutator)
    z=dict(base);z["promo"]=p;z["promotion_artifact"]=q.write(Path(td)/(name+".promotion.json"),fx.canon(p));return z

def outer_mutated(base,td,name,mutator,recompute=True):
    z=dict(base);o=copy.deepcopy(base["outer"]);mutator(o)
    if recompute:o["certificate_id"]=fx.outer_id(o)
    z["outer"]=o;z["outer_certificate"]=q.write(Path(td)/(name+".outer.json"),fx.canon(o));return z

def flip(x):
    return x[:-1]+("0" if x[-1]!="0" else "1")

def r0_record(idx):
    init=["C0","C1","X"];upd=["KEEP","CONST0","CONST1","COPY_X","NOT_Q_TABLE","ID_Q_TABLE","XOR_QX_TABLE","AND_QX_TABLE"]
    pred=["X_EQ0","X_EQ1","Q_EQ0","Q_EQ1","WORLD_EQ0","WORLD_EQ1"];pref=["NONE","E3"];tr=["A","B","AB","BA","AA","BB","ABA","BAB"]
    n=idx;f=n%8;n//=8;t=n%8;n//=8;pr=n%2;n//=2;pd=n%6;n//=6;u=n%8;n//=8;ini=n%3
    return {"descriptor_id":f"R0-{idx:05d}","initial_q":init[ini],"update":upd[u],"predicate":pred[pd],"prefix":pref[pr],"true_trace":tr[t],"false_trace":tr[f],"point_traces":[]}

def fake_rejectors(td):
    w10=Path(td)/"fake_w10_reject.py"
    w10.write_text('import json\nprint(json.dumps({"checker":"risu-k1-c3-cert-w10","proof_status":"REJECTED","semantic_claim":"NONE","authority_created":False,"reason":"P0 injected one-checker failure"}))\n')
    w11=Path(td)/"fake_w11_reject"
    w11.write_text('#!/usr/bin/env python3\nimport json\nprint(json.dumps({"checker":"risu-k1-c3-cert-w11","proof_status":"REJECTED","semantic_claim":"NONE","authority_created":False,"reason":"P0 injected one-checker failure"}))\n')
    w11.chmod(0o755)
    return w10,w11

def altered_source(td,real,name):
    p=Path(td)/name;p.write_bytes(Path(real).read_bytes()+b"\n");return p

def main():
    passed=0
    with tempfile.TemporaryDirectory() as s:
        td=Path(s)
        # Base pool for positive controls and coherent splices.
        base=fx.build(Path(q.BASE).read_bytes(),td,"base")
        state=fx.build(D["canon"](D["state_progress_profile"]()),td,"state")
        stress=fx.build(g1.encode(g1.make_stress(271828182,0)[0]),td,"stress")
        r0=fx.build(r0c.compile_bytes(r0_record(1)),td,"r0")
        rep=fx.build(D["representation_raw"](),td,"rep")
        order_obj=copy.deepcopy(D["BASE_OBJ"]);D["block"](order_obj,"alt")["ops"]=list(reversed(D["block"](order_obj,"alt")["ops"]))
        order=fx.build(D["canon"](order_obj),td,"order")
        pool=[base,state,stress,r0,rep,order]

        # Positives 8.
        check_pair(base,"ACCEPTED","P0-P01");passed+=1
        check_pair(state,"ACCEPTED","P0-P02");passed+=1
        check_pair(stress,"ACCEPTED","P0-P03");passed+=1
        check_pair(r0,"ACCEPTED","P0-P04");passed+=1
        praw=json.dumps(base["promo"],indent=2,sort_keys=False).encode()
        p05=fx.rebind(base,td,"p05",promo_raw=praw)
        check_pair(p05,"ACCEPTED","P0-P05");passed+=1
        p06=fx.build(Path(q.BASE).read_bytes(),td,"p06",c3_doc_mutator=lambda d:d["projected_realize"].reverse())
        check_pair(p06,"ACCEPTED","P0-P06");passed+=1
        check_pair(rep,"ACCEPTED","P0-P07");passed+=1
        check_pair(order,"ACCEPTED","P0-P08");passed+=1

        # Identity/version 01-10.
        p01=promo_mutated(base,td,"n01",lambda p:p.__setitem__("proof_kind","k1.capsule-closure/v1"),
                          outer_mutator=lambda o:(o["closure_proof"].__setitem__("kind","k1.capsule-closure/v1"),[x["proof"].__setitem__("kind","k1.capsule-closure/v1") for x in o["grounding_proofs"]]))
        check_pair(p01,"REJECTED","P0-01");passed+=1
        check_pair(promo_mutated(base,td,"n02",lambda p:p.__setitem__("proof_kind","k1.mediated-refinement/v0")),"REJECTED","P0-02");passed+=1
        check_pair(promo_mutated(base,td,"n03",lambda p:p.__setitem__("proof_format","risu.k1.mediated-refinement-proof/v0")),"REJECTED","P0-03");passed+=1
        p=copy.deepcopy(base["promo"]);p["qualified"]=True
        z=dict(base);z["promotion_artifact"]=q.write(td/"n04.promotion.json",fx.canon(p))
        check_pair(z,"REJECTED","P0-04");passed+=1
        raw=Path(base["promotion_artifact"]).read_text();raw=raw[:-1]+',"proof_kind":"k1.mediated-refinement/v1"}'
        z=dict(base);z["promotion_artifact"]=q.write(td/"n05.promotion.json",raw.encode())
        check_pair(z,"REJECTED","P0-05");passed+=1
        raw=json.dumps(base["promo"],indent=1).encode()
        z=dict(base);z["promotion_artifact"]=q.write(td/"n06.promotion.json",raw)
        check_pair(z,"REJECTED","P0-06");passed+=1
        z=outer_mutated(base,td,"n07",lambda o:o.__setitem__("certificate_id",flip(o["certificate_id"])),recompute=False)
        check_pair(z,"REJECTED","P0-07");passed+=1
        p=copy.deepcopy(base["promo"]);raw=json.dumps(p,indent=1).encode();z=fx.rebind(base,td,"n08-control",promo_raw=raw)
        oldroot=base["outer"]["evidence_roots"][0]
        z=outer_mutated(z,td,"n08",lambda o:o.__setitem__("evidence_roots",[oldroot]))
        check_pair(z,"REJECTED","P0-08");passed+=1
        c3=json.loads(Path(base["c3_certificate"]).read_text());c3path=write_json(td,"n09.c3.json",c3,pretty=True)
        z=dict(base);z["c3_certificate"]=c3path
        check_pair(z,"REJECTED","P0-09");passed+=1
        check_pair(promo_mutated(base,td,"n10",lambda p:p.__setitem__("c3_certificate_id",flip(p["c3_certificate_id"]))),"REJECTED","P0-10");passed+=1

        # Qualification rollback/pin 11-18.
        check_pair(promo_mutated(base,td,"n11",lambda p:p.__setitem__("q0_qualification_anchor_commit","d66cccb586893320235ba3bbb57429639debed0c")),"REJECTED","P0-11");passed+=1
        check_pair(promo_mutated(base,td,"n12",lambda p:p.__setitem__("q0_qualification_anchor_blob","b2ac1b0abc46f23ab8605ed71cdfc9b255403ec0")),"REJECTED","P0-12");passed+=1
        check_pair(promo_mutated(base,td,"n13",lambda p:p.__setitem__("q0_candidate_id","A0")),"REJECTED","P0-13");passed+=1
        check_pair(promo_mutated(base,td,"n14",lambda p:p.__setitem__("w10_blob","1ae9cb6a2a1fd134c53f7c79cbf4290c023889e1")),"REJECTED","P0-14");passed+=1
        check_pair(promo_mutated(base,td,"n15",lambda p:p.__setitem__("w11_blob","0"*40)),"REJECTED","P0-15");passed+=1
        check_pair(promo_mutated(base,td,"n16",lambda p:p.__setitem__("w10_blob","1ae9cb6a2a1fd134c53f7c79cbf4290c023889e1")),"REJECTED","P0-16");passed+=1
        check_pair(promo_mutated(base,td,"n17",lambda p:p.__setitem__("q0_candidate_id","A2")),"REJECTED","P0-17");passed+=1
        check_pair(promo_mutated(base,td,"n18",lambda p:p.__setitem__("q0_qualification_anchor_commit","02518e2d5aede48763a643a620c09c68c876db42")),"REJECTED","P0-18");passed+=1

        # Scope 19-28.
        check_pair(promo_mutated(base,td,"n19",lambda p:p.__setitem__("source_semantics","risu.native/v1")),"REJECTED","P0-19");passed+=1
        check_pair(promo_mutated(base,td,"n20",lambda p:p.__setitem__("source_semantics","*")),"REJECTED","P0-20");passed+=1
        check_pair(promo_mutated(base,td,"n21",lambda p:p.__setitem__("downstream_proof_kind","k1.unknown/v1")),"REJECTED","P0-21");passed+=1
        check_pair(promo_mutated(base,td,"n22",lambda p:p.__setitem__("downstream_proof_kind","risu.k1.w0")),"REJECTED","P0-22");passed+=1
        check_pair(promo_mutated(base,td,"n23",lambda p:p.__setitem__("authority_scope","ARBITRARY_NATIVE_PROGRAM")),"REJECTED","P0-23");passed+=1
        check_pair(promo_mutated(base,td,"n24",lambda p:p.__setitem__("authority_scope","*")),"REJECTED","P0-24");passed+=1
        z=dict(base);z["profile"]=order["profile"];check_pair(z,"REJECTED","P0-25");passed+=1
        z=dict(base);z["program"]=order["program"];check_pair(z,"REJECTED","P0-26");passed+=1
        z=dict(base);z["artifact"]=order["artifact"];check_pair(z,"REJECTED","P0-27");passed+=1
        z=outer_mutated(base,td,"n28",lambda o:o.__setitem__("target_id",flip(o["target_id"])))
        check_pair(z,"REJECTED","P0-28");passed+=1

        # Replay/splice 29-38.
        def shrink(o):
            o["realize"]=o["realize"][:-1];o["grounding_proofs"]=o["grounding_proofs"][:-1]
        check_pair(outer_mutated(base,td,"n29",shrink),"REJECTED","P0-29");passed+=1
        def widen(o):
            w=o["realize"][0][0];c="c:sha256:"+"0"*64
            if any(x[1]==c for x in o["realize"]):c="c:sha256:"+"1"*64
            pair=[w,c];o["realize"].append(pair);o["grounding_proofs"].append({"pair":pair,"proof":copy.deepcopy(o["closure_proof"])})
        check_pair(outer_mutated(base,td,"n30",widen),"REJECTED","P0-30");passed+=1
        other_claim=ROOT/"fixtures/k1_observed_pair_p1/claim_multi.json"
        check_pair(base,"REJECTED","P0-31",claim=other_claim);passed+=1
        claimb=json.loads(other_claim.read_text())["claim_id"]
        z=promo_mutated(base,td,"n32",lambda p:p.__setitem__("claim_id",claimb))
        check_pair(z,"REJECTED","P0-32",claim=other_claim);passed+=1
        def splice(p):
            for k in ("profile_sha256","c3_certificate_sha256","c3_certificate_id","c2_program_sha256","c2_artifact_id","c2_target_id"):p[k]=order["promo"][k]
        check_pair(promo_mutated(base,td,"n33",splice),"REJECTED","P0-33");passed+=1
        z=dict(base);z["c3_certificate"]=order["c3_certificate"];check_pair(z,"REJECTED","P0-34");passed+=1
        z=dict(base);z["profile"]=order["profile"];check_pair(z,"REJECTED","P0-35");passed+=1
        def cross_target(o):
            o["target_id"]=order["outer"]["target_id"];o["realize"]=copy.deepcopy(order["outer"]["realize"])
            o["grounding_proofs"]=[{"pair":copy.deepcopy(x),"proof":copy.deepcopy(o["closure_proof"])} for x in o["realize"]]
        check_pair(outer_mutated(base,td,"n36",cross_target),"REJECTED","P0-36");passed+=1
        check_pair(outer_mutated(base,td,"n37",lambda o:o.__setitem__("evidence_roots",copy.deepcopy(order["outer"]["evidence_roots"]))),"REJECTED","P0-37");passed+=1
        check_pair(outer_mutated(base,td,"n38",lambda o:o["closure_proof"].__setitem__("artifact",order["promotion_artifact_id"])),"REJECTED","P0-38");passed+=1

        # Partial-chain / grounding 39-44.
        check_pair(outer_mutated(base,td,"n39",lambda o:o["grounding_proofs"][0]["proof"].__setitem__("artifact",order["promotion_artifact_id"])),"REJECTED","P0-39");passed+=1
        check_pair(outer_mutated(base,td,"n40",lambda o:o["grounding_proofs"].pop()),"REJECTED","P0-40");passed+=1
        def dup_ground(o):
            if len(o["grounding_proofs"])<2:raise AssertionError("need two grounding rows")
            o["grounding_proofs"][-1]=copy.deepcopy(o["grounding_proofs"][0])
        check_pair(outer_mutated(base,td,"n41",dup_ground),"REJECTED","P0-41");passed+=1
        fw10,fw11=fake_rejectors(td)
        check_pair(base,"REJECTED","P0-42",exec_overrides={"w11":fw11});passed+=1
        check_pair(base,"REJECTED","P0-43",exec_overrides={"w10":fw10});passed+=1
        c3=copy.deepcopy(json.loads(Path(base["c3_certificate"]).read_text()))
        c3["c3_semantic_id"]=flip(c3["c3_semantic_id"]);c3["certificate_id"]=q.fx.c3id(c3)
        c3raw=fx.canon(c3);c3path=q.write(td/"n44.c3.json",c3raw)
        p=copy.deepcopy(base["promo"]);p["c3_certificate_sha256"]=hashlib.sha256(c3raw).hexdigest();p["c3_certificate_id"]=c3["certificate_id"]
        z=dict(base);z["c3_certificate"]=c3path;z["promo"]=p
        z=fx.rebind(z,td,"n44",promo=p)
        check_pair(z,"REJECTED","P0-44");passed+=1

        # Transitive source pin closure 45-50.
        bad=altered_source(td,SOURCE_DEFAULTS["w7_source"],"bad_w7.py")
        check_pair(base,"REJECTED","P0-45",source_overrides={"w7_source":bad});passed+=1
        bad=altered_source(td,SOURCE_DEFAULTS["w8_source"],"bad_w8.go")
        check_pair(base,"REJECTED","P0-46",source_overrides={"w8_source":bad});passed+=1
        bad=altered_source(td,SOURCE_DEFAULTS["w5_source"],"bad_w5.py")
        check_pair(base,"REJECTED","P0-47",source_overrides={"w5_source":bad});passed+=1
        bad=altered_source(td,SOURCE_DEFAULTS["w6_source"],"bad_w6.go")
        check_pair(base,"REJECTED","P0-48",source_overrides={"w6_source":bad});passed+=1
        bad=altered_source(td,SOURCE_DEFAULTS["w7_model_source"],"bad_w7_model.py")
        check_pair(base,"REJECTED","P0-49",source_overrides={"w7_model_source":bad});passed+=1
        bad=altered_source(td,SOURCE_DEFAULTS["w8_model_source"],"bad_w8_model.go")
        check_pair(base,"REJECTED","P0-50",source_overrides={"w8_model_source":bad});passed+=1

    if passed!=58:raise AssertionError(("P0 vector count",passed))
    print("P0_PRODUCTION_PROMOTION_ATTACK_PASS",passed)
    print("P0_POSITIVE 8")
    print("P0_NEGATIVE 50")
    print("AUTHORITY_CREATED false")
if __name__=="__main__":main()
