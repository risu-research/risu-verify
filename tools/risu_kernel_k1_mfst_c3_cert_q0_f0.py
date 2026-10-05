#!/usr/bin/env python3
"""Q0: replay all 62 frozen F0 oracles through the actual certificate object."""
from __future__ import annotations
import copy, hashlib, json, os, subprocess, sys, tempfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
TOOLS=ROOT/"tools";sys.path.insert(0,str(TOOLS))
import risu_kernel_k1_mfst_c3_cert_q0_common as q

CROSS=TOOLS/"risu_kernel_k1_mfst_c3_crossed_gate.py"
F0=json.loads((ROOT/"protocols/RISU_KERNEL_K1_MFST_C3_F0_FREEZE.json").read_text())

def load_defs():
    src=CROSS.read_text()
    marker="# Inventory is authority data"
    if marker not in src: raise AssertionError("crossed gate layout drift")
    code=src.split(marker,1)[0]
    ns={"__file__":str(CROSS),"__name__":"q0_f0_defs"}
    exec(compile(code,str(CROSS),"exec"),ns)
    return ns

D=load_defs()
BASEOBJ=D["BASE_OBJ"]

def accepted_raw(cid):
    p=copy.deepcopy(BASEOBJ);raw=D["canon"](p)
    if cid=="C3-P02":raw=D["representation_raw"]()
    elif cid in ("C3-P04","F0-02"):raw=D["canon"](D["state_progress_profile"]())
    elif cid in ("C3-P05","AM1-07"):raw=D["canon"](D["world_input_profile"]())
    elif cid=="C3-P06":
        D["block"](p,"safe")["ops"]=[{"op":"EMIT_HEX","payload":"aa"}];raw=D["canon"](p)
    elif cid in ("C3-P07","AM1-09"):raw=D["canon"](D["alias_profile"]())
    elif cid=="C3-P08":
        p["blocks"].append({"label":"dead","ops":[{"op":"EMIT_HEX","payload":"aa"}],"term":{"op":"HALT"}});raw=D["canon"](p)
    elif cid=="AM1-01":
        p["tables"][0]["arguments"][0]["name"]="renamed";raw=D["canon"](p)
    elif cid=="AM1-02":raw=D["canon"](D["binding_profile"]())
    elif cid=="AM1-10":
        p["tables"][0]["arguments"][0]["domain"].reverse();p["tables"][0]["rows"].reverse();raw=D["canon"](p)
    return raw

def parse_raws(cid):
    opmap={"C3-01":"EFFECT","C3-08":"ASYNC","C3-09":"SPAWN","C3-11":"HOSTCALL","C3-12":"DYNAMIC_LOAD",
           "C3-13":"EVAL","C3-14":"SHARED_MEMORY","C3-15":"THREAD","C3-16":"SIGNAL","C3-17":"CLOCK",
           "C3-18":"RNG","C3-19":"ENV_READ","C3-20":"PERSIST"}
    if cid in opmap:return [D["op_reject"](opmap[cid])]
    if cid=="C3-10":
        p=copy.deepcopy(BASEOBJ);p["blocks"][0]["ops"].insert(0,{"op":"SET_FROM","dst":"phase","source":{"kind":"ambient","name":"handle"}})
        return [D["canon"](p)]
    if cid=="C3-26":
        b=D["canon"](BASEOBJ)
        return [b[:-1]+b',"wire":"risu.k1.c3.mfst/v1"}',b+b"\x00",b.replace(b'"entry"',b'"entry\t"',1),b"\xff"+b,
                b[:-1]+b',"unknown":"x"}',b[:-1]+b',"unknown":1}',b[:-1]+b',"unknown":true}',b[:-1]+b',"unknown":null}']
    raise AssertionError(cid)

def semantic_raw(cid):
    p=copy.deepcopy(BASEOBJ)
    if cid=="C3-07":return D["canon"](D["forbidden_profile"](two=True))
    if cid=="C3-21":p["boundary"]["worlds"]=p["boundary"]["worlds"][:1]
    elif cid=="AM1-03":
        p["tables"][0]["arguments"][0]["domain"]=["p0"];p["tables"][0]["rows"]=[{"when":["p0"],"result":"p1"}]
    elif cid=="AM1-04":p["tables"][0]["rows"]=p["tables"][0]["rows"][:1]
    elif cid=="AM1-05":p["tables"][0]["rows"].append(copy.deepcopy(p["tables"][0]["rows"][0]))
    elif cid=="AM1-06":p["tables"][0]["rows"].append({"when":["p2"],"result":"p0"})
    elif cid=="AM1-08":p["blocks"][0]["ops"][0]["arguments"]=[{"kind":"input","name":"missing"}]
    elif cid=="F0-01":D["block"](p,"safe")["term"]={"op":"GOTO","target":"safe"}
    elif cid=="F0-03":D["block"](p,"safe")["ops"]=[]
    elif cid=="F0-04":p["blocks"].append({"label":"dead","ops":[],"term":{"op":"GOTO","target":"missing"}})
    elif cid=="F0-08":p["state"][0]["domain"]=["p0"]
    elif cid=="F0-12":p["boundary"]["slots"]["mode"]=["safe","alt"]+[f"v{i:04d}" for i in range(700)]
    else:raise AssertionError(cid)
    return D["canon"](p)

def profile_override(bundle,td,name,raw):
    p=q.write(Path(td)/(name+".profile.bin"),raw);z=dict(bundle);z["profile"]=p;return z

def fake_w8(td):
    p=Path(td)/"fake_w8.py"
    p.write_text("""#!/usr/bin/env python3
import json,subprocess,sys
real=sys.argv[1]
cp=subprocess.run([real]+sys.argv[2:],capture_output=True,text=True,check=True)
o=json.loads(cp.stdout);o['graph_id']='c3graph:sha256:'+'0'*64
print(json.dumps(o,separators=(',',':')))
""")
    p.chmod(0o755)
    wrapper=Path(td)/"fake_w8_exec"
    wrapper.write_text("#!/bin/sh\nexec python3 \""+str(p)+"\" \""+str(q.W8)+"\" \"$@\"\n")
    wrapper.chmod(0o755)
    return wrapper

def cross_attack(cid,base,td):
    # Each return is an actual candidate certificate submission.
    if cid=="C3-02":
        return q.mutate_cert(base,td,cid,lambda d:d.__setitem__("ordered_trace_map_id",q.fake_id("c3trace:sha256:","0")))
    if cid in ("C3-03","C3-04"):
        raw=D["canon"](D["forbidden_profile"](two=True));return profile_override(base,td,cid,raw)
    if cid=="C3-05":
        p=copy.deepcopy(BASEOBJ);D["block"](p,"safe")["ops"]=[{"op":"EMIT_HEX","payload":"aa"}]
        b=q.derive_bundle(D["canon"](p),td,cid+"-source")
        return q.mutate_cert(b,td,cid,lambda d:d.__setitem__("ordered_trace_map_id",base["doc"]["ordered_trace_map_id"]))
    if cid=="C3-06":
        return q.mutate_cert(base,td,cid,lambda d:d.__setitem__("projected_realize",d["projected_realize"][:-1]))
    if cid=="C3-22":
        art=json.loads(Path(base["artifact"]).read_text());art["boundary"]["slots"]["mode"]=["safe"]
        ap=q.write(Path(td)/(cid+".artifact.json"),q.canon(art));return q.bundle_with(base,artifact=ap)
    if cid=="C3-23":
        p=copy.deepcopy(BASEOBJ);D["block"](p,"safe")["ops"]=[{"op":"EMIT_HEX","payload":"aa"}]
        return profile_override(base,td,cid,D["canon"](p))
    if cid=="C3-24":
        raw=Path(base["program"]).read_bytes().replace(b"EMIT_HEX 03",b"EMIT_HEX 02",1)
        pp=q.write(Path(td)/(cid+".cap"),raw);return q.bundle_with(base,program=pp)
    if cid=="C3-25":
        art=json.loads(Path(base["artifact"]).read_text());art["boundary"]["gas"]+=1
        ap=q.write(Path(td)/(cid+".artifact.json"),q.canon(art));return q.bundle_with(base,artifact=ap)
    if cid=="C3-27":
        return q.mutate_cert(base,td,cid,lambda d:d.__setitem__("projected_realize",d["projected_realize"][:-1]))
    if cid=="C3-28":
        return q.mutate_cert(base,td,cid,lambda d:d.__setitem__("complete",True),recompute=False)
    if cid=="C3-29":
        return q.mutate_cert(base,td,cid,lambda d:d.__setitem__("c2_target_id",q.fake_id("t:sha256:","0")))
    if cid=="C3-30":
        p=Path(td)/(cid+".profile.json");p.write_text(json.dumps(BASEOBJ,indent=1),encoding="utf-8")
        return q.bundle_with(base,profile=p)
    if cid=="C3-31":
        p=copy.deepcopy(BASEOBJ);D["block"](p,"safe")["ops"].append({"op":"EMIT_HEX","payload":"aa"})
        return profile_override(base,td,cid,D["canon"](p))
    if cid=="C3-32":
        z=dict(base);z["w8"]=fake_w8(td);return z
    if cid=="F0-05":
        p=copy.deepcopy(BASEOBJ);D["block"](p,"alt")["ops"]=list(reversed(D["block"](p,"alt")["ops"]))
        alt=q.derive_bundle(D["canon"](p),td,cid+"-alt")
        return q.mutate_cert(base,td,cid,lambda d:d.__setitem__("ordered_trace_map_id",alt["doc"]["ordered_trace_map_id"]))
    if cid=="F0-06":
        p=copy.deepcopy(BASEOBJ);D["block"](p,"alt")["ops"].append({"op":"EMIT_HEX","payload":"03"})
        dup=q.derive_bundle(D["canon"](p),td,cid+"-dup")
        return q.mutate_cert(dup,td,cid,lambda d:d.__setitem__("ordered_trace_map_id",base["doc"]["ordered_trace_map_id"]))
    if cid=="F0-07":
        p=copy.deepcopy(BASEOBJ);D["block"](p,"alt")["ops"].append({"op":"EMIT_HEX","payload":"03"})
        dup=q.derive_bundle(D["canon"](p),td,cid+"-source")
        return q.mutate_cert(dup,td,cid,lambda d:d.__setitem__("ordered_trace_map_id",base["doc"]["ordered_trace_map_id"]))
    if cid=="F0-09":
        b=q.derive_bundle(D["canon"](D["state_progress_profile"](two_state=True)),td,cid+"-source")
        return q.mutate_cert(b,td,cid,lambda d:d.__setitem__("reachable_graph_id",q.fake_id("c3graph:sha256:","0")))
    if cid=="F0-10":
        pp=q.write(Path(td)/(cid+".cap"),Path(base["program"]).read_bytes()+b"LABEL C3.UNREACH\nEMIT_HEX 01\nHALT\n")
        return q.bundle_with(base,program=pp)
    if cid=="F0-11":
        art=json.loads(Path(base["artifact"]).read_text());art["boundary"]["gas"]-=1
        ap=q.write(Path(td)/(cid+".artifact.json"),q.canon(art));return q.bundle_with(base,artifact=ap)
    raise AssertionError(("unhandled cross",cid))

def inventory():
    groups={"ACCEPT":[],"PARSE_REJECT":[],"SEMANTIC_REJECT":[],"CROSSCHECK_REJECT":[]}
    for x in F0["positive_controls"]:groups[x["oracle"]].append(x["id"])
    for key in ("legacy_vectors","amendment_vectors","mandatory_additional_vectors"):
        for cid,name,oracle,note in F0[key]:groups[oracle].append(cid)
    return groups

def main():
    # Original intended-plane gate must remain fully green before certificate replay counts.
    cp=subprocess.run([sys.executable,str(CROSS)],capture_output=True,text=True,check=True)
    if "C3_CROSSED_F0_PASS 62" not in cp.stdout:raise AssertionError("frozen F0 gate missing pass marker")
    print("Q0_F0_ORIGINAL_GATE_PASS 62")
    g=inventory()
    with tempfile.TemporaryDirectory() as s:
        td=Path(s);base=q.derive_bundle(Path(q.BASE).read_bytes(),td,"baseline")
        q.check_pair(base,"ACCEPTED","F0-baseline-support")
        count=0
        for cid in g["ACCEPT"]:
            b=q.derive_bundle(accepted_raw(cid),td,"accept-"+cid)
            q.check_pair(b,"ACCEPTED","F0-"+cid);count+=1;print("Q0_F0_CERT_PASS",cid,"ACCEPTED")
        for cid in g["PARSE_REJECT"]:
            for j,raw in enumerate(parse_raws(cid)):
                z=profile_override(base,td,f"parse-{cid}-{j}",raw)
                q.check_pair(z,"REJECTED",f"F0-{cid}-{j}")
            count+=1;print("Q0_F0_CERT_PASS",cid,"REJECTED")
        for cid in g["SEMANTIC_REJECT"]:
            z=profile_override(base,td,"sem-"+cid,semantic_raw(cid))
            q.check_pair(z,"REJECTED","F0-"+cid);count+=1;print("Q0_F0_CERT_PASS",cid,"REJECTED")
        for cid in g["CROSSCHECK_REJECT"]:
            z=cross_attack(cid,base,td)
            overrides={k:z[k] for k in ("w7","w8","w5","w6") if k in z}
            q.check_pair(z,"REJECTED","F0-"+cid,overrides=overrides)
            count+=1;print("Q0_F0_CERT_PASS",cid,"REJECTED")
        if count!=62:raise AssertionError(("F0 certificate replay count",count))
        print("Q0_F0_CERTIFICATE_REPLAY_PASS 62")
        print("AUTHORITY_CREATED false")
if __name__=="__main__":main()
