#!/usr/bin/env python3
"""Q0 selected G1 certificate replay, one deterministic shard per invocation."""
from __future__ import annotations
import copy, json, sys, tempfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
TOOLS=ROOT/"tools";sys.path.insert(0,str(TOOLS))
import risu_kernel_k1_mfst_c3_cert_q0_common as q
import risu_kernel_k1_mfst_c3_g1_generator as gen

SEEDS=[271828182,314159265,161803398,141421356,173205080,223606797,244948974,264575131]
STRUCTURED=[0,2,3,4]
META_BASE=[0]
TRANSFORMS=[0,1,2,3]
STRESS=[0,7]
NEG=list(range(12))

def safe_structured(seed,i):
    j=i
    while True:
        p,m=gen.make_structured(seed,j)
        if len(p["state"])<=4:return p,m,j
        j+=997

def profile_override(bundle,td,name,raw):
    p=q.write(Path(td)/(name+".profile.bin"),raw);z=dict(bundle);z["profile"]=p;return z

def check_meta(base,changed,relation,label):
    br=base["r7"];cr=changed["r7"]
    def same(k):
        if br[k]!=cr[k]:raise AssertionError((label,relation,k,"expected same",br[k],cr[k]))
    def diff(k):
        if br[k]==cr[k]:raise AssertionError((label,relation,k,"expected different",br[k]))
    if relation=="G1-META-KEY-DECL-PERMUTE":
        for k in ("c3_semantic_id","graph_id","trace_map_id","projected_realize","c2_program_sha256"):same(k)
    elif relation=="G1-META-FORMAL-RENAME":
        diff("c3_semantic_id")
        for k in ("trace_map_id","projected_realize","c2_program_sha256"):same(k)
    elif relation=="G1-META-UNREACHABLE-BLOCK":
        diff("c3_source_id");diff("c3_semantic_id")
        for k in ("trace_map_id","projected_realize","c2_program_sha256"):same(k)
    elif relation=="G1-META-EFFECT-ORDER-MULTIPLICITY":
        diff("trace_map_id");same("projected_realize");diff("c2_program_sha256")
    else:raise AssertionError((label,"unknown relation",relation))

def negative_attack(base_obj,control,family,td,label):
    mutant,name=gen.mutate_negative_profile(base_obj,family)
    raw=gen.encode(mutant)
    if family in list(range(0,7))+[10]:
        z=profile_override(control,td,label,raw)
        q.check_pair(z,"REJECTED",label)
        return name
    if family==7:
        art=json.loads(Path(control["artifact"]).read_text())
        slots=art["boundary"]["slots"]
        if not slots:raise AssertionError((label,"no shrinkable slot"))
        slot=sorted(slots)[0];vals=sorted(slots[slot])
        if len(vals)<2:raise AssertionError((label,"slot too small"))
        slots[slot]=[vals[0]]
        ap=q.write(Path(td)/(label+".artifact.json"),q.canon(art))
        q.check_pair(q.bundle_with(control,artifact=ap),"REJECTED",label)
        return name
    if family==8:
        art=json.loads(Path(control["artifact"]).read_text())
        if art["boundary"]["gas"]<=1:raise AssertionError((label,"gas"))
        art["boundary"]["gas"]-=1
        ap=q.write(Path(td)/(label+".artifact.json"),q.canon(art))
        q.check_pair(q.bundle_with(control,artifact=ap),"REJECTED",label)
        return name
    if family==9:
        pp=q.write(Path(td)/(label+".cap"),Path(control["program"]).read_bytes()+b"\n")
        q.check_pair(q.bundle_with(control,program=pp),"REJECTED",label)
        return name
    if family==11:
        art=json.loads(Path(control["artifact"]).read_text())
        art["complete"]="true";art["producer_realize"]=control["doc"]["projected_realize"];art["producer_target_id"]=control["doc"]["c2_target_id"]
        ap=q.write(Path(td)/(label+".artifact.json"),q.canon(art))
        q.check_pair(q.bundle_with(control,artifact=ap),"REJECTED",label)
        return name
    raise AssertionError((label,family))

def main():
    if len(sys.argv)!=2:raise SystemExit("usage: q0_g1.py SHARD")
    shard=int(sys.argv[1])
    if shard<0 or shard>=8:raise SystemExit("bad shard")
    seed=SEEDS[shard]
    pos=0;neg=0;support=0
    with tempfile.TemporaryDirectory() as s:
        td=Path(s)
        # Selected structured profiles.
        for i in STRUCTURED:
            p,meta,source_index=safe_structured(seed,i)
            b=q.derive_bundle(gen.encode(p),td,f"s{shard}-v{i}")
            q.check_pair(b,"ACCEPTED",f"G1-S{shard}-V{i:03d}")
            pos+=1;print("Q0_G1_CERT_PASS",shard,"STRUCTURED",i,"SOURCE_INDEX",source_index)
        # One forced-meta base per shard, then all four frozen transformations.
        for i in META_BASE:
            base_obj,_=gen.make_meta_base(seed,i)
            base=q.derive_bundle(gen.encode(base_obj),td,f"s{shard}-mb{i}")
            q.check_pair(base,"ACCEPTED",f"G1-S{shard}-MB{i:03d}");support+=1
            for t in TRANSFORMS:
                _,raw,rel=gen.transform_meta(base_obj,t)
                changed=q.derive_bundle(raw,td,f"s{shard}-m{i}-{t}")
                check_meta(base,changed,rel,f"G1-S{shard}-M{i:03d}-{t}")
                q.check_pair(changed,"ACCEPTED",f"G1-S{shard}-M{i:03d}-{t}")
                pos+=1;print("Q0_G1_CERT_PASS",shard,"META",i,t,rel)
        # Every frozen negative mutation family once per seed, each with accepted support.
        for i in NEG:
            base_obj,_=gen.make_negative_base(seed,i)
            control=q.derive_bundle(gen.encode(base_obj),td,f"s{shard}-nc{i}")
            q.check_pair(control,"ACCEPTED",f"G1-S{shard}-NC{i:03d}");support+=1
            name=negative_attack(base_obj,control,i%12,td,f"G1-S{shard}-N{i:03d}-F{i%12:02d}")
            neg+=1;print("Q0_G1_CERT_PASS",shard,"NEGATIVE",i,name)
        # Two high-complexity profiles per seed.
        for i in STRESS:
            p,meta=gen.make_stress(seed,i)
            if meta["boundary_points"]!=48 or meta["state_count"]!=4 or meta["table_count"]!=3 or meta["max_table_arity"]!=3:
                raise AssertionError(("stress metadata drift",shard,i,meta))
            b=q.derive_bundle(gen.encode(p),td,f"s{shard}-x{i}")
            q.check_pair(b,"ACCEPTED",f"G1-S{shard}-X{i:03d}")
            pos+=1;print("Q0_G1_CERT_PASS",shard,"STRESS",i)
    if (pos,neg,support)!=(10,12,13):raise AssertionError(("counts",shard,pos,neg,support))
    print("Q0_G1_SHARD_PASS",shard,"POSITIVE",pos,"NEGATIVE",neg,"SUPPORT",support)
    print("AUTHORITY_CREATED false")
if __name__=="__main__":main()
