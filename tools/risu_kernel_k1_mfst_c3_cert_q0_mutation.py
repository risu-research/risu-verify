#!/usr/bin/env python3
"""Q0 seeded generative mutation campaign over the certificate object itself."""
from __future__ import annotations
import copy, hashlib, json, random, sys, tempfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1];TOOLS=ROOT/"tools";sys.path.insert(0,str(TOOLS))
import risu_kernel_k1_mfst_c3_cert_q0_common as q
import risu_kernel_k1_mfst_c3_g1_generator as gen
import risu_kernel_k1_mfst_c3_r0_compiler as r0c

NEG_SEED=5772156649
POS_SEED=1414213562
NEG_PER_SHARD=128
POS_PER_SHARD=32
SHARDS=8

def load_f0_defs():
    p=TOOLS/"risu_kernel_k1_mfst_c3_crossed_gate.py";src=p.read_text().split("# Inventory is authority data",1)[0]
    ns={"__file__":str(p),"__name__":"q0_mut_f0_defs"};exec(compile(src,str(p),"exec"),ns);return ns

D=load_f0_defs()

def r0_record(idx):
    init=["C0","C1","X"];upd=["KEEP","CONST0","CONST1","COPY_X","NOT_Q_TABLE","ID_Q_TABLE","XOR_QX_TABLE","AND_QX_TABLE"]
    pred=["X_EQ0","X_EQ1","Q_EQ0","Q_EQ1","WORLD_EQ0","WORLD_EQ1"];prefix=["NONE","E3"];tr=["A","B","AB","BA","AA","BB","ABA","BAB"]
    n=idx
    f=n%8;n//=8;t=n%8;n//=8;pr=n%2;n//=2;pd=n%6;n//=6;u=n%8;n//=8;ini=n%3
    return {"descriptor_id":f"R0-{idx:05d}","initial_q":init[ini],"update":upd[u],"predicate":pred[pd],
            "prefix":prefix[pr],"true_trace":tr[t],"false_trace":tr[f],"point_traces":[]}

def safe_structured(seed,i):
    j=i
    while True:
        p,m=gen.make_structured(seed,j)
        if len(p["state"])<=4:return p
        j+=997

def build_pool(td):
    raws=[]
    # Four frozen F0 ACCEPT sources.
    raws += [
      ("F0-baseline",Path(q.BASE).read_bytes()),
      ("F0-state-progress",D["canon"](D["state_progress_profile"]())),
      ("F0-world-input",D["canon"](D["world_input_profile"]())),
      ("F0-alias",D["canon"](D["alias_profile"]())),
    ]
    # Four selected G1 positive sources, all within the Q0 frozen selection.
    seed=271828182
    raws += [
      ("G1-structured-0",gen.encode(safe_structured(seed,0))),
      ("G1-structured-3",gen.encode(safe_structured(seed,3))),
      ("G1-meta-0-3",gen.transform_meta(gen.make_meta_base(seed,0)[0],3)[1]),
      ("G1-stress-0",gen.encode(gen.make_stress(seed,0)[0])),
    ]
    # Four Q0-selected R0 ordinary descriptors.
    for idx in (1,6348,12567,474):
        raws.append((f"R0-{idx:05d}",r0c.compile_bytes(r0_record(idx))))
    pool=[]
    h=hashlib.sha256()
    for name,raw in raws:
        b=q.derive_bundle(raw,td,"pool-"+name)
        q.check_pair(b,"ACCEPTED","POOL-"+name)
        pool.append(b)
        h.update((name+"|"+b["doc"]["c3_source_id"]+"|"+b["doc"]["certificate_id"]+"|"+b["doc"]["c2_target_id"]+"\n").encode())
    return pool,h.hexdigest()

def flip_hex_id(value):
    # Deterministically change the final hex nibble while retaining namespace/shape.
    last=value[-1];new="0" if last!="0" else "1";return value[:-1]+new

def negative(base,other,family,td,name):
    if family==0:
        return q.mutate_cert(base,td,name,lambda d:d.__setitem__("c3_source_id",flip_hex_id(d["c3_source_id"])),recompute=False)
    if family==1:
        return q.mutate_cert(base,td,name,lambda d:d.__setitem__("c3_source_id",flip_hex_id(d["c3_source_id"])))
    if family==2:
        return q.mutate_cert(base,td,name,lambda d:d.__setitem__("c3_semantic_id",flip_hex_id(d["c3_semantic_id"])))
    if family==3:
        return q.mutate_cert(base,td,name,lambda d:d.__setitem__("reachable_graph_id",flip_hex_id(d["reachable_graph_id"])))
    if family==4:
        return q.mutate_cert(base,td,name,lambda d:d.__setitem__("ordered_trace_map_id",flip_hex_id(d["ordered_trace_map_id"])))
    if family==5:
        return q.mutate_cert(base,td,name,lambda d:d.__setitem__("c2_program_sha256",flip_hex_id(d["c2_program_sha256"])))
    if family==6:
        return q.mutate_cert(base,td,name,lambda d:d.__setitem__("c2_artifact_id",flip_hex_id(d["c2_artifact_id"])))
    if family==7:
        return q.mutate_cert(base,td,name,lambda d:d.__setitem__("c2_target_id",flip_hex_id(d["c2_target_id"])))
    if family==8:
        return q.mutate_cert(base,td,name,lambda d:d.__setitem__("c2_certificate_id",flip_hex_id(d["c2_certificate_id"])))
    if family==9:
        def f(d):
            if not d["projected_realize"]:raise AssertionError("empty REALIZE")
            d["projected_realize"]=d["projected_realize"][:-1]
        return q.mutate_cert(base,td,name,f)
    if family==10:
        def f(d):
            w=d["projected_realize"][0][0];fake="c:sha256:"+"0"*64
            if any(x[1]==fake for x in d["projected_realize"]):fake="c:sha256:"+"1"*64
            d["projected_realize"].append([w,fake])
        return q.mutate_cert(base,td,name,f)
    if family==11:
        def f(d):d["projected_realize"].append(list(d["projected_realize"][0]))
        return q.mutate_cert(base,td,name,f,recompute=False)
    if family==12:
        return q.mutate_cert(base,td,name,lambda d:d.__setitem__("claim_id","claim:sha256:"+"0"*64))
    if family==13:
        def f(d):
            for k in ("c3_source_id","c3_semantic_id","reachable_graph_id","ordered_trace_map_id","c2_program_sha256",
                      "c2_artifact_id","c2_target_id","projected_realize","c2_certificate_id"):
                d[k]=copy.deepcopy(other["doc"][k])
        return q.mutate_cert(base,td,name,f)
    if family==14:
        return q.mutate_cert(base,td,name,lambda d:d.__setitem__("authority",True),recompute=False)
    if family==15:
        z=dict(base);p=Path(td)/(name+".cert.json")
        raw=Path(base["cert"]).read_text()
        raw=raw[:-1]+',"wire":"risu.k1.c3.refinement-certificate/v1"}'
        p.write_text(raw,encoding="utf-8");z["cert"]=p;return z
    raise AssertionError(family)

def positive(base,family,td,name,gi):
    d=copy.deepcopy(base["doc"]);p=Path(td)/(name+".cert.json")
    if family==0:
        rev={k:d[k] for k in reversed(list(d.keys()))};p.write_text(json.dumps(rev,separators=(",",":")),encoding="utf-8")
    elif family==1:
        p.write_text(json.dumps(d,indent=2,sort_keys=False),encoding="utf-8")
    elif family==2:
        rows=list(d["projected_realize"])
        if len(rows)>1:rows=rows[1:]+rows[:1]
        d["projected_realize"]=rows
        # transcript is set-canonical, therefore same certificate_id is retained.
        p.write_text(json.dumps(d,separators=(",",":")),encoding="utf-8")
    elif family==3:
        rng=random.Random(POS_SEED^gi)
        keys=list(d.keys());rng.shuffle(keys);o={k:d[k] for k in keys}
        p.write_text(json.dumps(o,separators=(",",":")),encoding="utf-8")
    else:raise AssertionError(family)
    z=dict(base);z["cert"]=p;z["doc"]=d;return z

def main():
    if len(sys.argv)!=2:raise SystemExit("usage: q0_mutation.py SHARD")
    shard=int(sys.argv[1])
    if shard<0 or shard>=SHARDS:raise SystemExit("bad shard")
    with tempfile.TemporaryDirectory() as s:
        td=Path(s);pool,pool_digest=build_pool(td)
        neg=pos=0
        for gi in range(shard*NEG_PER_SHARD,(shard+1)*NEG_PER_SHARD):
            fam=gi%16;rng=random.Random(NEG_SEED^gi)
            bi=rng.randrange(len(pool));oi=(bi+1+rng.randrange(len(pool)-1))%len(pool)
            z=negative(pool[bi],pool[oi],fam,td,f"neg-{gi:04d}")
            q.check_pair(z,"REJECTED",f"Q0-MUT-N{gi:04d}-F{fam:02d}")
            neg+=1
        for gi in range(shard*POS_PER_SHARD,(shard+1)*POS_PER_SHARD):
            fam=gi%4;rng=random.Random(POS_SEED^gi);bi=rng.randrange(len(pool))
            base=pool[bi];z=positive(base,fam,td,f"pos-{gi:04d}",gi)
            a,b=q.check_pair(z,"ACCEPTED",f"Q0-MUT-P{gi:04d}-F{fam:02d}")
            if a["certificate_id"]!=base["doc"]["certificate_id"] or b["certificate_id"]!=base["doc"]["certificate_id"]:
                raise AssertionError(("positive id drift",gi,fam,a,b,base["doc"]["certificate_id"]))
            pos+=1
    if (neg,pos)!=(128,32):raise AssertionError(("mutation shard count",shard,neg,pos))
    print("Q0_MUTATION_POOL_DIGEST",pool_digest)
    print("Q0_CERT_MUTATION_SHARD_PASS",shard,"NEGATIVE",neg,"POSITIVE",pos)
    print("AUTHORITY_CREATED false")
if __name__=="__main__":main()
