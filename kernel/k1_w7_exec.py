"""W7-only MFST execution, graph/trace commitments, and C2 normalization."""
from __future__ import annotations
import hashlib,itertools,json
from k1_w7_model import Reject,Unsupported,net,cnt,hid
MAXB=65536;MAXG=10000
def points(m):
    ns=sorted(m["slots"]); cc=list(itertools.product(*[sorted(m["slots"][n]) for n in ns])) if ns else [()]
    for w in sorted(m["worlds"]):
        for c in cc:
            p={"@world":w};p.update(zip(ns,c));yield p
def penc(p,ns):
    b=b"P"+net(p["@world"])+cnt(len(ns))
    for n in ns:b+=b"s"+net(n)+net(p[n])
    return b
def consequence(h):return hid("c:sha256:",b"RISU-K1-CAPSULE-CONSEQUENCE-V1\0"+bytes.fromhex(h))
def execute(m):
    sn=sorted(m["states"]);slots=sorted(m["slots"]);trs=[];secs=[];rel=set()
    def read(s,p,q):return q[s["name"]] if s["kind"]=="state" else p[s["name"]]
    for p in points(m):
        q={n:(m["states"][n]["initial"]["value"] if m["states"][n]["initial"]["kind"]=="const" else p[m["states"][n]["initial"]["name"]]) for n in sn}
        lab=m["entry"];seen=set();nodes=[];tr=[]
        while True:
            cfg=(lab,tuple(q[n] for n in sn))
            if cfg in seen:raise Reject("MFST closure incomplete: repeated configuration")
            seen.add(cfg);x=m["blocks"][lab];local=[]
            for o in x["ops"]:
                z=o["op"]
                if z=="SET_CONST":q[o["dst"]]=o["value"]
                elif z=="SET_FROM":q[o["dst"]]=read(o["source"],p,q)
                elif z=="APPLY_TABLE":
                    vv=tuple(read(a,p,q) for a in o["arguments"]);q[o["dst"]]=m["tables"][o["table"]]["mapping"][vv]
                else:local.append(o["payload"]);tr.append(o["payload"])
            t=x["term"]
            if t["op"]=="HALT":nodes.append((cfg,tuple(local),None));break
            nxt=t["target"] if t["op"]=="GOTO" else (t["if_true"] if read(t["source"],p,q)==t["value"] else t["if_false"])
            sc=(nxt,tuple(q[n] for n in sn));nodes.append((cfg,tuple(local),sc));lab=nxt
        if not tr:raise Reject("MFST closure incomplete: zero-effect HALT")
        for h in tr:rel.add((p["@world"],consequence(h)))
        trs.append((dict(p),tuple(tr)))
        def st(v):
            b=cnt(len(sn))
            for n,z in zip(sn,v):b+=net(n)+net(z)
            return b
        b=penc(p,slots)+cnt(len(nodes))
        for (bl,sv),ee,su in sorted(nodes,key=lambda z:(z[0][0],z[0][1])):
            b+=b"N"+net(bl)+st(sv)+cnt(len(ee))
            for h in ee:b+=b"e"+net(h)
            b+=b"H" if su is None else b"S"+net(su[0])+st(su[1])
        secs.append(b)
    gid=hid("c3graph:sha256:",b"RISU-K1-C3-MFST-GRAPH-V1\0"+b"".join(secs))
    b=b"RISU-K1-C3-MFST-TRACE-V1\0"
    for p,t in trs:
        b+=penc(p,slots)+cnt(len(t))
        for h in t:b+=b"e"+net(h)
    return trs,frozenset(rel),gid,hid("c3trace:sha256:",b)
def label(d,path,n):
    if d==0:return "C3N.ROOT"
    return ("C3L." if d==n else "C3N.")+".".join(map(str,path))
def c2_program(m,trs):
    dims=["@world"]+sorted(m["slots"]);dom=[sorted(m["worlds"])]+[sorted(m["slots"][n]) for n in sorted(m["slots"])]
    tm={tuple(p[d] for d in dims):t for p,t in trs};lines=[]
    def rec(d,path,vv):
        lines.append("LABEL "+label(d,path,len(dims)))
        if d==len(dims):
            for h in tm[tuple(vv)]:lines.append("EMIT_HEX "+h)
            lines.append("HALT");return
        for i,v in enumerate(dom[d]):lines.append(f"IF_EQ {dims[d]} {v} {label(d+1,path+(i,),len(dims))}")
        lines.append("GOTO C3.TRAP")
        for i,v in enumerate(dom[d]):rec(d+1,path+(i,),vv+[v])
    rec(0,(),[]);lines+=["LABEL C3.TRAP","GOTO C3.TRAP"];raw=("\n".join(lines)+"\n").encode()
    if len(raw)>MAXB:raise Unsupported("CBTNF-v1 exceeds C2 program byte limit")
    return raw
def parse_c2(raw):
    ins=[];labs={};refs=[]
    for i,l in enumerate(raw.decode().splitlines()):
        p=l.split(" ");z=p[0]
        if z=="LABEL" and len(p)==2:
            if p[1] in labs:raise Reject("internal C2 duplicate label")
            labs[p[1]]=i;ins.append(tuple(p))
        elif z=="IF_EQ" and len(p)==4:refs.append(p[3]);ins.append(tuple(p))
        elif z=="GOTO" and len(p)==2:refs.append(p[1]);ins.append(tuple(p))
        elif z=="EMIT_HEX" and len(p)==2:ins.append(tuple(p))
        elif z=="HALT" and len(p)==1:ins.append((z,))
        else:raise Reject("internal C2 malformed")
    if any(x not in labs for x in refs):raise Reject("internal C2 undefined label")
    return ins,labs
def replay(raw,m):
    ins,labs=parse_c2(raw);out=[];mg=0
    for p in points(m):
        pc=0;t=[];steps=0
        while True:
            if steps>=MAXG:raise Unsupported("CBTNF-v1 exceeds C2 gas limit")
            x=ins[pc];steps+=1
            if x[0]=="LABEL":pc+=1
            elif x[0]=="IF_EQ":pc=labs[x[3]] if p[x[1]]==x[2] else pc+1
            elif x[0]=="GOTO":pc=labs[x[1]]
            elif x[0]=="EMIT_HEX":t.append(x[1]);pc+=1
            else:break
        if not t:raise Reject("internal C2 zero trace")
        mg=max(mg,steps);out.append((dict(p),tuple(t)))
    return out,mg
def artifact(cid,m,prog,gas):
    o={"proof_format":"k1.capsule-closure/v1","claim_id":cid,"capsule_semantics":"risu.k1.capsule/v1","program_sha256":hashlib.sha256(prog).hexdigest(),"boundary":{"worlds":sorted(m["worlds"]),"slots":{n:sorted(m["slots"][n]) for n in sorted(m["slots"])},"gas":gas}}
    raw=json.dumps(o,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode()
    return raw,"p:sha256:"+hashlib.sha256(raw).hexdigest()
def target(psha,m,gas,rel):
    b=b"RISU-K1-TARGET-CAPSULE-V1\0"+b"S"+net("risu.k1.capsule/v1")+b"P"+net(psha)+b"G"+net(str(gas))
    ws=sorted(m["worlds"]);b+=b"W"+net(str(len(ws)))
    for w in ws:b+=b"w"+net(w)
    ns=sorted(m["slots"]);b+=b"D"+net(str(len(ns)))
    for n in ns:
        d=sorted(m["slots"][n]);b+=b"s"+net(n)+net(str(len(d)))
        for v in d:b+=b"v"+net(v)
    rr=sorted(rel);b+=b"R"+net(str(len(rr)))
    for w,c in rr:b+=b"r"+net(w)+net(c)
    return hid("t:sha256:",b)
