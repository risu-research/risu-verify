"""W7-only strict MFST parser and semantic model. Never imported by W8."""
from __future__ import annotations
import hashlib,itertools,json,re
TOKEN=re.compile(r"^[A-Za-z0-9_.@:-]+$"); WORLD=re.compile(r"^w:sha256:[0-9a-f]{64}$")
CLAIM=re.compile(r"^claim:sha256:[0-9a-f]{64}$"); HEX=re.compile(r"^(?:[0-9a-f]{2})+$")
class Reject(Exception): pass
class Unsupported(Exception): pass
def net(x):
    b=x if isinstance(x,bytes) else str(x).encode()
    return str(len(b)).encode()+b":"+b+b"," 
def cnt(n): return net(str(n))
def hid(prefix,b): return prefix+hashlib.sha256(b).hexdigest()
def exact(o,ks,w):
    if not isinstance(o,dict) or set(o)!=set(ks): raise Reject(w+": malformed object")
def tok(x,w):
    if not isinstance(x,str) or TOKEN.fullmatch(x) is None: raise Reject(w+": noncanonical token")
    return x
def loads(raw,w,profile=False):
    if not raw or raw.startswith(b"\xef\xbb\xbf") or any(x in raw for x in (b"\0",b"\r",b"\t")): raise Reject(w+": forbidden bytes")
    try: s=raw.decode("utf-8","strict")
    except UnicodeDecodeError as e: raise Reject(w+": invalid UTF-8") from e
    def hook(ps):
        d={}
        for k,v in ps:
            if k in d: raise Reject(w+": duplicate JSON key:"+k)
            d[k]=v
        return d
    try: o=json.loads(s,object_pairs_hook=hook)
    except Reject: raise
    except Exception as e: raise Reject(w+": invalid JSON") from e
    if profile:
        def walk(v,p):
            if isinstance(v,str):
                if any(c in v for c in "\0\r\t"): raise Reject(p+": forbidden string")
            elif isinstance(v,list):
                for i,x in enumerate(v): walk(x,f"{p}[{i}]")
            elif isinstance(v,dict):
                for k,x in v.items(): walk(x,p+"."+k)
            elif isinstance(v,(bool,int,float)) or v is None: raise Reject(p+": numbers/booleans/null not admitted")
            else: raise Reject(p+": unsupported JSON type")
        walk(o,w)
    return o
def vals(tag,xs):
    b=tag.encode()+cnt(len(xs))
    for x in xs:b+=b"V"+net(x)
    return b
def pairs(tag,xs):
    xs=sorted(xs); b=tag.encode()+cnt(len(xs))
    for w,c in xs:b+=b"P"+net(w)+net(c)
    return b
def claim_id(d):
    return hid("claim:sha256:",b"RISU-K1-CLAIM-W0\0"+b"S"+net(d["semantics"])+vals("W",sorted(d["worlds"]))+pairs("A",[tuple(x) for x in d["allow"]]))
def check_claim(d):
    exact(d,["wire","kind","semantics","worlds","allow","claim_id"],"claim")
    if (d["wire"],d["kind"],d["semantics"])!=("risu.k1.w0","claim","safety-subset-v1"):raise Reject("claim: unsupported")
    if not isinstance(d["worlds"],list) or not d["worlds"] or len(set(d["worlds"]))!=len(d["worlds"]):raise Reject("claim.worlds")
    for w in d["worlds"]:
        if not isinstance(w,str) or WORLD.fullmatch(w) is None:raise Reject("claim.world")
    if not isinstance(d["allow"],list) or not d["allow"]:raise Reject("claim.allow")
    a=set()
    for r in d["allow"]:
        if not isinstance(r,list) or len(r)!=2 or r[0] not in d["worlds"] or not isinstance(r[1],str) or not re.fullmatch(r"c:sha256:[0-9a-f]{64}",r[1]):raise Reject("claim.allow pair")
        if tuple(r) in a:raise Reject("claim.allow duplicate")
        a.add(tuple(r))
    if any(not any(x[0]==w for x in a) for w in d["worlds"]):raise Reject("claim.allow uncovered world")
    if not isinstance(d["claim_id"],str) or CLAIM.fullmatch(d["claim_id"]) is None or d["claim_id"]!=claim_id(d):raise Reject("claim.claim_id mismatch")
    return frozenset(d["worlds"]),frozenset(a)
def domain(v,w):
    if not isinstance(v,list) or not v or len(set(v))!=len(v):raise Reject(w+": malformed domain")
    for i,x in enumerate(v):tok(x,f"{w}[{i}]")
    return tuple(v)
def src(o,w):
    exact(o,["kind","name"],w)
    if o["kind"] not in ("input","state"):raise Reject(w+": bad source kind")
    tok(o["name"],w+".name"); return o["kind"],o["name"]
def validate(p,cworlds):
    exact(p,["wire","kind","claim_id","boundary","state","tables","entry","blocks"],"profile")
    if (p["wire"],p["kind"])!=("risu.k1.c3.mfst/v1","mediated_finite_state_transducer") or CLAIM.fullmatch(p.get("claim_id","")) is None:raise Reject("profile header")
    exact(p["boundary"],["worlds","slots"],"boundary"); worlds=domain(p["boundary"]["worlds"],"boundary.worlds")
    if any(WORLD.fullmatch(w) is None for w in worlds) or frozenset(worlds)!=cworlds:raise Reject("boundary.worlds: claim mismatch")
    if not isinstance(p["boundary"]["slots"],dict):raise Reject("boundary.slots")
    slots={}
    for n,d in p["boundary"]["slots"].items():
        tok(n,"slot");
        if n=="@world":raise Reject("slot @world reserved")
        slots[n]=domain(d,"slot."+n)
    if not isinstance(p["state"],list):raise Reject("state")
    states={}
    for i,c in enumerate(p["state"]):
        exact(c,["name","domain","initial"],f"state[{i}]"); n=tok(c["name"],f"state[{i}].name")
        if n=="@world" or n in slots or n in states:raise Reject("state name collision")
        states[n]={"domain":domain(c["domain"],"state."+n+".domain"),"initial":c["initial"]}
    def sdom(o,w):
        k,n=src(o,w)
        if k=="state":
            if n not in states:raise Reject(w+": unknown state source")
            return states[n]["domain"]
        if n=="@world":return worlds
        if n not in slots:raise Reject(w+": undeclared input source")
        return slots[n]
    for n,x in states.items():
        q=x["initial"]
        if not isinstance(q,dict) or q.get("kind") not in ("const","input"):raise Reject("state initial")
        if q["kind"]=="const":
            exact(q,["kind","value"],"initial"); tok(q["value"],"initial.value")
            if q["value"] not in x["domain"]:raise Reject("initial out of domain")
        else:
            exact(q,["kind","name"],"initial")
            if not set(sdom({"kind":"input","name":q["name"]},"initial")).issubset(x["domain"]):raise Reject("initial domain mismatch")
    if not isinstance(p["tables"],list):raise Reject("tables")
    tables={}
    for i,t in enumerate(p["tables"]):
        exact(t,["name","arguments","result_domain","rows"],f"table[{i}]"); n=tok(t["name"],"table.name")
        if n in tables:raise Reject("duplicate table")
        if not isinstance(t["arguments"],list):raise Reject("table.arguments")
        aa=[]; seen=set()
        for a in t["arguments"]:
            exact(a,["name","domain"],"formal"); an=tok(a["name"],"formal.name")
            if an in seen:raise Reject("duplicate formal")
            seen.add(an); aa.append((an,domain(a["domain"],"formal.domain")))
        rd=domain(t["result_domain"],"result_domain"); mp={}
        if not isinstance(t["rows"],list):raise Reject("rows")
        for r in t["rows"]:
            exact(r,["when","result"],"row")
            if not isinstance(r["when"],list) or len(r["when"])!=len(aa):raise Reject("row arity")
            k=tuple(r["when"])
            for j,v in enumerate(k):
                tok(v,"row.when")
                if v not in aa[j][1]:raise Reject("row out of domain")
            tok(r["result"],"row.result")
            if r["result"] not in rd or k in mp:raise Reject("row result/duplicate")
            mp[k]=r["result"]
        exp=set(itertools.product(*(x[1] for x in aa))) if aa else {()}
        if set(mp)!=exp:raise Reject("table not exactly total")
        tables[n]={"arguments":aa,"result_domain":rd,"mapping":mp}
    if not isinstance(p["blocks"],list) or not p["blocks"]:raise Reject("blocks")
    blocks={}; OPS={"SET_CONST","SET_FROM","APPLY_TABLE","EMIT_HEX"}; TERMS={"GOTO","IF_EQ","HALT"}
    for i,b in enumerate(p["blocks"]):
        exact(b,["label","ops","term"],f"block[{i}]"); lab=tok(b["label"],"block.label")
        if lab in blocks or not isinstance(b["ops"],list):raise Reject("duplicate block/ops")
        for o in b["ops"]:
            if not isinstance(o,dict) or o.get("op") not in OPS:raise Reject("unknown/ambient opcode")
            z=o["op"]
            if z=="SET_CONST":
                exact(o,["op","dst","value"],"SET_CONST")
                if o["dst"] not in states or o["value"] not in states[o["dst"]]["domain"]:raise Reject("bad SET_CONST")
            elif z=="SET_FROM":
                exact(o,["op","dst","source"],"SET_FROM")
                if o["dst"] not in states or not set(sdom(o["source"],"SET_FROM.source")).issubset(states[o["dst"]]["domain"]):raise Reject("bad SET_FROM")
            elif z=="APPLY_TABLE":
                exact(o,["op","dst","table","arguments"],"APPLY_TABLE")
                if o["dst"] not in states or o["table"] not in tables or not isinstance(o["arguments"],list):raise Reject("bad APPLY_TABLE")
                t=tables[o["table"]]
                if len(o["arguments"])!=len(t["arguments"]):raise Reject("APPLY_TABLE arity")
                for j,a in enumerate(o["arguments"]):
                    if set(sdom(a,"APPLY_TABLE.arg"))!=set(t["arguments"][j][1]):raise Reject("APPLY_TABLE formal domain mismatch")
                if not set(t["result_domain"]).issubset(states[o["dst"]]["domain"]):raise Reject("APPLY_TABLE result domain")
            else:
                exact(o,["op","payload"],"EMIT_HEX")
                if not isinstance(o["payload"],str) or HEX.fullmatch(o["payload"]) is None:raise Reject("bad payload")
        t=b["term"]
        if not isinstance(t,dict) or t.get("op") not in TERMS:raise Reject("bad terminator")
        if t["op"]=="GOTO":exact(t,["op","target"],"GOTO");tok(t["target"],"target")
        elif t["op"]=="IF_EQ":
            exact(t,["op","source","value","if_true","if_false"],"IF_EQ"); dd=sdom(t["source"],"IF_EQ.source");tok(t["value"],"IF_EQ.value");tok(t["if_true"],"IF_EQ.true");tok(t["if_false"],"IF_EQ.false")
            if t["value"] not in dd:raise Reject("IF_EQ out of domain")
        else:exact(t,["op"],"HALT")
        blocks[lab]=b
    entry=tok(p["entry"],"entry")
    if entry not in blocks:raise Reject("undefined entry")
    for lab,b in blocks.items():
        t=b["term"]; tg=[t["target"]] if t["op"]=="GOTO" else [t["if_true"],t["if_false"]] if t["op"]=="IF_EQ" else []
        if any(x not in blocks for x in tg):raise Reject("undefined target")
    return {"worlds":worlds,"slots":slots,"states":states,"tables":tables,"blocks":blocks,"entry":entry,"sdom":sdom}
def sd(o):return (b"I" if o["kind"]=="input" else b"S")+net(o["name"])
def semantic_id(p,m):
    b=b"RISU-K1-C3-MFST-SEMANTIC-V1\0"+b"C"+net(p["claim_id"])+b"E"+net(m["entry"])
    ws=sorted(m["worlds"]);b+=b"W"+cnt(len(ws))
    for w in ws:b+=b"w"+net(w)
    ns=sorted(m["slots"]);b+=b"D"+cnt(len(ns))
    for n in ns:
        d=sorted(m["slots"][n]);b+=b"s"+net(n)+cnt(len(d))
        for v in d:b+=b"v"+net(v)
    sn=sorted(m["states"]);b+=b"Q"+cnt(len(sn))
    for n in sn:
        x=m["states"][n];d=sorted(x["domain"]);b+=b"q"+net(n)+cnt(len(d))
        for v in d:b+=b"v"+net(v)
        q=x["initial"];b+=(b"C"+net(q["value"])) if q["kind"]=="const" else (b"I"+net(q["name"]))
    tn=sorted(m["tables"]);b+=b"T"+cnt(len(tn))
    for n in tn:
        t=m["tables"][n];b+=b"t"+net(n)+cnt(len(t["arguments"]))
        for an,d in t["arguments"]:
            b+=b"a"+net(an)+cnt(len(d))
            for v in sorted(d):b+=b"v"+net(v)
        b+=cnt(len(t["result_domain"]))
        for v in sorted(t["result_domain"]):b+=b"v"+net(v)
        rr=sorted(t["mapping"].items());b+=cnt(len(rr))
        for wh,res in rr:
            b+=b"r"+cnt(len(wh))
            for v in wh:b+=b"v"+net(v)
            b+=b"o"+net(res)
    labs=sorted(m["blocks"]);b+=b"B"+cnt(len(labs))
    for lab in labs:
        x=m["blocks"][lab];b+=b"b"+net(lab)+cnt(len(x["ops"]))
        for o in x["ops"]:
            z=o["op"]
            if z=="SET_CONST":b+=b"1"+net(o["dst"])+net(o["value"])
            elif z=="SET_FROM":b+=b"2"+net(o["dst"])+sd(o["source"])
            elif z=="APPLY_TABLE":
                b+=b"3"+net(o["dst"])+net(o["table"])+cnt(len(o["arguments"]))
                for a in o["arguments"]:b+=sd(a)
            else:b+=b"4"+net(o["payload"])
        t=x["term"]
        if t["op"]=="GOTO":b+=b"G"+net(t["target"])
        elif t["op"]=="IF_EQ":b+=b"I"+sd(t["source"])+net(t["value"])+net(t["if_true"])+net(t["if_false"])
        else:b+=b"H"
    return hid("c3sem:sha256:",b)
