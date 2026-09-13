#!/usr/bin/env python3
"""Seeded generative differential qualification for K1 C2 W5/W6."""

from __future__ import annotations

import argparse
import hashlib
import json
import random
from pathlib import Path

from risu_kernel_k1_capsule_c2_static_verify import (
    artifact_bytes,
    both,
    cert_id,
    consequence,
    fake,
    make_cert,
    make_claim,
    p_id,
    status_pair,
    target_id,
    world,
)

SEED=1123581321
TRIALS=96
PROPERTIES=8


def payload(trial,wi,mi,ei):
    return hashlib.sha256(f"c2g:{trial}:{wi}:{mi}:{ei}".encode()).digest()[:4]

def generate(trial,rng):
    nw=rng.randint(1,3);nm=rng.randint(1,3)
    worlds=[world(f"g{trial}-w{i}") for i in range(nw)];modes=[f"v{i}" for i in range(nm)]
    lines=[]
    for i,w in enumerate(worlds[:-1]): lines.append(f"IF_EQ @world {w} W{i}")
    lines.append(f"GOTO W{nw-1}")
    relation=set()
    for wi,w in enumerate(worlds):
        lines.append(f"LABEL W{wi}")
        for mi,m in enumerate(modes[:-1]): lines.append(f"IF_EQ mode {m} W{wi}M{mi}")
        lines.append(f"GOTO W{wi}M{nm-1}")
        for mi,m in enumerate(modes):
            lines.append(f"LABEL W{wi}M{mi}")
            # Two effects per operational point makes deletion tests non-vacuous.
            for ei in range(2):
                p=payload(trial,wi,mi,ei);lines.append("EMIT_HEX "+p.hex());relation.add((w,consequence(p)))
            lines.append("HALT")
    program=("\n".join(lines)+"\n").encode();boundary={"worlds":worlds,"slots":{"mode":modes},"gas":256}
    return program,boundary,sorted(relation)

def mutate_program(program):
    s=program.decode();pos=s.index("EMIT_HEX ")+len("EMIT_HEX ");ch=s[pos];rep="0" if ch!="0" else "1";return (s[:pos]+rep+s[pos+1:]).encode()

def reroot(c):
    c=json.loads(json.dumps(c));c["certificate_id"]=cert_id(c);return c

def main():
    ap=argparse.ArgumentParser();ap.add_argument("--w6",required=True);ap.add_argument("--output",required=True);args=ap.parse_args();rng=random.Random(SEED)
    passed=0;failures=[]
    for trial in range(TRIALS):
        program,boundary,relation=generate(trial,rng);extra=[]
        for w in boundary["worlds"]: extra.append((w,consequence(hashlib.sha256(f"extra:{trial}:{w}".encode()).digest()[:4])))
        claim=make_claim(boundary["worlds"],relation+extra);art=artifact_bytes(claim,program,boundary);cert=make_cert(claim,art,program,boundary,relation);expected_target=target_id(hashlib.sha256(program).hexdigest(),boundary,relation)
        a,b=both(args.w6,claim,cert,art,program)
        checks=[]
        checks.append(("relation",a.get("derived_realize")==b.get("derived_realize")==[list(x) for x in sorted(relation)]))
        checks.append(("target",a.get("target_id")==b.get("target_id")==expected_target))
        checks.append(("verdict",a.get("proof_status")==b.get("proof_status")=="ACCEPTED" and a.get("semantic_claim")==b.get("semantic_claim")=="PRESERVATION"))

        pb={"worlds":list(reversed(boundary["worlds"])),"slots":{"mode":list(reversed(boundary["slots"]["mode"]))},"gas":boundary["gas"]};part=artifact_bytes(claim,program,pb,pretty=True);pcert=make_cert(claim,part,program,pb,relation);pa,pb_out=both(args.w6,claim,pcert,part,program)
        checks.append(("permutation",status_pair(pa,pb_out,"ACCEPTED",expected_target,relation) and p_id(part)!=p_id(art)))

        short=relation[:-1];dcert=make_cert(claim,art,program,boundary,relation,realize=short,grounding=short);da,db=both(args.w6,claim,dcert,art,program);checks.append(("realize_delete",status_pair(da,db,"REJECTED")))
        surplus=(boundary["worlds"][0],consequence(hashlib.sha256(f"surplus:{trial}".encode()).digest()[:4]));ir=relation+[surplus];icert=make_cert(claim,art,program,boundary,relation,realize=ir,grounding=ir);ia,ib=both(args.w6,claim,icert,art,program);checks.append(("realize_insert",status_pair(ia,ib,"REJECTED")))
        mprog=mutate_program(program);ma,mb=both(args.w6,claim,cert,art,mprog);checks.append(("program_mutation",status_pair(ma,mb,"REJECTED")))
        aa,ab=both(args.w6,claim,cert,art+b"\n",program);checks.append(("artifact_mutation",status_pair(aa,ab,"REJECTED")))

        if len(checks)!=PROPERTIES: raise AssertionError(len(checks))
        for name,ok in checks:
            if ok: passed+=1
            else: failures.append({"trial":trial,"property":name})
    total=TRIALS*PROPERTIES;out={"gate":"RISU_KERNEL_K1_CAPSULE_CLOSURE_C2_GENERATIVE","status":"PASS" if passed==total and not failures else "FAIL","seed":SEED,"trials":TRIALS,"properties_per_trial":PROPERTIES,"comparisons":total,"passed":passed,"failed":failures,"semantic_kernel_changed":False}
    Path(args.output).write_text(json.dumps(out,sort_keys=True,indent=2)+"\n");print(json.dumps(out,sort_keys=True));return 0 if out["status"]=="PASS" else 1

if __name__=="__main__": raise SystemExit(main())
