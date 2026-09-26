#!/usr/bin/env python3
"""RISU K1 C3 W7. W7 alone creates no preservation authority."""
from __future__ import annotations
import argparse,hashlib,json,sys
from pathlib import Path
from k1_w7_model import Reject,Unsupported,loads,check_claim,validate,semantic_id,hid
from k1_w7_exec import execute,c2_program,replay,artifact,target

def check(claim_raw,profile_raw,outdir=None):
    c=loads(claim_raw,"claim");cw,allow=check_claim(c);p=loads(profile_raw,"profile",True)
    if p.get("claim_id")!=c["claim_id"]:raise Reject("profile.claim_id: claim mismatch")
    m=validate(p,cw);src=hid("c3src:sha256:",b"RISU-K1-C3-MFST-SOURCE-V1\0"+profile_raw);sem=semantic_id(p,m)
    trs,rel,gid,tid=execute(m);prog=c2_program(m,trs);rr,gas=replay(prog,m)
    if rr!=trs:raise Reject("W7 direct C3 versus W7 C2 replay mismatch")
    araw,aid=artifact(c["claim_id"],m,prog,gas);ps=hashlib.sha256(prog).hexdigest();forbid=sorted(rel-allow)
    if outdir:
        d=Path(outdir);d.mkdir(parents=True,exist_ok=True);(d/"c2_program.cap").write_bytes(prog);(d/"c2_artifact.json").write_bytes(araw)
    return {"checker":"risu-k1-checker-w7","proof_status":"ACCEPTED","semantic_claim":"CANDIDATE_REFINEMENT","authority_created":False,
      "c3_source_id":src,"c3_semantic_id":sem,"graph_id":gid,"trace_map_id":tid,"boundary_point_count":len(trs),
      "trace_payload_count":sum(len(t) for _,t in trs),"projected_realize":[list(x) for x in sorted(rel)],
      "forbidden_projected_pairs":[list(x) for x in forbid],"k1_subset_allowed":not forbid,"c2_program_sha256":ps,
      "c2_program_bytes":len(prog),"c2_derived_gas":gas,"c2_artifact_id":aid,"c2_target_id":target(ps,m,gas,rel),
      "direct_trace_map":[{"point":p,"payloads":list(t)} for p,t in trs]}

def main():
    a=argparse.ArgumentParser();a.add_argument("--claim",required=True);a.add_argument("--profile",required=True);a.add_argument("--out-dir");x=a.parse_args()
    try:r=check(Path(x.claim).read_bytes(),Path(x.profile).read_bytes(),x.out_dir)
    except Unsupported as e:r={"checker":"risu-k1-checker-w7","proof_status":"UNSUPPORTED","semantic_claim":"UNKNOWN","authority_created":False,"reason":str(e)}
    except (Reject,OSError,ValueError) as e:r={"checker":"risu-k1-checker-w7","proof_status":"REJECTED","semantic_claim":"NONE","authority_created":False,"reason":str(e)}
    print(json.dumps(r,sort_keys=True,separators=(",",":")))
if __name__=="__main__":sys.exit(main())
