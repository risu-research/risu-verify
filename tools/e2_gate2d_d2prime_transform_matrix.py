#!/usr/bin/env python3
from __future__ import annotations
import argparse,hashlib,json
from pathlib import Path
OLD={"B3A_GPT56_SOL_FRONTIER":"B3A_GPT56_SOL_COPILOT","B3B_CLAUDE_OPUS45_DATED":"B3B_CLAUDE_OPUS5_COPILOT"}
RAW_MANIFEST_SHA256="fe433e55b33da2ff84b74f4c9dd822403984184c3537b6d63a14073ca3154b28"
def cb(v):return (json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=False)+"\n").encode()
def sha(b):return hashlib.sha256(b).hexdigest()
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--raw",required=True);ap.add_argument("--out",required=True);ap.add_argument("--proof",required=True);a=ap.parse_args()
 raw=Path(a.raw);out=Path(a.out);proofp=Path(a.proof);(out/"cases").mkdir(parents=True,exist_ok=True)
 mb=(raw/"matrix_manifest.json").read_bytes()
 if sha(mb)!=RAW_MANIFEST_SHA256:raise SystemExit("RAW_MATRIX_MANIFEST_IDENTITY")
 man=json.loads(mb)
 if man.get("case_count")!=30 or len(man.get("cases",[]))!=30:raise SystemExit("RAW_MATRIX_COUNT")
 rows=[];newman=[]
 for ent in man["cases"]:
  cid=ent["id"];rp=raw/"cases"/(cid+".json");rb=rp.read_bytes()
  if sha(rb)!=ent["sha256"] or len(rb)!=ent["size"]:raise SystemExit("RAW_CASE_MANIFEST:"+cid)
  d=json.loads(rb);subs=0
  if isinstance(d,dict) and isinstance(d.get("baselines"),dict):
   b=d["baselines"]
   if set(OLD)&set(b)!=set(OLD):raise SystemExit("RAW_BASELINE_KEYS:"+cid)
   if set(OLD.values())&set(b):raise SystemExit("NEW_KEY_PREEXISTS:"+cid)
   for old,new in OLD.items():b[new]=b.pop(old);subs+=1
   tb=cb(d)
   inv=json.loads(tb);ib=inv["baselines"]
   for old,new in OLD.items():ib[old]=ib.pop(new)
   inverse_exact=cb(inv)==rb
  else:
   tb=rb;inverse_exact=True
  if not inverse_exact:raise SystemExit("INVERSE_RENAME_MISMATCH:"+cid)
  tp=out/"cases"/(cid+".json");tp.write_bytes(tb)
  newman.append({"id":cid,"sha256":sha(tb),"size":len(tb)})
  rows.append({"id":cid,"raw_sha256":sha(rb),"transformed_sha256":sha(tb),"substitution_count":subs,"inverse_rename_byte_exact":inverse_exact,"unchanged_policy_input":subs==0 and tb==rb})
 outman={"schema":"risu.e2-gate2d-d2p-synthetic-matrix/v0.1","case_count":30,"cases":newman,"source_raw_manifest_sha256":RAW_MANIFEST_SHA256,"mechanical_substitution":OLD,"d0_d2_matrix_exact":True}
 (out/"matrix_manifest.json").write_bytes(cb(outman))
 eval_rows=[x for x in rows if x["substitution_count"]]
 policy_rows=[x for x in rows if not x["substitution_count"]]
 status="PASS" if len(rows)==30 and len(eval_rows)==27 and len(policy_rows)==3 and all(x["substitution_count"]==2 and x["inverse_rename_byte_exact"] for x in eval_rows) and all(x["unchanged_policy_input"] for x in policy_rows) else "FAIL"
 proof={"schema":"risu.e2-gate2d-d2p-matrix-transform-proof/v0.1","status":status,"raw_manifest_sha256":RAW_MANIFEST_SHA256,"case_count":30,"evaluation_case_count":len(eval_rows),"policy_case_count":len(policy_rows),"rows":rows,"epistemic10_read":False,"truth_read":False,"fresh_target_read":False,"mutation_algebra_opened":False,"copilot_semantic_request_count":0}
 proofp.write_bytes(cb(proof))
 if status!="PASS":raise SystemExit(2)
if __name__=="__main__":main()
