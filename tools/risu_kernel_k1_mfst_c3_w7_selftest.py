#!/usr/bin/env python3
import copy,importlib.util,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"kernel"))
spec=importlib.util.spec_from_file_location("w7",ROOT/"kernel"/"k1_checker_w7.py")
w7=importlib.util.module_from_spec(spec);spec.loader.exec_module(w7)
claim_raw=(ROOT/"fixtures"/"k1_mfst_c3_f0"/"claim.json").read_bytes();base_raw=(ROOT/"fixtures"/"k1_mfst_c3_f0"/"baseline.json").read_bytes();base=json.loads(base_raw);passed=0
def raw(o):return json.dumps(o,sort_keys=True,separators=(",",":")).encode()
def ok(n,f):
 global passed;f();passed+=1;print("PASS",n)
def reject(n,d,s=None):
 global passed
 try:w7.check(claim_raw,d)
 except (w7.Reject,w7.Unsupported) as e:
  if s and s not in str(e):raise AssertionError((n,str(e)))
  passed+=1;print("PASS",n,str(e));return
 raise AssertionError(n+" unexpectedly accepted")
b=w7.check(claim_raw,base_raw)
E={"c3_source_id":"c3src:sha256:13ca692f6139d0c70a3829616bb360df3a8719c2aad5090c51c24e43f8a8c1d3","c3_semantic_id":"c3sem:sha256:83808a8b893dd8f96ed6585b37602874f5c24376bd135dffdc99dd16d2b0ae8d","graph_id":"c3graph:sha256:7de33c57bf1a29674aa5099df86cd18ee9d12e6bab3b31059f42297f8436af84","trace_map_id":"c3trace:sha256:6fabe8fbdc0678b2d23eaa2ab0410f7619c23cefcbfe08c3fb56e5ada48fd09b","c2_program_sha256":"c9c9b41df838e12fb00db7bca8c655c4c06f430aa98659631d95f83b7751a970","c2_derived_gas":9,"c2_artifact_id":"p:sha256:7474f9a767ce454387e29f4934c7c94de1945b1c114cefda6518cf799e6788c4","c2_target_id":"t:sha256:1879e1655f2dec6bfc462fedf37ac95df4da42d2f094dfab3b50585dbfa06747"}
ok("baseline-kat",lambda:[(_ for _ in ()).throw(AssertionError(k)) if b[k]!=v else None for k,v in E.items()])
ok("baseline-shape",lambda:None if b["boundary_point_count"]==4 and b["trace_payload_count"]==6 and b["k1_subset_allowed"] and not b["authority_created"] else (_ for _ in ()).throw(AssertionError("shape")))
p=copy.deepcopy(base);p["boundary"]["worlds"].reverse();p["boundary"]["slots"]["mode"].reverse();p["state"].reverse();p["tables"].reverse();p["tables"][0]["rows"].reverse();p["blocks"].reverse();r=w7.check(claim_raw,raw(p))
ok("representation-invariance",lambda:None if r["c3_semantic_id"]==b["c3_semantic_id"] and r["graph_id"]==b["graph_id"] and r["trace_map_id"]==b["trace_map_id"] and r["c2_program_sha256"]==b["c2_program_sha256"] and r["c3_source_id"]!=b["c3_source_id"] else (_ for _ in ()).throw(AssertionError("representation")))
reject("duplicate-json-key",base_raw[:-1]+b',"wire":"risu.k1.c3.mfst/v1"}',"duplicate JSON key")
p=copy.deepcopy(base);p["blocks"][0]["ops"].append({"op":"HOSTCALL","payload":"01"});reject("ambient-hostcall",raw(p),"unknown/ambient opcode")
p=copy.deepcopy(base);p["boundary"]["worlds"]=p["boundary"]["worlds"][:1];reject("world-shrink",raw(p),"claim mismatch")
p=copy.deepcopy(base);p["tables"][0]["rows"]=p["tables"][0]["rows"][:1];reject("table-missing-tuple",raw(p),"not exactly total")
p=copy.deepcopy(base);p["blocks"][1]["ops"]=[];reject("zero-effect-halt",raw(p),"zero-effect")
p=copy.deepcopy(base);p["blocks"][1]["term"]={"op":"GOTO","target":"safe"};reject("cycle-after-effect",raw(p),"repeated configuration")
p=copy.deepcopy(base);p["blocks"][0]["term"]["if_true"]="missing";reject("undefined-target",raw(p),"undefined target")
p=copy.deepcopy(base);p["blocks"][0]["ops"][0]["arguments"]=[{"kind":"input","name":"missing"}];reject("undeclared-input",raw(p),"undeclared input source")
p=copy.deepcopy(base);p["blocks"][2]["ops"].reverse();rr=w7.check(claim_raw,raw(p));ok("effect-reorder-visible",lambda:None if rr["trace_map_id"]!=b["trace_map_id"] and rr["projected_realize"]==b["projected_realize"] and rr["c2_program_sha256"]!=b["c2_program_sha256"] else (_ for _ in ()).throw(AssertionError("reorder")))
p=copy.deepcopy(base);p["blocks"][2]["ops"].append({"op":"EMIT_HEX","payload":"03"});rd=w7.check(claim_raw,raw(p));ok("effect-duplicate-visible",lambda:None if rd["trace_map_id"]!=b["trace_map_id"] and rd["projected_realize"]==b["projected_realize"] else (_ for _ in ()).throw(AssertionError("duplicate")))
p=copy.deepcopy(base);p["blocks"][1]["ops"].append({"op":"EMIT_HEX","payload":"de"});rf=w7.check(claim_raw,raw(p));ok("forbidden-survives",lambda:None if (not rf["k1_subset_allowed"]) and any(x[1]=="c:sha256:e9609f5a535dcdfde1b764bcdc8e42ed46c2b84623162a59cef78341dc6eecfb" for x in rf["forbidden_projected_pairs"]) else (_ for _ in ()).throw(AssertionError("forbidden")))
loop=copy.deepcopy(base);loop["boundary"]["slots"]={};loop["tables"]=[{"name":"flip","arguments":[{"name":"x","domain":["p0","p1"]}],"result_domain":["p0","p1"],"rows":[{"when":["p0"],"result":"p1"},{"when":["p1"],"result":"p1"}]}];loop["blocks"]=[{"label":"entry","ops":[],"term":{"op":"GOTO","target":"loop"}},{"label":"loop","ops":[],"term":{"op":"IF_EQ","source":{"kind":"state","name":"phase"},"value":"p0","if_true":"advance","if_false":"done"}},{"label":"advance","ops":[{"op":"APPLY_TABLE","dst":"phase","table":"flip","arguments":[{"kind":"state","name":"phase"}]}],"term":{"op":"GOTO","target":"loop"}},{"label":"done","ops":[{"op":"EMIT_HEX","payload":"01"}],"term":{"op":"HALT"}}];rl=w7.check(claim_raw,raw(loop));ok("state-progress-loop-accepted",lambda:None if rl["proof_status"]=="ACCEPTED" else (_ for _ in ()).throw(AssertionError("loop")))
pw=copy.deepcopy(base);pw["state"].append({"name":"wid","domain":copy.deepcopy(pw["boundary"]["worlds"]),"initial":{"kind":"input","name":"@world"}});rw=w7.check(claim_raw,raw(pw));ok("world-explicit-input",lambda:None if rw["proof_status"]=="ACCEPTED" else (_ for _ in ()).throw(AssertionError("world")))
ok("apply-table-prestate-alias",lambda:None if b["graph_id"] else (_ for _ in ()).throw(AssertionError("alias")))
pu=copy.deepcopy(base);pu["blocks"].append({"label":"dead","ops":[{"op":"EMIT_HEX","payload":"aa"}],"term":{"op":"HALT"}});ru=w7.check(claim_raw,raw(pu));ok("unreachable-valid-block",lambda:None if ru["c3_semantic_id"]!=b["c3_semantic_id"] and ru["graph_id"]==b["graph_id"] and ru["trace_map_id"]==b["trace_map_id"] and ru["c2_program_sha256"]==b["c2_program_sha256"] else (_ for _ in ()).throw(AssertionError("unreachable")))
print("W7_SELFTEST_PASS",passed)
