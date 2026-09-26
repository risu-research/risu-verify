#!/usr/bin/env python3
import copy,json,subprocess,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
BIN=ROOT/"build"/"k1_checker_w8"
CLAIM=ROOT/"fixtures"/"k1_mfst_c3_f0"/"claim.json"
BASEP=ROOT/"fixtures"/"k1_mfst_c3_f0"/"baseline.json"
base=json.loads(BASEP.read_text());passed=0
def enc(o):return json.dumps(o,sort_keys=True,separators=(",",":")).encode()
def run(raw):
    with tempfile.NamedTemporaryFile() as f:
        f.write(raw);f.flush();p=subprocess.run([str(BIN),"--claim",str(CLAIM),"--profile",f.name],capture_output=True,text=True,check=True);return json.loads(p.stdout)
def ok(n,cond):
    global passed
    if not cond:raise AssertionError(n)
    passed+=1;print("PASS",n)
b=run(BASEP.read_bytes());ok("baseline-accept",b["proof_status"]=="ACCEPTED" and not b["authority_created"])
p=copy.deepcopy(base);p["boundary"]["worlds"].reverse();p["boundary"]["slots"]["mode"].reverse();p["state"].reverse();p["tables"].reverse();p["tables"][0]["rows"].reverse();p["blocks"].reverse();r=run(enc(p));ok("representation-invariance",r["c3_semantic_id"]==b["c3_semantic_id"] and r["graph_id"]==b["graph_id"] and r["trace_map_id"]==b["trace_map_id"] and r["c2_program_sha256"]==b["c2_program_sha256"] and r["c3_source_id"]!=b["c3_source_id"])
r=run(BASEP.read_bytes()[:-1]+b',"wire":"risu.k1.c3.mfst/v1"}');ok("duplicate-json-key",r["proof_status"]=="REJECTED" and "duplicate JSON key" in r["reason"])
p=copy.deepcopy(base);p["blocks"][0]["ops"].append({"op":"HOSTCALL","payload":"01"});ok("ambient-hostcall",run(enc(p))["proof_status"]=="REJECTED")
p=copy.deepcopy(base);p["boundary"]["worlds"]=p["boundary"]["worlds"][:1];ok("world-shrink",run(enc(p))["proof_status"]=="REJECTED")
p=copy.deepcopy(base);p["tables"][0]["rows"]=p["tables"][0]["rows"][:1];ok("table-missing-tuple",run(enc(p))["proof_status"]=="REJECTED")
p=copy.deepcopy(base);p["blocks"][1]["ops"]=[];ok("zero-effect",run(enc(p))["proof_status"]=="REJECTED")
p=copy.deepcopy(base);p["blocks"][1]["term"]={"op":"GOTO","target":"safe"};ok("cycle",run(enc(p))["proof_status"]=="REJECTED")
p=copy.deepcopy(base);p["blocks"][0]["term"]["if_true"]="missing";ok("undefined-target",run(enc(p))["proof_status"]=="REJECTED")
p=copy.deepcopy(base);p["blocks"][0]["ops"][0]["arguments"]=[{"kind":"input","name":"missing"}];ok("undeclared-source",run(enc(p))["proof_status"]=="REJECTED")
p=copy.deepcopy(base);p["blocks"][2]["ops"].reverse();rr=run(enc(p));ok("effect-reorder-visible",rr["trace_map_id"]!=b["trace_map_id"] and rr["projected_realize"]==b["projected_realize"] and rr["c2_program_sha256"]!=b["c2_program_sha256"])
p=copy.deepcopy(base);p["blocks"][2]["ops"].append({"op":"EMIT_HEX","payload":"03"});rd=run(enc(p));ok("effect-duplicate-visible",rd["trace_map_id"]!=b["trace_map_id"] and rd["projected_realize"]==b["projected_realize"])
p=copy.deepcopy(base);p["blocks"][1]["ops"].append({"op":"EMIT_HEX","payload":"de"});rf=run(enc(p));ok("forbidden-survives",not rf["k1_subset_allowed"] and any(x[1]=="c:sha256:e9609f5a535dcdfde1b764bcdc8e42ed46c2b84623162a59cef78341dc6eecfb" for x in rf["forbidden_projected_pairs"]))
loop=copy.deepcopy(base);loop["boundary"]["slots"]={};loop["tables"]=[{"name":"flip","arguments":[{"name":"x","domain":["p0","p1"]}],"result_domain":["p0","p1"],"rows":[{"when":["p0"],"result":"p1"},{"when":["p1"],"result":"p1"}]}];loop["blocks"]=[{"label":"entry","ops":[],"term":{"op":"GOTO","target":"loop"}},{"label":"loop","ops":[],"term":{"op":"IF_EQ","source":{"kind":"state","name":"phase"},"value":"p0","if_true":"advance","if_false":"done"}},{"label":"advance","ops":[{"op":"APPLY_TABLE","dst":"phase","table":"flip","arguments":[{"kind":"state","name":"phase"}]}],"term":{"op":"GOTO","target":"loop"}},{"label":"done","ops":[{"op":"EMIT_HEX","payload":"01"}],"term":{"op":"HALT"}}];ok("state-progress-loop",run(enc(loop))["proof_status"]=="ACCEPTED")
p=copy.deepcopy(base);p["state"].append({"name":"wid","domain":copy.deepcopy(p["boundary"]["worlds"]),"initial":{"kind":"input","name":"@world"}});ok("world-explicit-input",run(enc(p))["proof_status"]=="ACCEPTED")
p=copy.deepcopy(base);p["blocks"].append({"label":"dead","ops":[{"op":"EMIT_HEX","payload":"aa"}],"term":{"op":"HALT"}});ru=run(enc(p));ok("unreachable-valid-block",ru["c3_semantic_id"]!=b["c3_semantic_id"] and ru["graph_id"]==b["graph_id"] and ru["trace_map_id"]==b["trace_map_id"] and ru["c2_program_sha256"]==b["c2_program_sha256"])
print("W8_SELFTEST_PASS",passed)
