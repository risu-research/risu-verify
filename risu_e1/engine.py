from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterable, List, Sequence, Set, Tuple

from .extractor import extract_packet_facts, is_versionish

PREDICTION_SCHEMA="risu.diff-e1-prediction/v0.1"
FACT_SCHEMA="risu.diff-e1-typed-facts/v0.1"
ROLE_SCHEMA="risu.diff-e1-material-role-proof/v0.1"
REQUEST_SCHEMA="risu.diff-e1-refinement-requests/v0.1"
MANIFEST_SCHEMA="risu.diff-e1-run-manifest/v0.1"
SEAL_SCHEMA="risu.diff-e1-output-seal/v0.1"

REQUIRED_ARTIFACTS=(
    "TYPED_FACTS.json","MATERIAL_ROLE_PROOF.json","E1_PREDICTION.json",
    "REFINEMENT_REQUESTS.json","E1_RUN_MANIFEST.json",
)
CONTROL_ARTIFACT="E1_OUTPUT_SEAL.json"
MAX_EVIDENCE_FILE_BYTES=5*1024*1024
MAX_PACKET_BYTES=20*1024*1024
_ALLOWED_KINDS={"SOURCE_TEXT","TARGET_TEXT","TOOL_SURFACE","MACHINE_OBSERVATION"}

def canonical_bytes(v:Any)->bytes:
    return (json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=False)+"\n").encode()
def sha256_bytes(b:bytes)->str:return hashlib.sha256(b).hexdigest()
def compact(s:str)->str:return re.sub(r"[^a-z0-9]+","",s.lower())

def _safe_relpath(value:str)->str:
    if not isinstance(value,str) or not value:raise ValueError("evidence path must be nonempty")
    q=PurePosixPath(value)
    if q.is_absolute() or "." in q.parts or ".." in q.parts or "\\" in value:raise ValueError(f"unsafe evidence path:{value!r}")
    return q.as_posix()

def load_machine_packet(packet_dir:Path)->Dict[str,Any]:
    packet_dir=packet_dir.resolve(); rf=packet_dir/"MACHINE_INPUT.json"
    raw_root=rf.read_bytes(); data=json.loads(raw_root.decode())
    required={"schema","run_id","unit_id","target_revision","screened_operation","surface","evidence_files"}
    if not required<=set(data):raise ValueError("machine input missing required fields")
    if data["schema"]!="risu.diff-e0-machine-input/v0.1":raise ValueError("unsupported machine input schema")
    if set(data)-{"schema","run_id","unit_id","target_revision","screened_operation","surface","evidence_files","acquisition"}:raise ValueError("unknown machine input fields")
    surface=data["surface"]
    if not isinstance(surface,dict) or set(surface)-{"name","arguments"}:raise ValueError("invalid surface")
    if not isinstance(surface.get("name"),str) or not isinstance(surface.get("arguments"),list):raise ValueError("invalid surface types")
    ev=[]; total=len(raw_root); declared=[]
    for row in data["evidence_files"]:
        if set(row)-{"path","sha256","kind","language"}:raise ValueError("unknown evidence fields")
        rel=_safe_relpath(row["path"])
        if row["kind"] not in _ALLOWED_KINDS:raise ValueError("unsupported evidence kind")
        p=packet_dir/rel; b=p.read_bytes()
        if len(b)>MAX_EVIDENCE_FILE_BYTES:raise ValueError("evidence too large")
        total+=len(b)
        if total>MAX_PACKET_BYTES:raise ValueError("packet too large")
        h=sha256_bytes(b)
        if h!=row["sha256"]:raise ValueError(f"evidence hash mismatch:{rel}")
        ev.append({"path":rel,"sha256":h,"kind":row["kind"],"language":row.get("language"),"bytes":b});declared.append(rel)
    actual=sorted(x.relative_to(packet_dir).as_posix() for x in packet_dir.rglob("*") if x.is_file())
    expected=sorted(["MACHINE_INPUT.json",*declared])
    if actual!=expected:raise ValueError("packet closure mismatch")
    identity={"machine_input_sha256":sha256_bytes(raw_root),"evidence_sha256":{r["path"]:r["sha256"] for r in sorted(ev,key=lambda x:x["path"])}}
    return {"input":data,"surface":{"name":surface["name"],"arguments":list(surface["arguments"])},"evidence":ev,
            "packet_identity":identity,"packet_digest":sha256_bytes(canonical_bytes(identity))}

def _surface_version_tokens(packet:Dict[str,Any])->Set[str]:
    return {compact(a) for a in packet["surface"]["arguments"] if any(t in compact(a) for t in ("sha","etag","version","revision","generation"))}

Node=Tuple[str,str] # (scope,name)

def _node(scope:str,name:str)->Node:return (scope,name)
def _fact_refs(rows:Iterable[Dict[str,Any]])->List[str]:return sorted({r["deterministic_fact_id"] for r in rows})
def _name_matches_surface(name:str,surface_tokens:Set[str])->bool:
    c=compact(name)
    return any(st in c or c in st for st in surface_tokens if st and c)

def _function_defs(facts:Sequence[Dict[str,Any]])->Dict[str,Dict[str,Any]]:
    out={}
    for f in facts:
        if f["type"]=="FUNCTION_DEF":
            out[f["name"]]=f
    return out

def _build_alias_closure(facts:Sequence[Dict[str,Any]],seed_nodes:Set[Node])->Set[Node]:
    aliases=set(seed_nodes)
    defs=_function_defs(facts)
    changed=True
    while changed:
        changed=False
        # intra-scope assignments
        for f in facts:
            if f["type"]!="ASSIGNMENT_FLOW":continue
            scope=f.get("scope","<module>")
            src={_node(scope,n) for n in f.get("from_names",[])}
            dst={_node(scope,n) for n in f.get("to_names",[])}
            if aliases & src:
                before=len(aliases);aliases|=dst;changed=changed or len(aliases)>before
        # explicit call parameter propagation
        for f in facts:
            if f["type"]!="CALL_EDGE":continue
            callee=f.get("callee","").split(".")[-1]
            d=defs.get(callee)
            if not d:continue
            caller_scope=f.get("scope","<module>")
            callee_scope=d.get("scope",callee)
            params=list(d.get("params",[]))
            for i,arg_group in enumerate(f.get("arg_names",[]) or []):
                if i>=len(params):break
                if any(_node(caller_scope,n) in aliases for n in arg_group):
                    target=_node(callee_scope,params[i])
                    if target not in aliases:aliases.add(target);changed=True
    return aliases

def assemble_material_roles(packet:Dict[str,Any],extracted:Dict[str,Any])->Dict[str,Any]:
    facts=extracted["facts"]; surface_tokens=_surface_version_tokens(packet)
    version_rows=[f for f in facts if f["type"]=="VERSION_LIKE_COORDINATE"]
    seed_nodes=set()
    for f in version_rows:
        scope=f.get("scope","<module>")
        for name in f.get("names",[]):
            if _name_matches_surface(name,surface_tokens):seed_nodes.add(_node(scope,name))
    aliases=_build_alias_closure(facts,seed_nodes)

    guard_rows=[]; current_nodes=set()
    for f in facts:
        if f["type"]!="COMPARISON_GUARD":continue
        scope=f.get("scope","<module>"); nodes={_node(scope,n) for n in f.get("names",[])}
        if nodes & aliases:
            other={n for n in nodes if n not in aliases and is_versionish(n[1])}
            if other:guard_rows.append(f);current_nodes|=other

    auth_rows=[f for f in version_rows if any(_node(f.get("scope","<module>"),n) in aliases for n in f.get("names",[]))]
    current_rows=[f for f in version_rows if any(_node(f.get("scope","<module>"),n) in current_nodes for n in f.get("names",[]))]

    branch_rows=[];effect_rows=[];stale_rows=[]
    for f in facts:
        if f["type"]!="BRANCH_CONTEXT":continue
        scope=f.get("scope","<module>"); cond={_node(scope,n) for n in f.get("condition_names",[])}
        if not cond & (aliases|current_nodes):continue
        branch_rows.append(f)
        tm=bool(f.get("then_mutation"));em=bool(f.get("else_mutation"))
        tb=bool(f.get("then_errorish") or f.get("then_return"));eb=bool(f.get("else_errorish") or f.get("else_return"))
        if tm and eb:effect_rows.append(f);stale_rows.append(f)
        if em and tb:effect_rows.append(f);stale_rows.append(f)

    roles={
        "authoritative_version_coordinate":{"status":"STRUCTURALLY_SUPPORTED" if auth_rows else "UNRESOLVED","fact_refs":_fact_refs(auth_rows)},
        "current_version_at_effect_coordinate":{"status":"STRUCTURALLY_SUPPORTED" if current_rows else "UNRESOLVED","fact_refs":_fact_refs(current_rows)},
        "binding_or_compare_guard":{"status":"STRUCTURALLY_SUPPORTED" if guard_rows else "UNRESOLVED","fact_refs":_fact_refs(guard_rows)},
        "declared_effect":{"status":"STRUCTURALLY_SUPPORTED" if effect_rows else "UNRESOLVED","fact_refs":_fact_refs(effect_rows)},
        "stale_mismatch_outcome_or_interpreter":{"status":"STRUCTURALLY_SUPPORTED" if stale_rows else "UNRESOLVED","fact_refs":_fact_refs(stale_rows)},
    }

    overwrite=[]
    for f in facts:
        if f["type"]!="OVERWRITE_LITERAL":continue
        scope=f.get("scope","<module>")
        if any(_node(scope,n) in aliases for n in f.get("names",[])):overwrite.append(f)
    mutation=[f for f in facts if f["type"]=="MUTATION_OR_EFFECT_CALL"]
    regression=None
    if overwrite and mutation and not guard_rows:
        regression={"kind":"SURFACE_VERSION_COORDINATE_OVERWRITTEN_BEFORE_UNGUARDED_EFFECT",
                    "overwrite_fact_refs":_fact_refs(overwrite),"effect_fact_refs":_fact_refs(mutation)}

    parse_failures=[r["path"] for r in extracted["files"] if r.get("parse_error")]
    return {"artifact_schema":ROLE_SCHEMA,"run_id":packet["input"]["run_id"],"surface_version_tokens":sorted(surface_tokens),
            "seed_nodes":[{"scope":s,"name":n} for s,n in sorted(seed_nodes)],
            "alias_closure":[{"scope":s,"name":n} for s,n in sorted(aliases)],
            "roles":roles,"regression_witness":regression,"material_parse_failures":sorted(parse_failures),
            "consequence_authority":False}

def predict(role_artifact:Dict[str,Any])->Dict[str,Any]:
    unresolved=sorted(k for k,v in role_artifact["roles"].items() if v["status"]!="STRUCTURALLY_SUPPORTED")
    if role_artifact.get("regression_witness") is not None:
        p="E1_PREDICTED_REGRESSION_WITNESS";stop=None
    elif not unresolved and not role_artifact.get("material_parse_failures"):
        p="E1_PREDICTED_PRESERVATION_EVIDENCE";stop=None
    else:
        p="E1_PREDICTED_ASSURANCE_INCOMPLETE";stop="UNRESOLVED_MATERIAL_OBLIGATION"
    return {"artifact_schema":PREDICTION_SCHEMA,"prediction":p,"hard_stop":stop,"unresolved_material_roles":unresolved,
            "regression_witness":role_artifact.get("regression_witness"),"canonical_scientific_authority":False,"consequence_authority":False}

def refinement_requests(role_artifact:Dict[str,Any])->Dict[str,Any]:
    req=[]
    for role,row in sorted(role_artifact["roles"].items()):
        if row["status"]!="STRUCTURALLY_SUPPORTED":
            req.append({"obligation":role,"machine_action":"ACQUIRE_OR_EXTRACT_ADDITIONAL_EXACT_REVISION_EVIDENCE","human_translation_required":False})
    for path in role_artifact.get("material_parse_failures",[]):
        req.append({"obligation":"material_parse_failure","evidence_path":path,"machine_action":"RETRY_WITH_LANGUAGE_EXTRACTOR_OR_ABSTAIN","human_translation_required":False})
    return {"artifact_schema":REQUEST_SCHEMA,"run_id":role_artifact["run_id"],"requests":req,"closed_loop_machine_action_permitted":True,
            "live_side_effects_permitted":False,"human_semantic_injection_before_seal":False}

def build_outputs(packet_dir:Path,engine_identity:Dict[str,Any],go_helper_path:Path|None=None)->Dict[str,bytes]:
    packet=load_machine_packet(packet_dir);ex=extract_packet_facts(packet["evidence"],go_helper_path)
    facts={"artifact_schema":FACT_SCHEMA,"run_id":packet["input"]["run_id"],"facts":ex["facts"],"files":ex["files"],"semantic_authority":False}
    roles=assemble_material_roles(packet,ex);pred=predict(roles);pred["run_id"]=packet["input"]["run_id"];req=refinement_requests(roles)
    first={"TYPED_FACTS.json":canonical_bytes(facts),"MATERIAL_ROLE_PROOF.json":canonical_bytes(roles),
           "E1_PREDICTION.json":canonical_bytes(pred),"REFINEMENT_REQUESTS.json":canonical_bytes(req)}
    manifest={"artifact_schema":MANIFEST_SCHEMA,"run_id":packet["input"]["run_id"],"unit_id":packet["input"]["unit_id"],
              "target_revision":packet["input"]["target_revision"],"screened_operation":packet["input"]["screened_operation"],
              "input_packet_digest":packet["packet_digest"],"input_packet_identity":packet["packet_identity"],"engine_identity":engine_identity,
              "pre_manifest_artifact_sha256":{k:sha256_bytes(v) for k,v in sorted(first.items())},
              "required_artifacts":list(REQUIRED_ARTIFACTS),"canonical_scientific_authority":False,"wall_clock_fields_present":False}
    outputs={**first,"E1_RUN_MANIFEST.json":canonical_bytes(manifest)}
    hashes={k:sha256_bytes(v) for k,v in sorted(outputs.items())}
    payload={"artifact_schema":SEAL_SCHEMA,"run_id":packet["input"]["run_id"],"input_packet_digest":packet["packet_digest"],
             "engine_identity_digest":engine_identity["engine_identity_digest"],"semantic_artifact_sha256":hashes,"required_artifacts":list(REQUIRED_ARTIFACTS)}
    outputs[CONTROL_ARTIFACT]=canonical_bytes({**payload,"seal_digest":sha256_bytes(canonical_bytes(payload))})
    return outputs

def write_outputs(packet_dir:Path,output_dir:Path,engine_identity:Dict[str,Any],go_helper_path:Path|None=None)->Dict[str,str]:
    out=build_outputs(packet_dir,engine_identity,go_helper_path);output_dir.mkdir(parents=True,exist_ok=True)
    for n,b in out.items():(output_dir/n).write_bytes(b)
    return {n:sha256_bytes(b) for n,b in sorted(out.items())}

def verify_output_dir(output_dir:Path)->Dict[str,Any]:
    missing=[x for x in (*REQUIRED_ARTIFACTS,CONTROL_ARTIFACT) if not (output_dir/x).is_file()]
    if missing:raise ValueError(f"missing output artifacts:{missing}")
    actual=sorted(p.name for p in output_dir.iterdir() if p.is_file());expected=sorted([*REQUIRED_ARTIFACTS,CONTROL_ARTIFACT])
    if actual!=expected:raise ValueError("output closure mismatch")
    seal=json.loads((output_dir/CONTROL_ARTIFACT).read_text())
    hashes={n:sha256_bytes((output_dir/n).read_bytes()) for n in sorted(REQUIRED_ARTIFACTS)}
    if hashes!=seal.get("semantic_artifact_sha256"):raise ValueError("semantic artifact hash mismatch")
    payload={k:v for k,v in seal.items() if k!="seal_digest"};digest=sha256_bytes(canonical_bytes(payload))
    if digest!=seal.get("seal_digest"):raise ValueError("seal digest mismatch")
    return {"status":"PASS","seal_digest":digest,"semantic_artifact_sha256":hashes}
