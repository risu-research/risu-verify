#!/usr/bin/env python3
from __future__ import annotations
import argparse, copy, hashlib, json, shutil
from pathlib import Path

PROFILE_ID = "version-bound-effect"
PROFILE_VERSION = "0.1-development"


def read_json(p: Path): return json.loads(p.read_text(encoding='utf-8'))
def write_json(p: Path, o):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(o, indent=2, sort_keys=True)+"\n", encoding='utf-8')
def sha256_file(p: Path): return hashlib.sha256(p.read_bytes()).hexdigest()

def get_expr(source, name): return {"op":"get","source":source,"path":[name]}
def lit(v): return {"op":"literal","value":v}
def eq(a,b): return {"op":"eq","left":a,"right":b}
def ife(c,t,e): return {"op":"if","cond":c,"then":t,"else":e}
def obj(fields): return {"op":"object","fields":fields}

def build_source(inst):
    s=inst['source']
    coords={s['current_coordinate']: s['current_domain']}
    reviewed=s['reviewed']
    if reviewed['mode']=='coordinate': coords[reviewed['name']]=reviewed['domain']
    for k,v in s.get('extra_coordinates',{}).items(): coords[k]=v
    right = get_expr('coord', reviewed['name']) if reviewed['mode']=='coordinate' else lit(reviewed['anchor'])
    out={
      "source_contract_version":"0.7",
      "contract_id":s['contract_id'],
      "metadata":s['metadata'],
      "constants":s.get('constants',{}),
      "coordinates":coords,
      "admissibility":s.get('admissibility', {"expr":lit(True)}),
      "consequence":{
        "lens":s['lens'], "codomain":[s['success_consequence'],s['stale_consequence']],
        "expr":ife(eq(get_expr('coord',s['current_coordinate']), right),lit(s['success_consequence']),lit(s['stale_consequence']))
      },
      "boundary":s['boundary'],
      "source_family":s['source_family'],
      "claim_boundary":s['claim_boundary'],
    }
    return out

def build_target(inst, envelope):
    t=inst['target']; s=inst['source']; pattern=t['pattern']; facts=t['facts']; anchor=t['reviewed_anchor_constant']
    cur=s['current_coordinate']; success=s['success_consequence']; stale=s['stale_consequence']
    pc={anchor: s['reviewed']['anchor']}

    if pattern=='PRESERVED_COMPARE':
        disc=ife(eq(get_expr('world',cur), get_expr('const',anchor)), lit('MATCH'), lit('MISMATCH'))
        sig=obj({t['signature_current_field']:get_expr('world',cur), t['signature_reviewed_field']:get_expr('const',anchor)})
        mech=ife(eq(get_expr('z',t['mechanism_current_field']), get_expr('z',t['mechanism_reviewed_field'])), lit({"kind":t['native_accept_kind']}), lit({"kind":t['native_stale_kind']}))
        interp=ife(eq(get_expr('native','kind'),lit(t['native_accept_kind'])),lit({"label":success,"space":"C"}),ife(eq(get_expr('native','kind'),lit(t['native_stale_kind'])),lit({"label":stale,"space":"C"}),obj({"native":{"op":"get","source":"native","path":[]},"space":lit("OUTSIDE_C")})))
        program={
          "discriminator":{"expr":disc,"required_fact_ids":facts['discriminator']},
          "operative_signature":{"expr":sig,"required_fact_ids":facts['operative_signature']},
          "mechanism":{"expr":mech,"required_fact_ids":facts['mechanism']},
          "interpreter":{"expr":interp,"required_fact_ids":facts['interpreter']},
          "program_version":t['program_version']}
        corr={"status":"ESTABLISHED"}; discharge={"evaluation_cut":"EFFECT","gates_effect":True,"mode":t['discharge_mode']}
    elif pattern=='OMITTED_REVIEWED_GUARD':
        extra=t['otherwise_effect_coordinate']
        disc=get_expr('world',cur)
        sig=obj({t['signature_expected_field']:lit(None), t['signature_current_field']:get_expr('world',cur), extra:get_expr('world',extra)})
        mismatch={"op":"and","args":[{"op":"not","expr":{"op":"is_null","expr":get_expr('z',t['signature_expected_field'])}}, {"op":"neq","left":get_expr('z',t['signature_current_field']),"right":get_expr('z',t['signature_expected_field'])}]}
        merged=obj({"kind":lit(t['native_accept_kind']), t['native_merged_field']:get_expr('z',t['signature_current_field'])})
        mech=ife(mismatch,lit({"kind":t['native_stale_kind']}),ife(get_expr('z',extra),merged,lit({"kind":t['native_other_failure_kind']})))
        accept_cond={"op":"and","args":[eq(get_expr('native','kind'),lit(t['native_accept_kind'])),eq(get_expr('native',t['native_merged_field']),get_expr('const',anchor))]}
        interp=ife(accept_cond,lit({"label":success,"space":"C"}),ife(eq(get_expr('native','kind'),lit(t['native_stale_kind'])),lit({"label":stale,"space":"C"}),obj({"native":{"op":"get","source":"native","path":[]},"space":lit("OUTSIDE_C")})))
        program={
          "discriminator":{"expr":disc,"required_fact_ids":facts['discriminator']},
          "operative_signature":{"expr":sig,"required_fact_ids":facts['operative_signature']},
          "mechanism":{"expr":mech,"required_fact_ids":facts['mechanism']},
          "interpreter":{"expr":interp,"required_fact_ids":facts['interpreter']},
          "program_version":t['program_version']}
        corr={"status":"ESTABLISHED"}; discharge={"evaluation_cut":"NONE","gates_effect":False,"mode":t['discharge_mode']}
    elif pattern=='WRONG_VALIDATOR_REJECT_PATH':
        disc=lit(t['discriminator_literal'])
        sig=obj({t['signature_validator_field']:lit(t['validator_kind']), t['signature_supplied_field']:get_expr('const',anchor)})
        mech=lit({"kind":t['native_stale_kind']})
        interp=ife(eq(get_expr('native','kind'),lit(t['native_stale_kind'])),lit({"label":stale,"space":"C"}),obj({"native":{"op":"get","source":"native","path":[]},"space":lit("OUTSIDE_C")}))
        program={
          "discriminator":{"expr":disc,"required_fact_ids":facts['discriminator']},
          "operative_signature":{"expr":sig,"required_fact_ids":facts['operative_signature']},
          "mechanism":{"expr":mech,"required_fact_ids":facts['mechanism']},
          "interpreter":{"expr":interp,"required_fact_ids":facts['interpreter']},
          "program_version":t['program_version']}
        corr={"status":"NOT_ESTABLISHED"}; discharge={"evaluation_cut":"NONE","gates_effect":False,"mode":t['discharge_mode']}
    else: raise ValueError(f'unsupported target pattern {pattern}')

    st=copy.deepcopy(envelope['structural_base'])
    st.update({"correspondence":corr,"discharge":discharge,"discriminator":{"visibility":t['discriminator_visibility']},"scope":{"id":t['scope_id'],"status":"IN_SCOPE"}})
    return {
      "coverage":{"in_scope":[t['scope_id']]},
      "derivation":{"facts":copy.deepcopy(envelope['derivation_facts']),"mode":"CONSEQUENCE_BLIND","profile_constants":pc,"program":program},
      "exact_enabled":True,
      "structural_template":st,
    }

def compile_instance(instance_path: Path, out: Path):
    inst=read_json(instance_path)
    if inst.get('profile')!=PROFILE_ID: raise ValueError('wrong profile')
    if inst.get('status') not in {'AUTHOR_ACCEPTED','CALIBRATION_ONLY'}: raise ValueError('VBE instance must be AUTHOR_ACCEPTED or CALIBRATION_ONLY before compilation')
    env=read_json((instance_path.parent/inst['carrier_envelope']).resolve())
    project=Path(__file__).resolve().parents[1]
    legacy=(project/inst['legacy_case']).resolve()
    legacy_meta=read_json(legacy/'case.json')
    legacy_assurance=(legacy/legacy_meta.get('assurance_dir','assurance')).resolve()

    if out.exists(): shutil.rmtree(out)
    (out/'assurance').mkdir(parents=True)
    for child in legacy_assurance.iterdir():
        if child.name in {'adapter.json','source-contract.json'}: continue
        dest=out/'assurance'/child.name
        if child.is_dir(): shutil.copytree(child,dest)
        else: shutil.copy2(child,dest)

    sc=build_source(inst); write_json(out/'assurance'/'source-contract.json',sc)
    ad=copy.deepcopy(env['adapter_base'])
    ad['source_contract']={"path":"source-contract.json","sha256":sha256_file(out/'assurance'/'source-contract.json')}
    ad['target']=build_target(inst,env)
    write_json(out/'assurance'/'adapter.json',ad)

    cm=copy.deepcopy(legacy_meta)
    cm.pop('predeclaration',None); cm.pop('provenance',None)
    cm['case_id']=inst['compiled_case_id']; cm['title']=f"VBE compiled calibration — {inst['instance_id']}"
    cm['kind']='VBE_PROFILE_COMPILED_CALIBRATION'
    cm['profile']={"id":PROFILE_ID,"version":PROFILE_VERSION,"instance":inst['instance_id'],"source_instance_sha256":sha256_file(instance_path)}
    write_json(out/'case.json',cm)
    write_json(out/'VBE_COMPILE_MANIFEST.json',{
      "compiler":"tools/vbe_compile.py","profile":PROFILE_ID,"profile_version":PROFILE_VERSION,
      "instance_sha256":sha256_file(instance_path),"carrier_envelope_sha256":sha256_file((instance_path.parent/inst['carrier_envelope']).resolve()),
      "legacy_case":inst['legacy_case'],"compiled_source_contract_sha256":sha256_file(out/'assurance'/'source-contract.json'),"compiled_adapter_sha256":sha256_file(out/'assurance'/'adapter.json')})
    return out

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('instance'); ap.add_argument('--output',required=True)
    a=ap.parse_args(); compile_instance(Path(a.instance).resolve(),Path(a.output).resolve()); print(Path(a.output).resolve())
if __name__=='__main__': main()
