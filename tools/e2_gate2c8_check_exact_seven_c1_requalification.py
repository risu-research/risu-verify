#!/usr/bin/env python3
from __future__ import annotations
import argparse, ast, hashlib, json
from pathlib import Path
from typing import Any, Mapping

SCHEMA='risu.e2-gate2c8-exact-seven-c1-independent-check/v0.1'
VALID='VALID_C1'; PRES='E2_PREDICTED_PRESERVATION_EVIDENCE'; INC='E2_PREDICTED_ASSURANCE_INCOMPLETE'
EXPECTED_ROLE='BOUND_VALUE:expected_coordinate'; CURRENT_ROLE='BOUND_VALUE:current_coordinate'
A3_NONROLE=['A3_P2_BINDING_IDENTITY','A3_P3_DEFINITION_SENSITIVITY','A3_P4_REPRESENTATION_SURVIVAL','A3_P5_PATH_REALIZABILITY']
A4=['A4_P1_EFFECT_BOUNDARY','A4_P2_EFFECTIVE_GUARD','A4_P3_GUARD_DOMINATES_EFFECT','A4_P4_CANONICAL_POLARITY','A4_P5_NO_BYPASS_OR_FALLBACK','A4_P6_ORDERING','A4_P7_OUTCOME_DISTINCTION']

def cb(v:Any)->bytes:return (json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False)+'\n').encode()
def sha(b:bytes)->str:return hashlib.sha256(b).hexdigest()
def dj(v:Any)->str:return sha(cb(v))
def readj(p:Path)->Any:return json.loads(p.read_bytes())
def sp(n:ast.AST):return (int(n.lineno),int(n.col_offset),int(n.end_lineno),int(n.end_col_offset))
def exact(tree,typ,coords):
    t=tuple(map(int,coords));return [n for n in ast.walk(tree) if isinstance(n,typ) and hasattr(n,'lineno') and sp(n)==t]

def step(n:ast.AST)->tuple[dict[str,str],str]:
    if isinstance(n,ast.Attribute):return {'kind':'ATTRIBUTE','token_digest_sha256':sha(n.attr.encode('utf-8'))},str(n.attr)
    if isinstance(n,ast.Subscript):
        if not isinstance(n.slice,ast.Constant) or n.slice.value is None:raise ValueError('DYNAMIC_SUBSCRIPT')
        k=n.slice.value;return {'kind':'SUBSCRIPT_LITERAL','token_digest_sha256':dj(k)},str(k)
    raise ValueError('UNSUPPORTED_PROJECTION')

def trace(e:ast.AST,env:Mapping[str,Mapping[str,Any]],params:Mapping[str,Mapping[str,Any]])->dict[str,Any]:
    if isinstance(e,ast.Name):
        r=env.get(e.id) or params.get(e.id)
        if r is None:raise ValueError('ROOT_MISSING')
        return {'root_role':str(r['root_role']),'steps':[dict(x) for x in r.get('steps',[])],'raw_origin':str(r['raw_origin'])}
    if isinstance(e,(ast.Attribute,ast.Subscript)):
        r=trace(e.value,env,params);s,tok=step(e)
        return {'root_role':r['root_role'],'steps':r['steps']+[s],'raw_origin':r['raw_origin']+'.slot:'+tok}
    raise ValueError('ROOT_OUTSIDE_FRAGMENT')

def env_for(fn:ast.AST,target_if:ast.If,sig:Mapping[str,Any]):
    ps=list(fn.args.posonlyargs)+list(fn.args.args)+list(fn.args.kwonlyargs);params={};claimed=set();env={};found=False
    for role,s in sorted((sig.get('source_roles',{}) or {}).items()):
        i=s.get('parameter_index')
        if not isinstance(i,int) or i<0 or i>=len(ps) or i in claimed:raise ValueError('ROLE_PARAMETER_INVALID')
        claimed.add(i);params[ps[i].arg]={'root_role':str(role),'steps':[],'raw_origin':str(role)}
    for st in fn.body:
        if st is target_if:found=True;break
        if isinstance(st,ast.Expr) and isinstance(st.value,ast.Constant):continue
        if isinstance(st,ast.Assign) and len(st.targets)==1 and isinstance(st.targets[0],ast.Name):name=st.targets[0].id;val=st.value
        elif isinstance(st,ast.AnnAssign) and isinstance(st.target,ast.Name) and st.value is not None:name=st.target.id;val=st.value
        else:raise ValueError('PREFIX_OUTSIDE_FRAGMENT')
        env[name]=trace(val,env,params)
    if not found:raise ValueError('GUARD_IF_NOT_FOUND')
    return env,params

def authority(canon:Mapping[str,Any]):
    body=dict(canon);claimed=body.pop('authority_digest_sha256',None)
    if claimed!=dj(body):raise ValueError('CANONICAL_AUTHORITY_DIGEST_MISMATCH')
    rows={str(r['root_role']):r for r in canon.get('roles',[])}
    if set(rows)!={EXPECTED_ROLE,CURRENT_ROLE}:raise ValueError('CANONICAL_ROLE_SET')
    for role,row in rows.items():
        payload={'root_role':role,'terminal_guard_operand_index':int(row['terminal_guard_operand_index']),'steps':[{'kind':str(x['kind']),'token_digest_sha256':str(x['token_digest_sha256'])} for x in row.get('steps',[]) or []]}
        if row.get('fingerprint_sha256')!=dj(payload):raise ValueError('CANONICAL_ROW_FINGERPRINT_MISMATCH:'+role)
    return rows,claimed

def producer_admissions(prod:Mapping[str,Any])->dict[str,bool]:
    return {str(k):bool((v or {}).get('satisfied')) for k,v in (prod.get('admissions',{}) or {}).items()}
def producer_wids(prod:Mapping[str,Any])->list[str]:
    return sorted(str(x.get('witness_id')) for x in prod.get('witnesses',[]) or [])

def receipt_expected(*,cid:str,bid:str,srcsha:str,slot:Mapping[str,Any],t:Mapping[str,Any],provenance:str)->dict[str,Any]:
    projection={'root_role':str(t['root_role']),'terminal_guard_operand_index':int(slot['operand_index']),'steps':[dict(x) for x in t['steps']]}
    fp=dj(projection)
    pcd=dj({'projection_certificate':projection,'authority_provenance':provenance})
    wrapper={'case_id':cid,'binding_id':bid,'source_sha256':srcsha,'raw_origin':str(t['raw_origin']),'binding_slot_identity':dict(slot),'certified_role':str(t['root_role']),'projection_fingerprint_sha256':fp,'projection_certificate_digest_sha256':pcd}
    return {'decision':'ADMIT','reason':'BINDING_CANONICAL_PROJECTION_AUTHORIZED' if projection['steps'] else 'BINDING_DIRECT_BASE_ROLE_AUTHORIZED','binding_wrapper':wrapper,'binding_wrapper_digest_sha256':dj(wrapper),'projection_certificate':projection,'authority_provenance':provenance,'derivation_source':'C1_RAW_BINDING_AST','world_evaluation_receipt_reused':False,'primary_derived':False}

def main()->int:
    ap=argparse.ArgumentParser()
    for x in ('gate2c8_protocol','gate2c7_ledger','gate2c7_diagnosis','canonical_authority','runner','c7_checker','observer','sources','cases','reports','output'):
        ap.add_argument('--'+x.replace('_','-'),required=True)
    a=ap.parse_args(); p=readj(Path(a.gate2c8_protocol)); old=readj(Path(a.gate2c7_ledger)); diag=readj(Path(a.gate2c7_diagnosis)); canon=readj(Path(a.canonical_authority)); run=readj(Path(a.runner)); c7check=readj(Path(a.c7_checker)); obs=readj(Path(a.observer)); arows,adig=authority(canon)
    ids=sorted(map(str,(p.get('population',{}) or {}).get('case_ids',[]) or []))
    if len(ids)!=7 or len(set(ids))!=7 or run.get('case_ids')!=ids or run.get('case_count')!=7 or obs.get('case_ids')!=ids or obs.get('case_count')!=7:raise ValueError('EXACT_SEVEN_BINDING_FAILURE')
    oldrows={str(x['case_id']):x for x in old.get('rows',[]) or []}; diags={str(x['case_id']):x for x in diag.get('cases',[]) or []}; runrows={str(x['case_id']):x for x in run.get('cases',[]) or []}; obsrows={str(x['case_id']):x for x in obs.get('cases',[]) or []}
    if set(oldrows)!=set(ids) or set(diags)!=set(ids) or set(runrows)!=set(ids) or set(obsrows)!=set(ids):raise ValueError('CASE_MAP_MISMATCH')
    results=[]
    for cid in ids:
        src=(Path(a.sources)/(cid+'.py')).read_bytes();srcsha=sha(src);d=Path(a.cases)/cid;cert=readj(d/'certificate.json');adapter=readj(d/'adapter_receipt.json');report=readj(Path(a.reports)/(cid+'.c1_report.json'))
        sig=adapter['execution_signature'];contract=cert['semantic_slice']['source_contract'];tree=ast.parse(src.decode('utf-8'))
        fns=exact(tree,ast.FunctionDef,contract['target_function_span'])+exact(tree,ast.AsyncFunctionDef,contract['target_function_span']);ifs=exact(tree,ast.If,contract['effective_if_span']);guards=exact(tree,ast.Compare,contract['anchors']['guard']['span'])
        if len(fns)!=1 or len(ifs)!=1 or len(guards)!=1:raise ValueError('SURFACE_NOT_UNIQUE:'+cid)
        env,params=env_for(fns[0],ifs[0],sig);g=guards[0];ops=[g.left]+list(g.comparators)
        specs=[x for x in sig.get('required_bindings',[]) or [] if x.get('kind')=='guard_operand'];byidx={int(x['operand_index']):x for x in specs if isinstance(x.get('operand_index'),int)}
        if set(byidx)!={0,1}:raise ValueError('GUARD_BINDING_SET_MISMATCH:'+cid)
        ob={str(x['binding_id']):x for x in obsrows[cid].get('guard_bindings',[]) or []}; sem=(report.get('c1_semantic_result',{}) or {}); rels=sem.get('binding_role_relations',{}) or {}
        bind_checks=[]
        for idx in (0,1):
            spec=byidx[idx];bid=str(spec['binding_id']);allowed=list(map(str,spec.get('allowed_origins',[]) or []));t=trace(ops[idx],env,params);role=str(t['root_role']);slot={'operand_index':idx}; projection={'root_role':role,'terminal_guard_operand_index':idx,'steps':[dict(x) for x in t['steps']]};fp=dj(projection)
            if role not in arows:raise ValueError('ROLE_NOT_CANONICAL:'+cid+':'+role)
            auth=arows[role];auth_payload={'root_role':role,'terminal_guard_operand_index':int(auth['terminal_guard_operand_index']),'steps':[{'kind':str(x['kind']),'token_digest_sha256':str(x['token_digest_sha256'])} for x in auth.get('steps',[]) or []]}
            authority_exact=(projection==auth_payload and fp==auth.get('fingerprint_sha256'))
            provenance='FROZEN_GATE2C5' if projection['steps'] else 'DIRECT_SOURCE_ROLE';exp_receipt=receipt_expected(cid=cid,bid=bid,srcsha=srcsha,slot=slot,t=t,provenance=provenance)
            o=ob.get(bid); receipt_exact=False; raw_lineage=False
            if isinstance(o,Mapping):
                receipts=o.get('binding_authority_receipts',[]) or []
                receipt_exact=(len(receipts)==1 and receipts[0]==exp_receipt)
                exp_lineage=[{'origin':t['raw_origin'],'edges':[{'kind':'BINDS_TO','from':t['raw_origin'],'to':bid,'path_id':'guard-direct'}]}]
                raw_lineage=(o.get('observed_origins')==[t['raw_origin']] and o.get('lineage_paths')==exp_lineage and o.get('slot_identity')==slot and o.get('allowed_origins')==allowed)
            expected_relation='EXACT_BASE_MATCH' if t['raw_origin'] in set(allowed) else ('CERTIFIED_PROJECTION_MATCH' if role in set(allowed) else 'CERTIFIED_NONMATCH')
            sr=rels.get(bid,[]) or []
            semantic_relation_exact=(len(sr)==1 and sr[0].get('raw_origin')==t['raw_origin'] and sr[0].get('relation')==expected_relation and sr[0].get('certified_role')==role)
            bind_checks.append({'binding_id':bid,'operand_index':idx,'raw_origin':t['raw_origin'],'certified_role':role,'allowed_origins':allowed,'projection_fingerprint_sha256':fp,'canonical_projection_exact':authority_exact,'expected_relation':expected_relation,'semantic_relation_exact':semantic_relation_exact,'binding_receipt_exact':receipt_exact,'raw_origin_and_lineage_exact':raw_lineage})
        prod=cert.get('producer_kernel_result',{}) or {};cur_ob=sem.get('obligations',{}) or {};prod_ob=prod.get('obligations',{}) or {}; cur_ad=sem.get('admissions',{}) or {};prod_ad=producer_admissions(prod)
        nonrole=all(cur_ob.get(k)==prod_ob.get(k) for k in A3_NONROLE);a4=all(cur_ob.get(k)==prod_ob.get(k) for k in A4);allobs=(cur_ob==prod_ob);admissions=(cur_ad==prod_ad);witnesses=(sorted(map(str,sem.get('witness_ids',[]) or []))==producer_wids(prod));world=(sem.get('world_relation')==prod.get('world_relation'))
        prior=oldrows[cid];dg=diags[cid];runner=runrows[cid]
        prior_exact=(prior.get('c1_checker_output')=='INVALID_CERTIFICATE' and prior.get('c1_machine_prediction')==INC and prior.get('reasons')==['PRIMARY_C1_PREDICTION_DISAGREEMENT'] and prior.get('expected_raw_origin')==[EXPECTED_ROLE+'.slot:guard'] and prior.get('current_raw_origin')==[CURRENT_ROLE] and prior.get('projection_authority_exact') is True)
        diagnosis_exact=(dg.get('c1_projection_authority_exact') is True and dg.get('producer_a3_p1_required_role_reachability') is True and dg.get('c1_expected_raw_origin')==[EXPECTED_ROLE+'.slot:guard'])
        current_exact=(report.get('checker_output')==VALID and report.get('machine_prediction')==PRES and sem.get('prediction')==PRES and runner.get('c1_checker_output')==VALID and runner.get('c1_machine_prediction')==PRES and cur_ob.get('A3_P1_REQUIRED_ROLE_REACHABILITY') is True)
        case_pass=(srcsha==prior.get('source_sha256')==runner.get('source_sha256') and obsrows[cid].get('source_sha256')==srcsha and obsrows[cid].get('binding_authority_source_sha256')==srcsha and obsrows[cid].get('binding_authority_derivation_errors')==[] and prior_exact and diagnosis_exact and current_exact and all(x['canonical_projection_exact'] and x['semantic_relation_exact'] and x['binding_receipt_exact'] and x['raw_origin_and_lineage_exact'] for x in bind_checks) and nonrole and a4 and allobs and admissions and witnesses and world)
        results.append({'case_id':cid,'source_sha256':srcsha,'gate2c7_checker_output':prior.get('c1_checker_output'),'gate2c7_machine_prediction':prior.get('c1_machine_prediction'),'gate2c8_checker_output':report.get('checker_output'),'gate2c8_machine_prediction':report.get('machine_prediction'),'gate2c8_a3_p1':cur_ob.get('A3_P1_REQUIRED_ROLE_REACHABILITY'),'binding_checks':bind_checks,'a3_nonrole_obligations_identical_to_frozen_producer':nonrole,'a4_obligations_identical_to_frozen_producer':a4,'all_obligations_identical_to_frozen_producer':allobs,'admissions_identical_to_frozen_producer':admissions,'witness_ids_identical_to_frozen_producer':witnesses,'world_relation_identical_to_frozen_producer':world,'prior_gate2c7_observation_exact':prior_exact,'gate2c7_diagnosis_precondition_exact':diagnosis_exact,'pass':case_pass})
    current_valid=sum(1 for x in results if x['gate2c8_checker_output']==VALID); current_pres=sum(1 for x in results if x['gate2c8_machine_prediction']==PRES)
    status='PASS' if (old.get('valid_c1_count')==0 and old.get('c1_preservation_count')==0 and current_valid==7 and current_pres==7 and c7check.get('status')=='PASS' and c7check.get('all_projection_authority_exact') is True and c7check.get('all_raw_origin_evidence_retained') is True and all(x['pass'] for x in results)) else 'FAIL'
    out={'schema':SCHEMA,'status':status,'case_count':7,'gate2c5_authority_digest_sha256':adig,'gate2c7_valid_c1_count':old.get('valid_c1_count'),'gate2c8_valid_c1_count':current_valid,'valid_c1_delta':current_valid-int(old.get('valid_c1_count',0)),'gate2c7_c1_preservation_count':old.get('c1_preservation_count'),'gate2c8_c1_preservation_count':current_pres,'all_seven_valid_c1':current_valid==7,'all_seven_c1_preservation':current_pres==7,'all_binding_receipts_independently_exact':all(all(b['binding_receipt_exact'] for b in x['binding_checks']) for x in results),'all_binding_relations_exact':all(all(b['semantic_relation_exact'] for b in x['binding_checks']) for x in results),'all_raw_origin_and_lineage_exact':all(all(b['raw_origin_and_lineage_exact'] for b in x['binding_checks']) for x in results),'all_a3_nonrole_obligations_invariant':all(x['a3_nonrole_obligations_identical_to_frozen_producer'] for x in results),'all_a4_obligations_invariant':all(x['a4_obligations_identical_to_frozen_producer'] for x in results),'all_world_relations_invariant':all(x['world_relation_identical_to_frozen_producer'] for x in results),'checker_imports_production_c1':False,'candidate_c1_execution_count_observed':7,'epistemic10_read':False,'truth_read':False,'mutation_algebra_opened':False,'cases':results}
    Path(a.output).write_bytes(cb(out));print(json.dumps({'schema':SCHEMA,'status':status,'gate2c7_valid_c1_count':old.get('valid_c1_count'),'gate2c8_valid_c1_count':current_valid,'case_count':7},sort_keys=True,separators=(',',':')));return 0
if __name__=='__main__':raise SystemExit(main())
