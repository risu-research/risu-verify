#!/usr/bin/env python3
from __future__ import annotations
import argparse,ast,hashlib,json
from pathlib import Path
from typing import Any,Mapping
SCHEMA='risu.e2-gate2c7-exact-seven-c1-independent-check/v0.1'; VALID='VALID_C1'; PRES='E2_PREDICTED_PRESERVATION_EVIDENCE'
def cb(v:Any)->bytes:return (json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False)+'\n').encode()
def sha(b:bytes)->str:return hashlib.sha256(b).hexdigest()
def dj(v:Any)->str:return sha(cb(v))
def readj(p:Path)->Any:return json.loads(p.read_bytes())
def sp(n:ast.AST):return (int(n.lineno),int(n.col_offset),int(n.end_lineno),int(n.end_col_offset))
def exact(tree,typ,coords):t=tuple(map(int,coords));return [n for n in ast.walk(tree) if isinstance(n,typ) and hasattr(n,'lineno') and sp(n)==t]
def step(n):
    if isinstance(n,ast.Attribute):return {'kind':'ATTRIBUTE','token_digest_sha256':sha(n.attr.encode())}
    if isinstance(n,ast.Subscript):
        try:k=ast.literal_eval(n.slice)
        except Exception:raise ValueError('DYNAMIC_SUBSCRIPT')
        return {'kind':'SUBSCRIPT_LITERAL','token_digest_sha256':dj(k)}
    raise ValueError('UNSUPPORTED_PROJECTION')
def trace(e,env,params):
    if isinstance(e,ast.Name):
        r=env.get(e.id) or params.get(e.id)
        if r is None:raise ValueError('ROOT_MISSING')
        return {'root_role':str(r['root_role']),'steps':[dict(x) for x in r.get('steps',[])]}
    if isinstance(e,(ast.Attribute,ast.Subscript)):
        r=trace(e.value,env,params);return {'root_role':r['root_role'],'steps':r['steps']+[step(e)]}
    raise ValueError('ROOT_OUTSIDE_FRAGMENT')
def raw_origin(t):
    o=t['root_role']
    for s in t['steps']:
        # This display is evidence only. Semantic admission uses only opaque digests.
        o += '.slot:<opaque>'
    return o
def env_for(fn,target_if,sig):
    ps=list(fn.args.posonlyargs)+list(fn.args.args)+list(fn.args.kwonlyargs); params={};claimed=set()
    for role,s in sorted((sig.get('source_roles',{}) or {}).items()):
        i=s.get('parameter_index')
        if not isinstance(i,int) or i<0 or i>=len(ps) or i in claimed:raise ValueError('ROLE_PARAMETER_INVALID')
        claimed.add(i);params[ps[i].arg]={'root_role':str(role),'steps':[]}
    env={}
    for st in fn.body:
        if st is target_if:break
        if isinstance(st,ast.Expr) and isinstance(st.value,ast.Constant):continue
        if isinstance(st,ast.Assign) and len(st.targets)==1 and isinstance(st.targets[0],ast.Name): name=st.targets[0].id; val=st.value
        elif isinstance(st,ast.AnnAssign) and isinstance(st.target,ast.Name) and st.value is not None:name=st.target.id;val=st.value
        else:raise ValueError('PREFIX_OUTSIDE_FRAGMENT')
        env[name]=trace(val,env,params)
    return env,params
def authority(canon):
    body=dict(canon);claimed=body.pop('authority_digest_sha256',None)
    if claimed!=dj(body):raise ValueError('CANONICAL_AUTHORITY_DIGEST_MISMATCH')
    rows={str(r['root_role']):r for r in canon.get('roles',[])}
    if set(rows)!={'BOUND_VALUE:expected_coordinate','BOUND_VALUE:current_coordinate'}:raise ValueError('CANONICAL_ROLE_SET')
    return rows,claimed
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--gate2c7-protocol',required=True);ap.add_argument('--canonical-authority',required=True);ap.add_argument('--runner',required=True);ap.add_argument('--sources',required=True);ap.add_argument('--cases',required=True);ap.add_argument('--output',required=True);a=ap.parse_args()
    p=readj(Path(a.gate2c7_protocol));r=readj(Path(a.runner));canon=readj(Path(a.canonical_authority));arows,adig=authority(canon);ids=sorted(map(str,p['population']['case_ids']))
    if len(ids)!=7 or r.get('case_ids')!=ids or r.get('case_count')!=7:raise ValueError('EXACT_SEVEN_BINDING_FAILURE')
    rr={str(x['case_id']):x for x in r.get('cases',[])};out=[]
    for cid in ids:
        row=rr[cid];src=(Path(a.sources)/(cid+'.py')).read_bytes();d=Path(a.cases)/cid;cert=readj(d/'certificate.json');adapter=readj(d/'adapter_receipt.json');sig=adapter['execution_signature'];contract=cert['semantic_slice']['source_contract'];tree=ast.parse(src.decode())
        fns=exact(tree,ast.FunctionDef,contract['target_function_span'])+exact(tree,ast.AsyncFunctionDef,contract['target_function_span']);ifs=exact(tree,ast.If,contract['effective_if_span']);guards=exact(tree,ast.Compare,contract['anchors']['guard']['span'])
        if len(fns)!=1 or len(ifs)!=1 or len(guards)!=1:raise ValueError('SURFACE_NOT_UNIQUE:'+cid)
        env,params=env_for(fns[0],ifs[0],sig);g=guards[0];ops=[g.left]+list(g.comparators)
        checks=[]
        for role,idx in [('BOUND_VALUE:expected_coordinate',0),('BOUND_VALUE:current_coordinate',1)]:
            t=trace(ops[idx],env,params);payload={'root_role':t['root_role'],'terminal_guard_operand_index':idx,'steps':t['steps']};fp=dj(payload);auth=arows[role]
            ok=(t['root_role']==role and fp==auth['fingerprint_sha256'] and [x['kind'] for x in t['steps']]==[x['kind'] for x in auth.get('steps',[])])
            checks.append({'role':role,'operand_index':idx,'root_role':t['root_role'],'projection_kind_sequence':[x['kind'] for x in t['steps']],'fingerprint_sha256':fp,'canonical_fingerprint_sha256':auth['fingerprint_sha256'],'exact_authority_match':ok,'raw_origin_shape':raw_origin(t)})
        prod_raw=row.get('raw_guard_origins',{}) or {}
        raw_retained=(prod_raw.get('BOUND_VALUE:expected_coordinate')==['BOUND_VALUE:expected_coordinate.slot:guard'] and prod_raw.get('BOUND_VALUE:current_coordinate')==['BOUND_VALUE:current_coordinate'])
        out.append({'case_id':cid,'source_sha256':sha(src),'c1_checker_output':row.get('c1_checker_output'),'c1_machine_prediction':row.get('c1_machine_prediction'),'all_projection_authority_exact':all(x['exact_authority_match'] for x in checks),'raw_origin_evidence_retained':raw_retained,'independent_projection_checks':checks})
    passed=all(x['c1_checker_output']==VALID and x['c1_machine_prediction']==PRES and x['all_projection_authority_exact'] and x['raw_origin_evidence_retained'] for x in out)
    res={'schema':SCHEMA,'status':'PASS' if passed else 'FAIL','case_count':7,'gate2c5_authority_digest_sha256':adig,'all_seven_valid_c1':all(x['c1_checker_output']==VALID for x in out),'all_seven_c1_preservation':all(x['c1_machine_prediction']==PRES for x in out),'all_projection_authority_exact':all(x['all_projection_authority_exact'] for x in out),'all_raw_origin_evidence_retained':all(x['raw_origin_evidence_retained'] for x in out),'checker_imports_production_c1':False,'epistemic10_read':False,'truth_read':False,'cases':out}
    Path(a.output).write_bytes(cb(res));print(json.dumps({'schema':SCHEMA,'status':res['status'],'case_count':7},sort_keys=True,separators=(',',':')));return 0
if __name__=='__main__':raise SystemExit(main())
