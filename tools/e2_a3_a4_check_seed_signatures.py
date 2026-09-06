#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json
from collections import defaultdict, deque
from pathlib import Path

OVERLAY_SHA="2d231b9eae523d7fb84925c302398c4913670b765cb10e2c4f76dc988cc5ea36"
PREREG="1efc11b4f5b3a3e51cc1168c076be67213f335e0"
ANCHOR_SHA="e88b1c91bc2006b262351f6ac6dff6733078589024cc20645795c1f352b69d8c"

def cb(v): return (json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=False)+"\n").encode()
def sh(b): return hashlib.sha256(b).hexdigest()
def fsha(p): return sh(p.read_bytes())
def inside(a,b):
 A=a['span'];B=b['span']; return A['path']==B['path'] and (A['start_line'],A['start_col'])<=(B['start_line'],B['start_col']) and (B['end_line'],B['end_col'])<=(A['end_line'],A['end_col'])
def adj(o,k):
 d=defaultdict(list)
 for e in o['edges']:
  if e['kind']==k:d[e['source']].append(e)
 return d
def reach(A,s):
 z={s};q=deque([s])
 while q:
  u=q.popleft()
  for e in A.get(u,[]):
   v=e['target']
   if v not in z:z.add(v);q.append(v)
 return z
def anchor(o,r):
 x=[n for n in o['nodes'] if n.get('attrs',{}).get('anchor_role')==r]
 if len(x)!=1: raise AssertionError((r,len(x)))
 return x[0]
def expected_for(item):
 o=item['overlay']; G=adj(o,'GUARDS');P=adj(o,'PRECEDES');D=adj(o,'DERIVES');C=adj(o,'COMPARES')
 g=anchor(o,'GUARD_COMPARISON');ef=anchor(o,'EFFECT_BOUNDARY');su=anchor(o,'SUCCESS_OUTCOME');re=anchor(o,'REJECTION_NO_EFFECT_OUTCOME')
 dg=G.get(g['id'],[]); chain=[]
 if len(dg)==2 and {e.get('attrs',{}).get('branch_polarity') for e in dg}=={False,True}:
  form='DIRECT_CONTROL'; eg=g; h=[]
 else:
  for a in D.get(g['id'],[]):
   if a.get('attrs',{}).get('derivation')!='comparison_result_to_return':continue
   for b in D.get(a['target'],[]):
    if b.get('attrs',{}).get('derivation')!='function_return_to_call_result':continue
    for c in C.get(b['target'],[]):
     if 'CONTROL_PREDICATE_RESULT' not in c.get('attrs',{}).get('operators',[]):continue
     if {e.get('attrs',{}).get('branch_polarity') for e in G.get(c['target'],[])}=={False,True}:chain.append(c['target'])
  if len(chain)!=1:raise AssertionError(('helper_chain',len(chain)))
  form='HELPER_CONTROL';eg=next(n for n in o['nodes'] if n['id']==chain[0]);h=['GUARD_COMPARISON_RESULT','RETURN_BOUNDARY','CALL_RESULT','CONSUMER_GUARD']
 br={e['attrs']['branch_polarity']:e['target'] for e in G[eg['id']]}; R={p:reach(P,v) for p,v in br.items()}
 ep=[p for p,z in R.items() if ef['id'] in z];rp=[p for p,z in R.items() if re['id'] in z]
 if len(ep)!=1 or len(rp)!=1 or ep[0]==rp[0]:raise AssertionError('polarity')
 if su['id'] not in reach(P,ef['id']):raise AssertionError('effect-success')
 ops=[n for n in o['nodes'] if n['kind']=='OPERATION' and inside(ef,n) and n.get('attrs',{}).get('operation_role') in {'call','representation_instance'}]
 if len(ops)!=1:raise AssertionError(('effectop',len(ops)))
 op=ops[0]; carr=[]
 for e in o['edges']:
  if e['target']==op['id'] and e['kind']=='CARRIES':carr.append({k:v for k,v in e.get('attrs',{}).items() if k in {'argument_index','field','receiver_role','resource_role','carrier_boundary'}})
 carr=sorted(carr,key=lambda z:json.dumps(z,sort_keys=True));bs=o['binding_slots'];roles=sorted(bs);lr=[]
 for r in roles:
  if len(bs[r].get('value_instance_ids',[]))!=1:raise AssertionError('slot cardinality')
  lr.append({'relation':'REACHES','source_role':f'BOUND_VALUE:{r}','terminal_role':f'GUARD_SLOT:{r}','slot':{'anchor':bs[r]['anchor'],'operand_index':bs[r]['operand_index']}})
 for i,a in enumerate(roles):
  for b in roles[i+1:]:
   va=bs[a]['value_instance_ids'][0];vb=bs[b]['value_instance_ids'][0]
   lr.append({'relation':'SAME_ORIGIN' if va==vb else 'DISTINCT_ORIGIN','role_a':f'GUARD_SLOT:{a}','role_b':f'GUARD_SLOT:{b}'})
 core={'seed_id':item['seed_id'],'source_sha256':o['files'][0]['sha256'],'anchor_contract_sha256':item['contract_canonical_sha256'],'guard_anchor_role':'GUARD_COMPARISON','effective_guard_form':form,'helper_passthrough_shape':h,'effect_polarity':ep[0],'rejection_polarity':rp[0],'required_binding_slot_roles':{k:{'anchor':v['anchor'],'operand_index':v['operand_index'],'cardinality':len(v.get('value_instance_ids',[]))} for k,v in sorted(bs.items())},'required_lineage_obligations':lr,'effect_invocation_binding_surface':{'resolution':'UNIQUE_STRUCTURAL_OPERATION_WITHIN_EFFECT_ANCHOR','operation_role':op.get('attrs',{}).get('operation_role'),'coordinate_carrier_slots':carr,'noncoordinate_representation_fields_not_promoted_to_a3_roles':op.get('attrs',{}).get('operation_role')=='representation_instance'},'opaque_lineage_equivalence':{'role_universe':[f'GUARD_SLOT:{k}' for k in roles],'relations':[r for r in lr if r['relation'] in {'SAME_ORIGIN','DISTINCT_ORIGIN'}]},'ordering_obligations':['EFFECT_BOUNDARY PRECEDES SUCCESS_OUTCOME','EFFECTIVE_GUARD PRECEDES EFFECT_BOUNDARY on effect polarity'],'terminal_obligations':['rejection polarity reaches REJECTION_NO_EFFECT_OUTCOME without prior EFFECT_BOUNDARY','effect polarity reaches EFFECT_BOUNDARY then SUCCESS_OUTCOME'],'control_scope_status':'COMPLETE','semantic_authority':False}
 core['canonical_signature_digest_sha256']=sh(cb(core)); return core

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--overlay-bundle',type=Path,required=True);ap.add_argument('--anchor-bundle',type=Path,required=True);ap.add_argument('--signatures',type=Path,required=True);ap.add_argument('--receipt',type=Path,required=True);a=ap.parse_args();errs=[]
 if fsha(a.anchor_bundle)!=ANCHOR_SHA:errs.append('ANCHOR_FILE_SHA')
 A=json.loads(a.anchor_bundle.read_text());am={r['seed_id']:r for r in A.get('contracts',[])}
 if len(am)!=6:errs.append('ANCHOR_SEED_COUNT')
 if fsha(a.overlay_bundle)!=OVERLAY_SHA:errs.append('OVERLAY_FILE_SHA')
 O=json.loads(a.overlay_bundle.read_text());S=json.loads(a.signatures.read_text())
 if S.get('preregistration_commit')!=PREREG:errs.append('PREREG_BINDING')
 if S.get('seed_count')!=6 or O.get('seed_count')!=6:errs.append('SEED_COUNT')
 for i in O['overlays']:
  ar=am.get(i['seed_id']);o=i['overlay']
  if not ar or ar.get('contract_canonical_sha256')!=i.get('contract_canonical_sha256'):errs.append('ANCHOR_CONTRACT_BINDING:'+i['seed_id']);continue
  if ar['declaration']['source']['sha256']!=o['files'][0]['sha256']:errs.append('ANCHOR_SOURCE_BINDING:'+i['seed_id'])
  for role,spec in ar['declaration']['binding_slots'].items():
   got=o['binding_slots'].get(role,{})
   if (got.get('anchor'),got.get('operand_index'))!=(spec.get('anchor'),spec.get('operand_index')):errs.append('ANCHOR_SLOT_BINDING:'+i['seed_id']+':'+role)
 exp=[expected_for(x) for x in sorted(O['overlays'],key=lambda z:z['seed_id'])]
 if S.get('signatures')!=exp:errs.append('INDEPENDENT_REDERIVATION_MISMATCH')
 core=dict(S);claimed=core.pop('bundle_digest_sha256',None)
 if claimed!=sh(cb(core)):errs.append('BUNDLE_INTERNAL_DIGEST')
 for s in S.get('signatures',[]):
  cc=dict(s);d=cc.pop('canonical_signature_digest_sha256',None)
  if d!=sh(cb(cc)):errs.append('PER_SEED_DIGEST:'+s.get('seed_id','?'))
 fw=S.get('firewall',{})
 if any(fw.get(k) is not False for k in ['candidate_or_mutant_bytes_read','mutation_truth_read','operator_metadata_read','fresh_target_bytes_read','identifier_spelling_used_as_semantic_role_authority','callee_spelling_used_as_effect_semantic_authority']):errs.append('FIREWALL')
 rec={'schema':'risu.e2-a3-a4-canonical-signature-independent-check/v0.1','status':'PASS' if not errs else 'FAIL','errors':errs,'seed_count':len(exp),'signatures_file_sha256':fsha(a.signatures),'independent_rederived_signature_digests':[{'seed_id':s['seed_id'],'sha256':s['canonical_signature_digest_sha256']} for s in exp],'firewall':{'candidate_or_mutant_bytes_read':False,'mutation_truth_read':False,'operator_metadata_read':False,'fresh_target_bytes_read':False,'primary_derivation_module_imported':False}}
 a.receipt.write_bytes(cb(rec));print(json.dumps(rec,sort_keys=True,separators=(',',':')));raise SystemExit(0 if not errs else 1)
if __name__=='__main__':main()
