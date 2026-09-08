#!/usr/bin/env python3
from __future__ import annotations
import argparse,json,hashlib,subprocess,sys,copy
from pathlib import Path
POL={'T23_PRE_INPUT_FAILURE_NOT_CONSUMED','T24_SEMANTIC_EXECUTION_FAILURE_CONSUMED','T25_POST_REPAIR_SAME_HELDOUT_LABEL'}
def cb(v):return (json.dumps(v,sort_keys=True,separators=(',',':'))+'\n').encode()
def run(cmd):
 p=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 if p.returncode:return {'ok':False,'returncode':p.returncode,'stdout':p.stdout.decode(errors='replace'),'stderr':p.stderr.decode(errors='replace')}
 return {'ok':True,'stdout':p.stdout.decode(errors='replace'),'stderr':p.stderr.decode(errors='replace')}
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--root',default='.');ap.add_argument('--matrix',required=True);ap.add_argument('--out',required=True);a=ap.parse_args()
 r=Path(a.root);m=Path(a.matrix);out=Path(a.out);out.mkdir(parents=True,exist_ok=True)
 ids=[x['id'] for x in json.loads((m/'matrix_manifest.json').read_bytes())['cases']];obs=[];orchestration=[]
 for cid in ids:
  src=m/'cases'/(cid+'.json');b0=src.read_bytes();cd=out/cid;cd.mkdir(exist_ok=True)
  if cid in POL:
   outs=[]
   for n in (1,2):
    op=cd/f'policy{n}.json';z=run([sys.executable,str(r/'tools/e2_gate2d_consumption_policy.py'),'--input',str(src),'--output',str(op)])
    if not z['ok']:orchestration.append({'id':cid,'stage':'policy','detail':z});break
    outs.append(op.read_bytes())
   obs.append({'id':cid,'kind':'consumption','dual_replay_byte_identical':len(outs)==2 and outs[0]==outs[1],'input_unchanged':src.read_bytes()==b0})
   continue
  res=[];cks=[]
  for n in (1,2):
   rp=cd/f'result{n}.json';z=run([sys.executable,str(r/'tools/e2_gate2d_evaluate_v3.py'),'--input',str(src),'--output',str(rp)])
   if not z['ok']:orchestration.append({'id':cid,'stage':'evaluator','detail':z});break
   cp=cd/f'check{n}.json';z=run([sys.executable,str(r/'tools/e2_gate2d_check_evaluation_v3.py'),'--input',str(src),'--result',str(rp),'--output',str(cp)])
   if not z['ok']:orchestration.append({'id':cid,'stage':'d1_checker','detail':z});break
   res.append(rp.read_bytes());cks.append(cp.read_bytes())
  rec={'id':cid,'kind':'evaluation','evaluator_dual_replay_byte_identical':len(res)==2 and res[0]==res[1],'checker_dual_replay_byte_identical':len(cks)==2 and cks[0]==cks[1],'d1_independent_checker_pass':len(cks)==2 and all(json.loads(x)['status']=='PASS' for x in cks),'input_unchanged':src.read_bytes()==b0}
  if cid=='T22_ABLATION_CANNOT_MUTATE_PRIMARY' and len(res)==2:
   d=json.loads(b0);v=copy.deepcopy(d)
   for aid in v['ablations']:
    v['ablations'][aid]['unit_outputs']={u['unit_id']:('DEFINITIVE_REGRESSION' if j%2 else 'DEFINITIVE_PRESERVATION') for j,u in enumerate(v['units'])}
   vp=cd/'isolation_variant.json';vp.write_bytes(cb(v));vr=cd/'isolation_result.json'
   z=run([sys.executable,str(r/'tools/e2_gate2d_evaluate_v3.py'),'--input',str(vp),'--output',str(vr)])
   if not z['ok']:orchestration.append({'id':cid,'stage':'isolation','detail':z})
   else:
    a0=json.loads(res[0]);a1=json.loads(vr.read_bytes())
    rec['shadow_ablation_primary_system_exact']=a0['system']==a1['system']
    rec['shadow_ablation_classification_exact']=a0['classification']==a1['classification']
    rec['primary_input_sha256_before']=hashlib.sha256(b0).hexdigest()
    rec['primary_input_sha256_after']=hashlib.sha256(src.read_bytes()).hexdigest()
    sp=cd/'shadow_tool_input.json';sp.write_bytes(cb({'tentative_kernel_prediction':'E2_PREDICTED_PRESERVATION_EVIDENCE'}));sb=sp.read_bytes();so=[]
    for n in (1,2):
     op=cd/f'shadow_tool_output{n}.json';z=run([sys.executable,str(r/'tools/e2_gate2d_ablation_shadow_v2.py'),'--ablation','A1_PRIMARY_ONLY_NO_C1_PROMOTION_GATE','--input',str(sp),'--output',str(op)])
     if not z['ok']:orchestration.append({'id':cid,'stage':'shadow_tool','detail':z});break
     so.append(op.read_bytes())
    rec['shadow_tool_a1_input_unchanged']=sp.read_bytes()==sb
    rec['shadow_tool_a1_dual_replay_byte_identical']=len(so)==2 and so[0]==so[1]
  obs.append(rec)
 report={'schema':'risu.e2-gate2d-d2-execution-observation/v0.1','case_count':len(ids),'observations':obs,'orchestration_failures':orchestration,'epistemic10_read':False,'truth_read':False,'fresh_target_read':False,'mutation_algebra_opened':False}
 (out/'D2_EXECUTION_OBSERVATION.json').write_bytes(cb(report))
if __name__=='__main__':main()
