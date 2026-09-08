#!/usr/bin/env python3
from __future__ import annotations
import argparse,json,hashlib
from pathlib import Path
P='DEFINITIVE_PRESERVATION';R='DEFINITIVE_REGRESSION';I='INCOMPLETE';X='EVALUATION_INVALID'
TP='TRUTH_PRESERVATION';TR='TRUTH_REGRESSION';TI='TRUTH_EPISTEMICALLY_INSUFFICIENT'
BS=['B0_STRUCTURAL_SCHEMA_DIFF','B1_AST_SYNTACTIC_DATAFLOW','B2_STRONG_STATIC_DATAFLOW','B3A_GPT56_SOL_FRONTIER','B3B_CLAUDE_OPUS45_DATED','B4_EXECUTION_ONLY_DIFFERENTIAL']
AB=['A1_PRIMARY_ONLY_NO_C1_PROMOTION_GATE','A2_C1_WITHOUT_AUTHORITY_SIDECARS','A3_C1_WITHOUT_CROSS_REPRESENTATION_EVIDENCE']
Z=('early_truth_read_count','heldout_replacement_count','heldout_drop_count','duplicate_unit_count','raw_source_log_exposure_count','full_system_dual_replay_mismatch_count','evaluator_dual_replay_mismatch_count','semantic_snapshot_identity_mismatch_count','post_freeze_metric_definition_change_count','post_freeze_support_boundary_change_count')
IDS=['T01_UNSAFE_FALSE_STABILITY_DETECTED','T02_FALSE_REGRESSION_IS_UTILITY_NOT_PRIMARY_SAFETY','T03_UNSUPPORTED_DEFINITIVE_DETECTED','T04_UNRESOLVED_AUTHORITY_DEFINITIVE_DETECTED','T05_CHECKER_DISAGREEMENT_DEFINITIVE_DETECTED','T06_INVALID_C1_DEFINITIVE_DETECTED','T07_EPISTEMIC_TRUTH_DEFINITIVE_OVERCLAIM_DETECTED','T08_INFO_REMOVAL_INCOMPLETE_TO_DEFINITIVE_DETECTED','T09_INFO_REMOVAL_INCOMPLETE_TO_INCOMPLETE','T10_INFO_REMOVAL_DEFINITIVE_TO_INCOMPLETE','T11_ALL_INCOMPLETE','T12_NONTRIVIAL_SELECTIVE_PASS','T13_MISSING_HELDOUT_UNIT','T14_DUPLICATE_HELDOUT_UNIT','T15_REPLACEMENT_HELDOUT_UNIT','T16_EARLY_TRUTH_READ','T17_FULL_SYSTEM_DUAL_REPLAY_MISMATCH','T18_EVALUATOR_DUAL_REPLAY_MISMATCH','T19_BASELINE_INAPPLICABLE_DENOMINATOR','T20_ZERO_DENOMINATOR_METRIC','T21_PRIMARY_BASELINE_DENOMINATORS_SEPARATE','T22_ABLATION_CANNOT_MUTATE_PRIMARY','T23_PRE_INPUT_FAILURE_NOT_CONSUMED','T24_SEMANTIC_EXECUTION_FAILURE_CONSUMED','T25_POST_REPAIR_SAME_HELDOUT_LABEL','T26_RAW_SOURCE_LOG_EXPOSURE','T27_UNSUPPORTED_SCOPE','T28_IN_SCOPE_INFRA_CRASH','T29_CANONICAL_METRIC_OUTPUT_DUAL_REPLAY','T30_FORBIDDEN_POPULATION_CLAIM_FLAG']
def cb(v):return (json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False)+'\n').encode()
def unit(i,t=TI,o=I,s=True,a='RESOLVED',c=True,c1='VALID_C1',al='C1_INDEPENDENT_SOURCE_EVIDENCE'):
 return {'unit_id':f'U{i:02d}','truth':{'admissible':True,'outcome':t},'support_eligible':s,'system':{'outcome':o,'authority_status':a,'checker_agreement':c,'c1_checker_output':c1,'assurance_level':al,'provenance_complete':True}}
def base():
 return {'schema':'risu.e2-gate2d-evaluation-input/v0.1','units':[unit(i) for i in range(1,11)],'integrity':{k:0 for k in Z},'information_removal_edges':[],'baselines':{b:{'unit_outputs':{}} for b in BS},'ablations':{a:{'unit_outputs':{}} for a in AB},'claim_flags':{}}
def setu(d,n,**kw):
 u=d['units'][n-1]
 if 't'in kw:u['truth']['outcome']=kw.pop('t')
 if 'o'in kw:u['system']['outcome']=kw.pop('o')
 if 's'in kw:u['support_eligible']=kw.pop('s')
 if 'a'in kw:u['system']['authority_status']=kw.pop('a')
 if 'c'in kw:u['system']['checker_agreement']=kw.pop('c')
 if 'c1'in kw:u['system']['c1_checker_output']=kw.pop('c1')
 if 'al'in kw:u['system']['assurance_level']=kw.pop('al')
 if kw:raise ValueError(kw)
def cases():
 x={}
 d=base();setu(d,1,t=TR,o=P);x[IDS[0]]=d
 d=base();setu(d,1,t=TP,o=R);x[IDS[1]]=d
 d=base();setu(d,1,t=TP,o=P,s=False);x[IDS[2]]=d
 d=base();setu(d,1,t=TP,o=P,a='UNRESOLVED');x[IDS[3]]=d
 d=base();setu(d,1,t=TP,o=P,c=False);x[IDS[4]]=d
 d=base();setu(d,1,t=TP,o=P,c1='INVALID_CERTIFICATE');x[IDS[5]]=d
 d=base();setu(d,1,t=TI,o=P);x[IDS[6]]=d
 d=base();setu(d,1,t=TP,o=I);setu(d,2,t=TP,o=P);d['information_removal_edges']=[{'parent_unit_id':'U01','child_unit_id':'U02'}];x[IDS[7]]=d
 d=base();setu(d,1,t=TP,o=I);setu(d,2,t=TP,o=I);d['information_removal_edges']=[{'parent_unit_id':'U01','child_unit_id':'U02'}];x[IDS[8]]=d
 d=base();setu(d,1,t=TP,o=P);setu(d,2,t=TP,o=I);d['information_removal_edges']=[{'parent_unit_id':'U01','child_unit_id':'U02'}];x[IDS[9]]=d
 d=base();setu(d,1,t=TP,o=I);setu(d,2,t=TR,o=I);x[IDS[10]]=d
 d=base();setu(d,1,t=TP,o=P);setu(d,2,t=TR,o=R);x[IDS[11]]=d
 d=base();d['units']=d['units'][:-1];x[IDS[12]]=d
 d=base();d['units'][9]['unit_id']='U09';x[IDS[13]]=d
 d=base();d['integrity']['heldout_replacement_count']=1;x[IDS[14]]=d
 d=base();d['integrity']['early_truth_read_count']=1;x[IDS[15]]=d
 d=base();d['integrity']['full_system_dual_replay_mismatch_count']=1;x[IDS[16]]=d
 d=base();d['integrity']['evaluator_dual_replay_mismatch_count']=1;x[IDS[17]]=d
 d=base();setu(d,1,t=TP,o=P);d['baselines'][BS[0]]['unit_outputs']={'U01':P,'U02':'INAPPLICABLE'};x[IDS[18]]=d
 d=base();d['baselines'][BS[0]]['unit_outputs']={};x[IDS[19]]=d
 d=base();setu(d,1,t=TP,o=P);d['baselines'][BS[0]]['unit_outputs']={'U01':P,'U02':I,'U03':I};x[IDS[20]]=d
 d=base();setu(d,1,t=TP,o=P);x[IDS[21]]=d
 x[IDS[22]]={'source_bytes_read':False,'truth_read':False,'full_system_semantic_execution_count':0,'baseline_execution_count':0,'ablation_execution_count':0,'machine_prediction_count':0}
 x[IDS[23]]={'source_bytes_read':True,'truth_read':False,'full_system_semantic_execution_count':1,'baseline_execution_count':0,'ablation_execution_count':0,'machine_prediction_count':0}
 x[IDS[24]]={'post_repair_same_heldout':True,'full_system_semantic_execution_count':1}
 d=base();d['integrity']['raw_source_log_exposure_count']=1;x[IDS[25]]=d
 d=base();setu(d,1,t=TI,o=I,s=False);x[IDS[26]]=d
 d=base();setu(d,1,t=TP,o=X);x[IDS[27]]=d
 d=base();setu(d,1,t=TP,o=P);setu(d,2,t=TR,o=R);x[IDS[28]]=d
 d=base();d['claim_flags']['forbidden_population_claim']=True;x[IDS[29]]=d
 return x
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--constitution',required=True);ap.add_argument('--protocol',required=True);ap.add_argument('--out',required=True);a=ap.parse_args()
 con=json.loads(Path(a.constitution).read_bytes());pro=json.loads(Path(a.protocol).read_bytes())
 d0=[(z['id'],z['expected']) for z in con['preregistered_gate2d_synthetic_evaluator_matrix']]
 d2=[(z['id'],z['expected']) for z in pro['matrix_source_rule']['exact_id_expected_pairs']]
 if d0!=d2 or [i for i,_ in d0]!=IDS:raise SystemExit('MATRIX_AUTHORITY_MISMATCH')
 out=Path(a.out);(out/'cases').mkdir(parents=True,exist_ok=True);cs=cases()
 if list(cs)!=IDS:raise SystemExit('GENERATOR_ID_ORDER_MISMATCH')
 man=[]
 for i in IDS:
  p=out/'cases'/(i+'.json');b=cb(cs[i]);p.write_bytes(b);man.append({'id':i,'sha256':hashlib.sha256(b).hexdigest(),'size':len(b)})
 (out/'matrix_manifest.json').write_bytes(cb({'schema':'risu.e2-gate2d-d2-synthetic-matrix/v0.1','case_count':30,'cases':man,'d0_d2_matrix_exact':True}))
if __name__=='__main__':main()
