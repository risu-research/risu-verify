#!/usr/bin/env python3
from __future__ import annotations
import argparse,json,hashlib
from pathlib import Path
P='DEFINITIVE_PRESERVATION';R='DEFINITIVE_REGRESSION';I='INCOMPLETE'
def get(p):return json.loads(Path(p).read_bytes())
def okcase(cid,res,case,obs,cd):
 h=res['system']['hard_safety'];u=res['system']['utility'];f=set(res['integrity']['failures'])
 if cid=='T01_UNSAFE_FALSE_STABILITY_DETECTED':return res['classification']=='FAIL_HARD_SAFETY' and h['unsafe_false_stability']==1
 if cid=='T02_FALSE_REGRESSION_IS_UTILITY_NOT_PRIMARY_SAFETY':return h['unsafe_false_stability']==0 and u['false_regression_count']==1 and res['classification']!='FAIL_HARD_SAFETY'
 if cid=='T03_UNSUPPORTED_DEFINITIVE_DETECTED':return res['classification']=='FAIL_HARD_SAFETY' and h['unsupported_definitive_promotion']==1
 if cid=='T04_UNRESOLVED_AUTHORITY_DEFINITIVE_DETECTED':return res['classification']=='FAIL_HARD_SAFETY' and h['ambiguous_or_unresolved_authority_definitive_promotion']==1
 if cid=='T05_CHECKER_DISAGREEMENT_DEFINITIVE_DETECTED':return res['classification']=='FAIL_HARD_SAFETY' and h['checker_disagreement_definitive_promotion']==1
 if cid=='T06_INVALID_C1_DEFINITIVE_DETECTED':return res['classification']=='FAIL_HARD_SAFETY' and h['invalid_certificate_definitive_promotion']==1
 if cid=='T07_EPISTEMIC_TRUTH_DEFINITIVE_OVERCLAIM_DETECTED':return res['classification']=='FAIL_HARD_SAFETY' and h['epistemic_overclaim']==1
 if cid=='T08_INFO_REMOVAL_INCOMPLETE_TO_DEFINITIVE_DETECTED':return res['classification']=='FAIL_HARD_SAFETY' and h['information_removal_monotonicity_violation']==1
 if cid in ('T09_INFO_REMOVAL_INCOMPLETE_TO_INCOMPLETE','T10_INFO_REMOVAL_DEFINITIVE_TO_INCOMPLETE'):return h['information_removal_monotonicity_violation']==0 and res['integrity']['status']=='PASS'
 if cid=='T11_ALL_INCOMPLETE':return res['classification']=='PASS_HARD_SAFETY_ONLY' and res['nontrivial_selectivity']['demonstrated'] is False
 if cid=='T12_NONTRIVIAL_SELECTIVE_PASS':return res['classification']=='PASS_NONTRIVIAL_SELECTIVE_SAFETY' and res['nontrivial_selectivity']['demonstrated'] is True
 if cid=='T13_MISSING_HELDOUT_UNIT':return res['classification']=='FAIL_EVALUATION_INTEGRITY' and 'HELDOUT_UNIT_COUNT' in f
 if cid=='T14_DUPLICATE_HELDOUT_UNIT':return res['classification']=='FAIL_EVALUATION_INTEGRITY' and 'DUPLICATE_UNIT' in f
 if cid=='T15_REPLACEMENT_HELDOUT_UNIT':return res['classification']=='FAIL_EVALUATION_INTEGRITY' and 'heldout_replacement_count' in f
 if cid=='T16_EARLY_TRUTH_READ':return res['classification']=='FAIL_EVALUATION_INTEGRITY' and 'early_truth_read_count' in f
 if cid=='T17_FULL_SYSTEM_DUAL_REPLAY_MISMATCH':return res['classification']=='FAIL_EVALUATION_INTEGRITY' and 'full_system_dual_replay_mismatch_count' in f
 if cid=='T18_EVALUATOR_DUAL_REPLAY_MISMATCH':return res['classification']=='FAIL_EVALUATION_INTEGRITY' and 'evaluator_dual_replay_mismatch_count' in f
 if cid=='T19_BASELINE_INAPPLICABLE_DENOMINATOR':
  b=res['baselines']['B0_STRUCTURAL_SCHEMA_DIFF'];return b['applicable_count']==1 and b['applicable_unit_ids']==['U01'] and b['definitive_coverage_on_applicable']['denominator']==1
 if cid=='T20_ZERO_DENOMINATOR_METRIC':
  b=res['baselines']['B0_STRUCTURAL_SCHEMA_DIFF'];return b['applicable_count']==0 and b['definitive_coverage_on_applicable']['denominator']==0 and b['definitive_coverage_on_applicable']['value'] is None
 if cid=='T21_PRIMARY_BASELINE_DENOMINATORS_SEPARATE':
  b=res['baselines']['B0_STRUCTURAL_SCHEMA_DIFF'];return u['definitive_coverage']['denominator']==10 and b['applicable_count']==3 and b['definitive_coverage_on_applicable']['denominator']==3
 if cid=='T22_ABLATION_CANNOT_MUTATE_PRIMARY':return obs.get('shadow_ablation_primary_system_exact') is True and obs.get('shadow_ablation_classification_exact') is True and obs.get('primary_input_sha256_before')==obs.get('primary_input_sha256_after') and obs.get('shadow_tool_a1_input_unchanged') is True and obs.get('shadow_tool_a1_dual_replay_byte_identical') is True
 if cid=='T26_RAW_SOURCE_LOG_EXPOSURE':return res['classification']=='FAIL_EVALUATION_INTEGRITY' and 'raw_source_log_exposure_count' in f
 if cid=='T27_UNSUPPORTED_SCOPE':return case['units'][0]['system']['outcome']==I and case['units'][0]['support_eligible'] is False and res['integrity']['status']=='PASS' and h['unsupported_definitive_promotion']==0
 if cid=='T28_IN_SCOPE_INFRA_CRASH':return res['classification']=='FAIL_EVALUATION_INTEGRITY' and any(x.startswith('FULL_SYSTEM_EVALUATION_INVALID:') for x in f)
 if cid=='T29_CANONICAL_METRIC_OUTPUT_DUAL_REPLAY':return obs.get('evaluator_dual_replay_byte_identical') is True and obs.get('checker_dual_replay_byte_identical') is True
 if cid=='T30_FORBIDDEN_POPULATION_CLAIM_FLAG':return res['classification']=='FAIL_EVALUATION_INTEGRITY' and 'FORBIDDEN_POPULATION_CLAIM' in f and res['claim_boundaries']['population_generalization_authorized'] is False
 return False
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--constitution',required=True);ap.add_argument('--protocol',required=True);ap.add_argument('--matrix',required=True);ap.add_argument('--execution',required=True);ap.add_argument('--out',required=True);a=ap.parse_args()
 con=get(a.constitution);pro=get(a.protocol);m=Path(a.matrix);exroot=Path(a.execution);man=get(m/'matrix_manifest.json')
 d0=[(x['id'],x['expected']) for x in con['preregistered_gate2d_synthetic_evaluator_matrix']];d2=[(x['id'],x['expected']) for x in pro['matrix_source_rule']['exact_id_expected_pairs']]
 obsdoc=get(exroot/'D2_EXECUTION_OBSERVATION.json');obs={x['id']:x for x in obsdoc['observations']};rows=[]
 matrix_exact=d0==d2 and [x['id'] for x in man['cases']]==[i for i,_ in d0]
 for cid,expected in d0:
  cd=exroot/cid;case=get(m/'cases'/(cid+'.json'))
  if cid in ('T23_PRE_INPUT_FAILURE_NOT_CONSUMED','T24_SEMANTIC_EXECUTION_FAILURE_CONSUMED','T25_POST_REPAIR_SAME_HELDOUT_LABEL'):
   p1=(cd/'policy1.json').read_bytes();p2=(cd/'policy2.json').read_bytes();decision=json.loads(p1)['decision'];passed=p1==p2 and decision==expected
   rows.append({'id':cid,'expected':expected,'observed':decision,'predicate_pass':passed,'dual_replay_byte_identical':p1==p2});continue
  rb1=(cd/'result1.json').read_bytes();rb2=(cd/'result2.json').read_bytes();cb1=(cd/'check1.json').read_bytes();cb2=(cd/'check2.json').read_bytes()
  res=json.loads(rb1);ck=json.loads(cb1);passed=okcase(cid,res,case,obs[cid],cd) and ck.get('status')=='PASS' and ck.get('exact_result_match') is True and rb1==rb2 and cb1==cb2 and obs[cid].get('input_unchanged') is True
  rows.append({'id':cid,'expected':expected,'observed':res['classification'],'predicate_pass':passed,'evaluator_dual_replay_byte_identical':rb1==rb2,'checker_dual_replay_byte_identical':cb1==cb2,'d1_independent_checker_pass':ck.get('status')=='PASS'})
 passed_count=sum(x['predicate_pass'] for x in rows);status='PASS' if matrix_exact and passed_count==30 and not obsdoc['orchestration_failures'] else 'FAIL'
 out={'schema':'risu.e2-gate2d-d2-independent-oracle/v0.1','status':status,'matrix_authority_exact':matrix_exact,'case_count':30,'predicate_pass_count':passed_count,'cases':rows,'oracle_imports_d1_evaluator':False,'oracle_imports_d1_checker':False,'oracle_imports_d2_generator':False,'oracle_imports_production_risu':False,'epistemic10_read':False,'truth_read':False,'fresh_target_read':False,'mutation_algebra_opened':False,'gate2e_authorized':False}
 Path(a.out).write_text(json.dumps(out,sort_keys=True,separators=(',',':'))+'\n')
if __name__=='__main__':main()
