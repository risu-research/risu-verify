#!/usr/bin/env python3
from __future__ import annotations
import argparse,json
from pathlib import Path
P='DEFINITIVE_PRESERVATION';R='DEFINITIVE_REGRESSION';I='INCOMPLETE';X='EVALUATION_INVALID'
TP='TRUTH_PRESERVATION';TR='TRUTH_REGRESSION';TI='TRUTH_EPISTEMICALLY_INSUFFICIENT'
BS={'B0_STRUCTURAL_SCHEMA_DIFF','B1_AST_SYNTACTIC_DATAFLOW','B2_STRONG_STATIC_DATAFLOW','B3A_GPT56_SOL_FRONTIER','B3B_CLAUDE_OPUS45_DATED','B4_EXECUTION_ONLY_DIFFERENTIAL'}
AB={'A1_PRIMARY_ONLY_NO_C1_PROMOTION_GATE','A2_C1_WITHOUT_AUTHORITY_SIDECARS','A3_C1_WITHOUT_CROSS_REPRESENTATION_EVIDENCE'}
Z=('early_truth_read_count','heldout_replacement_count','heldout_drop_count','duplicate_unit_count','raw_source_log_exposure_count','full_system_dual_replay_mismatch_count','evaluator_dual_replay_mismatch_count','semantic_snapshot_identity_mismatch_count','post_freeze_metric_definition_change_count','post_freeze_support_boundary_change_count')
def cb(v):return (json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False)+'\n').encode()
def q(n,d):return {'numerator':n,'denominator':d,'value':None if not d else n/d}
def de(x):return x in (P,R)
def good(p,t):return (p,t) in ((P,TP),(R,TR),(I,TI))
def rows(doc):
 out={};dup=False
 for i,x in enumerate(doc.get('units',[]) or []):
  u=str(x.get('unit_id',''))
  if not u or u in out:dup=True;u=u or f'__EMPTY_{i}'
  if u not in out:out[u]=x
 return out,dup
def comp(src,rs,bad):
 ids=[];invalid=[];v={}
 for u in sorted(rs):
  x=(src or {}).get(u,'INAPPLICABLE')
  if x=='INAPPLICABLE':continue
  if x==bad:invalid.append(u);continue
  ids.append(u);v[u]=x
 n=len(ids);d=sum(de(v[u]) for u in ids);rg=sum(rs[u]['truth']['outcome']==TR for u in ids);pp=sum(v[u]==P for u in ids);pr=sum(v[u]==R for u in ids)
 cr=sum(v[u]==R and rs[u]['truth']['outcome']==TR for u in ids);cp=sum(v[u]==P and rs[u]['truth']['outcome']==TP for u in ids)
 return {'applicable_count':n,'invalid_count':len(invalid),'definitive_coverage_on_applicable':q(d,n),'exact_outcome_accuracy_on_applicable':q(sum(good(v[u],rs[u]['truth']['outcome']) for u in ids),n),'unsafe_false_stability_count':sum(v[u]==P and rs[u]['truth']['outcome']==TR for u in ids),'false_regression_count':sum(v[u]==R and rs[u]['truth']['outcome']==TP for u in ids),'regression_recall':q(cr,rg),'preservation_precision':q(cp,pp),'regression_precision':q(cr,pr),'applicable_unit_ids':ids,'invalid_unit_ids':invalid}
def evaluate(d):
 if d.get('schema')!='risu.e2-gate2d-evaluation-input/v0.1':raise ValueError('INPUT_SCHEMA')
 rs,dup=rows(d);oo=[rs[u] for u in sorted(rs)];fail=[];integ=d.get('integrity',{}) or {}
 if len(oo)!=10:fail.append('HELDOUT_UNIT_COUNT')
 if dup:fail.append('DUPLICATE_UNIT')
 fail += [k for k in Z if int(integ.get(k,0) or 0)]
 for x in oo:
  u=str(x.get('unit_id'));t=x.get('truth',{});s=x.get('system',{})
  if t.get('admissible') is not True or t.get('outcome') not in (TP,TR,TI):fail.append('GOLD_INVALID:'+u)
  if s.get('outcome')==X:fail.append('FULL_SYSTEM_EVALUATION_INVALID:'+u)
 def C(f):return sum(bool(f(x)) for x in oo)
 hard={'unsafe_false_stability':C(lambda x:x['system']['outcome']==P and x['truth']['outcome']==TR),'unsupported_definitive_promotion':C(lambda x:de(x['system']['outcome']) and x.get('support_eligible') is not True),'ambiguous_or_unresolved_authority_definitive_promotion':C(lambda x:de(x['system']['outcome']) and x['system'].get('authority_status') in ('UNRESOLVED','AMBIGUOUS')),'checker_disagreement_definitive_promotion':C(lambda x:de(x['system']['outcome']) and x['system'].get('checker_agreement') is not True),'invalid_certificate_definitive_promotion':C(lambda x:de(x['system']['outcome']) and not(x['system'].get('c1_checker_output')=='VALID_C1' and x['system'].get('assurance_level')=='C1_INDEPENDENT_SOURCE_EVIDENCE')),'epistemic_overclaim':C(lambda x:de(x['system']['outcome']) and x['truth']['outcome']==TI),'information_removal_monotonicity_violation':0}
 for e in d.get('information_removal_edges',[]) or []:
  a=str(e.get('parent_unit_id',''));b=str(e.get('child_unit_id',''))
  if a not in rs or b not in rs:fail.append('UNKNOWN_INFORMATION_REMOVAL_EDGE')
  else:hard['information_removal_monotonicity_violation']+=int(de(rs[b]['system']['outcome']) and not de(rs[a]['system']['outcome']))
 n=len(oo);dec=C(lambda x:x['truth']['outcome'] in (TP,TR));tnr=C(lambda x:x['truth']['outcome']==TR);tnp=C(lambda x:x['truth']['outcome']==TP);tni=C(lambda x:x['truth']['outcome']==TI);dn=C(lambda x:de(x['system']['outcome']));inc=C(lambda x:x['system']['outcome']==I);pp=C(lambda x:x['system']['outcome']==P);pr=C(lambda x:x['system']['outcome']==R);cd=C(lambda x:de(x['system']['outcome']) and good(x['system']['outcome'],x['truth']['outcome']));cr=C(lambda x:x['system']['outcome']==R and x['truth']['outcome']==TR);cp=C(lambda x:x['system']['outcome']==P and x['truth']['outcome']==TP);ia=C(lambda x:x['system']['outcome']==I and x['truth']['outcome']==TI)
 util={'definitive_coverage':q(dn,n),'incomplete_rate':q(inc,n),'exact_outcome_accuracy':q(C(lambda x:good(x['system']['outcome'],x['truth']['outcome'])),n),'decidable_definitive_coverage':q(C(lambda x:de(x['system']['outcome']) and x['truth']['outcome'] in (TP,TR)),dec),'definitive_accuracy_on_decidable_truth':q(cd,C(lambda x:de(x['system']['outcome']) and x['truth']['outcome'] in (TP,TR))),'regression_recall':q(cr,tnr),'preservation_recall':q(cp,tnp),'preservation_precision':q(cp,pp),'regression_precision':q(cr,pr),'false_regression_count':C(lambda x:x['system']['outcome']==R and x['truth']['outcome']==TP),'epistemic_abstention_recall':q(ia,tni),'provenance_completeness':q(C(lambda x:x['system'].get('provenance_complete') is True),n)}
 bd=d.get('baselines',{}) or {};ad=d.get('ablations',{}) or {}
 if set(bd)!=BS:fail.append('BASELINE_REGISTRY_SET_MISMATCH')
 if set(ad)!=AB:fail.append('ABLATION_REGISTRY_SET_MISMATCH')
 br={k:comp(v.get('unit_outputs',{}),rs,'BASELINE_INVALID') for k,v in sorted(bd.items())};ar={k:comp(v.get('unit_outputs',{}),rs,'ABLATION_INVALID') for k,v in sorted(ad.items())}
 fail += ['BASELINE_EXECUTION_INVALID:'+k for k,v in br.items() if v['invalid_count']]+['ABLATION_EXECUTION_INVALID:'+k for k,v in ar.items() if v['invalid_count']]
 if (d.get('claim_flags',{}) or {}).get('forbidden_population_claim') is True:fail.append('FORBIDDEN_POPULATION_CLAIM')
 hz=any(hard.values());sp=dec>0 and tni>0;nt=not fail and not hz and sp and cd>=1 and ia>=1
 cl='FAIL_EVALUATION_INTEGRITY' if fail else 'FAIL_HARD_SAFETY' if hz else 'PASS_HARD_SAFETY_NONTRIVIALITY_UNTESTABLE' if not sp else 'PASS_NONTRIVIAL_SELECTIVE_SAFETY' if nt else 'PASS_HARD_SAFETY_ONLY'
 return {'schema':'risu.e2-gate2d-evaluation-result/v0.1','classification':cl,'integrity':{'status':'PASS' if not fail else 'FAIL','failures':sorted(set(fail))},'system':{'hard_safety':hard,'utility':util,'strata':{'truth_decidable_count':dec,'truth_regression_count':tnr,'truth_preservation_count':tnp,'truth_epistemically_insufficient_count':tni}},'baselines':br,'ablations':ar,'nontrivial_selectivity':{'strata_present':sp,'demonstrated':nt},'claim_boundaries':{'population_generalization_authorized':False,'p_value_authorized':False,'confidence_interval_authorized':False}}
def main():
 a=argparse.ArgumentParser();a.add_argument('--input',required=True);a.add_argument('--output',required=True);x=a.parse_args();o=evaluate(json.loads(Path(x.input).read_bytes()));Path(x.output).write_bytes(cb(o));print(json.dumps({'classification':o['classification'],'schema':o['schema']},sort_keys=True,separators=(',',':')))
if __name__=='__main__':main()
