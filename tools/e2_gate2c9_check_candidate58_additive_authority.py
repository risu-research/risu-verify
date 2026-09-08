#!/usr/bin/env python3
from __future__ import annotations
import argparse,hashlib,json
from pathlib import Path
from typing import Any
VALID='VALID_C1'; UNSUP='UNSUPPORTED_CERTIFICATE'; INVALID='INVALID_CERTIFICATE'; PRES='E2_PREDICTED_PRESERVATION_EVIDENCE'; INC='E2_PREDICTED_ASSURANCE_INCOMPLETE'; REG='E2_PREDICTED_REGRESSION_WITNESS'
def cb(v:Any)->bytes:return (json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False)+'\n').encode()
def sha(b:bytes)->str:return hashlib.sha256(b).hexdigest()
def dj(v:Any)->str:return sha(cb(v))
def readj(p:Path)->Any:return json.loads(p.read_bytes())
def agg(rows):return {'case_count':len(rows),'repair_applied_count':sum(x['repair_applied'] is True for x in rows),'untouched_count':sum(x['repair_applied'] is False for x in rows),'tentative_preservation_count':sum(x['historical_row']['tentative_kernel_prediction']==PRES for x in rows),'tentative_regression_count':sum(x['historical_row']['tentative_kernel_prediction']==REG for x in rows),'tentative_incomplete_count':sum(x['historical_row']['tentative_kernel_prediction']==INC for x in rows),'effective_final_preservation_count':sum(x['effective_machine_prediction']==PRES for x in rows),'effective_final_regression_count':sum(x['effective_machine_prediction']==REG for x in rows),'effective_final_incomplete_count':sum(x['effective_machine_prediction']==INC for x in rows),'effective_c1_valid_count':sum(x['effective_c1_checker_output']==VALID for x in rows),'effective_c1_invalid_count':sum(x['effective_c1_checker_output']==INVALID for x in rows),'effective_c1_unsupported_count':sum(x['effective_c1_checker_output']==UNSUP for x in rows)}
def main()->int:
 ap=argparse.ArgumentParser()
 for n in ('protocol','historical_matrix','repaired_freeze','repaired_ledger','reports','authority','output'):ap.add_argument('--'+n.replace('_','-'),required=True)
 a=ap.parse_args(); p=readj(Path(a.protocol)); m=readj(Path(a.historical_matrix)); rf=readj(Path(a.repaired_freeze)); rl=readj(Path(a.repaired_ledger)); got=readj(Path(a.authority)); reports=Path(a.reports)
 if p.get('schema')!='risu.e2-gate2c9-candidate58-additive-requalification-protocol/v0.2':raise ValueError('PROTOCOL')
 if got.get('schema')!='risu.e2-gate2c9-candidate58-additive-authority/v0.1':raise ValueError('AUTHORITY_SCHEMA')
 if sha(Path(a.historical_matrix).read_bytes())!=p['authority_locks']['historical_matrix_sha256']:raise ValueError('MATRIX_SHA')
 if rf.get('status')!='REPAIRED_C1_LANE_FIRST_COMPLETE_IMMUTABLY_FROZEN' or rf.get('repaired_lane_success') is not True:raise ValueError('REPAIR_FREEZE')
 repair=sorted(map(str,p['population']['repair_case_ids'])); hist={str(x['case_id']):x for x in m.get('cases',[])}; ids=sorted(hist); rows={str(x['case_id']):x for x in got.get('cases',[])}
 if len(ids)!=58 or sorted(rows)!=ids or len(repair)!=7 or sorted(str(x['case_id']) for x in rl.get('rows',[]))!=repair:raise ValueError('POPULATION')
 exact51=0; exact7=0
 for cid in ids:
  x=rows[cid]; h=hist[cid]
  if x.get('historical_row')!=h or x.get('historical_row_digest_sha256')!=dj(h):raise ValueError('HISTORICAL_ROW_REWRITE:'+cid)
  if cid not in repair:
   exp={'effective_c1_checker_output':h.get('c1_checker_output'),'effective_c1_report_sha256':h.get('c1_report_sha256'),'effective_assurance_level':h.get('assurance_level'),'effective_machine_prediction':h.get('machine_prediction'),'effective_promotion_basis':'HISTORICAL_GATE2C2A_ROW_UNCHANGED'}
   if x.get('repair_applied') is not False or x.get('repair_authority') is not None or any(x.get(k)!=v for k,v in exp.items()):raise ValueError('UNTOUCHED_ROW_CHANGED:'+cid)
   exact51+=1
  else:
   rp=reports/f'{cid}.c1_report.json'; b=rp.read_bytes(); r=readj(rp); pa=p['repair_report_authority'][cid]
   if sha(b)!=pa['c1_report_sha256'] or r.get('checker_output')!=VALID or r.get('machine_prediction')!=PRES or r.get('assurance_level')!='C1_INDEPENDENT_SOURCE_EVIDENCE':raise ValueError('REPAIR_REPORT:'+cid)
   ra=x.get('repair_authority') or {}
   if x.get('repair_applied') is not True or ra.get('c1_report_sha256')!=sha(b) or ra.get('checker_output')!=VALID or ra.get('machine_prediction')!=PRES or ra.get('assurance_level')!='C1_INDEPENDENT_SOURCE_EVIDENCE':raise ValueError('REPAIR_AUTHORITY:'+cid)
   exp={'effective_c1_checker_output':VALID,'effective_c1_report_sha256':sha(b),'effective_assurance_level':'C1_INDEPENDENT_SOURCE_EVIDENCE','effective_machine_prediction':PRES,'effective_promotion_basis':'GATE2C8_VALID_C1_ADDITIVE_AUTHORITY'}
   if any(x.get(k)!=v for k,v in exp.items()):raise ValueError('REPAIR_EFFECTIVE_FIELDS:'+cid)
   exact7+=1
 actual=agg([rows[c] for c in ids]); expected=p['preregistered_expected_aggregate_if_all_authorities_validate']
 passed=(actual==expected and got.get('aggregate')==expected and exact51==51 and exact7==7 and got.get('historical_rows_reexecuted')==0 and got.get('repaired_cases_reexecuted')==0 and got.get('candidate_execution_count')==0 and got.get('c1_execution_count')==0 and got.get('primary_adapter_execution_count')==0 and got.get('semantic_kernel_execution_count')==0 and got.get('certificate_reproduction_count')==0 and got.get('source_bytes_read') is False and got.get('truth_read') is False and got.get('epistemic10_read') is False and got.get('mutation_algebra_opened') is False)
 res={'schema':'risu.e2-gate2c9-candidate58-additive-independent-check/v0.1','status':'PASS' if passed else 'FAIL','case_count':58,'untouched_51_historical_rows_exact':exact51==51,'repaired_7_historical_rows_exact':exact7==7,'repaired_7_authorities_exact':exact7==7,'aggregate':actual,'aggregate_matches_preregistered':actual==expected,'historical_rows_reexecuted':0,'candidate_execution_count':0,'c1_execution_count':0,'source_bytes_read':False,'truth_read':False,'epistemic10_read':False,'mutation_algebra_opened':False,'checker_imports_producer':False}
 Path(a.output).write_bytes(cb(res)); print(json.dumps({'schema':res['schema'],'status':res['status'],'aggregate':actual},sort_keys=True,separators=(',',':')))
 if not passed:raise SystemExit(2)
 return 0
if __name__=='__main__':raise SystemExit(main())
