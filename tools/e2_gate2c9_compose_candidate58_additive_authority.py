#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json
from pathlib import Path
from typing import Any

SCHEMA='risu.e2-gate2c9-candidate58-additive-authority/v0.1'
PRES='E2_PREDICTED_PRESERVATION_EVIDENCE'
INC='E2_PREDICTED_ASSURANCE_INCOMPLETE'
REG='E2_PREDICTED_REGRESSION_WITNESS'
VALID='VALID_C1'; UNSUP='UNSUPPORTED_CERTIFICATE'; INVALID='INVALID_CERTIFICATE'

def cb(v:Any)->bytes:return (json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False)+'\n').encode()
def sha(b:bytes)->str:return hashlib.sha256(b).hexdigest()
def dj(v:Any)->str:return sha(cb(v))
def readj(p:Path)->Any:return json.loads(p.read_bytes())

def aggregate(rows:list[dict[str,Any]])->dict[str,int]:
    return {
      'case_count':len(rows),
      'repair_applied_count':sum(bool(x['repair_applied']) for x in rows),
      'untouched_count':sum(not bool(x['repair_applied']) for x in rows),
      'tentative_preservation_count':sum(x['historical_row']['tentative_kernel_prediction']==PRES for x in rows),
      'tentative_regression_count':sum(x['historical_row']['tentative_kernel_prediction']==REG for x in rows),
      'tentative_incomplete_count':sum(x['historical_row']['tentative_kernel_prediction']==INC for x in rows),
      'effective_final_preservation_count':sum(x['effective_machine_prediction']==PRES for x in rows),
      'effective_final_regression_count':sum(x['effective_machine_prediction']==REG for x in rows),
      'effective_final_incomplete_count':sum(x['effective_machine_prediction']==INC for x in rows),
      'effective_c1_valid_count':sum(x['effective_c1_checker_output']==VALID for x in rows),
      'effective_c1_invalid_count':sum(x['effective_c1_checker_output']==INVALID for x in rows),
      'effective_c1_unsupported_count':sum(x['effective_c1_checker_output']==UNSUP for x in rows),
    }

def main()->int:
    ap=argparse.ArgumentParser()
    for n in ('protocol','historical_matrix','historical_freeze','repaired_freeze','repaired_ledger','reports','output'):
        ap.add_argument('--'+n.replace('_','-'),required=True)
    a=ap.parse_args(); pp=Path(a.protocol); mp=Path(a.historical_matrix)
    p=readj(pp); m=readj(mp); hf=readj(Path(a.historical_freeze)); rf=readj(Path(a.repaired_freeze)); rl=readj(Path(a.repaired_ledger)); reports=Path(a.reports)
    if p.get('schema')!='risu.e2-gate2c9-candidate58-additive-requalification-protocol/v0.2': raise ValueError('PROTOCOL_NOT_V0_2')
    if p.get('status')!='PROSPECTIVE_CORRECTED_AND_SEALED_BEFORE_ANY_ADDITIVE_COMPOSITION_EXECUTION': raise ValueError('PROTOCOL_NOT_PROSPECTIVE')
    locks=p['authority_locks']
    if sha(mp.read_bytes())!=locks['historical_matrix_sha256']: raise ValueError('HISTORICAL_MATRIX_SHA_MISMATCH')
    if int(hf.get('case_count',-1))!=58 or hf.get('status')!='FIRST_COMPLETE_REPAIRED_CANDIDATE58_MACHINE_ONLY_IMMUTABLY_FROZEN_BY_CONTAINING_COMMIT': raise ValueError('HISTORICAL_FREEZE_INVALID')
    ha=hf.get('hosted_artifact',{}) or {}
    if str(ha.get('id'))!=str(locks['historical_artifact_id']) or ha.get('digest')!=locks['historical_artifact_digest_sha256']: raise ValueError('HISTORICAL_ARTIFACT_AUTHORITY_MISMATCH')
    if rf.get('status')!='REPAIRED_C1_LANE_FIRST_COMPLETE_IMMUTABLY_FROZEN' or rf.get('repaired_lane_success') is not True or rf.get('candidate58_additive_requalification_authorized_after_this_freeze') is not True: raise ValueError('REPAIRED_FREEZE_NOT_AUTHORIZED')
    if int(rf.get('hosted_artifact_id',-1))!=int(locks['repaired_artifact_id']) or str(rf.get('hosted_artifact_digest',''))!='sha256:'+locks['repaired_artifact_digest_sha256']: raise ValueError('REPAIRED_ARTIFACT_AUTHORITY_MISMATCH')
    repair=sorted(map(str,p['population']['repair_case_ids'])); mrows={str(x['case_id']):x for x in m.get('cases',[])}; ids=sorted(mrows)
    if len(ids)!=58 or len(repair)!=7 or len(set(repair))!=7 or not set(repair)<=set(ids): raise ValueError('POPULATION_PARTITION_INVALID')
    if sorted(str(x['case_id']) for x in rl.get('rows',[]))!=repair or rl.get('gate2c8_valid_c1_count')!=7: raise ValueError('REPAIRED_LEDGER_POPULATION_MISMATCH')
    present=sorted(x.name for x in reports.glob('*.c1_report.json'))
    expected_names=sorted(f'{cid}.c1_report.json' for cid in repair)
    if present!=expected_names: raise ValueError('REPAIR_REPORT_FILE_SET_MISMATCH')
    pre=p['composition_rule']['repaired_7_preconditions']; report_auth=p['repair_report_authority']; out=[]
    for cid in ids:
        h=mrows[cid]; hd=dj(h)
        if cid in repair:
            if h.get('tentative_kernel_prediction')!=pre['tentative_kernel_prediction'] or h.get('c1_checker_output')!=pre['historical_c1_checker_output'] or h.get('machine_prediction')!=pre['historical_machine_prediction'] or h.get('promotion_reasons')!=pre['historical_promotion_reasons']: raise ValueError('REPAIR_HISTORICAL_PRECONDITION:'+cid)
            rp=reports/f'{cid}.c1_report.json'; rb=rp.read_bytes(); r=readj(rp); aexp=report_auth[cid]
            if sha(rb)!=aexp['c1_report_sha256']: raise ValueError('REPAIR_REPORT_SHA:'+cid)
            for k,rk in [('checker_output','checker_output'),('machine_prediction','machine_prediction'),('assurance_level','assurance_level')]:
                if r.get(rk)!=aexp[k]: raise ValueError('REPAIR_REPORT_SEMANTICS:'+cid+':'+k)
            ra={'gate2c8_artifact_id':int(locks['repaired_artifact_id']),'gate2c8_artifact_digest_sha256':locks['repaired_artifact_digest_sha256'],'c1_report_sha256':sha(rb),'checker_output':r['checker_output'],'machine_prediction':r['machine_prediction'],'assurance_level':r['assurance_level'],'c1_result_digest_sha256':r.get('c1_result_digest_sha256')}
            eff=(r['checker_output'],sha(rb),r['assurance_level'],r['machine_prediction'],'GATE2C8_VALID_C1_ADDITIVE_AUTHORITY')
        else:
            ra=None; eff=(h.get('c1_checker_output'),h.get('c1_report_sha256'),h.get('assurance_level'),h.get('machine_prediction'),'HISTORICAL_GATE2C2A_ROW_UNCHANGED')
        out.append({'case_id':cid,'historical_row':h,'historical_row_digest_sha256':hd,'repair_applied':cid in repair,'repair_authority':ra,'effective_c1_checker_output':eff[0],'effective_c1_report_sha256':eff[1],'effective_assurance_level':eff[2],'effective_machine_prediction':eff[3],'effective_promotion_basis':eff[4]})
    agg=aggregate(out); expected=p['preregistered_expected_aggregate_if_all_authorities_validate']
    if agg!=expected: raise ValueError('PREREGISTERED_AGGREGATE_MISMATCH:'+json.dumps({'actual':agg,'expected':expected},sort_keys=True))
    res={'schema':SCHEMA,'status':'COMPLETE','authority_protocol_schema':p['schema'],'authority_protocol_sha256':sha(pp.read_bytes()),'historical_matrix_sha256':sha(mp.read_bytes()),'historical_case_count':58,'historical_rows_reexecuted':0,'repaired_cases_reexecuted':0,'candidate_execution_count':0,'c1_execution_count':0,'primary_adapter_execution_count':0,'semantic_kernel_execution_count':0,'certificate_reproduction_count':0,'source_bytes_read':False,'truth_read':False,'epistemic10_read':False,'mutation_algebra_opened':False,'population_partition':{'repair_case_ids':repair,'untouched_case_ids':sorted(set(ids)-set(repair))},'aggregate':agg,'cases':out}
    Path(a.output).write_bytes(cb(res)); print(json.dumps({'schema':SCHEMA,'status':'COMPLETE','aggregate':agg},sort_keys=True,separators=(',',':'))); return 0
if __name__=='__main__': raise SystemExit(main())
