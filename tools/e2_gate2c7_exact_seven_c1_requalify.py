#!/usr/bin/env python3
from __future__ import annotations
import argparse, ast, hashlib, json
from pathlib import Path
from typing import Any, Mapping
from risu_e2_c1.rechecker import recheck
from risu_e2_c1.source_extract import _extract_direct

SCHEMA='risu.e2-gate2c7-exact-seven-c1-development-requalification/v0.1'
VALID='VALID_C1'
PRESERVATION='E2_PREDICTED_PRESERVATION_EVIDENCE'

def cb(v:Any)->bytes:return (json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False)+'\n').encode()
def sha(b:bytes)->str:return hashlib.sha256(b).hexdigest()
def readj(p:Path)->Any:return json.loads(p.read_bytes())

def protocol_digests(p:Mapping[str,Any])->dict[str,str]:
    lock=p.get('normative_protocol_lock',{}) or {}
    names={'verdict_protocol':'E2_CANDIDATE58_SEMANTIC_VERDICT_PROTOCOL_v0.1','minimal_fragment':'E2_GATE1B1C_MINIMAL_SEMANTIC_FRAGMENT_v0.1','trust_boundary':'E2_CERTIFICATE_TRUST_BOUNDARY_v0.1'}
    out={}
    for k,n in names.items():
        v=str(lock.get(n,''))
        if not v.startswith('gitblob:'): raise ValueError('EXECUTION_PROTOCOL_IDENTITY_MISSING:'+n)
        out[k]=v.removeprefix('gitblob:')
    return out

def identities(f:Mapping[str,Any])->dict[str,str]:
    ids=f.get('content_addressed_identities',{}) or {}
    names={'semantic_engine':'semantic_engine_identity','certificate_producer':'certificate_producer_identity','source_evidence_checker':'source_evidence_checker_identity','semantic_checker':'semantic_checker_identity','minimal_semantic_fragment':'minimal_semantic_fragment_identity'}
    out={k:str(ids.get(n,'')) for k,n in names.items()}
    if any(not x for x in out.values()): raise ValueError('HISTORICAL_CERTIFICATE_IDENTITY_LOCK_INCOMPLETE')
    return out

def runtime(p:Mapping[str,Any])->dict[str,Any]:
    r=p.get('runtime_lock',{}) or {}
    out={'implementation':str(r.get('implementation','')),'python_major':int(r.get('python_major',-1)),'python_minor':int(r.get('python_minor',-1)),'python_micro':int(r.get('python_micro',-1)),'parser':str(r.get('parser',''))}
    if out!={'implementation':'CPython','python_major':3,'python_minor':13,'python_micro':5,'parser':'python_stdlib_ast'}: raise ValueError('RUNTIME_LOCK_MISMATCH')
    return out

def role_raw_origins(reconstructed:Mapping[str,Any])->dict[str,list[str]]:
    out={}
    for b in reconstructed.get('bindings',[]) or []:
        if not isinstance(b,Mapping): continue
        slot=b.get('slot_identity',{}) or {}
        allowed=list(map(str,b.get('allowed_origins',[]) or []))
        if 'operand_index' in slot and len(allowed)==1 and allowed[0] in {'BOUND_VALUE:expected_coordinate','BOUND_VALUE:current_coordinate'}:
            out[allowed[0]]=list(map(str,b.get('observed_origins',[]) or []))
    return out

def projection_receipt_summary(reconstructed:Mapping[str,Any])->dict[str,Any]:
    rows=reconstructed.get('projection_authority_receipts',[]) or []
    fps={0:set(),1:set()}; reasons={0:set(),1:set()}; decisions={0:set(),1:set()}
    for w in rows:
        for o in (w.get('operands',[]) if isinstance(w,Mapping) else []):
            idx=o.get('operand_index')
            if idx in fps:
                if o.get('fingerprint_sha256'): fps[idx].add(str(o['fingerprint_sha256']))
                reasons[idx].add(str(o.get('reason'))); decisions[idx].add(str(o.get('decision')))
    return {'world_receipt_count':len(rows),'operand0_fingerprints':sorted(fps[0]),'operand1_fingerprints':sorted(fps[1]),'operand0_reasons':sorted(reasons[0]),'operand1_reasons':sorted(reasons[1]),'operand0_decisions':sorted(decisions[0]),'operand1_decisions':sorted(decisions[1])}

def main()->int:
    ap=argparse.ArgumentParser();
    ap.add_argument('--gate2c7-protocol',required=True);ap.add_argument('--execution-protocol',required=True);ap.add_argument('--historical-implementation-freeze',required=True)
    ap.add_argument('--matrix',required=True);ap.add_argument('--sources',required=True);ap.add_argument('--cases',required=True);ap.add_argument('--output',required=True)
    a=ap.parse_args(); c7=readj(Path(a.gate2c7_protocol)); ep=readj(Path(a.execution_protocol)); hf=readj(Path(a.historical_implementation_freeze)); matrix=readj(Path(a.matrix))
    ids=sorted(map(str,(c7.get('population',{}) or {}).get('case_ids',[]) or []))
    if len(ids)!=7 or len(set(ids))!=7 or (c7.get('population',{}) or {}).get('case_count')!=7: raise ValueError('POPULATION_NOT_EXACT_SEVEN')
    mrows={str(r.get('case_id')):r for r in matrix.get('cases',[]) or []}
    pd=protocol_digests(ep); ei=identities(hf); rt=runtime(ep); outdir=Path(a.output); outdir.mkdir(parents=True,exist_ok=True); (outdir/'cases').mkdir(exist_ok=True)
    ledger=[]
    for cid in ids:
        if cid not in mrows: raise ValueError('MATRIX_CASE_MISSING:'+cid)
        mr=mrows[cid]
        if mr.get('language')!='python' or mr.get('tentative_kernel_prediction')!=PRESERVATION: raise ValueError('FROZEN_MATRIX_POPULATION_MISMATCH:'+cid)
        src=(Path(a.sources)/(cid+'.py')).read_bytes(); d=Path(a.cases)/cid; cert=readj(d/'certificate.json'); adapter=readj(d/'adapter_receipt.json')
        if sha(src)!=str(mr.get('candidate_source_sha256')): raise ValueError('SOURCE_SHA_MISMATCH:'+cid)
        if sha(cb(cert))!=str(mr.get('certificate_sha256')): raise ValueError('CERTIFICATE_SHA_MISMATCH:'+cid)
        if sha(cb(adapter))!=str(mr.get('adapter_receipt_sha256')): raise ValueError('ADAPTER_SHA_MISMATCH:'+cid)
        if str(cert.get('case_id'))!=cid: raise ValueError('CERTIFICATE_CASE_ID_MISMATCH:'+cid)
        signature=adapter.get('execution_signature')
        if not isinstance(signature,Mapping): raise ValueError('EXECUTION_SIGNATURE_MISSING:'+cid)
        contract=(cert.get('semantic_slice',{}) or {}).get('source_contract',{}) or {}; sp=str(contract.get('path',''))
        if not sp: raise ValueError('SOURCE_CONTRACT_PATH_MISSING:'+cid)
        report=recheck(certificate=cert,source_files={sp:src},canonical_signature=signature,expected_protocol_digests=pd,expected_identities=ei,expected_runtime=rt)
        reconstructed,bad=_extract_direct(source=src,tree=ast.parse(src.decode('utf-8')),signature=signature,contract=contract,case_id=cid)
        if reconstructed is None: raw_origins={}; prs={'reconstruction_error':sorted(set(bad))}
        else: raw_origins=role_raw_origins(reconstructed); prs=projection_receipt_summary(reconstructed)
        (outdir/'cases'/f'{cid}.c1_report.json').write_bytes(cb(report))
        ledger.append({'case_id':cid,'source_sha256':sha(src),'certificate_sha256':sha(cb(cert)),'adapter_receipt_sha256':sha(cb(adapter)),'historical_c1_checker_output':str(mr.get('c1_checker_output')),'historical_final_prediction':str(mr.get('machine_prediction')),'tentative_kernel_prediction':str(mr.get('tentative_kernel_prediction')),'c1_checker_output':str(report.get('checker_output')),'c1_machine_prediction':str(report.get('machine_prediction')),'assurance_level':str(report.get('assurance_level')),'reasons':list(map(str,report.get('reasons',[]) or [])),'c1_result_digest_sha256':report.get('c1_result_digest_sha256'),'c1_reconstructed_slice_digest_sha256':report.get('c1_reconstructed_slice_digest_sha256'),'raw_guard_origins':raw_origins,'projection_authority':prs})
    valid=sum(1 for r in ledger if r['c1_checker_output']==VALID)
    preserved=sum(1 for r in ledger if r['c1_machine_prediction']==PRESERVATION)
    result={'schema':SCHEMA,'status':'COMPLETE','case_count':7,'case_ids':ids,'valid_c1_count':valid,'c1_preservation_count':preserved,'all_seven_valid_c1':valid==7,'all_seven_c1_preservation':preserved==7,'raw_origin_evidence_rewritten':False,'primary_adapter_rerun':False,'semantic_kernel_rerun':False,'certificate_reproduced':False,'epistemic10_read':False,'truth_read':False,'mutation_algebra_opened':False,'cases':ledger}
    (outdir/'E2_GATE2C7_EXACT_SEVEN_C1_REQUALIFICATION.json').write_bytes(cb(result)); print(json.dumps({'schema':SCHEMA,'status':'COMPLETE','valid_c1_count':valid,'case_count':7},sort_keys=True,separators=(',',':'))); return 0
if __name__=='__main__': raise SystemExit(main())
