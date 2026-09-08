#!/usr/bin/env python3
from __future__ import annotations
import argparse, ast, hashlib, json
from pathlib import Path
from typing import Any, Mapping
from risu_e2_c1.source_extract import _extract_direct

SCHEMA='risu.e2-gate2c8-exact-seven-binding-authority-observation/v0.1'

def cb(v:Any)->bytes:return (json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False)+'\n').encode()
def sha(b:bytes)->str:return hashlib.sha256(b).hexdigest()
def readj(p:Path)->Any:return json.loads(p.read_bytes())

def main()->int:
    ap=argparse.ArgumentParser()
    ap.add_argument('--gate2c8-protocol',required=True)
    ap.add_argument('--sources',required=True)
    ap.add_argument('--cases',required=True)
    ap.add_argument('--output',required=True)
    a=ap.parse_args()
    p=readj(Path(a.gate2c8_protocol)); ids=sorted(map(str,(p.get('population',{}) or {}).get('case_ids',[]) or []))
    if len(ids)!=7 or len(set(ids))!=7 or (p.get('population',{}) or {}).get('case_count')!=7: raise ValueError('POPULATION_NOT_EXACT_SEVEN')
    rows=[]
    for cid in ids:
        src=(Path(a.sources)/(cid+'.py')).read_bytes(); d=Path(a.cases)/cid
        cert=readj(d/'certificate.json'); adapter=readj(d/'adapter_receipt.json')
        if str(cert.get('case_id'))!=cid: raise ValueError('CERTIFICATE_CASE_ID_MISMATCH:'+cid)
        sig=adapter.get('execution_signature'); contract=(cert.get('semantic_slice',{}) or {}).get('source_contract',{}) or {}
        if not isinstance(sig,Mapping): raise ValueError('EXECUTION_SIGNATURE_MISSING:'+cid)
        rec,bad=_extract_direct(source=src,tree=ast.parse(src.decode('utf-8')),signature=sig,contract=contract,case_id=cid)
        if rec is None: raise ValueError('GATE2C8_RECONSTRUCTION_FAILED:'+cid+':'+','.join(sorted(set(bad))))
        guard=[]
        for b in rec.get('bindings',[]) or []:
            slot=b.get('slot_identity',{}) or []
            if not isinstance(slot,Mapping) or not isinstance(slot.get('operand_index'),int): continue
            guard.append({
                'binding_id':str(b.get('binding_id')),
                'slot_identity':dict(slot),
                'allowed_origins':list(map(str,b.get('allowed_origins',[]) or [])),
                'observed_origins':list(map(str,b.get('observed_origins',[]) or [])),
                'lineage_paths':b.get('lineage_paths',[]) or [],
                'binding_complete':b.get('binding_complete'),
                'definitions_complete':b.get('definitions_complete'),
                'binding_authority_receipts':b.get('binding_authority_receipts',[]) or [],
            })
        rows.append({
            'case_id':cid,
            'source_sha256':sha(src),
            'binding_authority_source_sha256':str(rec.get('binding_authority_source_sha256','')),
            'binding_authority_derivation_errors':list(map(str,rec.get('binding_authority_derivation_errors',[]) or [])),
            'guard_bindings':sorted(guard,key=lambda x:(int((x.get('slot_identity') or {}).get('operand_index',-1)),x.get('binding_id',''))),
        })
    out={'schema':SCHEMA,'status':'COMPLETE','case_count':7,'case_ids':ids,'observer_c1_execution_count':0,'primary_adapter_rerun':False,'semantic_kernel_rerun':False,'certificate_reproduced':False,'epistemic10_read':False,'truth_read':False,'mutation_algebra_opened':False,'cases':rows}
    Path(a.output).write_bytes(cb(out));print(json.dumps({'schema':SCHEMA,'status':'COMPLETE','case_count':7},sort_keys=True,separators=(',',':')));return 0
if __name__=='__main__':raise SystemExit(main())
