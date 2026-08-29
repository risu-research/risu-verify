#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json, subprocess
from pathlib import Path

ADJUDICATION_RULE_ID="RISU_HISTORICAL_TRANSITION_V1"

def sha(p: Path):
    h=hashlib.sha256(); h.update(p.read_bytes()); return h.hexdigest()

def run_verify(root: Path, case: Path):
    p=subprocess.run([str(root/'risu-verify'),'verify',str(case),'--json'],cwd=root,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    if p.returncode not in {0,10,20}:
        raise RuntimeError(f'verify failed for {case}: exit={p.returncode}\n{p.stdout}')
    return p.returncode,json.loads(p.stdout)

def build_result(proto: dict, b: dict, br: int, x: dict, ar: int, source_contract_sha256: str) -> dict:
    bp=b['product_status']; apst=x['product_status']
    if bp=='CONSEQUENCE_REGRESSION' and apst in {'PRESERVED','PRESERVED_IN_DECLARED_SCOPE'}:
        cls='REPAIR_CONSISTENT_HISTORICAL_TRANSITION'
    elif bp in {'PRESERVED','PRESERVED_IN_DECLARED_SCOPE'} and apst=='CONSEQUENCE_REGRESSION':
        cls='REGRESSION_CONSISTENT_HISTORICAL_TRANSITION'
    else:
        cls='OBSERVED_HISTORICAL_TRANSITION_NO_DIRECTIONAL_LABEL'
    return {
      'transition_result_version':'1.1','adjudication_rule_id':ADJUDICATION_RULE_ID,'case_id':proto['case_id'],'classification':cls,
      'shared_source_contract_sha256':source_contract_sha256,'shared_source_contract_byte_identical':True,
      'predeclaration_seal_sha256':proto['predeclaration_seal_sha256'],
      'before':{'case_id':b['case_id'],'product_status':bp,'exit_code':br,'structural':b['structural'],'exact_realization':b['exact_realization'],'certificate_sha256':b['certificate']['sha256'],'provenance_sha256':b['provenance']['sha256']},
      'after':{'case_id':x['case_id'],'product_status':apst,'exit_code':ar,'structural':x['structural'],'exact_realization':x['exact_realization'],'certificate_sha256':x['certificate']['sha256'],'provenance_sha256':x['provenance']['sha256']},
      'semantic_delta':{
         'product_status':f'{bp} -> {apst}',
         'C':f"{b['structural']['C']} -> {x['structural']['C']}",
         'D':f"{b['structural']['D']} -> {x['structural']['D']}",
         'O':f"{b['structural']['O']} -> {x['structural']['O']}",
         'exact_status':f"{b['exact_realization']['status']} -> {x['exact_realization']['status']}",
         'exact_failure_mode':f"{b['exact_realization']['failure_mode']} -> {x['exact_realization']['failure_mode']}"
      },
      'boundary':'Pair classification is derived only from the two independently certificate-backed model-relative results. It is not a claim that the upstream PR fixed every reported issue or that live runtime behavior was reproduced by RISU.'
    }

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('transition'); ap.add_argument('--json',action='store_true'); ap.add_argument('--output')
    a=ap.parse_args(); root=Path(__file__).resolve().parents[1]; tdir=Path(a.transition)
    if not tdir.is_absolute(): tdir=(root/tdir).resolve()
    proto=json.loads((tdir/'TRANSITION_PROTOCOL.json').read_text())
    before=tdir/proto['before_case']; after=tdir/proto['after_case']
    bs=before/'assurance/source-contract.json'; ass=after/'assurance/source-contract.json'
    if bs.read_bytes()!=ass.read_bytes(): raise SystemExit('shared source contract byte identity failed')
    br,b=run_verify(root,before); ar,x=run_verify(root,after)
    out=build_result(proto,b,br,x,ar,sha(bs))
    text=json.dumps(out,indent=2,sort_keys=True)+'\n'
    if a.output: Path(a.output).write_text(text)
    if a.json or not a.output: print(text,end='')
if __name__=='__main__': main()
