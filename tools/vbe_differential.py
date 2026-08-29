#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, shutil, sys, tempfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
import risu_verify as rv
from vbe_compile import compile_instance

CAL=[
 ('001-github-guarded-merge','cases/github-guarded-merge'),
 ('002-azure-wiki-etag','cases/azure-devops-wiki-etag'),
 ('003-before-github-blob-sha','cases/github-create-update-sha-transition/before'),
 ('003-after-github-blob-sha','cases/github-create-update-sha-transition/after'),
]

def semantic_view(s):
    return {
      'product_status':s['product_status'],
      'source_semantic_digest':s['commitments']['source_semantic_digest'],
      'structural':s['structural'],
      'exact_status':s['exact_realization']['status'],
      'exact_failure_mode':s['exact_realization']['failure_mode'],
      'worlds':s['worlds'],
    }

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--output'); a=ap.parse_args()
    out=Path(a.output).resolve() if a.output else ROOT/'results'/'VBE_CALIBRATION_DIFFERENTIAL.json'
    rows=[]; ok=True
    with tempfile.TemporaryDirectory(prefix='risu-vbe-diff-') as td:
      td=Path(td)
      for name,legacy_rel in CAL:
        inst=ROOT/'profiles/version-bound-effect/calibration'/f'{name}.instance.json'
        compiled=td/name; compile_instance(inst,compiled)
        legacy_summary,_=rv.perform_verify(str(ROOT/legacy_rel), str(td/f'legacy-out-{name}'))
        compiled_summary,_=rv.perform_verify(str(compiled), str(td/f'compiled-out-{name}'))
        lv,cv=semantic_view(legacy_summary),semantic_view(compiled_summary)
        checks={k:lv[k]==cv[k] for k in lv}
        row={'instance':name,'legacy_case':legacy_rel,'checks':checks,'legacy':lv,'compiled':cv,'pass':all(checks.values())}
        rows.append(row); ok &= row['pass']
    result={'result_version':'0.1','profile':'version-bound-effect','profile_version':'0.1-development','status':'PASS' if ok else 'FAIL','calibration_count':len(rows),'rows':rows}
    out.parent.mkdir(parents=True,exist_ok=True); out.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    print(json.dumps({'status':result['status'],'calibration_count':len(rows),'output':str(out)},indent=2))
    raise SystemExit(0 if ok else 1)
if __name__=='__main__': main()
