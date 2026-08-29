#!/usr/bin/env python3
from pathlib import Path
import argparse,json,re

HEX64=re.compile(r'^[0-9a-f]{64}$')

def obj(path):
    x=json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(x,dict): raise ValueError(f'{path}: root is not object')
    return x

def req(x,keys,label):
    miss=[k for k in keys if k not in x]
    if miss: raise ValueError(f'{label}: missing required fields {miss}')

def validate(kind,path):
    x=obj(path)
    if kind=='case':
        req(x,['case_id','adapter','assurance_dir','title','kind'],path)
        if 'provenance' in x:
            req(x['provenance'],['manifest','sha256'],path)
            if not HEX64.fullmatch(x['provenance']['sha256']): raise ValueError(f'{path}: invalid provenance sha256')
    elif kind=='provenance':
        req(x,['provenance_version','case_id','artifacts','assertions','boundary'],path)
        for a in x['artifacts']:
            req(a,['id','kind','path','sha256'],path)
            if not HEX64.fullmatch(a['sha256']): raise ValueError(f'{path}: invalid artifact sha256 {a.get("id")}')
    elif kind=='lock':
        req(x,['lock_version','case_id','baseline_policy','commitments','commitments_sha256','provenance_commitments','provenance_commitments_sha256'],path)
        if x['baseline_policy'] not in {'PRESERVATION_GATE','RESEARCH_REPRODUCTION'}: raise ValueError(f'{path}: invalid lock policy')
    elif kind=='report': req(x,['case_id','product_status','structural','exact_realization','certificate','commitments'],path)
    elif kind=='transition': req(x,['transition_result_version','case_id','classification','before','after','semantic_delta','shared_source_contract_sha256'],path)
    else: raise ValueError(f'unknown schema kind {kind}')
    return True

def validate_release(root: Path):
    cases=[root/'cases/github-guarded-merge',root/'cases/azure-devops-wiki-etag',root/'cases/github-create-update-sha-transition/before',root/'cases/github-create-update-sha-transition/after']
    checks=[]
    for c in cases:
        validate('case',c/'case.json'); validate('provenance',c/'provenance/PROVENANCE_MANIFEST.json'); checks+=['case','provenance']
    for p in [root/'cases/github-guarded-merge/risu.lock.json',root/'cases/azure-devops-wiki-etag/risu.lock.json',root/'cases/github-create-update-sha-transition/after/risu.lock.json']:
        validate('lock',p); checks.append('lock')
    validate('transition',root/'cases/github-create-update-sha-transition/TRANSITION_RESULT.json'); checks.append('transition')
    # Schema documents themselves must be valid JSON and identify development maturity.
    for p in sorted((root/'schemas').glob('*.json')):
        s=obj(p); req(s,['$schema','$id','type'],p)
        if s.get('x-risu-maturity')!='development':
            # VBE v0.1alpha1 was protocol-pinned before this release validator learned the generic metadata field.
            # Preserve those exact sealed bytes; its development status is encoded by the profile_version const.
            pv=((s.get('properties') or {}).get('profile_version') or {}).get('const')
            if not (p.name=='vbe-instance.v0.1alpha1.schema.json' and pv=='0.1-development'):
                raise ValueError(f'{p}: schema maturity is not development')
        checks.append('schema-document')
    return {'status':'PASS','checks':len(checks)}

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--release',action='store_true'); ap.add_argument('kind',nargs='?'); ap.add_argument('path',nargs='?')
    a=ap.parse_args()
    if a.release:
        root=Path(__file__).resolve().parents[1]; print(json.dumps(validate_release(root),sort_keys=True)); return
    if not a.kind or not a.path: ap.error('provide KIND PATH or --release')
    validate(a.kind,Path(a.path)); print('PASS')
if __name__=='__main__': main()
