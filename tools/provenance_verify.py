#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json, re
from pathlib import Path


def sha256_file(p: Path) -> str:
    h=hashlib.sha256()
    with p.open('rb') as f:
        for c in iter(lambda:f.read(1024*1024),b''): h.update(c)
    return h.hexdigest()


def canonical(obj) -> str:
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False)+"\n"

def git_blob_sha1(data: bytes) -> str:
    header=f'blob {len(data)}\0'.encode('ascii')
    return hashlib.sha1(header+data).hexdigest()


def safe(base: Path, rel: str) -> Path:
    p=(base/rel).resolve(); b=base.resolve()
    try: p.relative_to(b)
    except ValueError: raise ValueError(f'path escapes case directory: {rel}')
    return p


def derive(case_dir: Path, manifest: dict) -> dict:
    artifacts={a['id']:a for a in manifest.get('artifacts',[])}
    facts=[]
    for a in manifest.get('assertions',[]):
        aid=a['artifact']; art=artifacts.get(aid)
        if not art: raise ValueError(f'assertion references unknown artifact {aid}')
        p=safe(case_dir, art['path'])
        text=p.read_text(encoding='utf-8')
        required=a.get('required_substrings',[])
        forbidden=a.get('forbidden_substrings',[])
        missing=[x for x in required if x not in text]
        present_forbidden=[x for x in forbidden if x in text]
        if missing: raise ValueError(f"{a['id']}: missing required source substring(s): {missing}")
        if present_forbidden: raise ValueError(f"{a['id']}: forbidden source substring(s) present: {present_forbidden}")
        if a.get('include_in_extracted_facts', True):
            facts.append({
                'id':a['id'], 'artifact':aid, 'status':'ESTABLISHED_BY_BUNDLED_BYTES',
                'required_substrings':required, 'forbidden_substrings':forbidden,
                'artifact_sha256':sha256_file(p), 'observation':a.get('observation','')
            })
    return {
        'extraction_version':'1.0',
        'case_id':manifest['case_id'],
        'facts':facts,
        'boundary':'Deterministic byte-level extraction only. It establishes occurrence/non-occurrence in bundled evidence bytes, not live-runtime truth or semantic adequacy.'
    }


def verify(case_dir: Path, write=False) -> dict:
    mpath=case_dir/'provenance'/'PROVENANCE_MANIFEST.json'
    if not mpath.is_file(): raise ValueError(f'provenance manifest missing: {mpath}')
    m=json.loads(mpath.read_text(encoding='utf-8'))
    checks=[]
    artifact_map={a['id']:a for a in m.get('artifacts',[])}
    for a in m.get('artifacts',[]):
        p=safe(case_dir,a['path'])
        ok=p.is_file() and sha256_file(p)==a['sha256']
        checks.append({'check':f"artifact:{a['id']}",'status':'PASS' if ok else 'FAIL','path':a['path']})
        if not ok: raise ValueError(f"artifact pin mismatch: {a['id']} {a['path']}")
        upstream=a.get('upstream')
        if upstream:
            commit=str(upstream.get('commit',''))
            blob=str(upstream.get('git_blob_sha1',''))
            repo=str(upstream.get('repository',''))
            mode=str(upstream.get('binding_mode','RECORDED_OBJECT_ID_ONLY'))
            if not repo or not commit or not re.fullmatch(r'[0-9a-f]{7,40}', commit):
                raise ValueError(f"invalid upstream revision identity: {a['id']}")
            if not re.fullmatch(r'[0-9a-f]{40}', blob):
                raise ValueError(f"invalid upstream Git blob identity: {a['id']}")
            if mode=='FULL_GIT_BLOB':
                actual=git_blob_sha1(p.read_bytes())
                if actual!=blob:
                    raise ValueError(f"full Git blob identity mismatch: {a['id']} expected={blob} actual={actual}")
                checks.append({'check':f"git-blob-cryptographic-binding:{a['id']}",'status':'PASS','repository':repo,'commit':commit,'git_blob_sha1':blob})
            elif mode=='RECORDED_OBJECT_ID_ONLY':
                checks.append({'check':f"upstream-object-id-recorded:{a['id']}",'status':'PASS','repository':repo,'commit':commit,'git_blob_sha1':blob,'boundary':'Bundled bytes are not cryptographically proven to be the full cited Git blob.'})
            else:
                raise ValueError(f"unsupported upstream binding mode: {mode}")
    derived=derive(case_dir,m)
    out=case_dir/'provenance'/'EXTRACTED_SOURCE_FACTS.json'
    if write:
        out.write_text(canonical(derived),encoding='utf-8')
    elif m.get('extracted_facts'):
        exp=m['extracted_facts']; p=safe(case_dir,exp['path'])
        if not p.is_file(): raise ValueError(f'extracted facts missing: {p}')
        actual_text=canonical(derived)
        if p.read_text(encoding='utf-8')!=actual_text: raise ValueError('deterministic extracted facts do not reproduce')
        if sha256_file(p)!=exp['sha256']: raise ValueError('extracted facts SHA-256 pin mismatch')
        checks.append({'check':'deterministic-extraction','status':'PASS','path':exp['path']})

    # Optional structural bridge: prove that the exact deterministic extraction consumed
    # by the frozen core is byte-identical to the provenance-side extraction output.
    for link in m.get('core_binding_checks', []):
        if link.get('mode') != 'BYTE_IDENTICAL':
            raise ValueError(f"unsupported core binding mode: {link.get('mode')}")
        left=safe(case_dir,link['left']); right=safe(case_dir,link['right'])
        if not left.is_file() or not right.is_file() or left.read_bytes()!=right.read_bytes():
            raise ValueError(f"core binding byte identity failed: {link['id']}")
        checks.append({'check':f"core-binding:{link['id']}",'status':'PASS','left':link['left'],'right':link['right'],'sha256':sha256_file(left)})

    # Optional structural bridge from byte-level source assertions to separately labeled
    # semantic interpretation snapshots. This does not make the interpretation itself
    # a byte fact; it proves that every claimed interpretation ID names an existing
    # source assertion and an existing observation in the pinned interpretation artifact.
    assertion_ids={a['id'] for a in m.get('assertions', [])}
    for link in m.get('semantic_links', []):
        if link['assertion'] not in assertion_ids:
            raise ValueError(f"semantic link references unknown assertion: {link['assertion']}")
        art=artifact_map.get(link['artifact'])
        if not art:
            raise ValueError(f"semantic link references unknown artifact: {link['artifact']}")
        obj=json.loads(safe(case_dir,art['path']).read_text(encoding='utf-8'))
        ids={x.get('id') for x in obj.get('observations', []) if isinstance(x,dict)}
        if link['observation_id'] not in ids:
            raise ValueError(f"semantic link observation missing: {link['observation_id']}")
        checks.append({'check':f"semantic-link:{link['id']}",'status':'PASS','assertion':link['assertion'],'artifact':link['artifact'],'observation_id':link['observation_id']})

    return {'status':'PASS','case_id':m['case_id'],'manifest_sha256':sha256_file(mpath),'checks':checks,'derived_fact_count':len(derived['facts'])}


def main():
    ap=argparse.ArgumentParser(); ap.add_argument('case'); ap.add_argument('--write',action='store_true')
    args=ap.parse_args(); r=verify(Path(args.case).resolve(),args.write); print(json.dumps(r,indent=2,sort_keys=True))
if __name__=='__main__': main()
