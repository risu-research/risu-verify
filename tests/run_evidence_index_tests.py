#!/usr/bin/env python3
from pathlib import Path
import hashlib,json,subprocess,sys,tempfile,shutil
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import evidence_index_verify as ev

passed=0; failed=0

def check(name,fn):
    global passed,failed
    try:
        fn(); print(f'PASS {name}'); passed+=1
    except Exception as e:
        print(f'FAIL {name}: {e}'); failed+=1

def load(rel): return json.loads((ROOT/rel).read_text())

def must(cond,msg='assertion failed'):
    if not cond: raise AssertionError(msg)

check('evidence index verifies current release', lambda: must(ev.verify(ROOT)['status']=='PASS'))
idx=load('EVIDENCE_INDEX.json')
check('index has six flagship claims', lambda: must(len(idx['claims'])==6))
check('each claim states support and boundary', lambda: must(all(c.get('establishes') and c.get('does_not_establish') for c in idx['claims'])))
check('historical transition claim is bounded', lambda: must('independently discovered' in next(c for c in idx['claims'] if c['claim_id']=='HIST-TRANSITION-003')['does_not_establish']))
check('VBE claim remains calibration-only', lambda: must('Prospective generalization' in next(c for c in idx['claims'] if c['claim_id']=='VBE-PROFILE-005')['does_not_establish']))
check('prospective protocol claim says timestamp incomplete', lambda: must('External timestamp completion' in next(c for c in idx['claims'] if c['claim_id']=='PROSPECTIVE-PROTOCOL-006')['does_not_establish']))
check('public overview exists', lambda: must((ROOT/'docs/PUBLIC_EVIDENCE_OVERVIEW.md').is_file()))
check('README links public evidence overview', lambda: must('PUBLIC_EVIDENCE_OVERVIEW.md' in (ROOT/'README.md').read_text()))
check('next gates no longer treats VBE creation as pending', lambda: must('Gate B — Version-Bound Effect development profile' not in (ROOT/'docs/NEXT_GATES.md').read_text()))
check('architecture documents v0.4 authoring layer', lambda: must('Layer 2.5 — development authoring profile' in (ROOT/'docs/ARCHITECTURE.md').read_text()))
check('trust surface documents untrusted VBE layer', lambda: must('Version-Bound Effect profile' in (ROOT/'docs/TRUST_AND_ATTACK_SURFACE.md').read_text()))

# Attack: changing an indexed artifact without updating the index must fail.
def tamper_hash():
    td=Path(tempfile.mkdtemp(prefix='risu-evidence-index-'))
    try:
        shutil.copytree(ROOT,td/'r',dirs_exist_ok=True)
        p=td/'r/examples/expected/azure-devops-wiki-etag.report.json'
        p.write_text(p.read_text()+'\n')
        try: ev.verify(td/'r')
        except SystemExit: return
        raise AssertionError('tampered artifact accepted')
    finally: shutil.rmtree(td,ignore_errors=True)
check('indexed artifact tamper is rejected', tamper_hash)

# Attack: changing a semantic assertion while recomputing the artifact hash in the index must still fail.
def tamper_semantic():
    td=Path(tempfile.mkdtemp(prefix='risu-evidence-index-sem-'))
    try:
        shutil.copytree(ROOT,td/'r',dirs_exist_ok=True)
        rp=td/'r/examples/expected/azure-devops-wiki-etag.report.json'
        d=json.loads(rp.read_text()); d['product_status']='INCOMPLETE_ASSURANCE'; rp.write_text(json.dumps(d,indent=2,sort_keys=True)+'\n')
        ip=td/'r/EVIDENCE_INDEX.json'; idx=json.loads(ip.read_text())
        digest=hashlib.sha256(rp.read_bytes()).hexdigest()
        for c in idx['claims']:
            for a in c.get('artifacts',[]):
                if a['path']=='examples/expected/azure-devops-wiki-etag.report.json': a['sha256']=digest
        ip.write_text(json.dumps(idx,indent=2,sort_keys=True)+'\n')
        try: ev.verify(td/'r')
        except SystemExit: return
        raise AssertionError('semantic substitution accepted after rehash')
    finally: shutil.rmtree(td,ignore_errors=True)
check('semantic substitution is rejected even after rehash', tamper_semantic)

print(f'\nEvidence-index qualification: {passed} passed, {failed} failed')
summary={'status':'PASS' if failed==0 else 'FAIL','taxonomy':'public claim-to-evidence indexing + coherence + tamper resistance','tests_total':passed+failed,'tests_passed':passed,'tests_failed':failed}
(ROOT/'results/V0.4.0_RC1_EVIDENCE_INDEX_QUALIFICATION.json').write_text(json.dumps(summary,indent=2,sort_keys=True)+'\n')
raise SystemExit(0 if failed==0 else 1)
