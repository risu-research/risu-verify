#!/usr/bin/env python3
from __future__ import annotations
import contextlib, hashlib, importlib.util, io, json, shutil, subprocess, tempfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location('risu_verify',ROOT/'src/risu_verify.py')
rv=importlib.util.module_from_spec(SPEC); assert SPEC.loader; SPEC.loader.exec_module(rv)
PASS=[]; FAIL=[]

def record(name,ok,detail=''):
    (PASS if ok else FAIL).append((name,detail)); print(f"{'PASS' if ok else 'FAIL'}  {name}"+(f' — {detail}' if detail else ''),flush=True)
def run(*args):
    return subprocess.run([str(ROOT/'risu-verify'),*map(str,args)],cwd=ROOT,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
def load(p): return json.loads(Path(p).read_text())
def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def cp_case(src,dst): shutil.copytree(src,dst)

case1=ROOT/'cases/github-guarded-merge'
case2=ROOT/'cases/azure-devops-wiki-etag'
tdir=ROOT/'cases/github-create-update-sha-transition'
before=tdir/'before'; after=tdir/'after'

with tempfile.TemporaryDirectory(prefix='risu-v03-qualification-') as raw:
    td=Path(raw)
    # Provenance gates over all inherited/new commissioning cases.
    for label,c in [('case001',case1),('case002',case2),('case003-before',before),('case003-after',after)]:
        p=subprocess.run(['python',str(ROOT/'tools/provenance_verify.py'),str(c)],cwd=ROOT,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        ok=p.returncode==0
        obj=json.loads(p.stdout) if ok else {}
        meta=load(c/'case.json')
        record(f'{label} evidence provenance gate passes',ok and obj.get('status')=='PASS')
        record(f'{label} case pin equals provenance manifest digest',ok and meta['provenance']['sha256']==obj.get('manifest_sha256'))

    # Structural provenance bridges added in v0.3.
    c2pv=json.loads(subprocess.run(['python',str(ROOT/'tools/provenance_verify.py'),str(case2)],cwd=ROOT,text=True,stdout=subprocess.PIPE).stdout)
    c2checks={x['check'] for x in c2pv['checks']}
    record('case002 source bytes are linked to all three semantic observation IDs',all(f'semantic-link:{x}' in c2checks for x in ['AZDO_LINK_INPUT','AZDO_LINK_BINDING','AZDO_LINK_OPERATIVE']))
    for label,c in [('before',before),('after',after)]:
        pv=json.loads(subprocess.run(['python',str(ROOT/'tools/provenance_verify.py'),str(c)],cwd=ROOT,text=True,stdout=subprocess.PIPE).stdout)
        record(f'case003 {label} deterministic extraction is byte-identical to frozen-core evidence', 'core-binding:EXTRACTION_TO_FROZEN_CORE' in {x['check'] for x in pv['checks']})

    # Predeclared natural transition invariants.
    seal=load(tdir/'PREDECLARATION_SEAL.json')
    record('base predeclaration digest remains original sealed value',seal['base_predeclaration']['sha256']=='d52e0760d02bd3b80e998436a022d42d55a1c41f374de1df7babc952418fd668' and sha(tdir/'PREDECLARATION.json')==seal['base_predeclaration']['sha256'])
    amend=seal['amendments'][0]
    record('evidence-role amendment was separately sealed',amend['sha256']=='eaf640da8b22a029748f3d03fd7e5112a437cf13a9dbda713d236db23bd7da11' and sha(tdir/'PREDECLARATION_AMENDMENT_001.json')==amend['sha256'] and amend['timing']=='BEFORE_ANY_V0_7_CORE_EVALUATION_OF_CASE_003')
    record('before and after use the same sealed predeclaration',load(before/'case.json')['predeclaration']['sha256']==load(after/'case.json')['predeclaration']['sha256']==sha(tdir/'PREDECLARATION_SEAL.json'))
    bsc=before/'assurance/source-contract.json'; asc=after/'assurance/source-contract.json'
    record('before and after source consequence contract is byte-identical',bsc.read_bytes()==asc.read_bytes())
    record('shared source contract has frozen expected SHA-256',sha(bsc)=='09825b375d92e17faa3146eddeb403a65d8cba9f75cffc02b326fef764508437')

    # Independent before/after verification.
    bo=td/'before-out'; ao=td/'after-out'
    pb=run('verify',before,'--output',bo); pa=run('verify',after,'--output',ao)
    b=load(bo/'report.json'); a=load(ao/'report.json')
    record('historical BEFORE is consequence regression',pb.returncode==10 and b['product_status']=='CONSEQUENCE_REGRESSION',f'exit={pb.returncode}')
    record('historical BEFORE is correspondence failure without invented D/O',b['structural']['C']=='C0' and b['structural']['D']=='NA' and b['structural']['O']=='NA' and b['structural']['classification']=='CORRESPONDENCE_NOT_ESTABLISHED')
    record('historical BEFORE exact path is contradicted for operative insufficiency',b['exact_realization']['status']=='REALIZATION_CONTRADICTED' and b['exact_realization']['failure_mode']=='OPERATIVE_INSUFFICIENCY')
    ce=b['exact_realization']['minimal_counterexample'] or {}
    record('historical BEFORE minimal witness collapses S0/S1 under HTTP_ETAG signature',ce.get('kind')=='CONSEQUENCE_DIVERGENT_PAIR_COLLAPSED_BY_Z' and ce.get('signature')=={'supplied_value':'S0','validator_kind':'HTTP_ETAG'} and set(ce.get('consequences',[]))=={'UPDATE_COMMITTED','STALE_UPDATE_REJECTED'})
    mism=[w for w in b['worlds'] if not w['matches']]
    record('historical BEFORE witness includes current S0 spuriously rejected',len(mism)==1 and mism[0]['coordinates']['current_blob_sha']=='S0' and mism[0]['required_consequence']=='UPDATE_COMMITTED')
    record('historical BEFORE negative certificate passes independent consumer',b['certificate']['consumer_check']=='PASS')

    record('historical AFTER is PRESERVED',pa.returncode==0 and a['product_status']=='PRESERVED',f'exit={pa.returncode}')
    record('historical AFTER is C1/D1/O1',tuple(a['structural'][k] for k in ['C','D','O'])==('C1','D1','O1') and a['structural']['classification']=='STRUCTURAL_ASSURANCE_ESTABLISHED')
    record('historical AFTER Exact Realization is established',a['exact_realization']['status']=='REALIZATION_ESTABLISHED' and a['exact_realization']['failure_mode']=='NONE')
    record('historical AFTER both bounded worlds match',len(a['worlds'])==2 and all(w['matches'] for w in a['worlds']))
    record('historical AFTER positive certificate passes independent consumer',a['certificate']['consumer_check']=='PASS')

    # Pair adjudication is a pure deterministic function over independently certificate-backed results.
    hs=importlib.util.spec_from_file_location('hist_transition',ROOT/'tools/historical_transition.py')
    hm=importlib.util.module_from_spec(hs); assert hs.loader; hs.loader.exec_module(hm)
    proto=load(tdir/'TRANSITION_PROTOCOL.json')
    tr=hm.build_result(proto,b,pb.returncode,a,pa.returncode,sha(bsc))
    tr2=hm.build_result(proto,b,pb.returncode,a,pa.returncode,sha(bsc))
    record('historical pair adjudicator derives a result from independent reports',tr['case_id']==proto['case_id'])
    record('historical pair is repair-consistent, not manually labeled',tr['classification']=='REPAIR_CONSISTENT_HISTORICAL_TRANSITION')
    record('historical semantic delta is exact expected transition',tr['semantic_delta']=={'product_status':'CONSEQUENCE_REGRESSION -> PRESERVED','C':'C0 -> C1','D':'NA -> D1','O':'NA -> O1','exact_status':'REALIZATION_CONTRADICTED -> REALIZATION_ESTABLISHED','exact_failure_mode':'OPERATIVE_INSUFFICIENCY -> NONE'})
    record('historical pair adjudication is deterministic',json.dumps(tr,sort_keys=True)==json.dumps(tr2,sort_keys=True))
    record('historical pair reproduces sealed transition result',tr==load(tdir/'TRANSITION_RESULT.json'))
    record('historical pair preserves source-contract identity',tr['shared_source_contract_byte_identical'] is True and tr['shared_source_contract_sha256']==sha(bsc))

    # Preservation lock for AFTER; BEFORE must never become production-style lock implicitly.
    alock=load(after/'risu.lock.json')
    record('historical AFTER lock is a preservation gate',alock['baseline_policy']=='PRESERVATION_GATE' and alock['commitments']['product_status']=='PRESERVED')
    record('historical AFTER preservation lock reproduces including provenance',not rv.compare_lock(a,alock) and alock['provenance_commitments']['evidence_provenance_sha256']==a['provenance']['sha256'])
    try:
        rv.make_lock(b); refused=False
    except SystemExit as e: refused=e.code==10
    record('historical BEFORE cannot be preservation-locked without explicit research acceptance',refused)

    # Fail-closed provenance attacks. These must die before frozen-core result production.
    attacks=[]
    x=td/'tamper-case002-bytes'; cp_case(case2,x); f=x/'provenance/wiki_upsert_page.pinned.excerpt.ts'; f.write_bytes(f.read_bytes()+b'\n// tamper\n'); attacks.append(('case002 bundled source-byte tamper',x))
    x=td/'tamper-before-bytes'; cp_case(before,x); f=x/'provenance/repositories.go.selected-excerpt.go'; f.write_bytes(f.read_bytes()+b'\n// tamper\n'); attacks.append(('case003 BEFORE source-byte tamper',x))
    x=td/'tamper-before-predecl'; cp_case(before,x); f=x/'PREDECLARATION.json'; f.write_bytes(f.read_bytes()+b'\n'); attacks.append(('case003 base predeclaration tamper',x))
    x=td/'tamper-before-amend'; cp_case(before,x); f=x/'PREDECLARATION_AMENDMENT_001.json'; f.write_bytes(f.read_bytes()+b'\n'); attacks.append(('case003 amendment tamper',x))
    x=td/'tamper-after-extract'; cp_case(after,x); f=x/'provenance/EXTRACTED_SOURCE_FACTS.json'; o=load(f); o['facts'][0]['observation']='tampered'; f.write_text(json.dumps(o,indent=2,sort_keys=True)+'\n'); attacks.append(('case003 deterministic extraction tamper',x))
    x=td/'tamper-after-corecopy'; cp_case(after,x); f=x/'assurance/evidence/extracted_source_facts.json'; f.write_bytes(f.read_bytes()+b'\n'); # adapter pin and provenance core binding both disagree
    # Update neither manifest nor adapter: should fail closed at provenance before core.
    attacks.append(('case003 frozen-core evidence-copy tamper',x))
    for name,c in attacks:
        p=run('verify',c,'--output',td/('out-'+name.replace(' ','-')))
        record(name+' fails closed',p.returncode==30,f'exit={p.returncode}')

    # Manifest substitution attack: attacker changes manifest and case pin together, but leaves
    # semantic-link target observation absent. Structural linkage must still fail.
    x=td/'tamper-semantic-link'; cp_case(case2,x)
    mf=x/'provenance/PROVENANCE_MANIFEST.json'; mo=load(mf); mo['semantic_links'][0]['observation_id']='NONEXISTENT_OBSERVATION'; mf.write_text(json.dumps(mo,indent=2,sort_keys=True)+'\n')
    cm=x/'case.json'; co=load(cm); co['provenance']['sha256']=sha(mf); cm.write_text(json.dumps(co,indent=2,sort_keys=True)+'\n')
    p=run('verify',x,'--output',td/'out-sem-link')
    record('semantic-link substitution fails even with recomputed manifest pin',p.returncode==30,f'exit={p.returncode}')

    # Revision-swap attack: AFTER assurance cannot be relabeled as BEFORE because the BEFORE
    # provenance manifest pins the core-bound extraction copy.
    x=td/'revision-swap'; cp_case(before,x); shutil.rmtree(x/'assurance'); shutil.copytree(after/'assurance',x/'assurance')
    p=run('verify',x,'--output',td/'out-revision-swap')
    record('revision-swap cannot turn BEFORE case into AFTER assurance',p.returncode==30,f'exit={p.returncode}')

print('\nV0.3 qualification summary')
print('='*72); print(f'PASS: {len(PASS)}'); print(f'FAIL: {len(FAIL)}')
if FAIL:
    for n,d in FAIL: print(f'  - {n}: {d}')
    raise SystemExit(1)
