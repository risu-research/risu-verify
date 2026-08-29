#!/usr/bin/env python3
from __future__ import annotations
import hashlib,json,subprocess,sys,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]

def load(p): return json.loads(p.read_text(encoding='utf-8'))
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
checks=[]
def ck(name, cond, detail=''): checks.append((name,bool(cond),str(detail)))

profile=load(ROOT/'profiles/version-bound-effect/PROFILE.json')
ck('profile id',profile.get('profile_id')=='version-bound-effect')
ck('profile maturity development',profile.get('maturity')=='development')
ck('profile outside scientific TCB',profile.get('trusted_status')=='UNTRUSTED_AUTHORING_PROFILE')
ck('profile supports three calibrated patterns',set(profile.get('supported_projection_patterns',[]))=={'PRESERVED_COMPARE','OMITTED_REVIEWED_GUARD','WRONG_VALIDATOR_REJECT_PATH'})
ck('profile forbids verdict issuance','declare PRESERVED or CONSEQUENCE_REGRESSION' in profile['trust_boundary']['profile_compiler_may_not'])

cal=ROOT/'profiles/version-bound-effect/calibration'
instances=sorted(cal.glob('*.instance.json'))
ck('four calibration instances',len(instances)==4,len(instances))
ck('four separate carrier envelopes',len(list(cal.glob('*.envelope.json')))==4)
for p in instances:
    x=load(p)
    ck(f'{p.stem} calibration-only',x.get('status')=='CALIBRATION_ONLY')
    ck(f'{p.stem} uses VBE',x.get('profile')=='version-bound-effect')

with tempfile.TemporaryDirectory(prefix='risu-vbe-test-') as td:
    td=Path(td)
    proc=subprocess.run([sys.executable,str(ROOT/'tools/vbe_differential.py'),'--output',str(td/'diff.json')],cwd=ROOT,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    ck('differential compiler execution',proc.returncode==0,proc.stdout[-1000:])
    if (td/'diff.json').is_file():
        d=load(td/'diff.json')
        ck('differential status PASS',d.get('status')=='PASS')
        ck('differential calibration count 4',d.get('calibration_count')==4)
        for row in d.get('rows',[]):
            ck(f"{row['instance']} semantic differential",row.get('pass') is True)
            ck(f"{row['instance']} source semantic digest equal",row['checks'].get('source_semantic_digest') is True)
            ck(f"{row['instance']} world consequence rows equal",row['checks'].get('worlds') is True)
            ck(f"{row['instance']} product status equal",row['checks'].get('product_status') is True)

with tempfile.TemporaryDirectory(prefix='risu-init-test-') as td:
    td=Path(td)/'new-case'
    proc=subprocess.run([str(ROOT/'risu-verify'),'init','--profile','version-bound-effect','--output',str(td),'--name','prospective-smoke'],cwd=ROOT,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    ck('risu init executes',proc.returncode==0,proc.stdout)
    if (td/'vbe-instance.json').is_file():
        x=load(td/'vbe-instance.json')
        ck('risu init emits DRAFT_UNVERIFIED',x.get('status')=='DRAFT_UNVERIFIED')
        ck('draft explicitly not verdict eligible',x.get('authoring_state',{}).get('verdict_eligible') is False)
        c=subprocess.run([sys.executable,str(ROOT/'tools/vbe_compile.py'),str(td/'vbe-instance.json'),'--output',str(td/'compiled')],cwd=ROOT,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        ck('compiler refuses draft instance',c.returncode!=0,c.stdout)

proto=load(ROOT/'protocols/PROSPECTIVE_CORPUS_0.1_PROTOCOL.json')
seal=load(ROOT/'protocols/PROSPECTIVE_CORPUS_0.1_PROTOCOL_SEAL.json')
attempt=load(ROOT/'protocols/EXTERNAL_TIMESTAMP_ATTEMPT_001.json')
ck('protocol identity',proto.get('protocol_id')=='PROSPECTIVE_CORPUS_0.1_PROTOCOL')
ck('protocol seal matches bytes',seal.get('protocol_sha256')==sha(ROOT/'protocols/PROSPECTIVE_CORPUS_0.1_PROTOCOL.json'))
ck('protocol pins profile',seal.get('profile_sha256')==sha(ROOT/'profiles/version-bound-effect/PROFILE.json'))
ck('protocol batch fixed at 8',proto['batch_design'].get('enrollment_target')==8)
ck('protocol has no result quota',proto['batch_design'].get('result_quota')=='NONE')
ck('protocol permits null regression result','no regressions' in proto['batch_design'].get('null_result_policy',''))
ck('known bug hunt prohibited',proto['selection'].get('known_bug_hunt_prohibited') is True)
ck('no screening at seal',proto['screening_state_at_local_seal'].get('candidate_screening_started') is False)
ck('external timestamp required before screening',proto['external_timestamp'].get('required_before_first_candidate_screening') is True)
ck('external timestamp not falsely claimed',proto['external_timestamp'].get('current_status')=='NOT_YET_EXTERNALLY_TIMESTAMPED')
ck('failed publication attempt recorded',attempt.get('attempt_status')=='FAILED_NO_WRITE_PERMISSION')
ck('screening gate remains closed',attempt.get('candidate_screening_gate')=='CLOSED')
for key,path in [('risu_verify_py_sha256',ROOT/'src/risu_verify.py'),('vbe_compile_py_sha256',ROOT/'tools/vbe_compile.py'),('vbe_differential_py_sha256',ROOT/'tools/vbe_differential.py')]:
    ck(f'protocol tool pin {key}',proto['adjudication']['implementation_pins'][key]==sha(path))
ck('protocol pins frozen core',proto['scientific_core']['archive_sha256']==load(ROOT/'CORE_PIN.json')['archive_sha256'])
ck('diversity org gate >=4',proto['diversity_gates']['minimum_independent_organizations']>=4)
ck('diversity mechanism gate >=3',proto['diversity_gates']['minimum_carrier_or_mechanism_families']>=3)
ck('maximum 2 units per organization',proto['diversity_gates']['maximum_units_from_one_organization']==2)

passed=sum(x[1] for x in checks); total=len(checks)
for name,ok,detail in checks:
    print(f"{'PASS' if ok else 'FAIL'}  {name}")
    if not ok and detail: print('      '+detail.replace('\n','\n      '))
print(f"\nVBE / PROSPECTIVE QUALIFICATION: {passed}/{total} PASS")
summary={'status':'PASS' if passed==total else 'FAIL','tests_total':total,'tests_passed':passed,'tests_failed':total-passed,'taxonomy':'VBE profile differential calibration + narrow init authoring + prospective corpus protocol sealing'}
(ROOT/'results/V0.4.0_RC1_VBE_PROSPECTIVE_QUALIFICATION.json').write_text(json.dumps(summary,indent=2,sort_keys=True)+'\n')
raise SystemExit(0 if passed==total else 1)
