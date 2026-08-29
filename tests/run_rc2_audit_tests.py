#!/usr/bin/env python3
from __future__ import annotations
import hashlib,json,shutil,subprocess,tempfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
PASS=[]; FAIL=[]
def rec(name,ok,detail=''):
    (PASS if ok else FAIL).append((name,detail)); print(f"{'PASS' if ok else 'FAIL'}  {name}"+(f' — {detail}' if detail else ''),flush=True)
def run(cmd,cwd=ROOT): return subprocess.run(cmd,cwd=cwd,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
def load(p): return json.loads(Path(p).read_text())
def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def cp_release(dst):
    shutil.copytree(ROOT,dst,ignore=shutil.ignore_patterns('.risu','__pycache__','*.pyc'))

def rebuild_manifest(r):
    p=run(['python','tools/build_manifest.py'],r)
    if p.returncode: raise RuntimeError(p.stdout)

# Current release-level contracts.
p=run(['python','tools/release_verify.py'])
rec('fast release verifier passes current package',p.returncode==0)
rec('fast release verifier reports provenance as replayed', 'Provenance replay: PASS 4/4 cases' in p.stdout)
rec('fast release verifier labels qualification as recorded, not rerun','Recorded qualification artifact:' in p.stdout and '\nQualification: PASS' not in p.stdout)
rec('full reproduction entrypoint exists and is executable',(ROOT/'reproduce-release.sh').is_file() and bool((ROOT/'reproduce-release.sh').stat().st_mode & 0o111))

# Exact-file-set attack from the hostile audit.
with tempfile.TemporaryDirectory(prefix='risu-rc2-extra-file-') as raw:
    r=Path(raw)/'release'; cp_release(r); (r/'UNMANIFESTED.txt').write_text('must fail\n')
    q=run(['python','tools/release_verify.py'],r)
    rec('unmanifested extra file is rejected',q.returncode!=0 and 'exact file-set mismatch' in q.stdout)

# Stored qualification must be bound to its test code via TOOLCHAIN_SEAL.
with tempfile.TemporaryDirectory(prefix='risu-rc2-test-tamper-') as raw:
    r=Path(raw)/'release'; cp_release(r); (r/'tests/run_v03_tests.py').write_text('#!/usr/bin/env python3\nraise SystemExit(1)\n')
    rebuild_manifest(r)
    q=run(['python','tools/release_verify.py'],r)
    rec('test-suite tamper is rejected even after package manifest rebuild',q.returncode!=0 and 'toolchain seal mismatch' in q.stdout)

# Provenance is really replayed, not accepted from self-consistent metadata.
with tempfile.TemporaryDirectory(prefix='risu-rc2-provenance-tamper-') as raw:
    r=Path(raw)/'release'; cp_release(r)
    c=r/'cases/azure-devops-wiki-etag'; src=c/'provenance/wiki_upsert_page.pinned.excerpt.ts'; src.write_text(src.read_text()+'\n// changed evidence bytes\n')
    mp=c/'provenance/PROVENANCE_MANIFEST.json'; m=load(mp)
    for a in m['artifacts']:
        if a['id']=='AZDO_WIKI_SOURCE_EXCERPT': a['sha256']=sha(src)
    mp.write_text(json.dumps(m,indent=2,sort_keys=True)+'\n')
    cm=c/'case.json'; o=load(cm); o['provenance']['sha256']=sha(mp); cm.write_text(json.dumps(o,indent=2,sort_keys=True)+'\n')
    rebuild_manifest(r)
    q=run(['python','tools/release_verify.py'],r)
    rec('provenance inconsistency is rejected even after manifest and case-pin recomputation',q.returncode!=0 and 'provenance replay failed' in q.stdout)

# Provenance strength is explicit rather than overstated.
case_paths=[ROOT/'cases/github-guarded-merge',ROOT/'cases/azure-devops-wiki-etag',ROOT/'cases/github-create-update-sha-transition/before',ROOT/'cases/github-create-update-sha-transition/after']
all_modes=[]
for c in case_paths:
    m=load(c/'provenance/PROVENANCE_MANIFEST.json')
    for a in m['artifacts']:
        if a.get('upstream'): all_modes.append(a['upstream'].get('binding_mode'))
rec('all recorded remote Git identities declare an explicit binding mode',all_modes and all(x in {'RECORDED_OBJECT_ID_ONLY','FULL_GIT_BLOB'} for x in all_modes))
rec('selected source excerpts do not falsely claim full Git-blob cryptographic binding','FULL_GIT_BLOB' not in all_modes)

# Historical raw/extracted/interpreted layering.
for side in ['before','after']:
    m=load(ROOT/f'cases/github-create-update-sha-transition/{side}/provenance/PROVENANCE_MANIFEST.json')
    aids={a['id'] for a in m['artifacts']}; lids={x['id'] for x in m.get('semantic_links',[])}
    rec(f'case003 {side} retains connector/docs snapshots as separately typed artifacts',{'GH_ISSUE_2133_CONNECTOR_SNAPSHOT','GH_PR_2134_CONNECTOR_SNAPSHOT','GH_CONTENTS_DOCS_SNAPSHOT','GH_CONDITIONAL_DOCS_SNAPSHOT'} <= aids)
    rec(f'case003 {side} links public/contract snapshots to labeled semantic observations',{'GH_LINK_ISSUE_HISTORICAL_ETAG','GH_LINK_ISSUE_HISTORICAL_REJECT','GH_LINK_CONTENTS_CONTRACT','GH_LINK_CONDITIONAL_CONTRACT'} <= lids)

# Sealed pre-run artifacts remain byte-identical to rc1, while post-run audit is additive.
ht=ROOT/'cases/github-create-update-sha-transition'
rec('sealed base predeclaration remains byte-identical',sha(ht/'PREDECLARATION.json')=='d52e0760d02bd3b80e998436a022d42d55a1c41f374de1df7babc952418fd668')
rec('sealed amendment remains byte-identical',sha(ht/'PREDECLARATION_AMENDMENT_001.json')=='eaf640da8b22a029748f3d03fd7e5112a437cf13a9dbda713d236db23bd7da11')
audit=load(ROOT/'POST_RUN_AUDIT_001.json')
rec('post-run audit explicitly refuses retroactive temporal upgrade',audit['sealed_artifacts_modified'] is False and any(x['id']=='AUDIT-PREDECLARATION-TEMPORAL-ANCHOR' for x in audit['findings']))
rec('post-run audit reclassifies amendment more strictly without rewriting it',any('substantive expansion' in x['finding'] for x in audit['findings']))

# Evidence-strength ablation.
abl=load(ht/'EVIDENCE_ABLATION_RESULT.json')
rec('ablation preserves issue-independent C0 finding',abl['issue_independent_structural_statement']['C']=='C0' and abl['issue_independent_structural_statement']['correspondence_directly_depends_on_issue_2133'] is False)
rec('ablation downgrades Exact rather than inventing a verdict',abl['exact_under_ablation']['status']=='NOT_EVALUATED_UNDER_EVIDENCE_ABLATION' and abl['exact_under_ablation']['dependency_detected'] is True)

# Development schemas and versioned adjudication.
p=run(['python','tools/schema_validate.py','--release'])
rec('development artifact schema checks pass',p.returncode==0)
tr=load(ht/'TRANSITION_RESULT.json'); proto=load(ht/'TRANSITION_PROTOCOL.json')
rec('historical pair records a versioned adjudication rule',tr.get('adjudication_rule_id')=='RISU_HISTORICAL_TRANSITION_V1' and proto.get('adjudication_rule_id')=='RISU_HISTORICAL_TRANSITION_V1')
rec('transition protocol discloses that executable rule pinning is post-run hardening','post-run' in proto.get('audit_note','').lower())

# Run manifest now captures convenience toolchain/runtime identity.
with tempfile.TemporaryDirectory(prefix='risu-rc2-runmanifest-') as raw:
    out=Path(raw)/'out'; q=run([str(ROOT/'risu-verify'),'verify',str(ROOT/'cases/azure-devops-wiki-etag'),'--output',str(out)])
    rm=load(out/'run-manifest.json') if q.returncode==0 else {}
    rec('run manifest v0.2 captures adapter/source/toolchain/runtime identity',rm.get('manifest_version')=='0.2' and bool(rm.get('adapter_sha256')) and bool(rm.get('source_contract_sha256')) and 'risu_verify' in rm.get('toolchain',{}) and bool(rm.get('runtime',{}).get('python')))

# CI hierarchy and third-party packaging.
wf=(ROOT/'.github/workflows/risu-verify.yml').read_text()
rec('CI keeps PR path fast and reserves full reproduction for main/tag/manual','pull_request:' in wf and 'full-reproduction:' in wf and './reproduce-release.sh' in wf and 'branches: [main]' in wf)
notices=(ROOT/'THIRD_PARTY_NOTICES.md').read_text()
rec('third-party notices identify retained upstream evidence sources','github/github-mcp-server' in notices and 'microsoft/azure-devops-mcp' in notices and 'google/go-github' in notices)

# Package/toolchain seals expose the hardened release contract.
seal=load(ROOT/'PACKAGE_SEAL.json'); ts=load(ROOT/'TOOLCHAIN_SEAL.json')
rec('package seal preserves rc2 audit-hardening contract',seal.get('release_status') in {'AUDIT_HARDENED_RC2','PROFILE_DRIVEN_PROSPECTIVE_FOUNDATION_RC1'})
critical={'src/risu_verify.py','tools/release_verify.py','tools/provenance_verify.py','tests/run_tests.py','tests/run_v03_tests.py','tests/run_rc2_audit_tests.py','reproduce-release.sh'}
rec('toolchain seal pins critical reproduction executables',critical <= {x['path'] for x in ts['files']})

print('\nRC2 audit-hardening summary')
print('='*72); print(f'PASS: {len(PASS)}'); print(f'FAIL: {len(FAIL)}')
if FAIL:
    for n,d in FAIL: print(f'  - {n}: {d}')
    raise SystemExit(1)
