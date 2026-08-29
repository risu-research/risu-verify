#!/usr/bin/env python3
from pathlib import Path
import argparse,json,subprocess,hashlib

def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def load(p): return json.loads(p.read_text())

def analyze(root: Path, case: Path):
    p=subprocess.run([str(root/'risu-verify'),'verify',str(case),'--json'],cwd=root,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    if p.returncode not in {0,10,20}: raise RuntimeError(p.stdout)
    report=json.loads(p.stdout)
    adapter=load(case/'assurance/adapter.json')
    issue_binding='B-GH-ISSUE-2133'
    issue_node='N-B-GH-ISSUE-2133'
    issue_fact='FACT-GH_BEFORE_SPURIOUS_REJECT'
    edges=adapter.get('provenance',{}).get('edges',[])
    c_issue_direct=any(e.get('from') in {issue_node,issue_fact} and e.get('to')=='CLAIM-C' for e in edges)
    exact_issue_dependency=any(e.get('from') in {issue_node,issue_fact} and e.get('to') in {'CLAIM-EXACT','DERIVE-EXACT'} for e in edges)
    mechanism=adapter['target']['derivation']['program']['mechanism']
    mechanism_dep=issue_fact.replace('FACT-','') in mechanism.get('required_fact_ids',[]) or 'GH_BEFORE_SPURIOUS_REJECT' in mechanism.get('required_fact_ids',[])
    return {
      'ablation_version':'1.0',
      'analysis_kind':'DEPENDENCY_ABLATION_NOT_A_NEW_CORE_RUN_WITH_ALTERED_PREMISES',
      'case_id':report['case_id'],
      'full_evidence_result':{
        'product_status':report['product_status'],'structural':report['structural'],'exact_realization':{'status':report['exact_realization']['status'],'failure_mode':report['exact_realization']['failure_mode']},'certificate_sha256':report['certificate']['sha256']
      },
      'removed_evidence_role':'Public historical empirical observation from issue #2133.',
      'issue_independent_structural_statement':{
        'C':report['structural']['C'],'D':report['structural']['D'],'O':report['structural']['O'],
        'correspondence_directly_depends_on_issue_2133':c_issue_direct,
        'interpretation':'C0 is supported by the source/contract correspondence analysis without using issue #2133 as a direct ground for CLAIM-C. D/O remain NA because structural evaluation stops at C0.'
      },
      'exact_under_ablation':{
        'status':'NOT_EVALUATED_UNDER_EVIDENCE_ABLATION',
        'reason':'The pre-fix Exact mechanism and derivation depend on the historical spurious-rejection fact. Removing that empirical evidence removes the declared grounding for the Exact contradiction rather than converting it into a positive result.',
        'dependency_detected':bool(exact_issue_dependency and mechanism_dep)
      },
      'adapter_sha256':sha(case/'assurance/adapter.json'),
      'boundary':'This is a post-run dependency analysis of the frozen Case 003 adapter. It does not alter the sealed predeclaration, does not issue a second certificate, and does not claim that the frozen core was rerun under a different unsealed model.'
    }

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--write',action='store_true'); a=ap.parse_args()
    root=Path(__file__).resolve().parents[1]; case=root/'cases/github-create-update-sha-transition/before'
    out=analyze(root,case)
    text=json.dumps(out,indent=2,sort_keys=True)+'\n'
    if a.write: (root/'cases/github-create-update-sha-transition/EVIDENCE_ABLATION_RESULT.json').write_text(text)
    print(text,end='')
if __name__=='__main__': main()
