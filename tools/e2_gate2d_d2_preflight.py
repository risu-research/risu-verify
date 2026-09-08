#!/usr/bin/env python3
from __future__ import annotations
import argparse,json,hashlib
from pathlib import Path
def blob(b):return hashlib.sha1(f'blob {len(b)}\0'.encode()+b).hexdigest()
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--root',default='.');ap.add_argument('--out',required=True);a=ap.parse_args();r=Path(a.root);fail=[]
 m=json.loads((r/'evaluation/gate2d/D1_IDENTITY_MANIFEST_v0.1.json').read_bytes())
 for p,x in sorted(m['files'].items()):
  b=(r/p).read_bytes()
  if hashlib.sha256(b).hexdigest()!=x['sha256'] or blob(b)!=x['git_blob'] or len(b)!=x['size']:fail.append('D1_IDENTITY:'+p)
 c=json.loads((r/'protocols/RISU_DIFF_E2_GATE2D_EVALUATION_CONSTITUTION_v0.1.json').read_bytes())
 for p,g in sorted(c['authority_locks']['semantic_snapshot']['critical_blob_locks'].items()):
  if blob((r/p).read_bytes())!=g:fail.append('SEMANTIC_SNAPSHOT:'+p)
 f=json.loads((r/'experiments/risu-diff-e2/qualification/gate2d-evaluation-constitution/d1-identity-first-complete/freeze_receipt.json').read_bytes())
 if f.get('status')!='GATE2D_D1_FIRST_COMPLETE_IDENTITY_QUALIFICATION_IMMUTABLY_FROZEN' or f.get('d1_success') is not True:fail.append('D1_FREEZE')
 out={'schema':'risu.e2-gate2d-d2-preflight/v0.1','status':'PASS' if not fail else 'FAIL','failures':fail,'d1_manifest_exact':not any(z.startswith('D1_') for z in fail),'semantic_snapshot_exact':not any(z.startswith('SEMANTIC_') for z in fail),'epistemic10_read':False,'truth_read':False,'fresh_target_read':False,'mutation_algebra_opened':False}
 Path(a.out).write_text(json.dumps(out,sort_keys=True,separators=(',',':'))+'\n')
 if fail:raise SystemExit(2)
if __name__=='__main__':main()
