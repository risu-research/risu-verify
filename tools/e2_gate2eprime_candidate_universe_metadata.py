#!/usr/bin/env python3
from __future__ import annotations
import hashlib,json,os,subprocess,urllib.parse,urllib.request
from pathlib import Path

QUERY='topic:mcp-server archived:false fork:false'
SEED='RISU_GATE2EPRIME_FRESHEPISTEMIC10_R1_V1'
LIMIT=40
UA='risu-verify-gate2eprime-metadata-snapshot/1'

def cj(x): return (json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False)+'\n').encode()
def get_json(url):
    req=urllib.request.Request(url,headers={'Accept':'application/vnd.github+json','User-Agent':UA,'X-GitHub-Api-Version':'2022-11-28'})
    with urllib.request.urlopen(req,timeout=30) as r:
        return json.load(r)
def rank(full,sha):
    return hashlib.sha256((SEED+'\0'+full+'\0'+sha).encode()).hexdigest()

def main():
    out=Path(os.environ.get('OUT','candidate-metadata-artifact/CANDIDATE_UNIVERSE.json'));out.parent.mkdir(parents=True,exist_ok=True)
    q=urllib.parse.quote_plus(QUERY)
    search_url=f'https://api.github.com/search/repositories?q={q}&per_page={LIMIT}'
    s=get_json(search_url)
    items=s.get('items',[])[:LIMIT]
    history=subprocess.run(['git','log','--all','-p','--no-color','--format='],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,check=True).stdout.lower()
    rows=[];fail=[]
    for item in items:
        full=item.get('full_name');branch=item.get('default_branch')
        if not isinstance(full,str) or not isinstance(branch,str): fail.append('MALFORMED_REPOSITORY_METADATA');continue
        owner=full.split('/',1)[0]
        ref_url='https://api.github.com/repos/'+urllib.parse.quote(full,safe='/')+'/git/ref/heads/'+urllib.parse.quote(branch,safe='')
        try: ref=get_json(ref_url);sha=ref['object']['sha']
        except Exception as e: fail.append('REF_RESOLUTION:'+full+':'+type(e).__name__);continue
        prior=full.lower().encode() in history
        rows.append({'full_name':full,'html_url':item.get('html_url'),'default_branch':branch,'head_sha':sha,'pushed_at':item.get('pushed_at'),'updated_at':item.get('updated_at'),'stargazers_count':item.get('stargazers_count'),'prior_risu_history_mention':prior,'eligible_metadata_only':not prior,'rank_sha256':rank(full,sha),'owner':owner})
    eligible=sorted((r for r in rows if r['eligible_metadata_only']),key=lambda r:(r['rank_sha256'],r['full_name']))
    diverse=[];deferred=[];seen=set()
    for r in eligible:
        if r['owner'] not in seen: diverse.append(r);seen.add(r['owner'])
        else: deferred.append(r)
    ordered=diverse+deferred
    snap={'schema':'risu.e2-gate2eprime-candidate-universe-metadata/v0.1','query':QUERY,'requested_limit':LIMIT,'returned_count':len(items),'resolved_count':len(rows),'failures':sorted(fail),'seed':SEED,'repositories':rows,'eligible_rank_order':[{'full_name':r['full_name'],'head_sha':r['head_sha'],'rank_sha256':r['rank_sha256'],'owner':r['owner']} for r in ordered],'source_bytes_read':False,'target_tree_endpoints_used':False,'target_blob_endpoints_used':False,'target_contents_endpoints_used':False,'raw_target_urls_used':False,'truth_read':False,'semantic_execution_count':0}
    snap['canonical_snapshot_sha256']=hashlib.sha256(cj({k:v for k,v in snap.items() if k!='canonical_snapshot_sha256'})).hexdigest()
    snap['status']='PASS' if len(items)>0 and len(rows)==len(items) and not fail and len(ordered)>=5 else 'FAIL'
    out.write_bytes(cj(snap))
    if snap['status']!='PASS': raise SystemExit(2)
if __name__=='__main__': main()
