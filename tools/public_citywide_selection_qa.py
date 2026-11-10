"""Citywide reconstruction test for a published rule-based selection procedure.

Only aggregate diagnostics are printed. This is NOT a causal RD design until
selection cutoff and all exclusions are reproduced independently.
"""
import collections,datetime,json,urllib.parse,urllib.request,time
HOST="https://data.cityofnewyork.us/resource/"
HDR={"User-Agent":"MunicipalSelectionReproductionQA/1.0"}
def get(ds,p):
    url=HOST+ds+".json?"+urllib.parse.urlencode(p)
    last=None
    for attempt in range(2):
        try:
            r=urllib.request.Request(url,headers=HDR)
            with urllib.request.urlopen(r,timeout=180) as f:return json.load(f)
        except Exception as ex:
            last=ex
            time.sleep(3)
    raise last
def season_pools(which,start,end):
    if which=="v":
        key,ds="buildingid","wvxf-dwi5"
        date="novissueddate"
        extra=" AND (novdescription like '%27-2029%' OR novdescription like '%27-2028%')"
        sel=key+",count(*) as n"
    else:
        key,ds="building_id","ygpa-z7cr"
        date="received_date"
        extra=" AND major_category='HEAT/HOT WATER' AND apartment is not null"
        sel=key+",count(distinct apartment) as n"
    where=date+" >= '"+start+"T00:00:00' AND "+date+" < '"+end+"T00:00:00'"+extra
    rows=get(ds,{"$select":sel,"$where":where,"$group":key,"$limit":"50000"})
    if len(rows)==50000:raise RuntimeError("Full-city aggregate truncated")
    print(which,start,"candidate buildings",len(rows),flush=True)
    return {str(r[key]):int(r["n"]) for r in rows}
hsp=get("h4mf-f24e",{"$limit":"500"})
selected={str(v["building_id"]) for v in hsp if str(v.get("program_start_date","")).startswith("2024")}
assert len(selected)==50
dates=[("2022","2022-10-01","2023-06-01"),("2023","2023-10-01","2024-06-01")]
v={};c={}
for name,start,end in dates:
    v[name]=season_pools("v",start,end)
    c[name]=season_pools("c",start,end)
ids=(set(v["2022"])&set(v["2023"])&set(c["2022"])&set(c["2023"]))
eligible={bid for bid in ids if v["2022"].get(bid,0)+v["2023"].get(bid,0)>=4
   and c["2022"].get(bid,0)>=2 and c["2023"].get(bid,0)>=2}
rank=lambda bid:v["2022"].get(bid,0)+v["2023"].get(bid,0)
aep=get("hcir-3275",{"$limit":"6000",
   "$select":"building_id,aep_start_date,discharge_date"})
active_aep=set()
ambiguous_aep=0
for r in aep:
    start=r.get("aep_start_date","")[:10]
    end=r.get("discharge_date","")[:10]
    if not start:
        ambiguous_aep+=1
        continue
    if start<="2024-07-01" and (not end or end>"2024-07-01"):
        active_aep.add(str(r["building_id"]))
eligible_no_aep=eligible-active_aep
sorted_all=sorted(eligible,key=lambda b:(-rank(b),b))
sorted_noaep=sorted(eligible_no_aep,key=lambda b:(-rank(b),b))
def indicators(sequence):
    top50=set(sequence[:50])
    score=rank(sequence[49]) if len(sequence)>=50 else None
    n_above=sum(rank(k)>score for k in sequence) if score is not None else None
    n_equal=sum(rank(k)==score for k in sequence) if score is not None else None
    return {"top50_selected_overlap":len(top50&selected),
            "rank50_violation_count":score,
            "count_strictly_above_cutoff":n_above,
            "count_at_cutoff":n_equal}
result={
 "sources":"NYC official public Socrata datasets; read-only",
 "checked_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),
 "published_selected_2024":len(selected),
 "selected_meeting_observable_eligibility":len(selected&eligible),
 "qualifying_citywide_prior_season_pool":len(eligible),
 "qualifying_pool_after_observable_AEP_exclusion":len(eligible_no_aep),
 "published_selected_excluded_by_AEP_proxy":len(selected&active_aep),
 "aep_missing_start_dates":ambiguous_aep,
 "ranking_without_exclusion":indicators(sorted_all),
 "ranking_with_AEP_proxy":indicators(sorted_noaep),
 "selected_rank_range_before_exclusion":[min(rank(b) for b in selected),max(rank(b) for b in selected)],
 "cautions":[
  "Matching free-text violation code markers is an unverified proxy for precise legal violation codes.",
  "Selection tie-break depends on percentage of affected dwelling units; this test omits tie-break.",
  "Article 7A, in rem foreclosure, and discretionary eligibility details are not resolved.",
  "AEP start/end interval is a historical exclusion proxy, not a complete legal status determination.",
  "Raw rank order and selected overlap are diagnostic only, not an identified RD estimate.",
  "Do not draw causal conclusions or infer agency noncompliance from rank mismatch."
 ]}
print("RESULT_BEGIN",flush=True)
print(json.dumps(result,indent=2,sort_keys=True),flush=True)
print("RESULT_END",flush=True)
