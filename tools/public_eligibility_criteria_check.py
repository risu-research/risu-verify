"""Check whether published program selections meet reconstructable prior-season criteria.

Read-only official APIs. Aggregated cohort feasibility only; no property IDs logged.
Rules may use nonpublic exclusions and dates not fully reconstructable.
"""
import collections
import datetime
import json
import urllib.parse
import urllib.request

HOST="https://data.cityofnewyork.us/resource/"
H={"User-Agent":"PublicEligibilityCriteriaQA/1.0"}
def get(ds,p):
    url=HOST+ds+".json?"+urllib.parse.urlencode(p)
    req=urllib.request.Request(url,headers=H)
    with urllib.request.urlopen(req,timeout=130) as f:return json.load(f)
hsp=get("h4mf-f24e",{"$limit":"500"})
target=[r for r in hsp if str(r.get("program_start_date","")).startswith("2024")]
ids={str(r["building_id"]) for r in target}
assert len(target)==50
term="("+",".join(sorted(ids))+")"
windows=[("2022","2022-10-01","2023-06-01"),("2023","2023-10-01","2024-06-01")]
v=collections.defaultdict(dict)
c=collections.defaultdict(dict)
for label,start,end in windows:
    vwhere=("buildingid in "+term+" AND novissueddate >= '"+start+
     "T00:00:00' AND novissueddate < '"+end+
     "T00:00:00' AND (novdescription like '%27-2029%' OR novdescription like '%27-2028%')")
    vrows=get("wvxf-dwi5",{"$select":"buildingid,count(*) as n",
         "$where":vwhere,"$group":"buildingid","$limit":"300"})
    for r in vrows:v[str(r["buildingid"])][label]=int(r["n"])
    cwhere=("building_id in "+term+" AND received_date >= '"+start+
     "T00:00:00' AND received_date < '"+end+
     "T00:00:00' AND major_category='HEAT/HOT WATER' AND apartment is not null")
    crows=get("ygpa-z7cr",{"$select":"building_id,count(distinct apartment) as units",
        "$where":cwhere,"$group":"building_id","$limit":"300"})
    for r in crows:c[str(r["building_id"])][label]=int(r["units"])
eligible_v_both=sum(v[k].get("2022",0)>=1 and v[k].get("2023",0)>=1 for k in ids)
eligible_v_total=sum(v[k].get("2022",0)+v[k].get("2023",0)>=4 for k in ids)
eligible_c_both=sum(c[k].get("2022",0)>=2 and c[k].get("2023",0)>=2 for k in ids)
all_observed=sum(v[k].get("2022",0)>=1 and v[k].get("2023",0)>=1
 and v[k].get("2022",0)+v[k].get("2023",0)>=4
 and c[k].get("2022",0)>=2 and c[k].get("2023",0)>=2 for k in ids)
summary={
 "source":"NYC public official API and 28 RCNY 56-02",
 "checked_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),
 "listed_2024_selections":len(target),"unique_listed_ids":len(ids),
 "violation_sections_in_both_prior_seasons":eligible_v_both,
 "violation_sections_at_least_four_total":eligible_v_total,
 "distinct_complaint_apartments_at_least_two_each_season":eligible_c_both,
 "all_three_observable_conditions":all_observed,
 "violation_counts_by_season_total":{y:sum(v[k].get(y,0) for k in ids) for y,_,_ in windows},
 "apartment_counts_by_season_total":{y:sum(c[k].get(y,0) for k in ids) for y,_,_ in windows},
 "warnings":[
   "Uses issue date and text mentions of 27-2029/27-2028 as PROXIES for legally classified violations.",
   "Empty apartment labels and inconsistent unit labels can bias distinct-apartment counts.",
   "The legal agency selection query may have additional eligibility rules, exclusions, timing and final ranking.",
   "Failure to reconstruct is not proof the agency breached the selection law.",
   "This is feasibility only, not a regression discontinuity identification."
 ]}
print(json.dumps(summary,indent=2))
