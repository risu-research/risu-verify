"""Frozen out-of-year one-record discrepancy: historical date and citation sensitivity.

Only public aggregate counts and pseudonymous ID. No parameter tuning to maximize hits.
"""
import collections,hashlib,json,urllib.parse,urllib.request,datetime
H="https://data.cityofnewyork.us/resource/"
def api(ds,params):
    u=H+ds+".json?"+urllib.parse.urlencode(params)
    with urllib.request.urlopen(urllib.request.Request(u,headers={"User-Agent":"HistoricalDateAudit/1.0"}),timeout=120) as r:return json.load(r)
hsp=api("h4mf-f24e",{"$limit":500})
sig=lambda b:hashlib.sha256(("rank-2024:"+str(b)).encode()).hexdigest()[:10]
hits=[v for v in hsp if sig(v.get("building_id"))=="4928681573"]
assert len(hits)==1
b=str(hits[0]["building_id"])
yearwindows={"2023":"2023-10-01T00:00:00/2024-06-01T00:00:00","2024":"2024-10-01T00:00:00/2025-06-01T00:00:00"}
def counts(col,lo,hi,filter_legal=True):
    where="buildingid="+b+" AND "+col+" >= '"+lo+"' AND "+col+" < '"+hi+"'"
    if filter_legal:where+=" AND (novdescription like '%27-2029%' OR novdescription like '%27-2028%')"
    rows=api("wvxf-dwi5",{"$select":"count(*) as n,count(distinct violationid) as ids",
                          "$where":where})
    return {k:int(v) for k,v in rows[0].items()}
report={"case":"4928681573","source":"NYC public HPD violations dataset",
 "checked_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),
 "windows":{}}
for label,w in yearwindows.items():
    lo,hi=w.split("/")
    report["windows"][label]={col:{
          "legal_citation_screen":counts(col,lo,hi,True),
          "any_violation":counts(col,lo,hi,False)}
      for col in ("novissueddate","approveddate","inspectiondate")}
# citation near-variants in 2023 and 2024 lookback
rows=api("wvxf-dwi5",{"$select":"novdescription,novissueddate,approveddate,inspectiondate,novtype,violationid",
 "$where":"buildingid="+b+" AND novissueddate >= '2023-10-01T00:00:00' AND novissueddate < '2025-06-01T00:00:00'",
 "$limit":2500})
assert len(rows)<2500
citation=collections.Counter()
for r in rows:
    t=str(r.get("novdescription","")).upper()
    if "27-2029" in t:citation["27-2029"]+=1
    elif "27-2028" in t:citation["27-2028"]+=1
    elif "HEAT" in t or "HOT WATER" in t:citation["heat_keyword_without_both_codes"]+=1
    else:citation["other_codes"]+=1
report["descriptive_case_counts"]={"records":len(rows),"citation_types":dict(citation),
"violation_ids_unique":len({r.get("violationid") for r in rows})}
report["reasoning_boundary"]="Alternative dates are sensitivity checks, not retrospective substitution of selection rule."
print(json.dumps(report,indent=2,sort_keys=True))
