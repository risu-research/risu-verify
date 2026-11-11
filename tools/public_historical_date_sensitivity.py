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
def records_for_case():
    where=("buildingid="+b+" AND novissueddate >= '2023-10-01T00:00:00' "
           "AND novissueddate < '2025-06-01T00:00:00'")
    try:
        return api("wvxf-dwi5",{"$select":"violationid,novdescription,novissueddate,approveddate,inspectiondate,novtype",
            "$where":where,"$limit":1000})
    except Exception as ex:
        return [{"error":type(ex).__name__+": "+str(ex)[:120]}]
def local_count(rows,col,lo,hi,filter_legal):
    picked=[r for r in rows if lo<=str(r.get(col,""))<hi and
          (not filter_legal or "27-2029" in str(r.get("novdescription","")) or
           "27-2028" in str(r.get("novdescription","")))]
    return {"n":len(picked),"ids":len(set(str(r.get("violationid")) for r in picked))}
rows=records_for_case()
if len(rows)>=1000:
    raise RuntimeError("Truncated data")
if rows and "error" in rows[0]:
    print("SOURCE_ERROR",rows[0],flush=True)
    raise SystemExit(0)
report={"case":"4928681573","source":"NYC public HPD violations dataset",
 "checked_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),
 "windows":{}}
for label,w in yearwindows.items():
    lo,hi=w.split("/")
    report["windows"][label]={col:{
          "legal_citation_screen":local_count(rows,col,lo,hi,True),
          "any_violation":local_count(rows,col,lo,hi,False)}
      for col in ("novissueddate","approveddate","inspectiondate")}
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
