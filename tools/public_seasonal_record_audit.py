"""Auditable, aggregate-only seasonal linkage for public municipal data.

This is a descriptive data quality audit. A program cohort is not a control group.
Building- or apartment-level records are never printed or uploaded.
"""
import collections
import concurrent.futures
import datetime
import json
import time
import urllib.error
import urllib.parse
import urllib.request

HOST="https://data.cityofnewyork.us/resource/"
SOURCES={"cohort":"h4mf-f24e","events":"ygpa-z7cr","enforcement":"wvxf-dwi5"}
HEAD={"User-Agent":"PublicDataSeasonalQA/1.0"}
CHUNK=25

def fetch(ds, params):
    url=HOST+ds+".json?"+urllib.parse.urlencode(params)
    for attempt in range(2):
        try:
            req=urllib.request.Request(url,headers=HEAD)
            with urllib.request.urlopen(req,timeout=130) as resp:
                return json.load(resp)
        except (urllib.error.URLError,TimeoutError):
            if attempt:raise
            time.sleep(3)

def season(y,m):
    y,m=int(y),int(m)
    return str(y if m>=10 else y-1) if m>=10 or m<=5 else None

def batch(seq,n):
    for start in range(0,len(seq),n):
        yield seq[start:start+n]

def query_one(spec):
    label,idx,ids=spec
    ds=SOURCES[label]
    if label=="events":
        key,dtfield="building_id","received_date"
        cond=" AND major_category in ('HEAT/HOT WATER','HEATING')"
        sel_extra=",count(distinct complaint_id) as unique_complaints"
    else:
        key,dtfield="buildingid","inspectiondate"
        cond=""
        sel_extra=""
    year="date_extract_y("+dtfield+")"
    month="date_extract_m("+dtfield+")"
    terms=key+" in ("+",".join(ids)+") AND "+dtfield+" >= '2018-01-01T00:00:00'"
    terms+=" AND "+dtfield+" < '2026-11-01T00:00:00'"+cond
    params={"$select":key+","+year+" as yr,"+month+" as mo,count(*) as n"+sel_extra,
            "$where":terms,"$group":key+","+year+","+month,"$limit":"12000"}
    rows=fetch(ds,params)
    if len(rows)>=12000:raise RuntimeError("Potential truncated aggregate response")
    for row in rows:
        row["buildingid_value"]=str(row[key])
    return label,idx,rows

def run():
    people=fetch(SOURCES["cohort"],{"$limit":"500"})
    by_id=collections.defaultdict(list)
    for p in people:
        bid=str(p.get("building_id",""))
        if bid.isdigit() and p.get("program_start_date"):
            by_id[bid].append(p["program_start_date"][:4])
    treatment_year={bid:min(yrs) for bid,yrs in by_id.items()}
    cohorts=collections.Counter(treatment_year.values())
    repeat=collections.Counter("/".join(sorted(ys)) for ys in by_id.values() if len(ys)>1)
    ids=sorted(treatment_year)
    specs=[]
    for k,c in enumerate(batch(ids,CHUNK),1):
        specs.extend([("events",k,c),("enforcement",k,c)])
    summaries={label:collections.Counter() for label in ("events","enforcement")}
    coverage={label:collections.defaultdict(set) for label in ("events","enforcement")}
    diagnostics=[]
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        futures={pool.submit(query_one,spec):spec for spec in specs}
        for fut in concurrent.futures.as_completed(futures):
            spec=futures[fut]
            try:
                label,idx,rows=fut.result()
                for row in rows:
                    bid=row["buildingid_value"]
                    sy=season(row["yr"],row["mo"])
                    if sy is None:continue
                    cohort=treatment_year[bid]
                    coverage[label][cohort].add(bid)
                    summaries[label][(cohort,sy,"rows")]+=int(row.get("n",0))
                    if label=="events":
                        summaries[label][(cohort,sy,"unique_complaints")]+=int(row.get("unique_complaints",0))
                print("COMPLETED",label,"chunk",idx,"aggregate_rows",len(rows),flush=True)
            except Exception as ex:
                diagnostics.append({"dataset":spec[0],"batch":spec[1],
                                    "error":type(ex).__name__+": "+str(ex)[:150]})
                print("ERROR",spec[0],spec[1],str(ex)[:150],flush=True)
    result={
        "source":"NYC Open Data official public API; read-only",
        "checked_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "observation":"Descriptive measurement feasibility; no treatment effects.",
        "target_records":len(people),"unique_buildings":len(ids),
        "earliest_entry_cohort_sizes":dict(sorted(cohorts.items())),
        "repeat_selection_patterns":dict(sorted(repeat.items())),
        "event_definition":"HEAT/HOT WATER and HEATING category problem rows; distinct complaint IDs within each building-month",
        "enforcement_definition":"ALL violation rows by inspection date, NOT heat-specific",
        "time_basis":"Oct-May heat season, labeled by October start year; 2026 season is partial through October",
        "matched_buildings_by_cohort":{lab:dict(sorted((c,len(v)) for c,v in vals.items())) for lab,vals in coverage.items()},
        "season_counts":{lab:[
            {"cohort":cohort,"season_start":start,"problems_or_violations":v,
             "unique_complaints":summaries[lab].get((cohort,start,"unique_complaints")) if lab=="events" else None}
            for (cohort,start,metric),v in sorted(summaries[lab].items()) if metric=="rows"]
            for lab in summaries},
        "failed_queries":diagnostics
    }
    print("RESULT_BEGIN",flush=True)
    print(json.dumps(result,sort_keys=True,indent=2),flush=True)
    print("RESULT_END",flush=True)
    if diagnostics:raise SystemExit(2)
if __name__=="__main__":run()
