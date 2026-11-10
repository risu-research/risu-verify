"""Read-only bounded micro-panel feasibility check for public municipal datasets.

Fetches four program records (one per cohort) and aggregates in memory.
No addresses, apartment identifiers or individual-level rows are published.
"""
import collections
import datetime
import json
import urllib.parse
import urllib.request

BASE="https://data.cityofnewyork.us/resource/"
def fetch(name,params):
    url=BASE+name+".json?"+urllib.parse.urlencode(params)
    r=urllib.request.Request(url,headers={"User-Agent":"PublicRecordMicroAudit/1.0"})
    with urllib.request.urlopen(r,timeout=90) as response:
        return json.load(response)
def season(stamp):
    if not stamp: return "MISSING"
    try:
        d=datetime.date.fromisoformat(stamp[:10])
        return str(d.year if d.month>=10 else d.year-1) if d.month>=10 or d.month<=5 else "OUTSIDE_HEAT_SEASON"
    except (ValueError,TypeError): return "INVALID"
def main():
    selection=fetch("h4mf-f24e",{"$limit":500})
    picked={}
    for row in selection:
        yr=row.get("program_start_date","")[:4]
        if yr and yr not in picked: picked[yr]=row
    ids=[str(v["building_id"]) for v in picked.values()]
    clause="("+",".join(ids)+")"
    eventrows=fetch("ygpa-z7cr",{
        "$select":"building_id,received_date,complaint_id,major_category,problem_duplicate_flag",
        "$where":"building_id in "+clause+" AND received_date >= '2021-01-01T00:00:00'",
        "$limit":50000})
    violrows=fetch("wvxf-dwi5",{
        "$select":"buildingid,inspectiondate,violationid,novdescription,class",
        "$where":"buildingid in "+clause+" AND inspectiondate >= '2021-01-01T00:00:00'",
        "$limit":50000})
    per=collections.Counter()
    unique=collections.defaultdict(set)
    category=collections.Counter()
    duplicates=collections.Counter()
    for r in eventrows:
        seasonid=season(r.get("received_date"))
        key=(str(r.get("building_id")),seasonid)
        per[key]+=1
        if r.get("complaint_id"):unique[key].add(r["complaint_id"])
        category[r.get("major_category") or "MISSING"]+=1
        duplicates[str(r.get("problem_duplicate_flag","MISSING"))]+=1
    violations=collections.Counter()
    heat_examples=collections.Counter()
    for r in violrows:
        key=(str(r.get("buildingid")),season(r.get("inspectiondate")))
        violations[key]+=1
        desc=(r.get("novdescription") or "").upper()
        if "HEAT" in desc or "HOT WATER" in desc:
            heat_examples["heat_or_hot_water_keyword"]+=1
        else:heat_examples["other"]+=1
    coverage={}
    for yr,row in sorted(picked.items()):
        bid=str(row["building_id"])
        coverage[yr]={
            "event_rows":sum(n for (k,s),n in per.items() if k==bid),
            "unique_complaint_ids":len(set().union(*(ids_set for (k,s),ids_set in unique.items() if k==bid))),
            "violation_rows":sum(n for (k,s),n in violations.items() if k==bid),
            "seasons":{s:{"problem_rows":n,"unique_complaints":len(unique[(k,s)]),
                "violation_rows":violations.get((k,s),0)}
                for (k,s),n in sorted(per.items()) if k==bid},
        }
    report={
        "checked_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "sample_size":len(ids),"cohorts":sorted(picked),
        "sample_coverage":coverage,
        "complaint_major_category_counts":dict(category.most_common(25)),
        "problem_duplicate_flag_counts":dict(duplicates),
        "violation_keyword_rough_screen":dict(heat_examples),
        "event_api_truncation_possible":len(eventrows)==50000,
        "violation_api_truncation_possible":len(violrows)==50000,
        "warning":"Keyword screen is exploratory; no causal-effect or true heat-code determination."
    }
    print(json.dumps(report,indent=2,sort_keys=True))
    assert not report["event_api_truncation_possible"] and not report["violation_api_truncation_possible"],"Truncated sample"
if __name__=="__main__":main()
