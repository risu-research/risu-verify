"""Public administrative category-drift checks; aggregates only, no row exports."""
import collections,json,urllib.parse,urllib.request
ROOT="https://data.cityofnewyork.us/resource/"
def get(ds,params):
    url=ROOT+ds+".json?"+urllib.parse.urlencode(params)
    req=urllib.request.Request(url,headers={"User-Agent":"OpenDataCategoryQA/1.0"})
    with urllib.request.urlopen(req,timeout=125) as r:return json.load(r)
hsp=get("h4mf-f24e",{"$limit":"500"})
ids=sorted({str(v["building_id"]) for v in hsp})
rows=get("ygpa-z7cr",{
 "$select":"date_extract_y(received_date) as yr,major_category,count(*) as n,count(distinct complaint_id) as c",
 "$where":"building_id in ("+",".join(ids)+") AND received_date >= '2017-01-01T00:00:00' AND major_category in ('HEATING','HEAT/HOT WATER')",
 "$group":"date_extract_y(received_date),major_category",
 "$order":"yr,major_category","$limit":"100"})
assert len(rows)<100
print(json.dumps({"source":"official NYC open data", "building_ids":len(ids),
  "year_category_problem_counts":rows,
  "warning":"Distinct complaints by category may overlap; do not sum category-level unique-complaint counts."},indent=2))
