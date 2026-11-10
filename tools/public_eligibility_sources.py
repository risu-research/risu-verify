"""Public program eligibility-source feasibility, without record-level publication."""
import collections,json,re,urllib.parse,urllib.request
HOST="https://data.cityofnewyork.us/resource/"
def get(ds,params):
    r=urllib.request.Request(HOST+ds+".json?"+urllib.parse.urlencode(params),
      headers={"User-Agent":"EligibilitySourcePreflight/1.0"})
    with urllib.request.urlopen(r,timeout=100) as f:return json.load(f)
cohort=get("h4mf-f24e",{"$limit":"500"})
ids=sorted({str(r["building_id"]) for r in cohort})
aep=get("hcir-3275",{"$limit":"6000",
 "$select":"building_id,aep_start_date,discharge_date,current_status"})
aep_ids=collections.defaultdict(list)
for r in aep:
    aep_ids[str(r.get("building_id"))].append(r)
overlaps=set(ids)&set(aep_ids)
official=get("kj4p-ruqc",{"$select":"buildingid,count(*) as n",
  "$where":"buildingid in ("+",".join(ids)+")","$group":"buildingid","$limit":"500"})
sample_ids=[str(r["building_id"]) for r in cohort if str(r.get("program_start_date","")).startswith("2024")][:5]
v=get("wvxf-dwi5",{"$select":"novdescription,novtype,inspectiondate",
 "$where":"buildingid in ("+",".join(sample_ids)+") AND inspectiondate >= '2022-10-01T00:00:00' AND inspectiondate < '2024-07-01T00:00:00'",
 "$limit":"15000"})
codes=collections.Counter()
word=collections.Counter()
for r in v:
    s=(r.get("novdescription") or "").upper()
    codes.update(set(re.findall(r'27[-– ]?202[89]', s)))
    if "HEAT" in s:word["HEAT"]+=1
    if "HOT WATER" in s:word["HOT WATER"]+=1
    if not s:word["EMPTY_DESCRIPTION"]+=1
novtypes=collections.Counter(str(r.get("novtype","MISSING")) for r in v)
print(json.dumps({
 "datasets":{"HPD_buildings":"kj4p-ruqc","AEP":"hcir-3275","HSP":"h4mf-f24e","violations":"wvxf-dwi5"},
 "hsp_unique_ids":len(ids),"hsp_linked_registry_ids":len(official),
 "aep_rows_fetched":len(aep),"unique_hsp_ids_ever_in_aep":len(overlaps),
 "sample_2024_hsp_buildings":len(sample_ids),
 "sample_past_violations":len(v),
 "code_marker_matches":dict(codes),"description_keyword_counts":dict(word),
 "novtype_distribution":dict(novtypes),
 "warning":"Past AEP participation does not establish simultaneous eligibility exclusion. Code regex is only a feasibility diagnostic; not a legal classification."
},indent=2))
assert len(v)<15000
