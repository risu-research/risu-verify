"""Diagnose one holdout disagreement without retuning selection logic.

Prints anonymized criteria flags only. The 2025 cohort is independent of the
2024 development cohort; no decision rules are altered by this report.
"""
import collections,hashlib,json,urllib.parse,urllib.request
HOST="https://data.cityofnewyork.us/resource/"
def get(ds,params):
    url=HOST+ds+".json?"+urllib.parse.urlencode(params)
    request=urllib.request.Request(url,headers={"User-Agent":"PublicSelectionErrorAnalysis/1.0"})
    with urllib.request.urlopen(request,timeout=120) as f:return json.load(f)
def aid(b):return hashlib.sha256(("rank-2024:"+str(b)).encode()).hexdigest()[:10]
hsp=get("h4mf-f24e",{"$limit":500})
sel={str(x["building_id"]) for x in hsp if str(x.get("program_start_date","")).startswith("2025")}
assert len(sel)==50
ids="("+",".join(sorted(sel))+")"
data={}
for y,start,end in [("2023","2023-10-01","2024-06-01"),("2024","2024-10-01","2025-06-01")]:
    violation=get("wvxf-dwi5",{"$select":"buildingid,count(*) as n",
       "$where":"buildingid in "+ids+" AND novissueddate >= '"+start+"T00:00:00' AND novissueddate < '"+end+"T00:00:00' AND (novdescription like '%27-2029%' OR novdescription like '%27-2028%')",
       "$group":"buildingid","$limit":100})
    complaints=get("ygpa-z7cr",{"$select":"building_id,count(distinct apartment) as n",
       "$where":"building_id in "+ids+" AND received_date >= '"+start+"T00:00:00' AND received_date < '"+end+"T00:00:00' AND major_category='HEAT/HOT WATER' AND apartment is not null",
       "$group":"building_id","$limit":100})
    data[y]={"v":{str(x["buildingid"]):int(x["n"]) for x in violation},
             "c":{str(x["building_id"]):int(x["n"]) for x in complaints}}
aep=get("hcir-3275",{"$select":"building_id,aep_start_date,discharge_date","$limit":6000})
active={str(x["building_id"]) for x in aep if x.get("aep_start_date")
    and str(x["aep_start_date"])[:10]<="2025-07-01"
    and (not x.get("discharge_date") or str(x["discharge_date"])[:10]>"2025-07-01")}
reg=get("kj4p-ruqc",{"$select":"buildingid,legalclassa,dobbuildingclass",
    "$where":"buildingid in "+ids,"$limit":100})
reg_by={str(r["buildingid"]):r for r in reg}
prior={str(x["building_id"]) for x in hsp if str(x.get("program_start_date","")).startswith(("2022","2024"))}
fail=[]
for b in sel:
    vals=[data[y][field].get(b,0) for y in ("2023","2024") for field in ("v","c")]
    v23,c23,v24,c24=vals
    eligible=(v23>=1 and v24>=1 and v23+v24>=4 and c23>=2 and c24>=2)
    try:class_eligible=int(reg_by.get(b,{}).get("legalclassa","0"))>=3
    except ValueError:class_eligible=False
    passall=eligible and class_eligible and b not in prior and b not in active
    if not passall:
        fail.append({"case":aid(b),"viol_2023":v23,"viol_2024":v24,
          "unique_apartment_labels_2023":c23,"unique_apartment_labels_2024":c24,
          "basic_eligibility":eligible,"class_a_eligible_current":class_eligible,
          "active_aep_proxy":b in active,"prior_program_proxy":b in prior,
          "building_class_current":reg_by.get(b,{}).get("dobbuildingclass"),
          "classification":"discrepancy in observed eligibility or history, not proof of legal ineligibility"})
print(json.dumps({"development_year":"2024","holdout_year":"2025",
 "holdout_listed":len(sel),"cases_missing_from_reconstructed_eligible_population":fail,
 "warnings":["No ranking thresholds or rules modified.","Violation legal-section text is a proxy.","Observation dates and HSP eligibility exclusions are not archived."]},indent=2))

# Frozen score diagnostic: selected buildings ranked below the 2025 proxy cutoff.
below=[]
for b in sorted(sel):
    s23=data["2023"]["v"].get(b,0)
    s24=data["2024"]["v"].get(b,0)
    if s23+s24<9:
        below.append({"case":aid(b),"prior_violation_proxy_total":s23+s24,
            "season_2023_violations":s23,"season_2024_violations":s24,
            "2023_distinct_apartment_labels":data["2023"]["c"].get(b,0),
            "2024_distinct_apartment_labels":data["2024"]["c"].get(b,0),
            "current_DOB_building_class":reg_by.get(b,{}).get("dobbuildingclass"),
            "candidate_eligible":True})
print("BELOW_CUTOFF_SELECTED",json.dumps(below,sort_keys=True),flush=True)
