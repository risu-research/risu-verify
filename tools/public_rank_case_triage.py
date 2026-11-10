"""Independent record-level discrepancy triage for a published selection ranking.

Uses only public administrative records. No addresses or apartment identifiers in logs.
All legal exclusion classifications are provisional absent appointment/deed evidence.
"""
import collections,datetime,hashlib,json,re,time,urllib.parse,urllib.request
BASE="https://data.cityofnewyork.us/resource/"
def get(ds,p):
    url=BASE+ds+".json?"+urllib.parse.urlencode(p)
    for attempt in range(2):
        try:
            with urllib.request.urlopen(urllib.request.Request(url,headers={"User-Agent":"PublicSelectionEvidenceQA/1.0"}),timeout=135) as f:return json.load(f)
        except Exception:
            if attempt==1:raise
            time.sleep(4)
def alias(x):return hashlib.sha256(("rank-2024:"+str(x)).encode()).hexdigest()[:10]
def aggregate(ds,key,date,start,end,more,measure):
    where=date+" >= '"+start+"T00:00:00' AND "+date+" < '"+end+"T00:00:00'"+more
    rows=get(ds,{"$select":key+","+measure+" as n","$where":where,"$group":key,"$limit":50000})
    assert len(rows)<50000
    return {str(x[key]):int(x["n"]) for x in rows}
hsp=get("h4mf-f24e",{"$limit":500})
selected={str(x["building_id"]) for x in hsp if str(x.get("program_start_date","")).startswith("2024")}
past_hsp=collections.defaultdict(set)
for x in hsp:
    past_hsp[str(x["building_id"])].add(str(x.get("program_start_date",""))[:4])
v,c={},{}
for yy,st,en in [("22","2022-10-01","2023-06-01"),("23","2023-10-01","2024-06-01")]:
    v[yy]=aggregate("wvxf-dwi5","buildingid","novissueddate",st,en,
      " AND (novdescription like '%27-2029%' OR novdescription like '%27-2028%')","count(*)")
    c[yy]=aggregate("ygpa-z7cr","building_id","received_date",st,en,
      " AND major_category='HEAT/HOT WATER' AND apartment is not null","count(distinct apartment)")
    print("LOADED",yy,len(v[yy]),len(c[yy]),flush=True)
pool=set(v["22"])&set(v["23"])&set(c["22"])&set(c["23"])
pool={b for b in pool if v["22"][b]+v["23"][b]>=4 and c["22"][b]>=2 and c["23"][b]>=2}
aep=get("hcir-3275",{"$limit":6000,"$select":"building_id,aep_start_date,discharge_date"})
active_aep={str(x["building_id"]) for x in aep if x.get("aep_start_date") and str(x["aep_start_date"])[:10]<="2024-07-01"
 and (not x.get("discharge_date") or str(x["discharge_date"])[:10]>"2024-07-01")}
pool-=active_aep
rank=lambda b:v["22"][b]+v["23"][b]
ranked=sorted(pool,key=lambda b:(-rank(b),b))
cut=rank(ranked[49])
above={b for b in pool if rank(b)>cut}
unselected_high=sorted(above-selected,key=lambda b:(-rank(b),b))
assert len(unselected_high)==10,("expected_10_high_unselected",len(unselected_high))
ids="("+",".join(unselected_high)+")"
reg=get("kj4p-ruqc",{"$select":"buildingid,managementprogram,dobbuildingclassid,boroid,block,lot",
 "$where":"buildingid in "+ids,"$limit":100})
regmap={str(x["buildingid"]):x for x in reg}
lit=get("59kj-x8nc",{"$select":"buildingid,casetype,caseopendate,casestatus,casejudgement",
 "$where":"buildingid in "+ids+" AND casetype='7A'","$limit":1000})
by_lit=collections.defaultdict(list)
for x in lit:by_lit[str(x["buildingid"])].append(x)
vrows=get("wvxf-dwi5",{"$select":"buildingid,novdescription,novissueddate,novtype,violationid",
 "$where":"buildingid in "+ids+" AND novissueddate >= '2022-10-01T00:00:00' AND novissueddate < '2024-06-01T00:00:00' AND (novdescription like '%27-2029%' OR novdescription like '%27-2028%')","$limit":20000})
assert len(vrows)<20000
by_viol=collections.defaultdict(list)
for x in vrows:by_viol[str(x["buildingid"])].append(x)
classified=[]
for b in unselected_high:
    cases=by_lit[b]
    pre=[x for x in cases if x.get("caseopendate","")[:10]<="2024-07-01"]
    vr=by_viol[b]
    counts=collections.Counter()
    for row in vr:
        s=str(row.get("novdescription") or "").upper()
        if "27-2028" in s:counts["2028_mention"]+=1
        if "27-2029" in s:
            if re.search(r"27[- ]2029\\s*\\(A\\)",s):counts["2029_explicit_a"]+=1
            elif re.search(r"27[- ]2029\\s*\\([BCD]\\)",s):counts["2029_explicit_other"]+=1
            else:counts["2029_subsection_not_explicit"]+=1
    regrow=regmap.get(b,{})
    classified.append({
      "case":alias(b),"ranked_violations":rank(b),"viol_2022":v["22"].get(b,0),
      "viol_2023":v["23"].get(b,0),"complaining_apartments_2022":c["22"].get(b,0),
      "complaining_apartments_2023":c["23"].get(b,0),
      "past_heat_sensor_selection":sorted(y for y in past_hsp[b] if y in ("2020","2022")),
      "HPD_management_program_current":regrow.get("managementprogram"),
      "HPD_DOB_class_ID_current":regrow.get("dobbuildingclassid"),
      "pre_cutoff_7A_litigation_records":len(pre),
      "7A_case_outcomes":collections.Counter(str(x.get("casestatus",""))+"/"+str(x.get("casejudgement","")) for x in pre),
      "legal_citation_screen":dict(counts),
      "matched_source_violations":len(vr),
      "screening_status":"UNRESOLVED: check court-appointed 7A/in-rem, legal citation, historical snapshot"
    })
print("RESULT_BEGIN",flush=True)
print(json.dumps({"timestamp_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),
  "above_cutoff_rank":cut,"above_cutoff_total":len(above),
  "selected_above":len(above&selected),"unselected_above":len(unselected_high),
  "historical_7A_proceeding_matches":sum(x["pre_cutoff_7A_litigation_records"]>0 for x in classified),
  "past_HSP_membership_matches":sum(bool(x["past_heat_sensor_selection"]) for x in classified),
  "cases":classified,
  "limits":["7A case filing does not prove court appointment.",
  "Current building management may differ from July 2024.",
  "Text citations are diagnostic proxies, not statutory legal classifications.",
  "Without historical in-rem deed/appointment records, exclusions cannot be certified.",
  "Prior HSP membership is a diagnostic clue, not automatically a statutory exclusion.",
  "No conclusion about agency rule compliance or RD identification is warranted."]},indent=2,sort_keys=True,default=dict),flush=True)
print("RESULT_END",flush=True)
