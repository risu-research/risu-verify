"""Reconstruct a citywide legal eligibility population and tie priority.

Public municipal API only. Aggregated pseudonymous audit, no addresses or apartment IDs.
This is a proxy reconstruction; no claim of official reproducibility or causal identification.
"""
import collections,datetime,hashlib,json,time,urllib.parse,urllib.request
ROOT="https://data.cityofnewyork.us/resource/"
def get(ds,p):
    u=ROOT+ds+".json?"+urllib.parse.urlencode(p)
    for attempt in range(2):
        try:
            with urllib.request.urlopen(urllib.request.Request(u,headers={"User-Agent":"PublicRegulatoryRankingQA/1.0"}),timeout=140) as r:
                return json.load(r)
        except Exception:
            if attempt:raise
            time.sleep(4)
def alias(b):return hashlib.sha256(("rank-2024:"+str(b)).encode()).hexdigest()[:10]
def counts(ds,key,date,fromdate,todate,extra,aggregation):
    cond=date+" >= '"+fromdate+"T00:00:00' AND "+date+" < '"+todate+"T00:00:00'"+extra
    x=get(ds,{"$select":key+","+aggregation+" as n","$where":cond,"$group":key,"$limit":50000})
    assert len(x)<50000
    return {str(r[key]):int(r["n"]) for r in x}
def standardize(s):
    if not s:return None
    s=" ".join(str(s).strip().upper().replace("#","").replace("APARTMENT","").replace("APT","").split())
    return s if s not in {"","BLDG","BUILDING","PUBLIC AREA","COMMON AREA","ALL","UNKNOWN","N/A","LOBBY"} else None
hsp=get("h4mf-f24e",{"$limit":500})
sel={str(r["building_id"]) for r in hsp if str(r.get("program_start_date","")).startswith("2024")}
prior2022={str(r["building_id"]) for r in hsp if str(r.get("program_start_date","")).startswith("2022")
  and str(r.get("current_status","")).upper()=="ACTIVE"}
assert len(sel)==50 and len(prior2022)==50
v,c={},{}
for y,st,en in [("22","2022-10-01","2023-06-01"),("23","2023-10-01","2024-06-01")]:
    v[y]=counts("wvxf-dwi5","buildingid","novissueddate",st,en,
      " AND (novdescription like '%27-2029%' OR novdescription like '%27-2028%')","count(*)")
    c[y]=counts("ygpa-z7cr","building_id","received_date",st,en,
      " AND major_category='HEAT/HOT WATER' AND apartment is not null","count(distinct apartment)")
    print("Citywide period",y,"loaded",flush=True)
base=set(v["22"])&set(v["23"])&set(c["22"])&set(c["23"])
qualified={b for b in base if v["22"][b]+v["23"][b]>=4 and c["22"][b]>=2 and c["23"][b]>=2}
score={b:v["22"].get(b,0)+v["23"].get(b,0) for b in qualified}
aep=get("hcir-3275",{"$limit":6000,"$select":"building_id,aep_start_date,discharge_date"})
active_aep={str(r["building_id"]) for r in aep if r.get("aep_start_date")
  and str(r["aep_start_date"])[:10]<="2024-07-01"
  and (not r.get("discharge_date") or str(r["discharge_date"])[:10]>"2024-07-01")}
after_aep=qualified-active_aep
print("After AEP:",len(after_aep),flush=True)
# Building-level LEGAL apartment counts. Current snapshot must not be passed off as a 2024 archive.
registry=get("kj4p-ruqc",{"$select":"buildingid,legalclassa,legalclassb,dobbuildingclass,managementprogram",
 "$where":"buildingid in ("+",".join(sorted(after_aep))+")","$limit":1000})
rr={str(r["buildingid"]):r for r in registry}
def class_a_units(b):
    try:return int(rr.get(b,{}).get("legalclassa","0"))
    except (ValueError,TypeError):return 0
one_two={b for b in after_aep if b in rr and class_a_units(b)<3}
missing_registry=after_aep-set(rr)
after_class=after_aep-one_two
prior_again=after_class&prior2022
final=after_class-prior_again
def stage_info(pool):
    ranked=sorted(pool,key=lambda b:(-score[b],b))
    cut=score[ranked[49]]
    high={b for b in pool if score[b]>cut};tie={b for b in pool if score[b]==cut}
    return {"population":len(pool),"rank50_violation_proxy":cut,
      "strictly_above":len(high),"at_cutoff":len(tie),"official_selected_high":len(high&sel),
      "official_selected_tied":len(tie&sel),"top50_overlap_id_fallback":len(sel&set(ranked[:50]))}
stages={"after_AEP":stage_info(after_aep),"after_class_A_apartment_screen":stage_info(after_class),
   "after_prior_2022_program_screen":stage_info(final)}
print("Selection stages complete",flush=True)
ranked=sorted(final,key=lambda b:(-score[b],b))
cut=score[ranked[49]]
above={b for b in final if score[b]>cut}
tie={b for b in final if score[b]==cut}
# Distinct apartment labels over the two prior heat seasons.
rows=get("ygpa-z7cr",{"$select":"building_id,apartment",
 "$where":"building_id in ("+",".join(sorted(tie))+") AND received_date >= '2022-10-01T00:00:00' AND received_date < '2024-06-01T00:00:00' AND major_category='HEAT/HOT WATER'",
 "$limit":45000})
assert len(rows)<45000
unit_labels=collections.defaultdict(set); unknown=collections.Counter();all_rows=collections.Counter()
for r in rows:
    b=str(r["building_id"]);all_rows[b]+=1
    a=standardize(r.get("apartment"))
    if a:unit_labels[b].add(a)
    else:unknown[b]+=1
ratios={}
for b in tie:
    units=class_a_units(b)
    ratios[b]=len(unit_labels[b])/units if units>0 else None
ranked_tie=sorted(tie,key=lambda b:(ratios[b] is None,-(ratios[b] or 0),b))
prediction=above|set(ranked_tie[:50-len(above)])
unmatched_high=sorted(above-sel)
unmatched_tie=sorted(tie-sel)
res={
 "utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),
 "registered_eligible":len(qualified),"AEP_excluded":len(qualified&active_aep),
 "class_A_lt_3_excluded":len(one_two),"missing_building_registry":len(missing_registry),
 "prior_2022_HSP_excluded_proxy":len(prior_again),
 "controls":{"selected_missed_by_class_screen":len(sel&one_two),
             "selected_missed_by_2022_HSP_screen":len(sel&prior_again)},
 "stages":stages,"final_cutoff":cut,
 "final_eligible_population":len(final),"above":len(above),"ties":len(tie),
 "final_selected_high":len(sel&above),"final_selected_in_tie":len(sel&tie),
 "prediction_overlap":len(prediction&sel),"false_included":len(prediction-sel),
 "official_selected_not_predicted":len(sel-prediction),
 "remaining_unselected_high":[alias(b) for b in unmatched_high],
 "remaining_unselected_tie":[alias(b) for b in unmatched_tie],
 "unmatched_selected":[alias(b) for b in sorted(sel-prediction)],
 "tie_ordered":[{"case":alias(b),"selected":b in sel,"violations":score[b],
   "legal_class_A_units_current":class_a_units(b),
   "distinct_apartment_labels":len(unit_labels[b]),"unknown_apartment_rows":unknown[b],
   "ratio":round(ratios[b],5) if ratios[b] is not None else None,
   "prior_2022_HSP":b in prior2022}
    for b in ranked_tie],
 "methodological_warnings":[
 "LEGAL CLASS A less than 3 is a current building-level administrative proxy, not an archived 2024 decision.",
 "Prior 2022 participation is not a statutory exclusion in section 56-02(b); it is a four-year-treatment duration proxy.",
 "The source may omit case-specific exclusions such as 7A administrator appointment or in-rem foreclosure.",
 "2024 official selection need not be fully deterministic because rule says criteria including but not limited to.",
 "Complaint apartment identifiers may be missing, incorrectly spelled or privacy-suppressed.",
 "No inference about actual administrative noncompliance or causal effects can be drawn."]}
print("RESULT_BEGIN",flush=True)
print(json.dumps(res,indent=2,sort_keys=True),flush=True)
print("RESULT_END",flush=True)
