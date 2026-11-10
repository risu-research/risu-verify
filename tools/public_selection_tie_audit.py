"""Audit ranking ties and unresolved selected cases in public municipal open data.

Read-only official Socrata queries. Output uses hashed, pseudonymous case labels.
No owner or apartment identifiers appear in logs; no causal conclusions.
"""
import collections,datetime,hashlib,json,time,urllib.parse,urllib.request
ROOT="https://data.cityofnewyork.us/resource/"
def get(ds,p):
    url=ROOT+ds+".json?"+urllib.parse.urlencode(p)
    for attempt in range(3):
        try:
            req=urllib.request.Request(url,headers={"User-Agent":"OpenDataRuleValidation/1.0"})
            with urllib.request.urlopen(req,timeout=160) as f:return json.load(f)
        except Exception:
            if attempt==2:raise
            time.sleep(3*(attempt+1))
def alias(x):return hashlib.sha256(("rank-2024:"+str(x)).encode()).hexdigest()[:10]
def ap(s):
    if s is None:return None
    s=" ".join(str(s).strip().upper().replace("#","").replace("APARTMENT","").replace("APT","").split())
    return s if s not in ("","BLDG","BUILDING","PUBLIC AREA","COMMON AREA","ALL","LOBBY","UNKNOWN","N/A") else None
def bbl(row):
    try:return str(int(row["boroid"]))+str(int(row["block"])).zfill(5)+str(int(row["lot"])).zfill(4)
    except (KeyError,ValueError,TypeError):return None
def count_group(ds,key,date,start,end,extra,expr):
    where=date+" >= '"+start+"T00:00:00' AND "+date+" < '"+end+"T00:00:00'"+extra
    out=get(ds,{"$select":key+","+expr+" as n","$where":where,"$group":key,"$limit":50000})
    assert len(out)<50000,"truncated count group"
    return {str(x[key]):int(x["n"]) for x in out}
hsp=get("h4mf-f24e",{"$limit":500})
selected={str(x["building_id"]) for x in hsp if str(x.get("program_start_date","")).startswith("2024")}
assert len(selected)==50
v,c={},{}
for y,start,end in [("22","2022-10-01","2023-06-01"),("23","2023-10-01","2024-06-01")]:
    v[y]=count_group("wvxf-dwi5","buildingid","novissueddate",start,end,
       " AND (novdescription like '%27-2029%' OR novdescription like '%27-2028%')","count(*)")
    c[y]=count_group("ygpa-z7cr","building_id","received_date",start,end,
       " AND major_category='HEAT/HOT WATER' AND apartment is not null","count(distinct apartment)")
    print("AGGREGATION",y,len(v[y]),len(c[y]),flush=True)
base=set(v["22"])&set(v["23"])&set(c["22"])&set(c["23"])
eligible={x for x in base if v["22"][x]+v["23"][x]>=4 and c["22"][x]>=2 and c["23"][x]>=2}
score={x:v["22"].get(x,0)+v["23"].get(x,0) for x in eligible}
aep=get("hcir-3275",{"$select":"building_id,aep_start_date,discharge_date","$limit":6000})
excluded={str(x["building_id"]) for x in aep if x.get("aep_start_date")
    and str(x["aep_start_date"])[:10]<="2024-07-01"
    and (not x.get("discharge_date") or str(x["discharge_date"])[:10]>"2024-07-01")}
pool=eligible-excluded
basic=sorted(pool,key=lambda x:(-score[x],x))
cut=score[basic[49]]
above={x for x in pool if score[x]>cut}
tie={x for x in pool if score[x]==cut}
assert cut==9 and len(tie)==17,(cut,len(tie))
original=set(basic[:50])
missed=selected-original
target=tie|missed
reg=get("kj4p-ruqc",{"$select":"buildingid,boroid,block,lot,managementprogram,dobbuildingclassid",
    "$where":"buildingid in ("+",".join(sorted(target))+")","$limit":200})
register={str(r["buildingid"]):r for r in reg}
bs=sorted({bbl(r) for r in reg if bbl(r)})
pluto={};pluto_error=None
try:
    p=get("64uk-42ks",{"$select":"bbl,unitsres","$where":"bbl in ("+",".join(bs)+")","$limit":300})
    pluto={str(int(float(z["bbl"]))):int(float(z["unitsres"])) for z in p
           if z.get("bbl") and z.get("unitsres") not in (None,"")}
except Exception as e:
    pluto_error=type(e).__name__+": "+str(e)[:140]
units_selected={str(x["building_id"]):int(x["total_units"]) for x in hsp
   if x.get("total_units") and str(x["building_id"]) in selected}
rows=get("ygpa-z7cr",{"$select":"building_id,apartment,received_date,problem_duplicate_flag",
 "$where":"building_id in ("+",".join(sorted(tie))+") AND received_date >= '2022-10-01T00:00:00' AND received_date < '2024-06-01T00:00:00' AND major_category='HEAT/HOT WATER'",
 "$limit":40000})
assert len(rows)<40000,"truncated apartment rows"
apts=collections.defaultdict(set)
raw=collections.Counter();unknown=collections.Counter()
for r in rows:
    k=str(r["building_id"]);raw[k]+=1
    n=ap(r.get("apartment"))
    if n:apts[k].add(n)
    else:unknown[k]+=1
tie_info={}
for x in tie:
    lot=bbl(register.get(x,{}))
    den=units_selected.get(x) or pluto.get(lot)
    ratio=(len(apts[x])/den if den and den>0 else None)
    tie_info[x]={"case":alias(x),"actual_selected":x in selected,
       "prior_violations":score[x],"complaining_unit_labels":len(apts[x]),
       "unknown_apartment_rows":unknown[x],"all_heat_problem_rows":raw[x],
       "dwelling_units_proxy":den,
       "denominator_source":"HSP_building" if x in units_selected else
          "current_PLUTO_tax_lot" if den else "missing",
       "priority_share":round(ratio,5) if ratio is not None else None,
       "invalid_share_above_1":bool(ratio is not None and ratio>1)}
ordered=sorted(tie,key=lambda x:(
    tie_info[x]["priority_share"] is None,
    -(tie_info[x]["priority_share"] or 0),x))
priority_pred=above|set(ordered[:50-len(above)])
unreproduced=[]
for x in sorted(missed,key=lambda a:(-score[a],a)):
    unreproduced.append({"case":alias(x),"violation_proxy":score[x],
        "2022_violations":v["22"].get(x,0),"2023_violations":v["23"].get(x,0),
        "2022_affected_apartment_labels":c["22"].get(x,0),
        "2023_affected_apartment_labels":c["23"].get(x,0),
        "reason_class":"tie_order_unresolved" if x in tie else
          "higher_rank_displacement_or_nonreproduced_exclusion" if x in above else "other",
        "in_tie_proxy_top50":x in priority_pred,
        "registry_management":register.get(x,{}).get("managementprogram"),
        "registry_class_id":register.get(x,{}).get("dobbuildingclassid")})
out={"checked_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),
   "qualified_eligible":len(pool),"rank_cutoff":cut,
   "rank_strictly_above":len(above),"rank_tied":len(tie),
   "selected_above":len(selected&above),"selected_tied":len(selected&tie),
   "unselected_above":len(above-selected),"unselected_tied":len(tie-selected),
   "original_top50_overlap":len(selected&original),
   "priority_proxy_top50_overlap":len(selected&priority_pred),
   "tie_affected_apartment_rows":len(rows),
   "tie_missing_denominator":sum(tie_info[x]["dwelling_units_proxy"] is None for x in tie),
   "tie_cases":[tie_info[x] for x in ordered],
   "ten_original_missed_selected_cases":unreproduced,
   "pluto_error":pluto_error,
   "notes":["Priority ratio uses distinct normalized dwelling-unit labels over two lookback seasons.",
    "Current PLUTO residential units refer to a tax lot, not necessarily a building; historical denominator unavailable.",
    "Unknown dwelling-unit labels and duplicate unit spellings limit exact numerator.",
    "The legal ranking includes other exclusions and uses criteria including but not limited to published conditions.",
    "Prioritization is a sensitivity check, not a validated official selection reconstruction."]}
print("RESULT_BEGIN",flush=True);print(json.dumps(out,indent=2,sort_keys=True),flush=True);print("RESULT_END",flush=True)
