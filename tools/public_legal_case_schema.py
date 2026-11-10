"""Probe official housing-case schema for reproducible exclusion analysis."""
import json,urllib.request
base="https://data.cityofnewyork.us/api/views/"
for ds in ["59kj-x8nc","kj4p-ruqc","64uk-42ks"]:
    req=urllib.request.Request(base+ds+".json",headers={"User-Agent":"PublicLawDataProvenanceQA/1.0"})
    with urllib.request.urlopen(req,timeout=90) as r:
        obj=json.load(r)
    fields=[{"name":x.get("fieldName"),"type":x.get("dataTypeName")} for x in obj.get("columns",[]) if x.get("fieldName") and not x["fieldName"].startswith(":")]
    print(json.dumps({"dataset":ds,"fields":fields},indent=2),flush=True)

# Aggregate-only outcome labels for 7A proceedings. Court appointment is NOT inferred from filing.
import urllib.parse
params={"$select":"casestatus,casejudgement,count(*) as n",
 "$where":"casetype='7A'",
 "$group":"casestatus,casejudgement","$limit":300}
q="https://data.cityofnewyork.us/resource/59kj-x8nc.json?"+urllib.parse.urlencode(params)
try:
    with urllib.request.urlopen(urllib.request.Request(q,headers={"User-Agent":"PublicLawDataProvenanceQA/1.0"}),timeout=110) as r:
        print(json.dumps({"7a_proceedings_outcome_labels":json.load(r)},indent=2))
except Exception as exc:
    print(json.dumps({"7a_outcomes_query_error":type(exc).__name__+":"+str(exc)[:160]}))

# Actual observed case type vocabulary, including spelling/case.
params={"$select":"casetype,count(*) as n","$group":"casetype","$order":"n DESC","$limit":100}
q="https://data.cityofnewyork.us/resource/59kj-x8nc.json?"+urllib.parse.urlencode(params)
with urllib.request.urlopen(urllib.request.Request(q,headers={"User-Agent":"PublicLawDataProvenanceQA/1.0"}),timeout=110) as r:
    print(json.dumps({"observed_litigation_case_types":json.load(r)},indent=2))
