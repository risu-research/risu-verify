"""Probe official housing-case schema for reproducible exclusion analysis."""
import json,urllib.request
base="https://data.cityofnewyork.us/api/views/"
for ds in ["59kj-x8nc","kj4p-ruqc","64uk-42ks"]:
    req=urllib.request.Request(base+ds+".json",headers={"User-Agent":"PublicLawDataProvenanceQA/1.0"})
    with urllib.request.urlopen(req,timeout=90) as r:
        obj=json.load(r)
    fields=[{"name":x.get("fieldName"),"type":x.get("dataTypeName")} for x in obj.get("columns",[]) if x.get("fieldName") and not x["fieldName"].startswith(":")]
    print(json.dumps({"dataset":ds,"fields":fields},indent=2),flush=True)
