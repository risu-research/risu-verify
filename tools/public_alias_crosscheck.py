"""Inspect two 2025 notice/live-data address discrepancies via official identifiers."""
import json,urllib.request,urllib.parse
def get(ds,p):
 u="https://data.cityofnewyork.us/resource/"+ds+".json?"+urllib.parse.urlencode(p)
 with urllib.request.urlopen(urllib.request.Request(u,headers={"User-Agent":"CivicIdentifierQA/1.0"}),timeout=100) as r:return json.load(r)
h=get("h4mf-f24e",{"$where":"program_start_date >= '2025-01-01T00:00:00' AND program_start_date < '2026-01-01T00:00:00'","$limit":100})
target=[x for x in h if (str(x.get("number",""))=="70" and "128" in x.get("street","")) or (str(x.get("number",""))=="2915")]
out=[]
for x in target:
 out.append({"api_primary_address":str(x.get("number"))+" "+str(x.get("street")),
     "borough":x.get("borough"),"total_units":x.get("total_units"),
     "building_id":x.get("building_id"),"BIN":x.get("bin"),"BBL":x.get("bbl"),
     "program_start_date":x.get("program_start_date")})
print(json.dumps({"source":"NYC public HSP API","records":out,
 "official_2025_pdf_discrepancy_1":"354 Lenox Avenue vs 70 West 128 Street",
 "official_2025_pdf_discrepancy_2":"2915 Claredon Road vs 2915 Clarendon Road",
 "caution":"Same BIN/BBL for different addresses requires independent municipal alias reference for as-of status."},indent=2))
