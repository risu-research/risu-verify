"""Official source verification of a historic address/denominator discrepancy."""
import json,urllib.request,urllib.parse
def get(ds,p):
 u="https://data.cityofnewyork.us/resource/"+ds+".json?"+urllib.parse.urlencode(p)
 with urllib.request.urlopen(urllib.request.Request(u,headers={"User-Agent":"PublicHistoricUnitQA/1.0"}),timeout=120) as r:return json.load(r)
b=get("kj4p-ruqc",{"$select":"buildingid,bin,bbl,legalclassa,legalclassb,dobbuildingclass,boro,housenumber,streetname",
 "$where":"bbl='1017250069' OR bin=1053660","$limit":100})
h=get("h4mf-f24e",{"$where":"bin=1053660","$limit":20})
print(json.dumps({"registry_records_same_tax_lot_or_BIN":b,"HSP_records_BIN":h,
 "external_official_PDF_2025":{"street":"354 LENOX AVENUE","reported_number_of_units":9},
 "caveat":"A shared BIN/BBL and alternate address do not prove historic registered dwelling-unit denominator was 9 or 18 at selection date."},indent=2))
