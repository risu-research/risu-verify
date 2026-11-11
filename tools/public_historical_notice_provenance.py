"""Independent provenance audit of dated municipal program designation notices.

Read-only retrieval of public official PDFs and public current dataset; captures hashes,
metadata, and 50-record census counts. Published list != historical scoring inputs.
"""
import collections
import datetime
import hashlib
import json
import pathlib
import re
import urllib.request

import pdfplumber

BASE="https://www.nyc.gov/assets/hpd/downloads/pdfs/services/"
YEARS=(2024,2025)
OUT=pathlib.Path("build/historical_notices")
OUT.mkdir(parents=True,exist_ok=True)
def normalize(value):
    t=re.sub(r"[^A-Z0-9-]+"," ",str(value).upper()).strip()
    t=re.sub(r"\bSTREET\b","ST",t)
    t=re.sub(r"\bAVENUE\b","AVE",t)
    t=re.sub(r"\bBOULEVARD\b","BLVD",t)
    t=re.sub(r"\s+"," ",t).strip()
    return t
def get(url):
    req=urllib.request.Request(url,headers={"User-Agent":"PublicCivicRecordsProvenance/1.0"})
    with urllib.request.urlopen(req,timeout=65) as r:return r.read(),dict(r.headers)
def count_rows(path):
    found=[]
    with pdfplumber.open(path) as pdf:
        meta=pdf.metadata
        for page in pdf.pages:
            for table in page.extract_tables() or []:
                for row in table:
                    cells=[" ".join(str(x or "").split()) for x in row]
                    if cells and cells[0].strip() in {"BK","BX","MN","QN","SI"}:
                        found.append(cells)
        return found,meta,len(pdf.pages)
def check_current(rows,year):
    url="https://data.cityofnewyork.us/resource/h4mf-f24e.json?$limit=500"
    b,_=get(url)
    current=json.loads(b)
    relevant=[r for r in current if str(r.get("program_start_date","")).startswith(str(year))]
    code={"BRONX":"BX","BROOKLYN":"BK","MANHATTAN":"MN","QUEENS":"QN","STATEN ISLAND":"SI",
          "BX":"BX","BK":"BK","MN":"MN","QN":"QN","SI":"SI"}
    k=lambda b,h,s:(b,normalize(h),normalize(s))
    s1={k(r[0],r[1],r[2]):r for r in rows if len(r)>=3}
    s2={k(code.get(str(r.get("borough","")).upper(),r.get("borough","")),r.get("number",""),r.get("street","")):r for r in relevant}
    overlap=set(s1)&set(s2)
    unmatched_notice=sorted(set(s1)-set(s2))
    unmatched_api=sorted(set(s2)-set(s1))
    return {"official_rows":len(s1),"api_cohort_rows":len(relevant),
      "match_normalized_keys":len(overlap),
      "not_matched_official_count":len(unmatched_notice),
      "not_matched_api_count":len(unmatched_api),
      "unmatched_official_examples":unmatched_notice[:8],
      "unmatched_api_examples":unmatched_api[:8],
      "note":"Address normalization is conservative; mismatches may be naming differences."}
manifest={"checked_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),
          "sources":{},"purpose":"Document authenticity and independent published list validation"}
for year in YEARS:
    url=BASE+"heat-sensor-program-building-list-"+str(year)+".pdf"
    body,headers=get(url)
    target=OUT/("official_selection_"+str(year)+".pdf")
    target.write_bytes(body)
    rows,meta,pages=count_rows(target)
    rec={"official_url":url,"file_sha256":hashlib.sha256(body).hexdigest(),
      "file_size_bytes":len(body),"http_last_modified":headers.get("Last-Modified"),
      "http_etag":headers.get("ETag"),"pdf_metadata_creation":meta.get("CreationDate"),
      "pdf_metadata_modification":meta.get("ModDate"),
      "pdf_page_count":pages,"extracted_table_rows":len(rows),
      "borough_counts":dict(collections.Counter(r[0] for r in rows)),
      "row_example_1":rows[0] if rows else None,
      "row_example_last":rows[-1] if rows else None}
    if rows:
        try:rec["comparison_to_current_API"]=check_current(rows,year)
        except Exception as e:rec["api_comparison_error"]=type(e).__name__+":"+str(e)[:200]
    manifest["sources"][str(year)]=rec
    print("YEAR",year,json.dumps(rec,sort_keys=True),flush=True)
(OUT/"manifest.json").write_text(json.dumps(manifest,indent=2,ensure_ascii=False)+"\n")
assert all(v["extracted_table_rows"]==50 for v in manifest["sources"].values()),"Review official PDF parse before claiming 50/50."
