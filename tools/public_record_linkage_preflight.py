"""Public-sector data source and join-key preflight; read-only aggregated diagnostics."""
import collections
import datetime
import json
import urllib.parse
import urllib.request

BASE = "https://data.cityofnewyork.us"
SOURCES = {"cohort": "h4mf-f24e", "events": "ygpa-z7cr", "enforcement": "wvxf-dwi5"}
HEADERS = {"User-Agent": "OpenDataCompatibilityCheck/1.0"}

def get(path, **params):
    url = BASE + path
    if params:
        url += "?" + urllib.parse.urlencode(params)
    request = urllib.request.Request(url, headers=HEADERS)
    with urllib.request.urlopen(request, timeout=75) as response:
        return json.load(response)

def fields(dataset):
    metadata = get("/api/views/" + dataset + ".json")
    return [c["fieldName"] for c in metadata.get("columns", [])
            if c.get("fieldName") and not c["fieldName"].startswith(":")]

def main():
    out = {"checked_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
           "schema": {}, "cohort": {}, "sample_link": {}}
    for label, dataset in SOURCES.items():
        f = fields(dataset)
        out["schema"][label] = {"dataset": dataset, "fields": sorted(f)}
    rows = get("/resource/" + SOURCES["cohort"] + ".json", **{"$limit": "500"})
    ids = [str(r.get("building_id", "")) for r in rows]
    dates = collections.Counter(str(r.get("program_start_date", ""))[:4] for r in rows)
    out["cohort"] = {"records": len(rows), "unique_ids": len(set(ids)),
                     "missing_ids": sum(not x for x in ids), "year_counts": dict(sorted(dates.items())),
                     "status_counts": dict(collections.Counter(r.get("current_status", "MISSING") for r in rows))}
    first = [x for x in ids if x.isdigit()][:5]
    for label in ("events", "enforcement"):
        f = out["schema"][label]["fields"]
        key = next((key for key in ("building_id", "buildingid") if key in f), None)
        out["sample_link"][label] = {"join_field": key}
        if key and first:
            clause = key + " in (" + ",".join(first) + ")"
            try:
                response = get("/resource/" + SOURCES[label] + ".json",
                               **{"$select": "count(*) as n", "$where": clause})
                out["sample_link"][label]["five_building_rows"] = int(response[0]["n"])
            except Exception as ex:
                out["sample_link"][label]["error"] = type(ex).__name__ + ": " + str(ex)[:160]
    print(json.dumps(out, indent=2, sort_keys=True))

if __name__ == "__main__":
    main()
