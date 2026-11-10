"""Read-only cohort-to-record linkage audit against three public municipal APIs.

Uses aggregated Socrata queries, no apartment-level exports and no credentials.
Metrics are observations, not causal effects.
"""
import collections
import datetime as dt
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = "https://data.cityofnewyork.us/resource/"
COHORT, EVENTS, VIOL = "h4mf-f24e", "ygpa-z7cr", "wvxf-dwi5"
HEADERS = {"User-Agent": "OpenDataSchemaAudit/0.2"}
BATCH = 25

def read(dataset, **query):
    url = BASE + dataset + ".json?" + urllib.parse.urlencode(query)
    request = urllib.request.Request(url, headers=HEADERS)
    for attempt in range(3):
        try:
            with urllib.request.urlopen(request, timeout=105) as response:
                return json.load(response)
        except (urllib.error.URLError, TimeoutError) as exc:
            if attempt == 2:
                raise RuntimeError(type(exc).__name__ + ": " + str(exc)[:200]) from exc
            time.sleep(2 * (attempt + 1))

def groups(seq, n):
    for k in range(0, len(seq), n):
        yield seq[k:k + n]

def nval(item, name):
    return int(item.get(name, 0) or 0)

def aggregate(dataset, key, datefield, ids, count_column, category=False):
    records = []
    failures = []
    for i, ids_chunk in enumerate(groups(ids, BATCH), 1):
        condition = key + " in (" + ",".join(ids_chunk) + ")"
        condition += " AND " + datefield + " >= '2017-01-01T00:00:00'"
        condition += " AND " + datefield + " < '2026-11-01T00:00:00'"
        params = {
            "$select": key + ",date_extract_y(" + datefield + ") as yr,count(*) as n",
            "$where": condition,
            "$group": key + ",date_extract_y(" + datefield + ")",
            "$limit": "10000",
        }
        if count_column:
            params["$select"] += ",count(distinct " + count_column + ") as unique_events"
        try:
            data = read(dataset, **params)
            records.extend(data)
        except Exception as ex:
            failures.append({"batch": i, "error": str(ex)[:160]})
            print("BATCH_ERROR", dataset, i, str(ex)[:160], flush=True)
    year_counts = collections.Counter()
    year_unique = collections.Counter()
    linked = set()
    for row in records:
        linked.add(str(row[key]))
        year_counts[str(row["yr"])] += nval(row, "n")
        year_unique[str(row["yr"])] += nval(row, "unique_events")
    return {"batches": (len(ids)+BATCH-1)//BATCH,
            "failed_batches": failures,
            "linked_buildings": len(linked),
            "all_period_records": sum(year_counts.values()),
            "all_period_distinct_events_sum": sum(year_unique.values()) if count_column else None,
            "rows_by_year": dict(sorted(year_counts.items())),
            "distinct_events_by_year": dict(sorted(year_unique.items())) if count_column else None}

def main():
    cohort = read(COHORT, **{"$limit": "500"})
    ids = sorted({str(x["building_id"]) for x in cohort if str(x.get("building_id","")).isdigit()})
    year_cohort = collections.defaultdict(set)
    by_id = collections.defaultdict(list)
    for x in cohort:
        key = str(x.get("building_id", ""))
        year = str(x.get("program_start_date",""))[:4]
        year_cohort[year].add(key)
        by_id[key].append(year)
    duplicate_cohort_patterns = collections.Counter(
        "/".join(sorted(ys)) for ys in by_id.values() if len(ys) > 1)
    report = {"timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
              "source": "NYC public official API, read-only",
              "cohort_rows": len(cohort), "unique_buildings": len(ids),
              "cohort_year_unique": {k:len(v) for k,v in sorted(year_cohort.items())},
              "duplicate_cohort_patterns": dict(duplicate_cohort_patterns),
              "measurement_window": "2017-01-01 to 2026-10-31",
              "events": {}, "enforcement": {}}
    sample = sys.argv[1] != "--full" if len(sys.argv) > 1 else True
    if sample:
        ids = ids[:25]
        report["mode"] = "first_25_ids_probe"
    else:
        report["mode"] = "all_199_ids"
    report["event_query_cohort_size"] = len(ids)
    print("Start aggregated source queries. No case-level rows exported.", flush=True)
    for label, dataset, key, datefield, distinct in [
        ("events", EVENTS, "building_id", "received_date", "complaint_id"),
        ("enforcement", VIOL, "buildingid", "inspectiondate", None),
    ]:
        result = aggregate(dataset, key, datefield, ids, distinct)
        report[label] = result
        print("Completed", label, "with", result["linked_buildings"], "matched IDs",
              "and", len(result["failed_batches"]), "failed batches", flush=True)
    # Summary category composition for the selected cohort; low-bandwidth grouped counts.
    ids_clause = "building_id in (" + ",".join(ids) + ")"
    try:
        categories = read(EVENTS, **{"$select":"major_category,count(*) as n",
                 "$where":ids_clause, "$group":"major_category", "$order":"n DESC",
                 "$limit":"100"})
        report["event_categories"] = [{"category": r.get("major_category","MISSING"),
                      "problems": nval(r,"n")} for r in categories]
    except Exception as ex:
        report["event_categories_error"] = str(ex)[:180]
    print(json.dumps(report, sort_keys=True, indent=2), flush=True)
    if report["events"].get("failed_batches") or report["enforcement"].get("failed_batches"):
        raise SystemExit(2)

if __name__ == "__main__":
    main()
