"""Reusable public JSON endpoint schema smoke test (stdlib only)."""
import json
import urllib.request
from datetime import datetime, timezone

URL = "https://data.cityofnewyork.us/resource/h4mf-f24e.json?$limit=1"
request = urllib.request.Request(URL, headers={"User-Agent": "PublicDataSchemaCheck/1.0"})
with urllib.request.urlopen(request, timeout=35) as response:
    rows = json.load(response)
assert isinstance(rows, list), "Expected a JSON array"
assert rows, "Expected at least one record"
assert isinstance(rows[0], dict), "Expected object records"
print(json.dumps({
    "checked_at": datetime.now(timezone.utc).isoformat(),
    "endpoint": URL.split("?")[0],
    "sample_records": len(rows),
    "fields": sorted(rows[0]),
}, indent=2))
