#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json, os, subprocess, sys, time, urllib.error, urllib.request
from pathlib import Path

def cb(v):
    return (json.dumps(v, sort_keys=True, separators=(",",":"), ensure_ascii=False) + "\n").encode()

def sha256(b):
    return hashlib.sha256(b).hexdigest()

def run(cmd):
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return p.returncode, p.stdout, p.stderr

def send_json(endpoint: str, body: dict, headers: dict, retries: int, error_path: Path):
    data = json.dumps(body, sort_keys=False, separators=(",",":"), ensure_ascii=False).encode()
    retryable_http = {408, 409, 425, 429, 500, 502, 503, 504}
    attempts = 0
    last = {"kind":"NO_ATTEMPT"}
    while attempts <= retries:
        attempts += 1
        req = urllib.request.Request(endpoint, data=data, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                raw = r.read()
                return {"ok": True, "attempts": attempts, "http_status": int(r.status), "raw": raw}
        except urllib.error.HTTPError as e:
            raw = e.read()
            error_path.write_bytes(raw)
            last = {"kind":"HTTPError","http_status":int(e.code),"error_response_sha256":sha256(raw),"error_response_size":len(raw)}
            if e.code not in retryable_http or attempts > retries:
                break
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            last = {"kind":type(e).__name__}
            if attempts > retries:
                break
        if attempts <= retries:
            time.sleep(min(5, attempts * 2))
    return {"ok":False,"attempts":attempts,**last}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".")
    ap.add_argument("--protocol", required=True)
    ap.add_argument("--preflight", required=True)
    ap.add_argument("--outdir", required=True)
    a = ap.parse_args()

    root = Path(a.root).resolve()
    out = Path(a.outdir).resolve()
    out.mkdir(parents=True, exist_ok=True)
    protocol = json.loads(Path(a.protocol).read_bytes())
    pf = json.loads(Path(a.preflight).read_bytes())

    base = {
        "schema":"risu.e2-gate2d-d3-provider-smoke/v0.1",
        "status":"FAIL",
        "preflight_status":pf.get("status"),
        "provider_request_count":0,
        "lanes":{},
        "semantic_outcomes_used_for_d3_success":False,
        "epistemic10_read":False,
        "truth_read":False,
        "fresh_target_read":False,
        "mutation_algebra_opened":False,
        "gate2e_authorized":False,
    }
    if pf.get("status") != "PASS":
        base["status"] = "SKIPPED_PRE_PROVIDER_PREFLIGHT_FAIL"
        (out / "D3_PROVIDER_SMOKE.json").write_bytes(cb(base))
        return

    smoke_root = out / "smoke_root"
    fixture = protocol["b3_provider_smoke"]["fixture"]
    fpath = smoke_root / fixture["path"]
    fpath.parent.mkdir(parents=True, exist_ok=True)
    fpath.write_text(fixture["content"], encoding="utf-8")
    manifest = protocol["b3_provider_smoke"]["manifest"]
    manifest_path = out / "D3_SMOKE_MANIFEST.json"
    manifest_path.write_bytes(cb(manifest))

    builder = root / "tools/e2_gate2d_llm_request_builder.py"
    normalizer = root / "tools/e2_gate2d_llm_response_normalizer.py"
    prompt = root / "evaluation/gate2d/B3_LLM_PROMPT_v0.1.txt"
    schema = root / "evaluation/gate2d/B3_LLM_RESPONSE_SCHEMA_v0.1.json"
    config = root / "evaluation/gate2d/B3_LLM_CONFIG_v0.1.json"
    cfg = json.loads(config.read_bytes())

    for pname in ("openai","anthropic"):
        lane_spec = protocol["b3_provider_smoke"]["required_lanes"][pname]
        lane = {
            "lane_id":lane_spec["lane_id"],
            "request_built":False,
            "credential_present":False,
            "provider_request_emitted":False,
            "transport_ok":False,
            "semantically_valid_response":False,
        }
        req_path = out / f"D3_{pname.upper()}_REQUEST.json"
        rc, so, se = run([
            sys.executable, str(builder),
            "--provider", pname,
            "--root", str(smoke_root),
            "--manifest", str(manifest_path),
            "--prompt", str(prompt),
            "--schema", str(schema),
            "--config", str(config),
            "--output", str(req_path),
        ])
        if rc != 0 or not req_path.is_file():
            lane["builder_failure"] = True
            lane["builder_returncode"] = rc
            base["lanes"][pname] = lane
            continue

        req = json.loads(req_path.read_bytes())
        lane["request_built"] = True
        lane["request_sha256"] = sha256(req_path.read_bytes())
        lane["visible_input_bytes"] = req.get("visible_input_bytes")
        identity_ok = (
            req.get("provider") == pname and
            req.get("lane_id") == lane_spec["lane_id"] and
            req.get("endpoint") == lane_spec["endpoint"] and
            (req.get("body") or {}).get("model") == lane_spec["model"] and
            (req.get("headers_template") or {}).get("Content-Type") == "application/json"
        )
        lane["request_identity_exact"] = identity_ok
        if not identity_ok:
            base["lanes"][pname] = lane
            continue

        secret_name = lane_spec["secret_env"]
        key = os.environ.get(secret_name, "")
        if not key:
            lane["credential_missing"] = True
            base["lanes"][pname] = lane
            continue
        lane["credential_present"] = True

        headers = {"Content-Type":"application/json"}
        if pname == "openai":
            if req["headers_template"].get("Authorization") != "Bearer ${OPENAI_API_KEY}":
                lane["header_template_mismatch"] = True
                base["lanes"][pname] = lane
                continue
            headers["Authorization"] = "Bearer " + key
        else:
            pc = cfg["providers"]["anthropic"]
            if req["headers_template"].get("x-api-key") != "${ANTHROPIC_API_KEY}" or req["headers_template"].get("anthropic-version") != pc["anthropic_version"]:
                lane["header_template_mismatch"] = True
                base["lanes"][pname] = lane
                continue
            headers["x-api-key"] = key
            headers["anthropic-version"] = pc["anthropic_version"]

        err_path = out / f"D3_{pname.upper()}_TRANSPORT_ERROR_RESPONSE.bin"
        tr = send_json(req["endpoint"], req["body"], headers, int(cfg["providers"][pname]["transport_retry_cap"]), err_path)
        lane["provider_request_emitted"] = True
        base["provider_request_count"] += 1
        lane["transport_attempt_count"] = tr.get("attempts")
        if not tr.get("ok"):
            lane["transport_error_type"] = tr.get("kind")
            if "http_status" in tr:
                lane["http_status"] = tr["http_status"]
            if "error_response_sha256" in tr:
                lane["error_response_sha256"] = tr["error_response_sha256"]
                lane["error_response_size"] = tr["error_response_size"]
            base["lanes"][pname] = lane
            continue

        lane["transport_ok"] = True
        lane["http_status"] = tr["http_status"]
        raw = tr["raw"]
        raw_path = out / f"D3_{pname.upper()}_RAW_RESPONSE.json"
        raw_path.write_bytes(raw)
        lane["raw_response_sha256"] = sha256(raw)
        lane["raw_response_size"] = len(raw)

        norm_path = out / f"D3_{pname.upper()}_NORMALIZED.json"
        rc, so, se = run([sys.executable,str(normalizer),"--provider",pname,"--response",str(raw_path),"--output",str(norm_path)])
        if rc != 0 or not norm_path.is_file():
            lane["normalizer_failure"] = True
            lane["normalizer_returncode"] = rc
            base["lanes"][pname] = lane
            continue
        norm_b = norm_path.read_bytes()
        norm = json.loads(norm_b)
        lane["normalized_sha256"] = sha256(norm_b)
        lane["normalizer_baseline_id_exact"] = norm.get("baseline_id") == lane_spec["lane_id"]
        lane["semantically_valid_response"] = lane["normalizer_baseline_id_exact"] and norm.get("normalized_outcome") != "BASELINE_INVALID"
        base["lanes"][pname] = lane

    base["status"] = "PASS" if set(base["lanes"]) == {"openai","anthropic"} and all(base["lanes"][p].get("semantically_valid_response") is True for p in ("openai","anthropic")) else "FAIL"
    (out / "D3_PROVIDER_SMOKE.json").write_bytes(cb(base))

if __name__ == "__main__":
    main()
