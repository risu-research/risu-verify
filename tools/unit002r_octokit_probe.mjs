#!/usr/bin/env node
import { pathToFileURL } from "node:url";
import { resolve } from "node:path";
import { writeFile } from "node:fs/promises";

const [targetRootArg, outputArg] = process.argv.slice(2);
if (!targetRootArg || !outputArg) {
  console.error("usage: node tools/unit002r_octokit_probe.mjs <target-root> <output-json>");
  process.exit(2);
}

const TARGET_REVISION = "cd9cb8cd4965d99c7dac8c87d249308956250be3";
const targetRoot = resolve(targetRootArg);
const output = resolve(outputArg);
const moduleUrl = pathToFileURL(resolve(targetRoot, "pkg/dist-src/index.js")).href;
const { Octokit } = await import(moduleUrl);

function normalizeBody(body) {
  if (body == null || body === "") return null;
  if (typeof body === "string") return JSON.parse(body);
  throw new Error(`unexpected request body type: ${typeof body}`);
}

async function exercise(status) {
  const calls = [];
  const fetch = async (url, init = {}) => {
    calls.push({
      url: String(url),
      method: String(init.method || "GET").toUpperCase(),
      body: normalizeBody(init.body),
      content_type: new Headers(init.headers || {}).get("content-type"),
    });
    const data =
      status === 200
        ? { sha: "MERGE_COMMIT", merged: true, message: "Pull Request successfully merged" }
        : { message: "Head branch was modified" };
    return new Response(JSON.stringify(data), {
      status,
      headers: { "content-type": "application/json; charset=utf-8" },
    });
  };

  const octokit = new Octokit({ request: { fetch } });
  let outcome;
  try {
    const response = await octokit.rest.pulls.merge({
      owner: "owner",
      repo: "repo",
      pull_number: 7,
      sha: "H0",
    });
    outcome = { kind: "RESOLVED", status: response.status };
  } catch (error) {
    outcome = {
      kind: "REJECTED",
      status: Number(error?.status),
      name: String(error?.name || ""),
    };
  }

  if (calls.length !== 1) throw new Error(`expected exactly one fetch call, saw ${calls.length}`);
  const call = calls[0];
  if (call.method !== "PUT") throw new Error(`expected PUT, saw ${call.method}`);
  if (call.url !== "https://api.github.com/repos/owner/repo/pulls/7/merge") {
    throw new Error(`unexpected URL: ${call.url}`);
  }
  if (JSON.stringify(call.body) !== JSON.stringify({ sha: "H0" })) {
    throw new Error(`sha was not preserved as sole non-path body field: ${JSON.stringify(call.body)}`);
  }
  if (call.content_type !== "application/json; charset=utf-8") {
    throw new Error(`unexpected content-type: ${call.content_type}`);
  }

  if (status === 200 && !(outcome.kind === "RESOLVED" && outcome.status === 200)) {
    throw new Error(`200 path did not resolve normally: ${JSON.stringify(outcome)}`);
  }
  if (status === 409 && !(outcome.kind === "REJECTED" && outcome.status === 409)) {
    throw new Error(`409 path did not reject with status 409: ${JSON.stringify(outcome)}`);
  }
  return { mocked_provider_status: status, request: call, client_outcome: outcome };
}

const success = await exercise(200);
const mismatch = await exercise(409);

const result = {
  schema: "risu.unit002-r-target-qualification/v0.1alpha1",
  qualification_id: "UNIT002_R_OCTOKIT_MERGE_SHA_CARRIER_001",
  unit_id: "corpus01-unit-002",
  target: {
    repository: "octokit/rest.js",
    revision: TARGET_REVISION,
    operation: "octokit.rest.pulls.merge",
  },
  mode: "TARGET_ONLY_BLACK_BOX_WITH_MOCK_PROVIDER_RESPONSE",
  provider_live_service_contacted: false,
  primary_risu_verifier_executed: false,
  reviewed_sha: "H0",
  observations: {
    success_path: success,
    stale_path: mismatch,
  },
  assertions: {
    single_request_per_invocation: true,
    merge_route_exact: true,
    method_put: true,
    reviewed_sha_preserved_in_json_body: true,
    success_200_resolves: true,
    mismatch_409_rejects: true,
    no_silent_retry_observed: true,
  },
  claim_boundary: {
    establishes: [
      "pinned target runtime exposes the merge route through the built Octokit client",
      "sha=H0 survives the selected client path into the JSON request body",
      "a 409 provider response is surfaced as a rejected client operation rather than success"
    ],
    does_not_establish: [
      "live GitHub provider conformance",
      "which response the live provider returns in any real pull request state",
      "RISU semantic preservation verdict"
    ]
  },
  status: "PASS"
};

await writeFile(output, JSON.stringify(result, null, 2) + "\n", "utf8");
console.log(JSON.stringify(result, null, 2));
